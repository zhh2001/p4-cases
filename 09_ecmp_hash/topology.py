#!/usr/bin/env python3
"""Mininet topology for Case 09: ECMP hash.

One switch, three hosts (h1 is the traffic source; h2, h3 are the two
ECMP members). Test generates several UDP flows from h1 with
different (sport,dport) pairs so the 5-tuple hash produces different
ecmp_select values; we count how many land on h2 vs h3 and expect
both > 0 (i.e. the switch actually fanned traffic out).
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch  # noqa: E402


def host_ip(n: int) -> str:
    return f"10.0.0.{n}/24"


def host_mac(n: int) -> str:
    return f"00:00:00:00:00:{n:02d}"


class EcmpTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        for i in range(1, 4):
            self.addHost(f"h{i}", ip=host_ip(i), mac=host_mac(i))
            self.addLink(f"h{i}", sw)


def run_controller(controller_bin: str, p4info: str, config: str) -> subprocess.Popen:
    info("*** Launching Go controller\n")
    return subprocess.Popen(
        [controller_bin, "-addr", "127.0.0.1:9559", "-p4info", p4info, "-config", config],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def wait_ready(proc: subprocess.Popen, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else b""
        if not line:
            if proc.poll() is not None:
                return False
            time.sleep(0.05)
            continue
        decoded = line.decode(errors="replace").rstrip()
        info(f"    controller: {decoded}\n")
        if "ecmp ready" in decoded:
            return True
    return False


def populate_arp(net: Mininet) -> None:
    for i in range(1, 4):
        h = net.get(f"h{i}")
        for j in range(1, 4):
            if j == i:
                continue
            h.cmd(f"arp -s 10.0.0.{j} 00:00:00:00:00:{j:02d}")


def run_test(net: Mininet, n_flows: int = 20) -> int:
    """h1 sends n_flows UDP packets with distinct src-ports. We count
    arrivals on h2 and h3; expect both > 0."""
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")

    # Bring up sniffers on h2 and h3. They match any UDP with our
    # test payload prefix (the switch rewrites dst MAC but keeps the
    # IP intact, which stays 10.0.0.100 — not each host's own IP).
    sniff_script = (
        "from scapy.all import AsyncSniffer, UDP; "
        "s = AsyncSniffer(iface='{iface}', count={n}, timeout=5, "
        "lfilter=lambda p: UDP in p and p[UDP].dport == 5000 and bytes(p[UDP].payload).startswith(b'ecmp-test')); "
        "s.start(); s.join(); "
        "print(len(s.results or []))"
    )
    rx2 = h2.popen(
        ["python3", "-c", sniff_script.format(iface="h2-eth0", n=n_flows)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    rx3 = h3.popen(
        ["python3", "-c", sniff_script.format(iface="h3-eth0", n=n_flows)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    time.sleep(0.6)

    # h1 sends 20 UDP flows — each with a distinct sport. We alternate
    # the dst IP between h2 (which matches the direct /32) and a
    # non-h2-non-h3 address so the ECMP group is the one that routes
    # it. Actually for the test, we want the ECMP path to be exercised
    # specifically; use 10.0.0.100 (hits /24, which is the ECMP entry).
    h1.cmd(
        "python3 -c \""
        "from scapy.all import Ether, IP, UDP, sendp; "
        "[sendp(Ether(src='00:00:00:00:00:01',dst='00:00:00:00:00:01')/"
        "IP(src='10.0.0.1',dst='10.0.0.100',ttl=64)/"
        "UDP(sport=1000+i, dport=5000)/b'ecmp-test', "
        "iface='h1-eth0', verbose=False) for i in range({n})]\"".format(n=n_flows)
    )

    try:
        out2, _ = rx2.communicate(timeout=7)
    except subprocess.TimeoutExpired:
        rx2.kill()
        out2, _ = rx2.communicate()
    try:
        out3, _ = rx3.communicate(timeout=7)
    except subprocess.TimeoutExpired:
        rx3.kill()
        out3, _ = rx3.communicate()

    n2 = _last_int(out2)
    n3 = _last_int(out3)
    print(f"h2 received: {n2}/{n_flows}")
    print(f"h3 received: {n3}/{n_flows}")
    if n2 + n3 >= n_flows and n2 > 0 and n3 > 0:
        print(f"SUCCESS: ECMP distributed {n2 + n3}/{n_flows} flows across both members")
        return 0
    print(f"FAILURE: expected both paths to receive >0, got h2={n2} h3={n3}")
    return 1


def _last_int(b: bytes) -> int:
    for line in reversed((b or b"").decode(errors="replace").splitlines()):
        line = line.strip()
        if line.isdigit():
            return int(line)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=EcmpTopo(), controller=None)
    net.start()
    populate_arp(net)

    ctrl = run_controller(args.controller, args.p4info, args.config)
    if not wait_ready(ctrl):
        print("!!! controller did not reach ready state")
        if ctrl.stdout:
            print(ctrl.stdout.read().decode(errors="replace"))
        net.stop()
        sys.exit(2)

    rc = 0
    try:
        if args.run_test:
            rc = run_test(net)
        else:
            CLI(net)
    finally:
        info("*** Stopping controller\n")
        if ctrl.poll() is None:
            ctrl.send_signal(signal.SIGTERM)
            try:
                ctrl.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ctrl.kill()
        net.stop()

    sys.exit(rc)


if __name__ == "__main__":
    main()
