#!/usr/bin/env python3
"""Mininet topology for Case 10: Firewall ACL.

Single switch, two hosts (h1 = 10.0.0.1, h2 = 10.0.0.2). Tests drive
three flows and assert the DENY / ALLOW decisions:

  1. h1 -> h2  TCP/80    (allowed by rule 2 at prio 90)
  2. h1 -> h2  TCP/22    (denied by rule 1 at prio 100)
  3. h1 -> h2  UDP/5000  (denied by rule 3 at prio 80)
  4. h1 -> h2  UDP/1234  (allowed — no rule matches, default action)
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


class ACLTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        self.addLink(h1, sw)
        self.addLink(h2, sw)


def run_controller(controller_bin: str, p4info: str, config: str) -> subprocess.Popen:
    info("*** Launching Go controller\n")
    return subprocess.Popen(
        [controller_bin, "-addr", "127.0.0.1:9559", "-p4info", p4info, "-config", config],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
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
        if "firewall ready" in decoded:
            return True
    return False


def populate_arp(net: Mininet) -> None:
    h1 = net.get("h1")
    h2 = net.get("h2")
    h1.cmd("arp -s 10.0.0.2 00:00:00:00:00:02")
    h2.cmd("arp -s 10.0.0.1 00:00:00:00:00:01")


def probe(sender, iface_peer: str, proto: str, dport: int, n: int = 5) -> int:
    """Send n probes. Returns count received on peer."""
    # sniffer on peer
    script = (
        "from scapy.all import AsyncSniffer, TCP, UDP; "
        "s = AsyncSniffer(iface='{iface}', count={n}, timeout=3, "
        "lfilter=lambda p: ({proto} in p) and (p[{proto}].dport == {dport})); "
        "s.start(); s.join(); print(len(s.results or []))"
    ).format(iface=iface_peer, proto=proto, dport=dport, n=n)
    rx = sender.peer.popen(["python3", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(0.4)

    # sender blasts n probes
    layer = "TCP" if proto == "TCP" else "UDP"
    sender.cmd(
        "python3 -c \""
        "from scapy.all import Ether, IP, {layer}, sendp; "
        "[sendp(Ether(src='{smac}',dst='{dmac}')/"
        "IP(src='{sip}',dst='{dip}',ttl=64)/"
        "{layer}(sport=4000+i, dport={dport})/b'acl-probe', "
        "iface='{iface}', verbose=False) for i in range({n})]\"".format(
            layer=layer,
            smac=sender.mac, dmac=sender.peer_mac, sip=sender.ip, dip=sender.peer_ip,
            dport=dport, iface=sender.iface, n=n))
    try:
        out, _ = rx.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        rx.kill()
        out, _ = rx.communicate()
    for line in reversed((out or b"").decode(errors="replace").splitlines()):
        line = line.strip()
        if line.isdigit():
            return int(line)
    return 0


class Sender:
    """Convenience wrapper bundling the sender host + its peer for probe()."""
    def __init__(self, net: Mininet, me: str, peer: str, dst_ip: str, dst_mac: str):
        self.h = net.get(me)
        self.peer = net.get(peer)
        self.ip = self.h.IP()
        self.mac = self.h.MAC()
        self.iface = self.h.defaultIntf().name
        self.peer_ip = dst_ip
        self.peer_mac = dst_mac

    def cmd(self, c):
        return self.h.cmd(c)


def run_test(net: Mininet) -> int:
    populate_arp(net)
    s = Sender(net, "h1", "h2", "10.0.0.2", "00:00:00:00:00:02")

    info("*** flow 1: TCP/80 (expect ALLOW via rule 2)\n")
    r1 = probe(s, "h2-eth0", "TCP", 80, n=5)
    info("*** flow 2: TCP/22 (expect DENY via rule 1)\n")
    r2 = probe(s, "h2-eth0", "TCP", 22, n=5)
    info("*** flow 3: UDP/5000 (expect DENY via rule 3)\n")
    r3 = probe(s, "h2-eth0", "UDP", 5000, n=5)
    info("*** flow 4: UDP/1234 (expect ALLOW via default_action)\n")
    r4 = probe(s, "h2-eth0", "UDP", 1234, n=5)

    print(f"TCP/80  received: {r1}/5  (want 5)")
    print(f"TCP/22  received: {r2}/5  (want 0)")
    print(f"UDP/5000 received: {r3}/5  (want 0)")
    print(f"UDP/1234 received: {r4}/5  (want 5)")

    if r1 == 5 and r2 == 0 and r3 == 0 and r4 == 5:
        print("SUCCESS: ACL rules + priorities + default action all working")
        return 0
    print("FAILURE: ACL behaviour does not match expectations")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=ACLTopo(), controller=None)
    net.start()

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
