#!/usr/bin/env python3
"""Mininet topology for Case 11: VXLAN encap.

h1 sends a plain Ethernet frame to a synthetic inner MAC; h2 receives
the frame wrapped in VXLAN over UDP and verifies the outer stack +
VNI + inner MAC.
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


class VxlanTopo(Topo):
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
        if "vxlan ready" in decoded:
            return True
    return False


def run_test(net: Mininet) -> int:
    h1 = net.get("h1")
    h2 = net.get("h2")

    # h2 waits for a VXLAN-over-UDP packet (outer UDP dstPort==4789).
    sniff = h2.popen(
        ["python3", f"{HERE}/test_sniff.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(0.7)

    # h1 sends a plain Ethernet frame to inner MAC 00:00:00:11:11:11
    h1.cmd(
        "python3 -c \""
        "from scapy.all import Ether, sendp; "
        "sendp(Ether(src='00:00:00:00:00:01',dst='00:00:00:11:11:11')/b'inner-payload', "
        "iface='h1-eth0', verbose=False)\""
    )

    try:
        out, _ = sniff.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        sniff.kill()
        out, _ = sniff.communicate()
    text = (out or b"").decode(errors="replace")
    sys.stdout.write(text)

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    got_count = lines and lines[0].isdigit() and int(lines[0]) > 0
    vni_line = next((ln for ln in lines if ln.startswith("vni=")), "")

    if not got_count:
        print("FAILURE: h2 received no VXLAN-over-UDP packet")
        return 1
    if "vni=5000" not in vni_line or "inner_dst=00:00:00:11:11:11" not in vni_line:
        print(f"FAILURE: wrong VNI or inner MAC: {vni_line!r}")
        return 1
    print("SUCCESS: VXLAN encap observed on h2 with VNI=5000 and expected inner MAC")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=VxlanTopo(), controller=None)
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
