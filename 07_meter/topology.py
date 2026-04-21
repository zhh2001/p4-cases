#!/usr/bin/env python3
"""Mininet topology for Case 07: meter-based policing.

Single switch with two hosts. All packets default to egress port 2,
so h1 (port 1) always tries to send to h2 (port 2). The meter is
armed for src MAC aa:aa:aa:aa:aa:aa; other src MACs skip the meter
and pass unconditionally.
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


class MeterTopo(Topo):
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
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def wait_controller_ready(proc: subprocess.Popen, timeout: float = 15.0) -> bool:
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
        if "meter-switch ready" in decoded:
            return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=MeterTopo(), controller=None)
    net.start()

    ctrl = run_controller(args.controller, args.p4info, args.config)
    if not wait_controller_ready(ctrl):
        print("!!! controller did not reach ready state")
        if ctrl.stdout:
            print(ctrl.stdout.read().decode(errors="replace"))
        net.stop()
        sys.exit(2)

    rc = 0
    try:
        if args.run_test:
            h1 = net.get("h1")
            h2 = net.get("h2")

            info("*** Phase 1: send 30 packets from non-metered src (expect ~30 on h2)\n")
            unmetered = run_burst(h1, h2, src_mac="bb:bb:bb:bb:bb:bb", n=30, gap=0.01)

            info("*** Phase 2: send 30 packets from metered src (expect partial drop)\n")
            metered = run_burst(h1, h2, src_mac="aa:aa:aa:aa:aa:aa", n=30, gap=0.005)

            print(f"Unmetered received: {unmetered}/30")
            print(f"Metered   received: {metered}/30")
            if unmetered >= 28 and metered < 25:
                print("SUCCESS: non-metered MAC passes, metered MAC experiences drops")
                rc = 0
            else:
                print("FAILURE: expected unmetered>=28 and metered<25")
                rc = 1
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


def run_burst(sender, receiver, src_mac: str, n: int, gap: float) -> int:
    """Run scapy from sender, count how many of the `n` labelled frames
    the receiver actually sees."""
    # Start sniffer on receiver in background.
    sniff_proc = receiver.popen(
        [
            "python3", "-c",
            (
                "import sys; from scapy.all import AsyncSniffer, Ether; "
                f"s = AsyncSniffer(iface='{receiver.defaultIntf().name}', count={n}, timeout=4, "
                f"lfilter=lambda p: Ether in p and p[Ether].src=='{src_mac}'); "
                "s.start(); s.join(); print(len(s.results or []))"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(0.5)  # sniffer warm-up

    # Blast packets from sender.
    sender.cmd(
        "python3 -c \""
        "from scapy.all import Ether, sendp; import time; "
        f"[ (sendp(Ether(src='{src_mac}',dst='00:00:00:00:00:02')/b'x'*64, iface='{sender.defaultIntf().name}', verbose=False), "
        f"time.sleep({gap})) for _ in range({n}) ]\""
    )

    try:
        out, _ = sniff_proc.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        sniff_proc.kill()
        out, _ = sniff_proc.communicate()
    try:
        return int(out.decode().strip().splitlines()[-1])
    except Exception:
        return 0


if __name__ == "__main__":
    main()
