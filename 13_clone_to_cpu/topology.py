#!/usr/bin/env python3
"""Mininet topology for Case 13: clone to CPU.

2 hosts on s1 ports 1 and 2. The switch is started with a CPU port
(510) so BMv2 bridges that port to the P4Runtime PacketIn stream.
h1 sends N packets to h2; the controller should receive N
packet-ins via PacketIn handler.
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


class CpuTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1, cpu_port=510)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        self.addLink(h1, sw)
        self.addLink(h2, sw)


def start_controller(controller_bin: str, p4info: str, config: str) -> subprocess.Popen:
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
        if "clone-to-cpu ready" in decoded:
            return True
    return False


def count_packet_ins(proc: subprocess.Popen, seconds: float) -> int:
    """Drain the controller output for `seconds` and count lines that
    begin with 'packet-in #'."""
    deadline = time.time() + seconds
    count = 0
    while time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else b""
        if not line:
            if proc.poll() is not None:
                return count
            time.sleep(0.03)
            continue
        decoded = line.decode(errors="replace").rstrip()
        info(f"    controller: {decoded}\n")
        if decoded.startswith("packet-in #"):
            count += 1
    return count


def run_test(net: Mininet, ctrl: subprocess.Popen) -> int:
    h1 = net.get("h1")

    n = 10
    info(f"*** h1 sending {n} frames to h2\n")
    h1.cmd(
        "python3 -c \""
        "from scapy.all import Ether, sendp; "
        f"[sendp(Ether(src='00:00:00:00:00:01',dst='00:00:00:00:00:02')/b'cpu-clone-%d' %% i, "
        "iface='h1-eth0', verbose=False) for i in range({n})]\"".format(n=n)
    )

    got = count_packet_ins(ctrl, seconds=3.0)
    print(f"packet-in arrivals: {got} (expected >= {n})")
    if got >= n:
        print("SUCCESS: every data-plane packet was cloned to the controller")
        return 0
    print(f"FAILURE: expected >= {n} packet-ins, got {got}")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=CpuTopo(), controller=None)
    net.start()

    ctrl = start_controller(args.controller, args.p4info, args.config)
    if not wait_ready(ctrl):
        print("!!! controller did not reach ready state")
        if ctrl.stdout:
            print(ctrl.stdout.read().decode(errors="replace"))
        net.stop()
        sys.exit(2)

    rc = 0
    try:
        if args.run_test:
            rc = run_test(net, ctrl)
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
