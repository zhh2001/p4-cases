#!/usr/bin/env python3
"""Mininet topology for Case 04: L2 broadcast switch.

Single switch with four hosts. Unlike case 03 we do NOT pre-populate
ARP; the switch's multicast groups flood ARP broadcasts to all ports
except the ingress, so the usual learn-on-reply flow works.
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


class BroadcastTopo(Topo):
    def build(self, n_hosts: int = 4, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        for i in range(1, n_hosts + 1):
            self.addHost(f"h{i}", ip=host_ip(i), mac=host_mac(i))
            self.addLink(f"h{i}", sw)


def run_controller(controller_bin: str, p4info: str, config: str, hosts: int) -> subprocess.Popen:
    info("*** Launching Go controller\n")
    return subprocess.Popen(
        [
            controller_bin,
            "-addr", "127.0.0.1:9559",
            "-p4info", p4info,
            "-config", config,
            "-hosts", str(hosts),
        ],
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
        if "broadcast-switch ready" in decoded:
            return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--n-hosts", type=int, default=4)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=BroadcastTopo(n_hosts=args.n_hosts), controller=None)
    net.start()

    ctrl = run_controller(args.controller, args.p4info, args.config, args.n_hosts)
    if not wait_controller_ready(ctrl):
        print("!!! controller did not reach ready state")
        if ctrl.stdout:
            print(ctrl.stdout.read().decode(errors="replace"))
        net.stop()
        sys.exit(2)

    rc = 0
    try:
        if args.run_test:
            info("*** Running pingAll (ARP broadcasts should flood)\n")
            dropped = net.pingAll(timeout="3")
            print(f"ping drop ratio: {dropped}%")
            rc = 0 if dropped == 0 else 1
            print("SUCCESS: ARP + unicast reachable via dmac + multicast groups" if rc == 0
                  else "FAILURE: some pings dropped")
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
