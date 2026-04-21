#!/usr/bin/env python3
"""Mininet topology for Case 05: L2 learning switch (digest variant).

Same host/port layout as case 04. The switch starts with empty smac /
dmac tables; ARPs trigger digests, the Go controller learns each MAC
and programs the forwarding/learn tables, and pingAll succeeds.
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


class LearningTopo(Topo):
    def build(self, n_hosts: int = 4, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        for i in range(1, n_hosts + 1):
            self.addHost(f"h{i}", ip=host_ip(i), mac=host_mac(i))
            self.addLink(f"h{i}", sw)


def run_controller(controller_bin: str, p4info: str, config: str, ports: int) -> subprocess.Popen:
    info("*** Launching Go controller (digest learner)\n")
    return subprocess.Popen(
        [
            controller_bin,
            "-addr", "127.0.0.1:9559",
            "-p4info", p4info,
            "-config", config,
            "-ports", str(ports),
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
        if "learning-switch ready" in decoded:
            return True
    return False


def drain_controller(proc: subprocess.Popen, seconds: float) -> None:
    """Print whatever the controller emits during the grace window so
    the learning log is visible alongside the test."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else b""
        if not line:
            if proc.poll() is not None:
                return
            time.sleep(0.05)
            continue
        info(f"    controller: {line.decode(errors='replace').rstrip()}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--n-hosts", type=int, default=4)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=LearningTopo(n_hosts=args.n_hosts), controller=None)
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
            info("*** Running pingAll — MAC learning occurs in-flight\n")
            dropped = net.pingAll(timeout="3")
            print(f"ping drop ratio: {dropped}%")

            # Second pingAll: after the first round every MAC has been
            # learned, so traffic is all unicast — a stricter check.
            info("*** Running pingAll again — everything should now be unicast\n")
            dropped2 = net.pingAll(timeout="3")
            print(f"second ping drop ratio: {dropped2}%")

            drain_controller(ctrl, 0.5)
            rc = 0 if (dropped == 0 and dropped2 == 0) else 1
            print("SUCCESS: learning switch reached steady state" if rc == 0
                  else "FAILURE: one of the pingAll rounds lost packets")
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
