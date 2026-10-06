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
import sys

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402


class CpuTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1, cpu_port=510)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        self.addLink(h1, sw)
        self.addLink(h2, sw)


def start_controller(
    runtime: NetworkRuntime, controller_bin: str, p4info: str, config: str
) -> Controller:
    info("*** Launching Go controller\n")
    return runtime.start_controller(
        [
            controller_bin,
            "-addr",
            "127.0.0.1:9559",
            "-p4info",
            p4info,
            "-config",
            config,
        ],
    )


def wait_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("clone-to-cpu ready", timeout)


def count_packet_ins(proc: Controller, seconds: float) -> int:
    """Count PacketIn log lines during a bounded observation window."""
    return sum(line.startswith("packet-in #") for line in proc.lines_for(seconds))


def run_test(net: Mininet, ctrl: Controller) -> int:
    h1 = net.get("h1")

    n = 10
    info(f"*** h1 sending {n} frames to h2\n")
    h1.cmd(
        'python3 -c "'
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
    with NetworkRuntime(CpuTopo()) as runtime:
        net = runtime.net

        ctrl = start_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)

        rc = 0
        if args.run_test:
            rc = run_test(net, ctrl)
        else:
            CLI(net)

    sys.exit(rc)


if __name__ == "__main__":
    main()
