#!/usr/bin/env python3
"""Mininet topology for Case 04: L2 broadcast switch.

Single switch with four hosts. Unlike case 03 we do NOT pre-populate
ARP; the switch's multicast groups flood ARP broadcasts to all ports
except the ingress, so the usual learn-on-reply flow works.
"""

from __future__ import annotations

import argparse
import os
import sys

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402


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


def run_controller(
    runtime: NetworkRuntime, controller_bin: str, p4info: str, config: str, hosts: int
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
            "-hosts",
            str(hosts),
        ],
    )


def wait_controller_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("broadcast-switch ready", timeout)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--n-hosts", type=int, default=4)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    with NetworkRuntime(BroadcastTopo(n_hosts=args.n_hosts)) as runtime:
        net = runtime.net

        ctrl = run_controller(
            runtime, args.controller, args.p4info, args.config, args.n_hosts
        )
        if not wait_controller_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)

        rc = 0
        if args.run_test:
            info("*** Running pingAll (ARP broadcasts should flood)\n")
            dropped = net.pingAll(timeout="3")
            print(f"ping drop ratio: {dropped}%")
            rc = 0 if dropped == 0 else 1
            print(
                "SUCCESS: ARP + unicast reachable via dmac + multicast groups"
                if rc == 0
                else "FAILURE: some pings dropped"
            )
        else:
            CLI(net)

    sys.exit(rc)


if __name__ == "__main__":
    main()
