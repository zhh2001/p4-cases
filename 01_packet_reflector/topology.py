#!/usr/bin/env python3
"""Mininet topology for Case 01: packet reflector.

Single-switch, single-host network. The switch reflects every incoming
packet back to its ingress port after swapping src/dst MAC addresses.
No table entries are needed because the P4 program hard-codes the
reflect logic; the controller only pushes the pipeline.
"""

from __future__ import annotations

import argparse
import os
import sys

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.topo import Topo

# Allow `from common.p4switch import ...` when this file is run from its
# own directory.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402


class ReflectorTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        self.addLink(h1, sw)


def run_controller(
    runtime: NetworkRuntime, controller_bin: str, p4info: str, config: str
):
    info("*** Launching Go controller to push pipeline\n")
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


def wait_controller_ready(proc: Controller, timeout: float = 10.0) -> bool:
    return proc.wait_ready("pipeline installed", timeout)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument(
        "--run-test",
        action="store_true",
        help="run test.py in h1 and exit with its result",
    )
    args = parser.parse_args()

    setLogLevel("info")
    with NetworkRuntime(ReflectorTopo()) as runtime:
        net = runtime.net

        ctrl = run_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_controller_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)

        rc = 0
        if args.run_test:
            h1 = net.get("h1")
            info("*** Running test in h1\n")
            out = h1.cmd(f"python3 {HERE}/test.py")
            sys.stdout.write(out)
            rc = 0 if "SUCCESS" in out else 1
        else:
            CLI(net)

    sys.exit(rc)


if __name__ == "__main__":
    main()
