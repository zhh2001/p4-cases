#!/usr/bin/env python3
"""Mininet topology for Case 08: per-port counter.

Single switch with two hosts. The P4 program cross-forwards port 1
and port 2 and auto-increments port_counter[ingress_port] for every
packet. The controller exposes a `dump` command over its stdin that
returns counter values; we drive it from here.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402


class CounterTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        self.addLink(h1, sw)
        self.addLink(h2, sw)


def start_controller(
    runtime: NetworkRuntime, controller_bin: str, p4info: str, config: str
) -> Controller:
    info("*** Launching Go controller (counter reader)\n")
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
        interactive=True,
    )


def wait_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("counter ready", timeout)


def dump_counters(proc: Controller) -> dict[int, dict[str, int]]:
    """Send 'dump' and require a complete reply within four seconds."""
    proc.send("dump")
    out: dict[int, dict[str, int]] = {}
    for line in proc.lines_for(4.0):
        if line == "dump-done":
            return out
        if line.startswith("port="):
            parts = dict(kv.split("=") for kv in line.split())
            p = int(parts["port"])
            out[p] = {"packets": int(parts["packets"]), "bytes": int(parts["bytes"])}
    raise RuntimeError("controller did not complete the counter dump within 4s")


def blast(sender, n: int) -> None:
    """Send n scapy Ethernet frames from sender."""
    sender.cmd(
        'python3 -c "'
        "from scapy.all import Ether, sendp; "
        f"[ sendp(Ether(src='00:00:00:00:00:01',dst='00:00:00:00:00:02')/b'P'*60, "
        f"iface='{sender.defaultIntf().name}', verbose=False) for _ in range({n}) ]\""
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    with NetworkRuntime(CounterTopo()) as runtime:
        net = runtime.net

        ctrl = start_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)

        rc = 0
        if args.run_test:
            h1 = net.get("h1")

            info("*** Initial counter snapshot\n")
            before = dump_counters(ctrl)
            info("*** Sending 20 frames from h1\n")
            blast(h1, 20)
            time.sleep(0.5)
            info("*** Post-blast counter snapshot\n")
            after = dump_counters(ctrl)

            p1_delta = after.get(1, {}).get("packets", 0) - before.get(1, {}).get(
                "packets", 0
            )
            print(f"port 1 packet delta = {p1_delta} (expected >= 20)")
            rc = 0 if p1_delta >= 20 else 1
            print(
                "SUCCESS: port 1 counter incremented by the blasted frames"
                if rc == 0
                else "FAILURE: counter did not capture the blast"
            )
        else:
            CLI(net)

    sys.exit(rc)


if __name__ == "__main__":
    main()
