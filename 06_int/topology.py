#!/usr/bin/env python3
"""Mininet topology for Case 06: In-band Network Telemetry.

Three switches (s1..s3), four hosts (h1..h4). Link order is chosen so
that the mininet-assigned port numbers match the per-switch entries
in controller/main.go:

    s1: port 1 -> h1, port 2 -> s2, port 3 -> s3
    s2: port 1 -> h2, port 2 -> s1
    s3: port 1 -> h3, port 2 -> h4, port 3 -> s1

Each switch gets its own BMv2 instance on an auto-allocated gRPC port
(9559, 9560, 9561). The topology spawns one Go controller per switch
in parallel.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch, reset_port_allocators  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402


HOSTS = [
    ("h1", "10.0.1.1/24", "00:00:0a:00:01:01"),
    ("h2", "10.0.2.2/24", "00:00:0a:00:02:02"),
    ("h3", "10.0.3.3/24", "00:00:0a:00:03:03"),
    ("h4", "10.0.3.4/24", "00:00:0a:00:03:04"),
]


class INTTopo(Topo):
    def build(self, **_opts) -> None:
        # Add switches first — mininet will resolve port order when we
        # call addLink below.
        s1 = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        s2 = self.addSwitch("s2", cls=P4RuntimeSwitch, device_id=2)
        s3 = self.addSwitch("s3", cls=P4RuntimeSwitch, device_id=3)
        # Hosts
        for name, ip, mac in HOSTS:
            self.addHost(name, ip=ip, mac=mac)
        # Links — order matters for port numbering.
        # s1: port 1 -> h1, port 2 -> s2, port 3 -> s3
        self.addLink("h1", s1)
        # s2: port 1 -> h2 needs h2-s2 before s1-s2
        self.addLink("h2", s2)
        # s3: port 1 -> h3, port 2 -> h4 before s1-s3
        self.addLink("h3", s3)
        self.addLink("h4", s3)
        # Inter-switch:
        self.addLink(s1, s2)  # s1 port 2, s2 port 2
        self.addLink(s1, s3)  # s1 port 3, s3 port 3


def start_controllers(
    runtime: NetworkRuntime, ctrl_bin: str, p4info: str, config: str, switches
) -> list[Controller]:
    """Spawn one controller per switch."""
    procs: list[Controller] = []
    for sw_name, device_id, grpc_port in switches:
        info(
            f"*** Launching controller for {sw_name} @ :{grpc_port} (switch-id={device_id})\n"
        )
        p = runtime.start_controller(
            [
                ctrl_bin,
                "-addr",
                f"127.0.0.1:{grpc_port}",
                "-p4info",
                p4info,
                "-config",
                config,
                "-switch-id",
                str(device_id),
            ],
            label=sw_name,
        )
        procs.append(p)
    return procs


def wait_all_ready(procs: list[Controller], timeout: float = 20.0) -> bool:
    """Wait for all controllers within one shared deadline."""
    deadline = time.monotonic() + timeout
    return all(
        proc.wait_ready(f"s{i + 1} ready", max(0, deadline - time.monotonic()))
        for i, proc in enumerate(procs)
    )


def populate_arp(net: Mininet) -> None:
    """Static ARP entries so hosts don't need to resolve. We map every
    other host's IP to that host's MAC."""
    info("*** Populating static ARP\n")
    for name, ip, _mac in HOSTS:
        host = net.get(name)
        for other, other_ip, other_mac in HOSTS:
            if other == name:
                continue
            # other_ip is e.g. "10.0.3.4/24"; strip the /prefix.
            target_ip = other_ip.split("/")[0]
            host.cmd(f"arp -s {target_ip} {other_mac}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    reset_port_allocators()
    with NetworkRuntime(INTTopo()) as runtime:
        net = runtime.net
        populate_arp(net)

        # The P4RuntimeSwitch class auto-allocated ports 9559, 9560, 9561
        # in creation order. Read them back.
        s1 = net.get("s1")
        s2 = net.get("s2")
        s3 = net.get("s3")
        controllers = start_controllers(
            runtime,
            args.controller,
            args.p4info,
            args.config,
            [("s1", 1, s1.grpc_port), ("s2", 2, s2.grpc_port), ("s3", 3, s3.grpc_port)],
        )
        if not wait_all_ready(controllers):
            print("!!! at least one controller failed to become ready")
            sys.exit(2)

        rc = 0
        if args.run_test:
            h1 = net.get("h1")
            h2 = net.get("h2")
            info("*** Sending INT-carrying UDP packet h1 -> h2\n")
            # Start receiver on h2
            rx = h2.popen(
                ["python3", f"{HERE}/test_receive.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            time.sleep(1.0)
            # Send from h1
            h1.cmd(f"python3 {HERE}/test_send.py")
            try:
                out, _ = rx.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                rx.kill()
                out, _ = rx.communicate()
            sys.stdout.write(out.decode(errors="replace"))
            rc = 0 if b"SUCCESS" in out else 1
        else:
            CLI(net)

    sys.exit(rc)


if __name__ == "__main__":
    main()
