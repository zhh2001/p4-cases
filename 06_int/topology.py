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
from common.p4switch import P4RuntimeSwitch, reset_port_allocators  # noqa: E402


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


def start_controllers(ctrl_bin: str, p4info: str, config: str, switches) -> list[subprocess.Popen]:
    """Spawn one controller per switch."""
    procs: list[subprocess.Popen] = []
    for sw_name, device_id, grpc_port in switches:
        info(f"*** Launching controller for {sw_name} @ :{grpc_port} (switch-id={device_id})\n")
        p = subprocess.Popen(
            [
                ctrl_bin,
                "-addr", f"127.0.0.1:{grpc_port}",
                "-p4info", p4info,
                "-config", config,
                "-switch-id", str(device_id),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        procs.append(p)
    return procs


def wait_all_ready(procs: list[subprocess.Popen], timeout: float = 20.0) -> bool:
    """Wait for each controller to print its ready banner."""
    remaining = set(range(len(procs)))
    deadline = time.time() + timeout
    while remaining and time.time() < deadline:
        for i in list(remaining):
            p = procs[i]
            line = p.stdout.readline() if p.stdout else b""
            if not line:
                if p.poll() is not None:
                    return False
                continue
            decoded = line.decode(errors="replace").rstrip()
            info(f"    ctrl{i + 1}: {decoded}\n")
            # "s1 ready" / "s2 ready" / "s3 ready"
            if decoded == f"s{i + 1} ready":
                remaining.discard(i)
        time.sleep(0.03)
    return not remaining


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
    net = Mininet(topo=INTTopo(), controller=None)
    net.start()
    populate_arp(net)

    # The P4RuntimeSwitch class auto-allocated ports 9559, 9560, 9561
    # in creation order. Read them back.
    s1 = net.get("s1")
    s2 = net.get("s2")
    s3 = net.get("s3")
    controllers = start_controllers(
        args.controller, args.p4info, args.config,
        [("s1", 1, s1.grpc_port), ("s2", 2, s2.grpc_port), ("s3", 3, s3.grpc_port)],
    )
    if not wait_all_ready(controllers):
        print("!!! at least one controller failed to become ready")
        for i, p in enumerate(controllers):
            if p.stdout:
                print(f"--- ctrl{i + 1} remaining ---")
                print(p.stdout.read().decode(errors="replace"))
        net.stop()
        sys.exit(2)

    rc = 0
    try:
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
    finally:
        info("*** Stopping controllers\n")
        for p in controllers:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
        net.stop()

    sys.exit(rc)


if __name__ == "__main__":
    main()
