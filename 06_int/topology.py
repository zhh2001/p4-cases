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
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch, reset_port_allocators  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402

packets = importlib.import_module("06_int.packets")


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
    """Configure routes and static neighbours in each host namespace."""
    info("*** Configuring host routes and static ARP\n")
    for name, _ip, _mac in HOSTS:
        host = net.get(name)
        iface = host.defaultIntf().name
        commands = [["ip", "route", "replace", "default", "dev", iface]]
        for other, other_ip, other_mac in HOSTS:
            if other == name:
                continue
            target_ip = other_ip.split("/")[0]
            commands.append(
                [
                    "ip",
                    "neigh",
                    "replace",
                    target_ip,
                    "lladdr",
                    other_mac,
                    "nud",
                    "permanent",
                    "dev",
                    iface,
                ]
            )
        for command in commands:
            output, error, code = host.pexec(command)
            if code:
                raise RuntimeError(f"cannot configure {name}: {output} {error}")


def read_probe(proc: subprocess.Popen, timeout: float = 6) -> dict:
    output, error = proc.communicate(timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"packet probe failed: {output.strip()} {error.strip()}")
    try:
        reply = json.loads(output)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("packet probe returned invalid JSON") from exc
    if not isinstance(reply, dict):
        raise RuntimeError("packet probe reply must be an object")
    return reply


def frame_list(reply: dict) -> list[bytes]:
    frames = reply.get("frames")
    if not isinstance(frames, list) or any(
        not isinstance(frame, str) for frame in frames
    ):
        raise RuntimeError("capture reply must contain frame hex strings")
    try:
        return [bytes.fromhex(frame) for frame in frames]
    except ValueError as exc:
        raise RuntimeError("capture reply contains invalid frame bytes") from exc


def stop_probe(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


def check_delivery(probes: list[dict], received: dict[str, list[bytes]]) -> None:
    if set(received) != {"h1", "h2", "h3", "h4"}:
        raise RuntimeError("capture replies must include all four hosts")
    identities = {item["frame"][26:30]: item for item in probes}
    if len(identities) != len(probes):
        raise RuntimeError("test packets must have unique IPv4 sources")
    arrivals = {key: [] for key in identities}
    for host, frames in received.items():
        if not isinstance(frames, list):
            raise RuntimeError("capture replies must contain frame lists")
        for frame in frames:
            if (
                not isinstance(frame, bytes)
                or len(frame) < 30
                or frame[26:30] not in identities
            ):
                raise RuntimeError(
                    "capture contains an unrecognised or incomplete frame"
                )
            arrivals[frame[26:30]].append((host, frame))
    for identity, item in identities.items():
        actual = arrivals[identity]
        expected = 1 if item["allowed"] else 0
        if len(actual) != expected:
            raise RuntimeError(
                f"{item['name']} received {len(actual)} frames, expected {expected}"
            )
        if actual:
            host, frame = actual[0]
            if host != item["receiver"]:
                raise RuntimeError(f"{item['name']} arrived at the wrong host")
            packets.check_forwarded(item["frame"], frame, item["path"])
        print(f"{item['name']}: received={len(actual)}, expected={expected}")


def run_test(net: Mininet, controllers: list[Controller]) -> int:
    procs = []
    try:
        if any(ctrl.proc.poll() is not None for ctrl in controllers):
            raise RuntimeError("controller exited before the INT test")
        prefix = bytes((198, 18)) + uuid.uuid4().bytes[:1]
        probes = packets.make_probes(prefix)
        with tempfile.TemporaryDirectory(prefix="p4-int-") as directory:
            receivers = {}
            for name, _, _ in HOSTS:
                host = net.get(name)
                ready = Path(directory) / f"{name}-ready"
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/test_receive.py",
                        "--iface",
                        host.defaultIntf().name,
                        "--prefix",
                        prefix.hex(),
                        "--ready",
                        str(ready),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                procs.append(proc)
                receivers[name] = (proc, ready)
            deadline = time.monotonic() + 3
            while not all(
                ready.exists() and ready.read_text() == "ready\n"
                for _, ready in receivers.values()
            ):
                if time.monotonic() >= deadline or any(
                    proc.poll() is not None for proc, _ in receivers.values()
                ):
                    raise RuntimeError("packet receivers did not become ready")
                time.sleep(0.02)
            for name, _, _ in HOSTS:
                sent = [item["frame"] for item in probes if item["sender"] == name]
                manifest = Path(directory) / f"{name}.json"
                manifest.write_text(json.dumps([frame.hex() for frame in sent]))
                host = net.get(name)
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/test_send.py",
                        "--iface",
                        host.defaultIntf().name,
                        "--frames",
                        str(manifest),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                procs.append(proc)
                reply = read_probe(proc)
                if type(reply.get("sent")) is not int or reply["sent"] != len(sent):
                    raise RuntimeError("sender did not confirm all test frames")
            captured = {
                name: frame_list(read_probe(proc))
                for name, (proc, _) in receivers.items()
            }
        check_delivery(probes, captured)
        if any(ctrl.proc.poll() is not None for ctrl in controllers):
            raise RuntimeError("controller exited during the INT test")
    except (
        RuntimeError,
        OSError,
        ValueError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    finally:
        for proc in procs:
            stop_probe(proc)
    print(
        f"SUCCESS: {len(probes)} INT and IPv4 cases preserve complete packets and expected paths"
    )
    return 0


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

        rc = run_test(net, controllers) if args.run_test else 0
        if not args.run_test:
            CLI(net)

    sys.exit(rc)


if __name__ == "__main__":
    main()
