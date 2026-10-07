#!/usr/bin/env python3
"""Validate IPv6 LPM routing, complete frames and explicit drop cases."""

from __future__ import annotations

import argparse
from collections import Counter
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

packets = importlib.import_module("14_ipv6_lpm.packets")


class IPv6Topo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        for number in packets.HOST_MACS:
            host = self.addHost(
                f"h{number}", ip=None, mac=packets.HOST_MACS[number].hex(":")
            )
            self.addLink(host, sw)


def checked_command(node, command: list[str]) -> None:
    output, error, code = node.pexec(command)
    if code:
        raise RuntimeError(
            f"interface command failed: {output.strip()} {error.strip()}"
        )


def configure_ipv6(net: Mininet) -> None:
    """Configure addresses for interactive use without waiting for DAD."""
    for number, address in packets.HOST_ADDRESSES.items():
        host = net.get(f"h{number}")
        iface = host.defaultIntf().name
        checked_command(
            host,
            [
                "sysctl",
                "-q",
                "-w",
                f"net.ipv6.conf.{iface}.disable_ipv6=0",
                f"net.ipv6.conf.{iface}.dad_transmits=0",
                f"net.ipv6.conf.{iface}.accept_dad=0",
            ],
        )
        checked_command(
            host, ["ip", "-6", "addr", "replace", f"{address}/64", "dev", iface]
        )


def configure_test_interfaces(net: Mininet) -> None:
    # Raw Ethernet probes do not need kernel IPv6 responses or neighbour discovery.
    for name in ("h1", "h2", "h3", "s1"):
        node = net.get(name)
        settings = [
            f"net.ipv6.conf.{intf.name}.disable_ipv6=1"
            for intf in node.intfList()
            if intf.name != "lo"
        ]
        checked_command(node, ["sysctl", "-q", "-w", *settings])


def run_controller(
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
        ]
    )


def wait_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("ipv6 router ready", timeout)


def read_probe(proc: subprocess.Popen, timeout: float = 4) -> dict:
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


def check_delivery(probes: list[dict], received: dict[str, list[bytes]]) -> None:
    if set(received) != {"h1", "h2", "h3"}:
        raise RuntimeError("capture replies must include all three hosts")
    for name, frames in received.items():
        expected = [
            packets.expected_frame(item["frame"], name)
            for item in probes
            if item["allowed"] and item["receiver"] == name
        ]
        if (
            not isinstance(frames, list)
            or any(not isinstance(frame, bytes) for frame in frames)
            or Counter(frames) != Counter(expected)
        ):
            raise RuntimeError(
                f"{name} did not receive exactly the expected complete frames"
            )


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


def run_probes(
    net: Mininet, ctrl: Controller, prefix: bytes, probes: list[dict]
) -> None:
    if ctrl.proc.poll() is not None:
        raise RuntimeError("controller exited before the IPv6 routing test")
    procs = []
    try:
        with tempfile.TemporaryDirectory(prefix="p4-ipv6-") as directory:
            receivers = {}
            for name in ("h1", "h2", "h3"):
                host = net.get(name)
                ready = Path(directory) / f"{name}-ready"
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/probe.py",
                        "receive",
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
            deadline = time.monotonic() + 2
            while not all(
                ready.exists() and ready.read_text() == "ready\n"
                for _, ready in receivers.values()
            ):
                if time.monotonic() >= deadline or any(
                    proc.poll() is not None for proc, _ in receivers.values()
                ):
                    raise RuntimeError("packet receivers did not become ready")
                time.sleep(0.02)
            senders = []
            for name in ("h1", "h2", "h3"):
                frames = [item["frame"] for item in probes if item["sender"] == name]
                if not frames:
                    continue
                manifest = Path(directory) / f"{name}.json"
                manifest.write_text(json.dumps([frame.hex() for frame in frames]))
                host = net.get(name)
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/probe.py",
                        "send",
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
                senders.append((proc, len(frames)))
            for proc, count in senders:
                reply = read_probe(proc)
                if type(reply.get("sent")) is not int or reply["sent"] != count:
                    raise RuntimeError("sender did not confirm all test frames")
            captured = {
                name: frame_list(read_probe(proc))
                for name, (proc, _) in receivers.items()
            }
        check_delivery(probes, captured)
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited during the IPv6 routing test")
    finally:
        for proc in procs:
            stop_probe(proc)


def run_test(net: Mininet, ctrl: Controller) -> int:
    try:
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited before the IPv6 routing test")
        configure_test_interfaces(net)
        prefix = b"\x02" + uuid.uuid4().bytes[:3]
        probes = packets.make_probes(prefix)
        run_probes(net, ctrl, prefix, probes)
    except (
        RuntimeError,
        OSError,
        ValueError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    forwarded = sum(item["allowed"] for item in probes)
    print(
        f"IPv6 probes: sent={len(probes)} forwarded={forwarded} dropped={len(probes)-forwarded}"
    )
    print("SUCCESS: IPv6 longest-prefix routing and complete frames validated")
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
    with NetworkRuntime(IPv6Topo()) as runtime:
        net = runtime.net
        ctrl = run_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)
        rc = 0
        if args.run_test:
            rc = run_test(net, ctrl)
        else:
            configure_ipv6(net)
            CLI(net)
    sys.exit(rc)


if __name__ == "__main__":
    main()
