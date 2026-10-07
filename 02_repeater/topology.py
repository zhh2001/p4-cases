#!/usr/bin/env python3
"""Validate two-port forwarding, complete frames and probe lifecycles."""

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

packets = importlib.import_module("02_repeater.packets")


class RepeaterTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        # Port order: h1 gets port 1, h2 gets port 2.
        self.addLink(h1, sw)
        self.addLink(h2, sw)


def configure_test_interfaces(net: Mininet) -> None:
    for name in ("h1", "h2", "s1"):
        node = net.get(name)
        settings = [
            f"net.ipv6.conf.{intf.name}.disable_ipv6=1"
            for intf in node.intfList()
            if intf.name != "lo"
        ]
        output, error, code = node.pexec(["sysctl", "-q", "-w", *settings])
        if code:
            raise RuntimeError(
                f"interface command failed: {output.strip()} {error.strip()}"
            )


def run_controller(
    runtime: NetworkRuntime, controller_bin: str, p4info: str, config: str
) -> Controller:
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
    return proc.wait_ready("repeater ready", timeout)


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
    if set(received) != {"h1", "h2"}:
        raise RuntimeError("capture replies must include every host")
    for name, frames in received.items():
        expected = [item["frame"] for item in probes if item["receiver"] == name]
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
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


def run_probes(
    net: Mininet, ctrl: Controller, prefix: bytes, probes: list[dict]
) -> None:
    if ctrl.proc.poll() is not None:
        raise RuntimeError("controller exited before the repeater test")
    duration = 2
    names = ("h1", "h2")
    procs = []
    try:
        with tempfile.TemporaryDirectory(prefix="p4-repeater-") as directory:
            receivers = {}
            for name in names:
                host = net.get(name)
                ready = Path(directory) / f"{name}-ready"
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/test.py",
                        "receive",
                        "--iface",
                        host.defaultIntf().name,
                        "--prefix",
                        prefix.hex(),
                        "--seconds",
                        str(duration),
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
            for name in names:
                frames = [item["frame"] for item in probes if item["sender"] == name]
                if not frames:
                    continue
                manifest = Path(directory) / f"{name}.json"
                manifest.write_text(json.dumps([frame.hex() for frame in frames]))
                host = net.get(name)
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/test.py",
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
                name: frame_list(read_probe(proc, timeout=duration + 5))
                for name, (proc, _) in receivers.items()
            }
        check_delivery(probes, captured)
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited during the repeater test")
    finally:
        for proc in procs:
            stop_probe(proc)


def run_test(net: Mininet, ctrl: Controller) -> int:
    try:
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited before the repeater test")
        configure_test_interfaces(net)
        prefix = b"\x02" + uuid.uuid4().bytes[:3]
        probes = packets.make_probes(prefix)
        run_probes(net, ctrl, prefix, probes)
        dropped = net.pingAll(timeout="2")
        if type(dropped) not in (int, float) or dropped != 0:
            raise RuntimeError(
                f"pingAll returned a nonzero or invalid drop ratio: {dropped}"
            )
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited during the repeater test")
    except (
        RuntimeError,
        OSError,
        ValueError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    print(f"Repeater probes: sent={len(probes)} received={len(probes)}")
    print(f"ping drop ratio: {dropped}%")
    print("SUCCESS: bidirectional repeater forwarding and complete frames validated")
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
    with NetworkRuntime(RepeaterTopo()) as runtime:
        net = runtime.net

        ctrl = run_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_controller_ready(ctrl):
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
