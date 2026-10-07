#!/usr/bin/env python3
"""Check bidirectional forwarding and per-port packet and byte counters."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

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


def configure_test_interfaces(net) -> None:
    for name in ("h1", "h2", "s1"):
        node = net.get(name)
        settings = [
            f"net.ipv6.conf.{intf.name}.disable_ipv6=1"
            for intf in node.intfList()
            if intf.name != "lo"
        ]
        output, error, code = node.pexec(["sysctl", "-q", "-w", *settings])
        if code:
            raise RuntimeError(f"cannot configure {name}: {output} {error}")


def dump_counters(proc: Controller) -> dict[int, dict[str, int]]:
    """Require both port samples and a terminator within four seconds."""
    proc.send("dump")
    result = {}
    for line in proc.lines_for(4.0):
        if line == "dump-done":
            if set(result) != {1, 2}:
                raise RuntimeError("counter dump must include ports 1 and 2")
            return result
        if line.startswith("ERR"):
            raise RuntimeError(f"counter read failed: {line}")
        if line.startswith("port="):
            match = re.fullmatch(r"port=([12]) packets=(\d+) bytes=(\d+)", line)
            if match is None:
                raise RuntimeError(f"invalid counter sample: {line}")
            port, packets, length = map(int, match.groups())
            if port in result:
                raise RuntimeError(f"duplicate counter sample for port {port}")
            result[port] = {"packets": packets, "bytes": length}
    raise RuntimeError("controller did not complete the counter dump within 4s")


def make_frames(prefix: bytes, sender_port: int) -> list[bytes]:
    if len(prefix) != 4 or sender_port not in (1, 2):
        raise ValueError("frames require a four-byte prefix and port 1 or 2")
    frames = []
    destination = bytes.fromhex(f"00000000000{3 - sender_port}")
    for size in (60, 64, 128, 512, 1500, 1514):
        for _ in range(5):
            sequence = len(frames) + 1
            source = prefix + bytes((sender_port, sequence))
            payload = b"p4-counter:" + source
            payload += bytes((sequence + offset) % 256 for offset in range(size))
            frames.append((destination + source + b"\x88\xb5" + payload)[:size])
    return frames


def check_counters(before: dict, after: dict, frames: dict[int, list[bytes]]) -> None:
    for snapshot in (before, after):
        if (
            not isinstance(snapshot, dict)
            or set(snapshot) != {1, 2}
            or any(
                not isinstance(value, dict)
                or set(value) != {"packets", "bytes"}
                or any(
                    type(number) is not int or number < 0 for number in value.values()
                )
                for value in snapshot.values()
            )
        ):
            raise RuntimeError(
                "counter snapshots must contain complete nonnegative samples"
            )
    for port in (1, 2):
        sent = frames.get(port, [])
        for field, wanted in (("packets", len(sent)), ("bytes", sum(map(len, sent)))):
            actual = after[port][field] - before[port][field]
            print(f"port {port} {field} delta={actual}, expected={wanted}")
            if actual != wanted:
                raise RuntimeError(
                    f"port {port} {field} delta is {actual}, expected {wanted}"
                )


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


def check_delivery(
    frames: dict[int, list[bytes]], received: dict[str, list[bytes]]
) -> None:
    for name, port in (("h1", 2), ("h2", 1)):
        actual = received.get(name)
        if not isinstance(actual, list) or Counter(actual) != Counter(
            frames.get(port, [])
        ):
            raise RuntimeError(f"{name} did not receive exactly the expected frames")


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


def run_burst(
    net, ctrl: Controller, prefix: bytes, frames: dict[int, list[bytes]]
) -> None:
    before = dump_counters(ctrl)
    procs = []
    try:
        with tempfile.TemporaryDirectory(prefix="p4-counter-") as directory:
            receivers = {}
            for name in ("h1", "h2"):
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
            for port, sent in frames.items():
                manifest = Path(directory) / f"port-{port}.json"
                manifest.write_text(json.dumps([frame.hex() for frame in sent]))
                host = net.get(f"h{port}")
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
                reply = read_probe(proc)
                if type(reply.get("sent")) is not int or reply["sent"] != len(sent):
                    raise RuntimeError("sender did not confirm all test frames")
            received = {
                name: frame_list(read_probe(proc))
                for name, (proc, _) in receivers.items()
            }
            check_delivery(frames, received)
    finally:
        for proc in procs:
            stop_probe(proc)
    check_counters(before, dump_counters(ctrl), frames)
    if ctrl.proc.poll() is not None:
        raise RuntimeError("controller exited during the counter test")


def run_test(net, ctrl: Controller) -> int:
    try:
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited before the counter test")
        prefix = b"\x02" + uuid.uuid4().bytes[:3]
        for name, frames in (
            ("idle", {}),
            ("h1 -> h2", {1: make_frames(prefix, 1)}),
            ("h2 -> h1", {2: make_frames(prefix, 2)}),
        ):
            info(f"*** Checking {name}\n")
            run_burst(net, ctrl, prefix, frames)
    except (
        RuntimeError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        TypeError,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    print(
        "SUCCESS: both ports forward complete frames and count exact packets and bytes"
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
    with NetworkRuntime(CounterTopo()) as runtime:
        net = runtime.net
        if args.run_test:
            configure_test_interfaces(net)
        ctrl = start_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)
        rc = run_test(net, ctrl) if args.run_test else 0
        if not args.run_test:
            CLI(net)
    sys.exit(rc)


if __name__ == "__main__":
    main()
