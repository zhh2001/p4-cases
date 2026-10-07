#!/usr/bin/env python3
"""Mininet topology for Case 12: register-based flow counter.

Check complete bidirectional delivery and every register slot's delta.
The Go controller attempts a P4Runtime seed write. Thrift snapshots
and deliberate seeds validate nonzero state, collisions and wraparound.
"""

from __future__ import annotations

import argparse
from collections import Counter
import importlib
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
from mininet.net import Mininet
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch, reset_port_allocators  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402

packets = importlib.import_module("12_register_flow_counter.packets")


class RegTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
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
        interactive=True,
    )


def wait_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("register-counter ready", timeout)


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
            raise RuntimeError(f"cannot configure {name}: {output} {error}")


def validate_snapshot(values: list[int]) -> None:
    if (
        not isinstance(values, list)
        or len(values) != packets.REGISTER_SIZE
        or any(
            type(value) is not int or not 0 <= value < packets.COUNTER_MODULUS
            for value in values
        )
    ):
        raise RuntimeError(
            "register snapshot must contain all 1024 unsigned 32-bit values"
        )


def parse_register_dump(output: str) -> list[int]:
    if re.search(
        r"\b(error|invalid|unknown command|traceback|exception)\b", output, re.I
    ):
        raise RuntimeError("Thrift CLI reported an error")
    samples = list(
        re.finditer(
            r"^(?:RuntimeCmd:\s*)*(?:MyIngress\.)?flow_counter(?:\[(\d+)\])?\s*=\s*([^\n]+)",
            output,
            re.M,
        )
    )
    declared = re.findall(
        r"^(?:RuntimeCmd:\s*)*(?:MyIngress\.)?flow_counter\b[^\n]*", output, re.M
    )
    if len(declared) != len(samples):
        raise RuntimeError("Thrift register dump contains malformed samples")
    if len(samples) == 1 and samples[0].group(1) is None:
        value = samples[0].group(2).strip()
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1].strip()
        if not (
            re.fullmatch(r"\d+(?:\s*,\s*\d+)*", value)
            or re.fullmatch(r"\d+(?:\s+\d+)*", value)
        ):
            raise RuntimeError("Thrift register array contains invalid values")
        result = [int(token) for token in re.split(r"[,\s]+", value)]
    else:
        values = {}
        for sample in samples:
            index, value = sample.groups()
            if index is None or not re.fullmatch(r"\d+", value.strip()):
                raise RuntimeError("Thrift register samples are incomplete or mixed")
            index = int(index)
            if index in values or not 0 <= index < packets.REGISTER_SIZE:
                raise RuntimeError("Thrift register index is duplicate or out of range")
            values[index] = int(value)
        if set(values) != set(range(packets.REGISTER_SIZE)):
            raise RuntimeError("Thrift register dump did not include every slot")
        result = [values[index] for index in range(packets.REGISTER_SIZE)]
    validate_snapshot(result)
    return result


def thrift_command(thrift_port: int, commands: str) -> str:
    if type(thrift_port) is not int or not 1 <= thrift_port <= 65535:
        raise ValueError("invalid Thrift port")
    result = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input=commands,
        capture_output=True,
        text=True,
        timeout=6,
    )
    if result.returncode or re.search(
        r"\b(error|invalid|unknown command|traceback|exception)\b",
        result.stdout + result.stderr,
        re.I,
    ):
        raise RuntimeError(
            f"Thrift command failed: {result.stdout.strip()} {result.stderr.strip()}"
        )
    return result.stdout


def thrift_register_dump(thrift_port: int) -> list[int]:
    return parse_register_dump(
        thrift_command(thrift_port, "register_read MyIngress.flow_counter\n")
    )


def seed_register(thrift_port: int, slot: int, value: int) -> list[int]:
    if (
        type(slot) is not int
        or not 0 <= slot < packets.REGISTER_SIZE
        or type(value) is not int
        or not 0 <= value < packets.COUNTER_MODULUS
    ):
        raise ValueError("invalid register seed index or value")
    before = thrift_register_dump(thrift_port)
    output = thrift_command(
        thrift_port,
        f"register_write MyIngress.flow_counter {slot} {value}\n"
        "register_read MyIngress.flow_counter\n",
    )
    after = parse_register_dump(output)
    expected = before.copy()
    expected[slot] = value
    if after != expected:
        raise RuntimeError("register seed did not change only the requested slot")
    return after


def check_counts(before: list[int], after: list[int], probes: list[dict]) -> None:
    validate_snapshot(before)
    validate_snapshot(after)
    expected = Counter(
        packets.flow_slot(item["frame"]) for item in probes if item["counted"]
    )
    for slot in range(packets.REGISTER_SIZE):
        actual = (after[slot] - before[slot]) % packets.COUNTER_MODULUS
        if actual != expected[slot]:
            raise RuntimeError(
                f"slot {slot} delta is {actual}, expected {expected[slot]}"
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


def check_delivery(probes: list[dict], received: dict[str, list[bytes]]) -> None:
    if set(received) != {"h1", "h2"}:
        raise RuntimeError("capture replies must include both hosts")
    for name in ("h1", "h2"):
        frames = received[name]
        expected = [
            item["frame"]
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


def run_batch(
    net: Mininet, ctrl: Controller, thrift_port: int, prefix: bytes, probes: list[dict]
) -> None:
    if ctrl.proc.poll() is not None:
        raise RuntimeError("controller exited before the register test")
    before = thrift_register_dump(thrift_port)
    procs = []
    try:
        with tempfile.TemporaryDirectory(prefix="p4-register-") as directory:
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
            senders = []
            for name in ("h1", "h2"):
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
        after = thrift_register_dump(thrift_port)
        check_counts(before, after, probes)
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited during the register test")
    finally:
        for proc in procs:
            stop_probe(proc)


def run_test(net: Mininet, ctrl: Controller, thrift_port: int) -> int:
    try:
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited before the register test")
        configure_test_interfaces(net)
        prefix = b"\x02" + uuid.uuid4().bytes[:3]
        batches = packets.make_batches(prefix)
        before = seed_register(thrift_port, 1023, 42)
        time.sleep(0.15)
        check_counts(before, thrift_register_dump(thrift_port), [])
        for name, probes in batches:
            if name == "wraparound":
                seed_register(thrift_port, 0, packets.COUNTER_MODULUS - 2)
            run_batch(net, ctrl, thrift_port, prefix, probes)
            forwarded = sum(item["allowed"] for item in probes)
            counted = sum(item["counted"] for item in probes)
            print(
                f"{name}: sent={len(probes)} forwarded={forwarded} dropped={len(probes)-forwarded} counted={counted}"
            )
    except (
        RuntimeError,
        OSError,
        ValueError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    print(
        f"SUCCESS: {sum(len(probes) for _, probes in batches)} frames preserve forwarding and exact register deltas"
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
    with NetworkRuntime(RegTopo()) as runtime:
        net = runtime.net

        sw = net.get("s1")
        thrift_port = sw.thrift_port

        ctrl = start_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)

        rc = 0
        if args.run_test:
            rc = run_test(net, ctrl, thrift_port)
        else:
            CLI(net)

    sys.exit(rc)


if __name__ == "__main__":
    main()
