#!/usr/bin/env python3
"""Mininet topology for Case 07: meter-based policing.

Single switch with two hosts. All packets default to egress port 2,
so h1 (port 1) always tries to send to h2 (port 2). The meter is
armed for src MAC aa:aa:aa:aa:aa:aa; other src MACs skip the meter
and pass unconditionally.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import math
import os
from pathlib import Path
import struct
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

METERED_MAC = "aa:aa:aa:aa:aa:aa"
UNMETERED_MAC = "02:bb:bb:bb:bb:bb"
CIR = 10
CBURST = 5
PIR = 20
PBURST = 10
MAX_BURST_SECONDS = 0.5


class MeterTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        self.addLink(h1, sw)
        self.addLink(h2, sw)


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
            "-cir",
            str(CIR),
            "-cburst",
            str(CBURST),
            "-pir",
            str(PIR),
            "-pburst",
            str(PBURST),
        ],
    )


def wait_controller_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("meter-switch ready", timeout)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    with NetworkRuntime(MeterTopo()) as runtime:
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


def make_frames(source: str, marker: bytes, phase: int, count: int) -> list[bytes]:
    mac = bytes.fromhex(source.replace(":", ""))
    if len(mac) != 6 or len(marker) != 8 or count <= 0:
        raise ValueError(
            "frames require a MAC, an eight-byte marker and a positive count"
        )
    header = bytes.fromhex("000000000002") + mac + b"\x88\xb5"
    return [
        (header + marker + struct.pack("!BI", phase, sequence)).ljust(
            60 + sequence % 4 * 20, b"\0"
        )
        for sequence in range(count)
    ]


def read_probe(proc: subprocess.Popen, timeout: float = 4) -> dict:
    output, error = proc.communicate(timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"packet probe failed: {output.strip()} {error.strip()}")
    try:
        reply = json.loads(output)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("packet probe returned invalid JSON") from exc
    if not isinstance(reply, dict):
        raise RuntimeError("packet probe reply must be an object")
    return reply


def timestamp(value) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise RuntimeError("packet probe returned an invalid timestamp")
    return float(value)


def check_burst(frames: list[bytes], sent: dict, capture: dict, limited: bool) -> str:
    if type(sent.get("sent")) is not int or sent["sent"] != len(frames):
        raise RuntimeError("sender did not confirm all test frames")
    started, finished = timestamp(sent.get("started")), timestamp(sent.get("finished"))
    if finished < started:
        raise RuntimeError("sender timestamps are out of order")
    records = capture.get("frames")
    if not isinstance(records, list):
        raise RuntimeError("capture reply must contain a frame list")
    received = []
    last = finished
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("frame"), str):
            raise RuntimeError("capture reply contains an invalid frame")
        try:
            received.append(bytes.fromhex(record["frame"]))
        except ValueError as exc:
            raise RuntimeError("capture reply contains invalid frame bytes") from exc
        at = timestamp(record.get("at"))
        if at < started:
            raise RuntimeError("capture contains a frame from before this burst")
        last = max(last, at)
    actual, expected = Counter(received), Counter(frames)
    if actual - expected:
        raise RuntimeError("capture contains duplicated, unexpected or changed frames")
    elapsed = last - started
    if elapsed > MAX_BURST_SECONDS:
        raise RuntimeError(
            f"burst took {elapsed:.3f}s, exceeding the {MAX_BURST_SECONDS:g}s timing budget"
        )
    if limited:
        upper = CBURST + math.ceil(CIR * elapsed)
        if not all(actual[frame] == 1 for frame in frames[:CBURST]):
            raise RuntimeError("meter did not deliver the initial committed burst")
        if len(received) > upper or len(received) >= len(frames):
            raise RuntimeError(
                f"meter delivered {len(received)} frames, expected {CBURST}..{upper} with drops"
            )
        wanted = f"{CBURST}..{upper}"
    else:
        if actual != expected:
            raise RuntimeError(
                f"allowed burst lost frames: received {len(received)}/{len(frames)}"
            )
        wanted = str(len(frames))
    return f"received={len(received)}/{len(frames)}, expected={wanted}, burst={elapsed:.6f}s"


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
    sender, receiver, source: str, marker: bytes, phase: int, count: int, limited: bool
) -> str:
    procs = []
    try:
        frames = make_frames(source, marker, phase, count)
        with tempfile.TemporaryDirectory(prefix="p4-meter-") as directory:
            ready = Path(directory) / "ready"
            capture = receiver.popen(
                [
                    "python3",
                    f"{HERE}/test.py",
                    "receive",
                    "--iface",
                    receiver.defaultIntf().name,
                    "--source",
                    source,
                    "--ready",
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(capture)
            deadline = time.monotonic() + 2
            while not (ready.exists() and ready.read_text() == "ready\n"):
                if time.monotonic() >= deadline or capture.poll() is not None:
                    raise RuntimeError("packet receiver did not become ready")
                time.sleep(0.02)
            manifest = Path(directory) / "frames.json"
            manifest.write_text(json.dumps([frame.hex() for frame in frames]))
            transmit = sender.popen(
                [
                    "python3",
                    f"{HERE}/test.py",
                    "send",
                    "--iface",
                    sender.defaultIntf().name,
                    "--frames",
                    str(manifest),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(transmit)
            sent = read_probe(transmit)
            received = read_probe(capture)
            return check_burst(frames, sent, received, limited)
    finally:
        for proc in procs:
            stop_probe(proc)


def run_test(net, ctrl: Controller | None = None) -> int:
    try:
        h1, h2 = net.get("h1"), net.get("h2")
        marker = uuid.uuid4().bytes[:8]
        phases = [
            ("unmetered-before", UNMETERED_MAC, 30, False),
            ("metered-burst", METERED_MAC, 30, True),
            ("metered-after-refill", METERED_MAC, CBURST, False),
            ("unmetered-after", UNMETERED_MAC, 30, False),
        ]
        for phase, (name, source, count, limited) in enumerate(phases):
            if name == "metered-after-refill":
                time.sleep(CBURST / CIR + 0.1)
            if ctrl is not None and ctrl.proc.poll() is not None:
                raise RuntimeError("controller exited during the meter test")
            info(f"*** Checking {name}\n")
            result = run_burst(h1, h2, source, marker, phase, count, limited)
            print(f"{name}: {result}")
        if ctrl is not None and ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited during the meter test")
    except (
        RuntimeError,
        OSError,
        subprocess.TimeoutExpired,
        TypeError,
        ValueError,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    print(
        "SUCCESS: unmetered delivery, burst policing and token refill match expectations"
    )
    return 0


if __name__ == "__main__":
    main()
