#!/usr/bin/env python3
"""Mininet topology for Case 13: clone to CPU.

2 hosts on s1 ports 1 and 2. The switch is started with a CPU port
(510) so BMv2 bridges that port to the P4Runtime PacketIn stream.
Each direction sends uniquely labelled frames. The test checks original
delivery and complete PacketIn copies with the matching ingress port.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import struct
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
from common.p4switch import P4RuntimeSwitch  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402


class CpuTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1, cpu_port=510)
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
    )


def wait_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("clone-to-cpu ready", timeout)


def packet_ins(proc: Controller, token: str, seconds: float) -> list[tuple[int, bytes]]:
    """Observe only packets carrying this run's token within a fixed deadline."""
    packets = []
    for line in proc.lines_for(seconds):
        if not line.startswith("packet-in #"):
            continue
        match = re.fullmatch(
            r"packet-in #\d+ ingress_port=(\d+) payload=([0-9a-fA-F]+)", line
        )
        if match is None:
            raise RuntimeError(f"malformed PacketIn log: {line}")
        payload = bytes.fromhex(match[2])
        if token.encode("ascii") in payload[16:]:
            packets.append((int(match[1]), payload))
    return packets


def read_probe(proc: subprocess.Popen, timeout: float = 5) -> dict:
    output, error = proc.communicate(timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"packet probe failed: {output.strip()} {error.strip()}")
    try:
        data = json.loads(output)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"invalid packet probe reply: {output!r}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("packet probe reply must be an object")
    return data


def frame_list(reply: dict) -> list[bytes]:
    frames = reply.get("frames")
    if not isinstance(frames, list) or any(
        not isinstance(frame, str) for frame in frames
    ):
        raise RuntimeError("packet probe reply must contain a frame list")
    try:
        return [bytes.fromhex(frame) for frame in frames]
    except ValueError as exc:
        raise RuntimeError("packet probe returned invalid frame bytes") from exc


def check_sent(reply: dict, src: str, dst: str, token: str, count: int) -> list[bytes]:
    frames = frame_list(reply)
    header = bytes.fromhex(dst.replace(":", "") + src.replace(":", "")) + b"\x88\xb5"
    if reply.get("sent") != count or len(frames) != count or len(set(frames)) != count:
        raise RuntimeError("sender did not confirm distinct test frames")
    if any(
        not frame.startswith(header) or token.encode("ascii") not in frame[14:]
        for frame in frames
    ):
        raise RuntimeError("sender reported unexpected test frames")
    return frames


def check_copies(
    frames: list[bytes],
    received: list[bytes],
    clones: list[tuple[int, bytes]],
    ingress: int,
) -> None:
    if Counter(received) != Counter(frames):
        raise RuntimeError(
            f"forwarded frames differ: received {len(received)}, expected {len(frames)}"
        )
    expected = [
        frame[:12] + b"\x10\x10" + struct.pack("!H", ingress) + frame[14:]
        for frame in frames
    ]
    if any(port != ingress for port, _ in clones):
        raise RuntimeError("PacketIn reported an unexpected ingress port")
    if Counter(payload for _, payload in clones) != Counter(expected):
        raise RuntimeError(
            f"CPU copies differ: received {len(clones)}, expected {len(frames)}"
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


def check_direction(
    net: Mininet, ctrl: Controller, sender_name: str, receiver_name: str
) -> None:
    sender, receiver = net.get(sender_name), net.get(receiver_name)
    token = uuid.uuid4().hex
    count = 10
    procs = []
    with tempfile.TemporaryDirectory(prefix="p4-clone-") as directory:
        ready = Path(directory) / "receiver"
        try:
            rx = receiver.popen(
                [
                    "python3",
                    f"{HERE}/test.py",
                    "receive",
                    "--iface",
                    receiver.defaultIntf().name,
                    "--token",
                    token,
                    "--ready",
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(rx)
            deadline = time.monotonic() + 3
            while not ready.exists() or ready.read_text() != "ready\n":
                if rx.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("packet receiver did not become ready")
                time.sleep(0.02)
            tx = sender.popen(
                [
                    "python3",
                    f"{HERE}/test.py",
                    "send",
                    "--iface",
                    sender.defaultIntf().name,
                    "--src",
                    sender.MAC(),
                    "--dst",
                    receiver.MAC(),
                    "--token",
                    token,
                    "--count",
                    str(count),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(tx)
            frames = check_sent(
                read_probe(tx), sender.MAC(), receiver.MAC(), token, count
            )
            clones = packet_ins(ctrl, token, seconds=3)
            received = frame_list(read_probe(rx))
            ingress = int(sender_name[1:])
            check_copies(frames, received, clones, ingress)
            if ctrl.proc.poll() is not None:
                raise RuntimeError("controller exited during the packet test")
            print(
                f"{sender_name} -> {receiver_name}: sent={count}, forwarded={len(received)}, cloned={len(clones)}, ingress_port={ingress}"
            )
        finally:
            for proc in procs:
                stop_probe(proc)


def run_test(net: Mininet, ctrl: Controller) -> int:
    try:
        info("*** Checking forwarded frames and CPU copies in both directions\n")
        check_direction(net, ctrl, "h1", "h2")
        check_direction(net, ctrl, "h2", "h1")
    except (
        RuntimeError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        TypeError,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    print("SUCCESS: every test frame was forwarded and cloned with its ingress port")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    with NetworkRuntime(CpuTopo()) as runtime:
        net = runtime.net

        ctrl = start_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_ready(ctrl):
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
