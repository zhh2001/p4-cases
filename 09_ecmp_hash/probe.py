#!/usr/bin/env python3
"""Send manifests and capture labelled incoming IPv4 frames."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import time


def send_frames(iface: str, filename: str) -> None:
    values = json.loads(Path(filename).read_text())
    if (
        not isinstance(values, list)
        or not values
        or any(not isinstance(value, str) for value in values)
    ):
        raise ValueError("manifest must contain frame hex strings")
    frames = [bytes.fromhex(value) for value in values]
    if any(len(frame) < 14 for frame in frames):
        raise ValueError("manifest must contain complete Ethernet headers")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind((iface, 0))
        for frame in frames:
            if sock.send(frame) != len(frame):
                raise RuntimeError("incomplete Ethernet frame send")
            time.sleep(0.003)
    print(json.dumps({"sent": len(frames)}), flush=True)


def receive_frames(iface: str, prefix: str, seconds: float, ready: str) -> None:
    marker = bytes.fromhex(prefix)
    if len(marker) != 3:
        raise ValueError("capture prefix must contain three IPv4 source bytes")
    if seconds <= 0:
        raise ValueError("capture duration must be positive")
    frames = []
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind((iface, 0))
        Path(ready).write_text("ready\n")
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                frame, address = sock.recvfrom(65549)
            except socket.timeout:
                break
            if address[2] != socket.PACKET_OUTGOING and frame[26:29] == marker:
                frames.append(frame.hex())
    print(json.dumps({"frames": frames}), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    send = commands.add_parser("send")
    send.add_argument("--iface", required=True)
    send.add_argument("--frames", required=True)
    receive = commands.add_parser("receive")
    receive.add_argument("--iface", required=True)
    receive.add_argument("--prefix", required=True)
    receive.add_argument("--seconds", type=float, default=5)
    receive.add_argument("--ready", required=True)
    args = parser.parse_args()
    if args.command == "send":
        send_frames(args.iface, args.frames)
    else:
        receive_frames(args.iface, args.prefix, args.seconds, args.ready)


if __name__ == "__main__":
    main()
