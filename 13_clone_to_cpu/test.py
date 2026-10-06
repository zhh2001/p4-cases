#!/usr/bin/env python3
"""Send and capture uniquely labelled frames inside Mininet hosts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import struct
import time


ETHER_TYPE = 0x88B5
PREFIX = b"p4-cases-clone:"


def make_frame(src: str, dst: str, token: str, sequence: int) -> bytes:
    header = bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", ""))
    payload = PREFIX + token.encode("ascii") + b":" + struct.pack("!I", sequence)
    return header + struct.pack("!H", ETHER_TYPE) + payload.ljust(46, b"\0")


def send_frames(iface: str, src: str, dst: str, token: str, count: int) -> None:
    if count <= 0:
        raise ValueError("frame count must be positive")
    frames = [make_frame(src, dst, token, number) for number in range(count)]
    with socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_TYPE)
    ) as sock:
        sock.bind((iface, 0))
        for frame in frames:
            if sock.send(frame) != len(frame):
                raise RuntimeError("incomplete Ethernet frame send")
            time.sleep(0.01)
    print(
        json.dumps({"sent": count, "frames": [frame.hex() for frame in frames]}),
        flush=True,
    )


def receive_frames(iface: str, token: str, seconds: float, ready: str) -> None:
    frames = []
    prefix = PREFIX + token.encode("ascii") + b":"
    with socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_TYPE)
    ) as sock:
        sock.bind((iface, 0))
        Path(ready).write_text("ready\n")
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                frame, address = sock.recvfrom(65535)
            except socket.timeout:
                break
            if address[2] != socket.PACKET_OUTGOING and frame[14:].startswith(prefix):
                frames.append(frame.hex())
    print(json.dumps({"frames": frames}), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    send = commands.add_parser("send")
    send.add_argument("--iface", required=True)
    send.add_argument("--src", required=True)
    send.add_argument("--dst", required=True)
    send.add_argument("--token", required=True)
    send.add_argument("--count", type=int, default=10)
    receive = commands.add_parser("receive")
    receive.add_argument("--iface", required=True)
    receive.add_argument("--token", required=True)
    receive.add_argument("--seconds", type=float, default=3)
    receive.add_argument("--ready", required=True)
    args = parser.parse_args()
    if args.command == "send":
        send_frames(args.iface, args.src, args.dst, args.token, args.count)
    else:
        receive_frames(args.iface, args.token, args.seconds, args.ready)


if __name__ == "__main__":
    main()
