#!/usr/bin/env python3
"""Send complete frames and capture marked incoming L2 traffic."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import struct
import time

SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
PACKET_AUXDATA = 8
AUXDATA = struct.Struct("=IIIHHHH")


def restore_vlan(frame: bytes, ancillary: list, flags: int) -> bytes:
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise RuntimeError("capture contains truncated bytes or ancillary data")
    samples = [
        data
        for level, kind, data in ancillary
        if level == SOL_PACKET and kind == PACKET_AUXDATA
    ]
    if len(samples) > 1:
        raise RuntimeError("capture contains duplicate packet metadata")
    if samples:
        if len(samples[0]) != AUXDATA.size:
            raise RuntimeError("capture contains malformed packet metadata")
        status, _, _, _, _, tci, tpid = AUXDATA.unpack(samples[0])
        if status & (1 << 4):
            if len(frame) < 14:
                raise RuntimeError("VLAN capture lacks a complete Ethernet header")
            tpid = tpid if status & (1 << 6) else 0x8100
            frame = frame[:12] + struct.pack("!HH", tpid, tci) + frame[12:]
    return frame


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
            time.sleep(0.001)
    print(json.dumps({"sent": len(frames)}), flush=True)


def receive_frames(iface: str, prefix: str, seconds: float, ready: str) -> None:
    marker = bytes.fromhex(prefix)
    if len(marker) != 4 or seconds <= 0:
        raise ValueError("capture needs four MAC bytes and a positive duration")
    frames = []
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        sock.bind((iface, 0))
        Path(ready).write_text("ready\n")
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                frame, ancillary, flags, address = sock.recvmsg(
                    65549, socket.CMSG_SPACE(AUXDATA.size)
                )
            except socket.timeout:
                break
            frame = restore_vlan(frame, ancillary, flags)
            if address[2] != socket.PACKET_OUTGOING and frame[6:10] == marker:
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
    receive.add_argument("--seconds", type=float, default=2)
    receive.add_argument("--ready", required=True)
    args = parser.parse_args()
    if args.command == "send":
        send_frames(args.iface, args.frames)
    else:
        receive_frames(args.iface, args.prefix, args.seconds, args.ready)


if __name__ == "__main__":
    main()
