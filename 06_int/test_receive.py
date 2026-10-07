#!/usr/bin/env python3
"""Capture labelled IPv4 frames or validate the standalone h1-to-h2 INT demo."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import tempfile
import time

if __package__:
    from .packets import (
        HOST_IPS,
        PATHS,
        check_forwarded,
        int_option,
        make_frame,
        parse_frame,
    )
else:
    from packets import (
        HOST_IPS,
        PATHS,
        check_forwarded,
        int_option,
        make_frame,
        parse_frame,
    )


def receive_frames(
    iface: str, prefix: str, seconds: float, ready: str, limit: int | None = None
) -> list[bytes]:
    marker = bytes.fromhex(prefix)
    if len(marker) != 3:
        raise ValueError("capture prefix must contain three IPv4 source bytes")
    frames = []
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind((iface, 0))
        Path(ready).write_text("ready\n")
        if limit is not None:
            print(f"receiver ready on {iface}", flush=True)
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                frame, address = sock.recvfrom(65549)
            except socket.timeout:
                break
            if address[2] != socket.PACKET_OUTGOING and frame[26:29] == marker:
                frames.append(frame)
                if limit is not None and len(frames) >= limit:
                    break
    return frames


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="h2-eth0")
    parser.add_argument("--prefix")
    parser.add_argument("--seconds", type=float, default=4)
    parser.add_argument("--ready")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="p4-int-receiver-") as directory:
        source = ipaddress.IPv4Address(HOST_IPS[1]).packed
        frames = receive_frames(
            args.iface,
            args.prefix or source[:3].hex(),
            args.seconds,
            args.ready or str(Path(directory) / "ready"),
            limit=None if args.prefix is not None else 1,
        )
    if args.prefix is not None:
        print(json.dumps({"frames": [frame.hex() for frame in frames]}), flush=True)
        return 0
    try:
        if len(frames) != 1:
            raise RuntimeError(f"expected one demo frame, received {len(frames)}")
        check_forwarded(
            make_frame(source, 1, 2, int_option([])), frames[0], PATHS[1, 2]
        )
        for swid, depth, port in parse_frame(frames[0])["traces"]:
            print(f"swid={swid} qdepth={depth} portid={port}")
    except RuntimeError as exc:
        print(f"FAILURE: {exc}")
        return 1
    print("SUCCESS: complete INT packet carries the expected s1 and s2 traces")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
