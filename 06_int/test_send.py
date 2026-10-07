#!/usr/bin/env python3
"""Send a frame manifest or one empty-INT UDP packet from h1 to h2."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import time

if __package__:
    from .packets import HOST_IPS, int_option, make_frame
else:
    from packets import HOST_IPS, int_option, make_frame


def send_frames(iface: str, filename: str | None = None) -> int:
    if filename is None:
        frames = [
            make_frame(ipaddress.IPv4Address(HOST_IPS[1]).packed, 1, 2, int_option([]))
        ]
    else:
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
            time.sleep(0.005)
    return len(frames)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="h1-eth0")
    parser.add_argument("--frames")
    args = parser.parse_args()
    print(json.dumps({"sent": send_frames(args.iface, args.frames)}), flush=True)


if __name__ == "__main__":
    main()
