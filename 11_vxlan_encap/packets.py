"""Build labelled inner frames and the expected IPv4 VXLAN encapsulation."""

from __future__ import annotations

import ipaddress
import struct


INNER_DEST = bytes.fromhex("000000111111")
OUTER_DEST = bytes.fromhex("000000000002")
OUTER_SOURCE = bytes.fromhex("000000dead01")
OUTER_IP_SOURCE = ipaddress.IPv4Address("192.168.1.1").packed
OUTER_IP_DEST = ipaddress.IPv4Address("192.168.1.2").packed


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_probes(prefix: bytes) -> list[dict]:
    if len(prefix) != 4:
        raise ValueError("test prefix must contain four MAC bytes")
    sequence = 0
    probes = []
    shapes = [
        (f"raw-{size}", size, "raw", True) for size in (60, 64, 128, 512, 1500, 1514)
    ]
    shapes += [
        ("vlan", 128, "vlan", True),
        ("ipv4", 128, "ipv4", True),
        ("arp", 60, "arp", True),
    ]
    shapes += [
        ("unmatched-60", 60, "raw", False),
        ("unmatched-1514", 1514, "raw", False),
    ]
    for name, size, protocol, allowed in shapes:
        frames = []
        for _ in range(5):
            sequence += 1
            source = prefix + sequence.to_bytes(2, "big")
            destination = INNER_DEST if allowed else bytes.fromhex("000000222222")
            payload = b"p4-vxlan:" + sequence.to_bytes(4, "big")
            payload += bytes((sequence + offset) % 256 for offset in range(size))
            if protocol == "vlan":
                body = b"\x81\x00" + struct.pack("!HH", 100, 0x88B5) + payload
            elif protocol == "arp":
                body = b"\x08\x06" + struct.pack(
                    "!HHBBH6s4s6s4s",
                    1,
                    0x0800,
                    6,
                    4,
                    1,
                    source,
                    ipaddress.IPv4Address("10.0.0.1").packed,
                    bytes(6),
                    ipaddress.IPv4Address("10.0.0.2").packed,
                )
                body += payload
            elif protocol == "ipv4":
                data = payload[: size - 14 - 20]
                header = struct.pack(
                    "!BBHHHBBH4s4s",
                    0x45,
                    0,
                    20 + len(data),
                    sequence,
                    0,
                    64,
                    253,
                    0,
                    ipaddress.IPv4Address("10.0.0.1").packed,
                    ipaddress.IPv4Address("10.0.0.2").packed,
                )
                header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
                body = b"\x08\x00" + header + data
            else:
                body = b"\x88\xb5" + payload
            frames.append((destination + source + body)[:size])
        probes.append({"name": name, "allowed": allowed, "frames": frames})
    return probes


def encapsulate(inner: bytes) -> bytes:
    if len(inner) < 14 or len(inner) > 65499:
        raise ValueError("inner frame cannot fit in an IPv4 VXLAN packet")
    outer_eth = OUTER_DEST + OUTER_SOURCE + b"\x08\x00"
    outer_ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        36 + len(inner),
        0,
        0,
        64,
        17,
        0,
        OUTER_IP_SOURCE,
        OUTER_IP_DEST,
    )
    outer_ip = outer_ip[:10] + struct.pack("!H", checksum(outer_ip)) + outer_ip[12:]
    outer_udp = struct.pack("!HHHH", 12345, 4789, 16 + len(inner), 0)
    vxlan = b"\x08\0\0\0" + (5000).to_bytes(3, "big") + b"\0"
    return outer_eth + outer_ip + outer_udp + vxlan + inner
