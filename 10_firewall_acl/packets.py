"""Construct labelled Ethernet test frames, including malformed IPv4 inputs."""

from __future__ import annotations

import ipaddress
import struct


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_frame(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    dport: int,
    options: bytes,
    sequence: int,
    fault: str = "",
    flags: int = 0,
    offset: int = 0,
) -> bytes:
    if len(options) > 40 or len(options) % 4:
        raise ValueError("IPv4 options must occupy 0 to 40 bytes in four-byte units")
    src, dst = (
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )
    payload = b"p4-acl:" + struct.pack("!I", sequence)
    ethernet = dst_mac + src_mac
    if protocol == "ARP":
        arp = struct.pack(
            "!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, src_mac, src, bytes(6), dst
        )
        return (ethernet + b"\x08\x06" + arp).ljust(60, b"\0")
    number = {"TCP": 6, "UDP": 17, "ICMP": 1}[protocol]
    if flags & 1:
        header_size = 20 if protocol == "TCP" else 8
        payload += bytes(-(header_size + len(payload)) % 8)
    if protocol == "TCP":
        transport = (
            struct.pack(
                "!HHIIBBHHH",
                4000 + sequence % 1000,
                dport,
                sequence,
                0,
                0x50,
                2,
                8192,
                0,
                0,
            )
            + payload
        )
        position = 16
    elif protocol == "UDP":
        transport = (
            struct.pack("!HHHH", 4000 + sequence % 1000, dport, 8 + len(payload), 0)
            + payload
        )
        position = 6
    else:
        transport = struct.pack("!BBHHH", 8, 0, 0, 1, sequence) + payload
        position = 2
    pseudo = (
        src + dst + struct.pack("!BBH", 0, number, len(transport))
        if number != 1
        else b""
    )
    value = checksum(pseudo + transport)
    if number == 17 and value == 0:
        value = 0xFFFF
    transport = (
        transport[:position] + struct.pack("!H", value) + transport[position + 2 :]
    )
    ihl = 5 + len(options) // 4
    total = 20 + len(options) + len(transport)
    version = 4
    if fault == "bad-version":
        version = 6
    elif fault == "short-ihl":
        ihl = 4
    elif fault == "short-total":
        total = 20
    elif fault == "long-total":
        total = 65535
    elif fault == "short-tcp":
        total = ihl * 4 + 19
    elif fault == "short-udp":
        total = ihl * 4 + 7
    header = (
        struct.pack(
            "!BBHHHBBH4s4s",
            (version << 4) | ihl,
            0,
            total,
            sequence,
            (flags << 13) | offset,
            64,
            number,
            0,
            src,
            dst,
        )
        + options
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    frame = ethernet + b"\x08\x00" + header + transport
    if fault == "truncated-ip":
        return frame[:26]
    if fault == "truncated-options":
        return frame[:36]
    return frame.ljust(60, b"\0")
