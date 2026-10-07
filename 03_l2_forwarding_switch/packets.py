"""Build static L2 traffic with complete frames and explicit next hops."""

from __future__ import annotations

import ipaddress
import struct


def validate_host_count(number: int) -> None:
    if type(number) is not int or not 1 <= number <= 254:
        raise ValueError("host count must be between 1 and 254 for the /24 topology")


def host_ip(number: int) -> str:
    validate_host_count(number)
    return f"10.0.0.{number}"


def host_mac(number: int) -> str:
    validate_host_count(number)
    return f"00:00:00:00:00:{number:02x}"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_udp(sender: int, receiver: int, identification: int, ttl: int = 64) -> bytes:
    source = ipaddress.IPv4Address(f"198.18.0.{sender}").packed
    destination = ipaddress.IPv4Address(host_ip(receiver)).packed
    payload = identification.to_bytes(4, "big") + bytes(range(29))
    udp = struct.pack("!HHHH", 1111, 2222, 8 + len(payload), 0) + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 17, len(udp))
    value = checksum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", value) + udp[8:]
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0x2A,
        20 + len(udp),
        identification & 0xFFFF,
        0x4000,
        ttl,
        17,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + udp


def ipv6_udp(
    sender: int, receiver: int, identification: int, hop_limit: int = 64
) -> bytes:
    source = ipaddress.IPv6Address(f"2001:db8:ff00::{sender:x}").packed
    destination = ipaddress.IPv6Address(f"2001:db8::{receiver:x}").packed
    payload = identification.to_bytes(4, "big") + bytes(range(29))
    udp = struct.pack("!HHHH", 1111, 2222, 8 + len(payload), 0) + payload
    pseudo = source + destination + struct.pack("!I3xB", len(udp), 17)
    value = checksum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", value) + udp[8:]
    return (
        struct.pack(
            "!IHBB16s16s",
            (6 << 28) | (0x2A << 20) | (identification & 0xFFFFF),
            len(udp),
            17,
            hop_limit,
            source,
            destination,
        )
        + udp
    )


def make_frame(
    prefix: bytes,
    identification: int,
    destination: bytes,
    ether_type: int = 0x88B5,
    body: bytes = b"",
) -> bytes:
    if (
        len(prefix) != 4
        or prefix[0] & 1
        or len(destination) != 6
        or type(identification) is not int
        or not 0 < identification < (1 << 32)
    ):
        raise ValueError("invalid marker, identity or destination MAC")
    source = prefix + struct.pack("!H", identification & 0xFFFF)
    return (destination + source + struct.pack("!H", ether_type) + body).ljust(
        60, b"\xa5"
    )


def make_probes(prefix: bytes, n_hosts: int = 4) -> list[dict]:
    validate_host_count(n_hosts)
    probes = []

    def add(name, sender, receiver, kind="opaque", destination=None, allowed=True):
        identification = len(probes) + 1
        target = bytes.fromhex(host_mac(receiver).replace(":", ""))
        destination = target if destination is None else destination
        ipv4 = ipv4_udp(sender, receiver, identification)
        ipv6 = ipv6_udp(sender, receiver, identification)
        ether_type, body = 0x88B5, identification.to_bytes(4, "big") + bytes(range(29))
        if kind == "ipv4":
            ether_type, body = 0x0800, ipv4
        elif kind in ("ttl-zero", "ttl-one"):
            ether_type, body = 0x0800, ipv4_udp(
                sender, receiver, identification, 0 if kind == "ttl-zero" else 1
            )
        elif kind == "bad-ipv4-checksum":
            ether_type, body = 0x0800, ipv4[:10] + bytes((ipv4[10] ^ 1,)) + ipv4[11:]
        elif kind == "ipv6":
            ether_type, body = 0x86DD, ipv6
        elif kind == "hop-zero":
            ether_type, body = 0x86DD, ipv6_udp(sender, receiver, identification, 0)
        elif kind == "arp":
            ether_type = 0x0806
            body = struct.pack(
                "!HHBBH6s4s6s4s",
                1,
                0x0800,
                6,
                4,
                2,
                prefix + struct.pack("!H", identification & 0xFFFF),
                ipaddress.IPv4Address(host_ip(sender)).packed,
                target,
                ipaddress.IPv4Address(host_ip(receiver)).packed,
            )
        elif kind == "vlan":
            ether_type, body = 0x8100, struct.pack("!HH", 0xA007, 0x0800) + ipv4
        elif kind == "qinq":
            ether_type, body = (
                0x88A8,
                struct.pack("!HHHH", 42, 0x8100, 7, 0x86DD) + ipv6,
            )
        elif kind == "empty":
            body = b""
        elif kind == "mtu":
            body = identification.to_bytes(4, "big") + (bytes(range(256)) * 6)[:1496]
        frame = make_frame(prefix, identification, destination, ether_type, body)
        probes.append(
            {
                "name": name,
                "sender": f"h{sender}",
                "receiver": f"h{receiver}" if allowed else None,
                "allowed": allowed,
                "frame": frame,
            }
        )

    for sender in range(1, n_hosts + 1):
        for receiver in range(1, n_hosts + 1):
            if receiver != sender:
                for repeat in range(3 if n_hosts <= 4 else 1):
                    add(f"pair-{sender}-{receiver}-{repeat}", sender, receiver)
        receiver = sender % n_hosts + 1
        for kind in (
            "ipv4",
            "ttl-zero",
            "ttl-one",
            "bad-ipv4-checksum",
            "ipv6",
            "hop-zero",
            "arp",
            "vlan",
            "qinq",
            "empty",
            "mtu",
        ):
            add(
                f"content-{sender}-{kind}",
                sender,
                receiver,
                kind,
                allowed=receiver != sender,
            )
        for kind in ("opaque", "ipv4", "ipv6", "vlan"):
            add(f"same-port-{sender}-{kind}", sender, sender, kind, allowed=False)
        target = bytes.fromhex(host_mac(receiver).replace(":", ""))
        unknown = (
            bytes((2,)) + target[1:],
            target[:2] + b"\x01" + target[3:],
            target[:4] + b"\x01" + target[5:],
            bytes(6),
        )
        for index, destination in enumerate(
            (
                *unknown,
                b"\xff" * 6,
                bytes.fromhex("01005e000001"),
                bytes.fromhex("333300000001"),
            )
        ):
            add(
                f"unmatched-{sender}-{index}",
                sender,
                receiver,
                destination=destination,
                allowed=False,
            )
    return probes
