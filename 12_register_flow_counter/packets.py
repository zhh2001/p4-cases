"""Build labelled register traffic and predict hash bucket increments."""

from __future__ import annotations

import ipaddress
import struct


REGISTER_SIZE = 1024
COUNTER_MODULUS = 1 << 32
HOST_MACS = {number: bytes.fromhex(f"0000000000{number:02x}") for number in (1, 2)}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def crc16(data: bytes) -> int:
    """CRC-16/ARC with BMv2's zero initial remainder and final XOR."""
    result = 0
    for byte in data:
        result ^= byte
        for _ in range(8):
            result = (result >> 1) ^ (0xA001 if result & 1 else 0)
    return result


def hash_slot(source: str, destination: str, sport: int, dport: int) -> int:
    data = (
        ipaddress.IPv4Address(source).packed
        + ipaddress.IPv4Address(destination).packed
        + struct.pack("!HH", sport, dport)
    )
    return crc16(data) % REGISTER_SIZE


def flow_slot(frame: bytes) -> int:
    start = 14 + (frame[14] & 15) * 4
    return crc16(frame[26:34] + frame[start : start + 4]) % REGISTER_SIZE


def ports_for_slot(source: str, destination: str, target: int) -> tuple[int, int]:
    if type(target) is not int or not 0 <= target < REGISTER_SIZE:
        raise ValueError("register index is outside the array")
    found = []
    for port in range(10000, 65536):
        if hash_slot(source, destination, port, 2222) == target:
            found.append(port)
            if len(found) == 2:
                return tuple(found)
    raise RuntimeError("could not find two UDP flows for the requested slot")


def recalculate_checksum(frame: bytes) -> bytes:
    result = bytearray(frame)
    end = 14 + max(20, (frame[14] & 15) * 4)
    result[24:26] = b"\0\0"
    result[24:26] = struct.pack("!H", checksum(bytes(result[14:end])))
    return bytes(result)


def make_frame(
    prefix: bytes,
    identification: int,
    sender: int = 1,
    source: str | None = None,
    destination: str | None = None,
    sport: int = 1111,
    dport: int = 2222,
    options: bytes = b"",
    payload_size: int = 24,
    protocol: int = 17,
    ttl: int = 64,
    flags: int = 0,
    transport: bytes | None = None,
    udp_checksum: bool = True,
    datagram_id: int | None = None,
) -> bytes:
    if (
        len(prefix) != 4
        or sender not in HOST_MACS
        or len(options) % 4
        or len(options) > 40
        or not 0 <= payload_size <= 1472
    ):
        raise ValueError("invalid prefix, sender, options or payload length")
    source_ip = ipaddress.IPv4Address(source or f"10.0.0.{sender}").packed
    target_ip = ipaddress.IPv4Address(destination or f"10.0.0.{3 - sender}").packed
    payload = (
        b"register:" + struct.pack("!H", identification) + bytes(range(256)) * 6
    )[:payload_size]
    if transport is None:
        if protocol == 17:
            transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        elif protocol == 6:
            transport = struct.pack(
                "!HHIIBBHHH", sport, dport, identification, 0, 0x50, 0x18, 4096, 0, 0
            )
        else:
            transport = b""
        transport += payload
        if protocol == 6 or (protocol == 17 and udp_checksum):
            pseudo = (
                source_ip + target_ip + struct.pack("!BBH", 0, protocol, len(transport))
            )
            offset = 16 if protocol == 6 else 6
            value = checksum(pseudo + transport)
            if protocol == 17 and value == 0:
                value = 0xFFFF
            transport = (
                transport[:offset] + struct.pack("!H", value) + transport[offset + 2 :]
            )
    header = (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45 + len(options) // 4,
            0x2A,
            20 + len(options) + len(transport),
            identification if datagram_id is None else datagram_id,
            flags,
            ttl,
            protocol,
            0,
            source_ip,
            target_ip,
        )
        + options
    )
    frame = (
        HOST_MACS[3 - sender]
        + prefix
        + struct.pack("!H", identification)
        + b"\x08\x00"
        + header
        + transport
    )
    return recalculate_checksum(frame).ljust(60, b"\0")


def make_batches(prefix: bytes) -> list[tuple[str, list[dict]]]:
    if len(prefix) != 4:
        raise ValueError("capture prefix must contain four MAC bytes")
    batches = []
    sequence = 0

    def add(
        batch, name, sender=1, allowed=True, counted=True, transform=None, **kwargs
    ):
        nonlocal sequence
        sequence += 1
        frame = make_frame(prefix, sequence, sender=sender, **kwargs)
        if transform is not None:
            frame = transform(frame)
        batch.append(
            {
                "name": name,
                "frame": frame,
                "sender": f"h{sender}",
                "receiver": f"h{3 - sender}",
                "allowed": allowed,
                "counted": counted,
            }
        )

    def replace(offset, data):
        return lambda frame: recalculate_checksum(
            frame[:offset] + data + frame[offset + len(data) :]
        )

    flows = []
    for sender in (1, 2):
        for repeat in range(30):
            add(
                flows,
                f"h{sender}-repeated-{repeat}",
                sender=sender,
                options=(b"", b"\x01" * 4, b"\x01" * 40)[repeat % 3],
                payload_size=(24, 127, 1024)[repeat % 3],
            )
        for field in ("source", "destination", "sport", "dport"):
            for value in range(4):
                changed = {
                    "source": f"192.0.2.{value + 10}",
                    "destination": f"198.51.100.{value + 10}",
                    "sport": value + 3000,
                    "dport": value + 4000,
                }
                add(
                    flows,
                    f"h{sender}-{field}-{value}",
                    sender=sender,
                    options=b"\x01" * 4,
                    **{field: changed[field]},
                )
        for size in (0, 1472):
            add(flows, f"h{sender}-udp-size-{size}", sender=sender, payload_size=size)
        add(flows, f"h{sender}-udp-zero-checksum", sender=sender, udp_checksum=False)
        add(flows, f"h{sender}-dont-fragment", sender=sender, flags=0x4000)
        for ttl in (0, 1):
            add(flows, f"h{sender}-ttl-{ttl}", sender=sender, ttl=ttl)
    batches.append(("udp-flows", flows))

    collisions = []
    for sender, target, sizes in ((1, 1023, (7, 11)), (2, 0, (5, 9))):
        ports = ports_for_slot(f"10.0.0.{sender}", f"10.0.0.{3 - sender}", target)
        for port, count in zip(ports, sizes):
            for repeat in range(count):
                add(
                    collisions,
                    f"slot-{target}-port-{port}-{repeat}",
                    sender=sender,
                    sport=port,
                    options=b"\x01" * (4 * (repeat % 3)),
                )
    batches.append(("collisions", collisions))

    excluded = []
    for sender in (1, 2):
        for protocol in (6, 1, 253):
            add(
                excluded,
                f"h{sender}-protocol-{protocol}",
                sender=sender,
                protocol=protocol,
                counted=False,
                options=b"\x01" * 4,
            )
        add(
            excluded,
            f"h{sender}-opaque-empty",
            sender=sender,
            protocol=253,
            payload_size=0,
            counted=False,
        )
        add(
            excluded,
            f"h{sender}-non-ipv4",
            sender=sender,
            counted=False,
            transform=lambda frame: frame[:12] + b"\x88\xb5" + frame[14:],
        )

        def arp(frame):
            payload = struct.pack(
                "!HHBBH6s4s6s4s",
                1,
                0x0800,
                6,
                4,
                1,
                frame[6:12],
                ipaddress.IPv4Address(f"10.0.0.{sender}").packed,
                bytes(6),
                ipaddress.IPv4Address(f"10.0.0.{3 - sender}").packed,
            )
            return (b"\xff" * 6 + frame[6:12] + b"\x08\x06" + payload).ljust(60, b"\0")

        add(excluded, f"h{sender}-arp", sender=sender, counted=False, transform=arp)
        for protocol in (17, 6):
            fragment_id = sequence + 1
            datagram = make_frame(
                prefix,
                sequence + 1,
                sender=sender,
                protocol=protocol,
                payload_size=40 if protocol == 17 else 28,
            )[34:82]
            for piece in range(3):
                add(
                    excluded,
                    f"h{sender}-fragment-{protocol}-{piece}",
                    sender=sender,
                    protocol=protocol,
                    datagram_id=fragment_id,
                    counted=False,
                    options=b"\x01" * 4,
                    flags=piece * 2 | (0x2000 if piece < 2 else 0),
                    transport=datagram[16 * piece : 16 * (piece + 1)],
                )
        bad = {"sender": sender, "allowed": False, "counted": False}
        add(excluded, f"h{sender}-bad-version", transform=replace(14, b"\x65"), **bad)
        add(excluded, f"h{sender}-short-ihl", transform=replace(14, b"\x44"), **bad)
        add(excluded, f"h{sender}-long-ihl", transform=replace(14, b"\x4f"), **bad)
        add(
            excluded,
            f"h{sender}-short-total",
            options=b"\x01" * 4,
            transform=replace(16, struct.pack("!H", 20)),
            **bad,
        )
        add(
            excluded,
            f"h{sender}-long-total",
            transform=replace(16, struct.pack("!H", 600)),
            **bad,
        )
        add(
            excluded,
            f"h{sender}-truncated-ip",
            transform=lambda frame: frame[:30],
            **bad,
        )
        add(
            excluded,
            f"h{sender}-truncated-options",
            options=b"\x01" * 40,
            transform=lambda frame: frame[:60],
            **bad,
        )
        for options in (b"", b"\x01" * 40):
            add(
                excluded,
                f"h{sender}-bad-checksum-{len(options)}",
                options=options,
                transform=lambda frame: frame[:24]
                + bytes((frame[24] ^ 1,))
                + frame[25:],
                **bad,
            )
        add(excluded, f"h{sender}-short-udp", transport=bytes(7), **bad)
        for length in (7, 80):
            add(
                excluded,
                f"h{sender}-bad-udp-length-{length}",
                transform=replace(38, struct.pack("!H", length)),
                **bad,
            )
    batches.append(("excluded-and-malformed", excluded))

    wrapping = []
    port = ports_for_slot("10.0.0.1", "10.0.0.2", 0)[0]
    for sender in (1, 2):
        for repeat in range(16):
            add(
                wrapping,
                f"h{sender}-wrap-{repeat}",
                sender=sender,
                source="10.0.0.1",
                destination="10.0.0.2",
                sport=port,
                options=b"\x01" * (4 * (repeat % 3)),
            )
    batches.append(("wraparound", wrapping))
    return batches
