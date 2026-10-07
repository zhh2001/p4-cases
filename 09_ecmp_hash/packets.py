"""Build ECMP traffic and independently predict complete routed frames."""

from __future__ import annotations

import ipaddress
import struct


HOST_MACS = {number: bytes.fromhex(f"0000000000{number:02x}") for number in (1, 2, 3)}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def crc16(data: bytes) -> int:
    """CRC-16/ARC, matching BMv2's crc16 with a zero initial remainder."""
    result = 0
    for byte in data:
        result ^= byte
        for _ in range(8):
            result = (result >> 1) ^ (0xA001 if result & 1 else 0)
    return result


def recalculate_checksum(frame: bytes) -> bytes:
    result = bytearray(frame)
    end = 14 + max(20, (frame[14] & 15) * 4)
    result[24:26] = b"\0\0"
    result[24:26] = struct.pack("!H", checksum(bytes(result[14:end])))
    return bytes(result)


def make_frame(
    source: bytes,
    destination: str,
    sender: int,
    identification: int,
    protocol: int = 17,
    sport: int = 1000,
    dport: int = 5000,
    options: bytes = b"",
    tcp_options: bytes = b"",
    payload_size: int = 24,
    ttl: int = 64,
    flags: int = 0,
    transport: bytes | None = None,
    udp_checksum: bool = True,
) -> bytes:
    if (
        len(source) != 4
        or sender not in HOST_MACS
        or len(options) % 4
        or len(options) > 40
        or len(tcp_options) % 4
        or len(tcp_options) > 40
        or payload_size < 0
    ):
        raise ValueError("invalid host, source, options or payload length")
    target = ipaddress.IPv4Address(destination).packed
    payload = (b"ecmp:" + struct.pack("!H", identification) + bytes(range(256)) * 6)[
        :payload_size
    ]
    if payload_size > len(payload):
        raise ValueError("payload exceeds the test frame size limit")
    if transport is None:
        if protocol == 17:
            transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        elif protocol == 6:
            transport = (
                struct.pack(
                    "!HHIIBBHHH",
                    sport,
                    dport,
                    identification,
                    0,
                    (5 + len(tcp_options) // 4) << 4,
                    0x18,
                    4096,
                    0,
                    0,
                )
                + tcp_options
            )
        else:
            transport = b""
        transport += payload
        if protocol == 6 or (protocol == 17 and udp_checksum):
            pseudo = source + target + struct.pack("!BBH", 0, protocol, len(transport))
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
            identification,
            flags,
            ttl,
            protocol,
            0,
            source,
            target,
        )
        + options
    )
    frame = HOST_MACS[sender] * 2 + b"\x08\x00" + header + transport
    return recalculate_checksum(frame).ljust(60, b"\0")


def identity(frame: bytes) -> bytes:
    if not isinstance(frame, bytes) or len(frame) < 30:
        raise RuntimeError("capture contains an incomplete IPv4 identity")
    return frame[18:22] + frame[26:30]


def hash_input(frame: bytes) -> bytes:
    ports = b"\0" * 4
    if int.from_bytes(frame[20:22], "big") & 0x3FFF == 0 and frame[23] in (6, 17):
        start = 14 + (frame[14] & 15) * 4
        ports = frame[start : start + 4]
    return frame[26:34] + frame[23:24] + ports


def expected_host(frame: bytes) -> str:
    destination = ipaddress.IPv4Address(frame[30:34])
    for number in HOST_MACS:
        if str(destination) == f"10.0.0.{number}":
            return f"h{number}"
    if destination in ipaddress.IPv4Network("10.0.0.0/24"):
        return f"h{2 + crc16(hash_input(frame)) % 2}"
    raise RuntimeError("packet has no configured IPv4 route")


def expected_frame(sent: bytes, host: str | None = None) -> bytes:
    host = expected_host(sent) if host is None else host
    result = bytearray(sent)
    result[:6] = HOST_MACS[int(host[1:])]
    result[6:12] = sent[:6]
    result[22] -= 1
    return recalculate_checksum(bytes(result))


def check_forwarded(sent: bytes, received: bytes, host: str) -> None:
    if received != expected_frame(sent, host):
        raise RuntimeError("routed frame differs in MACs, TTL, checksum or contents")


def make_probes(prefix: bytes, n_flows: int = 20) -> list[dict]:
    if len(prefix) != 3 or type(n_flows) is not int or not 2 <= n_flows <= 100:
        raise ValueError("test needs a three-byte prefix and 2..100 flows")
    probes = []

    def add(
        name,
        sender=1,
        destination="10.0.0.100",
        source=None,
        allowed=True,
        transform=None,
        identification=None,
        **kwargs,
    ):
        frame = make_frame(
            source or prefix + b"\x4d",
            destination,
            sender,
            len(probes) + 1 if identification is None else identification,
            **kwargs,
        )
        if transform is not None:
            frame = transform(frame)
        probes.append(
            {
                "name": name,
                "sender": f"h{sender}",
                "receiver": expected_host(frame) if allowed else None,
                "allowed": allowed,
                "frame": frame,
            }
        )

    def replace(offset, data):
        return lambda frame: recalculate_checksum(
            frame[:offset] + data + frame[offset + len(data) :]
        )

    for protocol in (17, 6):
        for sender in HOST_MACS:
            for receiver in HOST_MACS:
                if sender != receiver:
                    add(
                        f"direct-{protocol}-h{sender}-h{receiver}",
                        sender=sender,
                        destination=f"10.0.0.{receiver}",
                        protocol=protocol,
                    )
        for flow in range(n_flows):
            for repeat in range(3):
                add(
                    f"ecmp-{protocol}-{flow}-{repeat}",
                    sender=repeat + 1,
                    protocol=protocol,
                    sport=1000 + flow,
                    options=(b"", b"\x01" * 4, b"\x01" * 40)[repeat],
                    tcp_options=b"\x01" * 4 if repeat == 2 and protocol == 6 else b"",
                    payload_size=(24, 127, 1376)[repeat],
                    ttl=64 + repeat,
                )
        for field in ("source", "destination", "sport", "dport"):
            for value in range(8):
                changed = {
                    "source": prefix + bytes((value + 80,)),
                    "destination": f"10.0.0.{value + 100}",
                    "sport": value + 2000,
                    "dport": value + 6000,
                }
                add(
                    f"tuple-{protocol}-{field}-{value}",
                    protocol=protocol,
                    **{field: changed[field]},
                )

    for protocol in (1, 253):
        for repeat in range(3):
            add(
                f"opaque-{protocol}-{repeat}",
                protocol=protocol,
                transport=bytes((repeat + 1,)) * (16 + repeat * 8),
                options=b"\x01" * (4 * repeat),
            )
    for protocol in (17, 6):
        for destination in ("10.0.0.2", "10.0.0.100"):
            ident = len(probes) + 1
            datagram = make_frame(
                prefix + b"\x4d",
                destination,
                1,
                ident,
                protocol=protocol,
                payload_size=40 if protocol == 17 else 28,
            )[34:82]
            for piece in range(3):
                add(
                    f"fragment-{protocol}-{destination}-{piece}",
                    destination=destination,
                    protocol=protocol,
                    identification=ident,
                    flags=piece * 2 | (0x2000 if piece < 2 else 0),
                    transport=datagram[16 * piece : 16 * (piece + 1)],
                    options=b"\x01" * 4,
                )
    for destination in ("10.0.0.2", "10.0.0.100"):
        for ttl in (0, 1, 2, 255):
            add(
                f"ttl-{destination}-{ttl}",
                destination=destination,
                ttl=ttl,
                allowed=ttl > 1,
            )
    add("udp-no-checksum", udp_checksum=False)
    add("udp-minimum", payload_size=0)
    add("tcp-minimum", protocol=6, payload_size=0)
    add("udp-mtu", payload_size=1472)
    add("tcp-mtu", protocol=6, payload_size=1460)
    add("unknown-route", destination="192.0.2.1", allowed=False)
    add(
        "non-ipv4",
        allowed=False,
        transform=lambda frame: frame[:12] + b"\x88\xb5" + frame[14:],
    )
    add("bad-version", allowed=False, transform=replace(14, b"\x65"))
    add("short-ihl", allowed=False, transform=replace(14, b"\x44"))
    add(
        "short-total",
        options=b"\x01" * 4,
        allowed=False,
        transform=replace(16, struct.pack("!H", 20)),
    )
    add("long-total", allowed=False, transform=replace(16, struct.pack("!H", 600)))
    add("truncated-ip", allowed=False, transform=lambda frame: frame[:30])
    add(
        "truncated-options",
        options=b"\x01" * 40,
        allowed=False,
        transform=lambda frame: frame[:60],
    )
    for options in (b"", b"\x01" * 40):
        add(
            f"bad-checksum-{len(options)}",
            options=options,
            allowed=False,
            transform=lambda frame: frame[:24] + bytes((frame[24] ^ 1,)) + frame[25:],
        )
    for protocol, size in ((17, 7), (6, 19)):
        add(
            f"short-transport-{protocol}",
            protocol=protocol,
            transport=bytes(size),
            allowed=False,
        )
    for value in (7, 80):
        add(
            f"bad-udp-length-{value}",
            allowed=False,
            transform=replace(38, struct.pack("!H", value)),
        )
    for value in (4, 15):
        add(
            f"bad-tcp-offset-{value}",
            protocol=6,
            allowed=False,
            transform=replace(46, bytes((value << 4,))),
        )
    return probes
