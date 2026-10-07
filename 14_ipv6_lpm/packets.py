"""Build IPv6 routing probes and predict complete forwarded frames."""

from __future__ import annotations

import ipaddress
import struct


HOST_MACS = {number: bytes.fromhex(f"0000000000{number:02x}") for number in (1, 2, 3)}
HOST_ADDRESSES = {number: f"2001:db8:{number}::1" for number in HOST_MACS}
GATEWAY_MAC = "00:00:00:00:0a:01"
HOST_ROUTE = ipaddress.IPv6Address("2001:db8:3::42")
SUBNETS = {
    number: ipaddress.IPv6Network(f"2001:db8:{number}::/64") for number in HOST_MACS
}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def transport_segment(
    source: str, destination: str, protocol: int, identification: int, size: int
) -> bytes:
    payload = (
        b"ipv6-lpm:" + struct.pack("!H", identification) + bytes(range(256)) * 6
    )[:size]
    if protocol == 17:
        segment = struct.pack("!HHHH", 1111, 2222, 8 + size, 0) + payload
        offset = 6
    elif protocol == 6:
        segment = (
            struct.pack(
                "!HHIIBBHHH", 1111, 2222, identification, 0, 0x50, 0x18, 4096, 0, 0
            )
            + payload
        )
        offset = 16
    elif protocol == 58:
        segment = struct.pack("!BBHHH", 128, 0, 0, 1234, identification) + payload
        offset = 2
    else:
        return payload
    pseudo = (
        ipaddress.IPv6Address(source).packed
        + ipaddress.IPv6Address(destination).packed
        + struct.pack("!I3xB", len(segment), protocol)
    )
    value = checksum(pseudo + segment)
    if protocol == 17 and value == 0:
        value = 0xFFFF
    return segment[:offset] + struct.pack("!H", value) + segment[offset + 2 :]


def make_frame(
    prefix: bytes,
    identification: int,
    sender: int = 1,
    destination: str = "2001:db8:2::1",
    protocol: int = 17,
    payload_size: int = 24,
    hop_limit: int = 64,
    body: bytes | None = None,
    flow_label: int | None = None,
) -> bytes:
    if (
        len(prefix) != 4
        or prefix[0] & 1
        or type(identification) is not int
        or not 1 <= identification <= 65535
        or type(sender) is not int
        or sender not in HOST_MACS
        or not 0 <= payload_size <= 1452
    ):
        raise ValueError("invalid marker, identity, host or payload length")
    source = HOST_ADDRESSES[sender]
    if body is None:
        body = transport_segment(
            source, destination, protocol, identification, payload_size
        )
    if len(body) > 1460:
        raise ValueError("IPv6 packet exceeds the 1500-byte test MTU")
    label = identification if flow_label is None else flow_label
    if not 0 <= label < (1 << 20):
        raise ValueError("flow label exceeds 20 bits")
    header = struct.pack(
        "!IHBB16s16s",
        (6 << 28) | (0x2A << 20) | label,
        len(body),
        protocol,
        hop_limit,
        ipaddress.IPv6Address(source).packed,
        ipaddress.IPv6Address(destination).packed,
    )
    # The marked gateway remains in Ethernet.src after the router's rewrite.
    frame = (
        prefix
        + b"\x0a\x01"
        + prefix
        + struct.pack("!H", identification)
        + b"\x86\xdd"
        + header
        + body
    )
    return frame.ljust(60, b"\xa5")


def expected_host(destination: str) -> str | None:
    address = ipaddress.IPv6Address(destination)
    if address == HOST_ROUTE:
        return "h2"
    return next(
        (f"h{number}" for number, subnet in SUBNETS.items() if address in subnet), None
    )


def expected_frame(frame: bytes, receiver: str) -> bytes:
    if receiver not in {"h1", "h2", "h3"} or len(frame) < 54 or frame[21] <= 1:
        raise ValueError("forwarding requires an IPv6 header and a valid next hop")
    result = bytearray(frame)
    result[:6] = HOST_MACS[int(receiver[1:])]
    result[6:12] = frame[:6]
    result[21] -= 1
    return bytes(result)


def make_probes(prefix: bytes) -> list[dict]:
    probes = []

    def add(
        name,
        sender=1,
        destination="2001:db8:2::1",
        allowed=True,
        transform=None,
        **kwargs,
    ):
        frame = make_frame(prefix, len(probes) + 1, sender, destination, **kwargs)
        if transform is not None:
            frame = transform(frame)
        receiver = expected_host(destination) if allowed else None
        if allowed and receiver is None:
            raise ValueError("forwarded probe must have a configured route")
        probes.append(
            {
                "name": name,
                "sender": f"h{sender}",
                "receiver": receiver,
                "allowed": allowed,
                "frame": frame,
            }
        )

    def replace(offset, value):
        return lambda frame: frame[:offset] + value + frame[offset + len(value) :]

    for sender in HOST_MACS:
        for receiver in HOST_MACS:
            if receiver == sender:
                continue
            for protocol in (17, 6, 58):
                for repeat in range(2):
                    add(
                        f"pair-{sender}-{receiver}-{protocol}-{repeat}",
                        sender,
                        HOST_ADDRESSES[receiver],
                        protocol=protocol,
                        payload_size=23 + repeat,
                    )
        for destination in ("2001:db8:3::41", "2001:db8:3::42", "2001:db8:3::43"):
            for protocol in (17, 6, 58, 253):
                add(
                    f"lpm-{sender}-{destination}-{protocol}",
                    sender,
                    destination,
                    protocol=protocol,
                )
        for subnet in SUBNETS.values():
            for destination in (subnet.network_address, subnet.broadcast_address):
                add(f"boundary-{sender}-{destination}", sender, str(destination))
        for size in (0, 1, 127, 1452):
            add(f"udp-size-{sender}-{size}", sender, payload_size=size)
        for limit in (2, 255):
            add(f"hop-{sender}-{limit}", sender, hop_limit=limit)
        add(f"no-next-empty-{sender}", sender, protocol=59, body=b"")
        add(f"no-next-body-{sender}", sender, protocol=59, body=b"opaque trailer")
        add(f"unknown-next-{sender}", sender, protocol=253, payload_size=33)
        for destination in ("2001:db8:3::42", "2001:db8:3::43"):
            segment = transport_segment(
                HOST_ADDRESSES[sender], destination, 17, len(probes) + 1, 33
            )
            chain = bytes((60, 0, 1, 4, 0, 0, 0, 0, 17, 0, 1, 4, 0, 0, 0, 0))
            add(
                f"extensions-{sender}-{destination}",
                sender,
                destination,
                protocol=0,
                body=chain + segment,
            )
            for protocol in (17, 6):
                datagram_id = len(probes) + 1
                segment = transport_segment(
                    HOST_ADDRESSES[sender],
                    destination,
                    protocol,
                    datagram_id,
                    40 if protocol == 17 else 28,
                )
                spans = (
                    ((0, 16), (16, 32), (32, 48))
                    if protocol == 17
                    else ((0, 24), (24, 40), (40, 48))
                )
                for piece, (start, end) in enumerate(spans):
                    fragment = struct.pack(
                        "!BBHI",
                        protocol,
                        0,
                        (start // 8 << 3) | (piece < 2),
                        datagram_id,
                    )
                    add(
                        f"fragment-{sender}-{destination}-{protocol}-{piece}",
                        sender,
                        destination,
                        protocol=44,
                        body=fragment + segment[start:end],
                        flow_label=datagram_id,
                    )

        for destination in (*HOST_ADDRESSES.values(), str(HOST_ROUTE)):
            for limit in (0, 1):
                add(
                    f"expired-{sender}-{destination}-{limit}",
                    sender,
                    destination,
                    hop_limit=limit,
                    allowed=False,
                )
        for destination in (
            "2001:db8::1",
            "2001:db8:4::1",
            "2001:db8:3:1::42",
            "2001:db8:2:ffff::1",
            "ff02::1",
        ):
            add(f"no-route-{sender}-{destination}", sender, destination, allowed=False)
        for version in (4, 15):
            add(
                f"bad-version-{sender}-{version}",
                sender,
                allowed=False,
                transform=replace(14, bytes(((version << 4) | 2,))),
            )
        add(
            f"long-payload-{sender}",
            sender,
            allowed=False,
            transform=replace(18, b"\xff\xff"),
        )
        for length in (22, 53):
            add(
                f"short-header-{sender}-{length}",
                sender,
                allowed=False,
                transform=lambda frame, end=length: frame[:end],
            )
        add(
            f"short-payload-{sender}",
            sender,
            allowed=False,
            transform=lambda frame: frame[:-12],
        )
        add(
            f"empty-long-payload-{sender}",
            sender,
            allowed=False,
            protocol=59,
            body=b"",
            transform=replace(18, b"\0\x07"),
        )
        for ether_type in (b"\x08\x00", b"\x88\xb5"):
            add(
                f"non-ipv6-{sender}-{ether_type.hex()}",
                sender,
                allowed=False,
                transform=replace(12, ether_type),
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
                bytes((10, 0, 0, sender)),
                bytes(6),
                bytes((10, 0, 0, 4)),
            )
            return (b"\xff" * 6 + frame[6:12] + b"\x08\x06" + payload).ljust(60, b"\0")

        add(f"arp-{sender}", sender, allowed=False, transform=arp)
    return probes
