"""Build IPv4 INT packets and check their complete routed wire representation."""

from __future__ import annotations

import ipaddress
import struct


MAX_TRACES = 9
HOST_IPS = {1: "10.0.1.1", 2: "10.0.2.2", 3: "10.0.3.3", 4: "10.0.3.4"}
HOST_MACS = {
    number: bytes.fromhex("00000a" + ipaddress.IPv4Address(ip).packed[1:].hex())
    for number, ip in HOST_IPS.items()
}
NEXT_HOPS = {
    (1, 1): HOST_MACS[1],
    (1, 2): bytes.fromhex("00010a000202"),
    (1, 3): bytes.fromhex("000000030100"),
    (2, 1): HOST_MACS[2],
    (2, 2): bytes.fromhex("000000010200"),
    (3, 1): HOST_MACS[3],
    (3, 2): HOST_MACS[4],
    (3, 3): bytes.fromhex("000000010300"),
}
PATHS = {
    (1, 2): [(1, 2), (2, 1)],
    (1, 3): [(1, 3), (3, 1)],
    (1, 4): [(1, 3), (3, 2)],
    (2, 1): [(2, 2), (1, 1)],
    (2, 3): [(2, 2), (1, 3), (3, 1)],
    (2, 4): [(2, 2), (1, 3), (3, 2)],
    (3, 1): [(3, 3), (1, 1)],
    (3, 2): [(3, 3), (1, 2), (2, 1)],
    (3, 4): [(3, 2)],
    (4, 1): [(3, 3), (1, 1)],
    (4, 2): [(3, 3), (1, 2), (2, 1)],
    (4, 3): [(3, 1)],
}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def trace_bytes(trace: tuple[int, int, int]) -> bytes:
    swid, depth, port = trace
    if not (0 <= swid < 8192 and 0 <= depth < 8192 and 0 <= port < 64):
        raise ValueError("trace fields exceed their wire widths")
    return struct.pack("!I", swid << 19 | depth << 6 | port)


def int_option(traces: list[tuple[int, int, int]], copied: bool = False) -> bytes:
    if len(traces) > MAX_TRACES:
        raise ValueError("INT options support at most nine traces")
    body = b"".join(map(trace_bytes, traces))
    return (
        struct.pack("!BBH", 0x9F if copied else 0x1F, 4 + len(body), len(traces)) + body
    )


def make_frame(
    source: bytes,
    sender: int,
    receiver: int,
    options: bytes = b"",
    ttl: int = 64,
    flags: int = 0,
    payload_size: int = 48,
) -> bytes:
    if len(source) != 4 or len(options) % 4 or len(options) > 40 or payload_size < 16:
        raise ValueError(
            "frame requires an IPv4 source, aligned options and labelled payload"
        )
    destination = ipaddress.IPv4Address(HOST_IPS[receiver]).packed
    payload = (b"p4-int:" + source + bytes(range(256)) * ((payload_size + 255) // 256))[
        :payload_size
    ]
    udp = struct.pack("!HHHH", 4321, 1234, 8 + len(payload), 0) + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    header = (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45 + len(options) // 4,
            0x2A,
            20 + len(options) + len(udp),
            int.from_bytes(source[-2:], "big"),
            flags,
            ttl,
            17,
            0,
            source,
            destination,
        )
        + options
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return HOST_MACS[receiver] + HOST_MACS[sender] + b"\x08\x00" + header + udp


def recalculate_checksum(frame: bytes) -> bytes:
    result = bytearray(frame)
    end = 14 + max(20, (frame[14] & 15) * 4)
    result[24:26] = b"\0\0"
    result[24:26] = struct.pack("!H", checksum(bytes(result[14:end])))
    return bytes(result)


def make_probes(prefix: bytes) -> list[dict]:
    if len(prefix) != 3:
        raise ValueError("test prefix must contain three IPv4 source bytes")
    probes = []

    def add(
        name, sender=2, receiver=4, options=None, allowed=True, transform=None, **kwargs
    ):
        source = prefix + bytes((len(probes) + 1,))
        frame = make_frame(
            source,
            sender,
            receiver,
            int_option([]) if options is None else options,
            **kwargs,
        )
        if transform is not None:
            frame = transform(frame)
        probes.append(
            {
                "name": name,
                "sender": f"h{sender}",
                "receiver": f"h{receiver}",
                "path": PATHS[sender, receiver],
                "allowed": allowed,
                "frame": frame,
            }
        )

    def replace(offset, data):
        return lambda frame: recalculate_checksum(
            frame[:offset] + data + frame[offset + len(data) :]
        )

    for sender, receiver in PATHS:
        for kind, options in (("plain", b""), ("int", int_option([]))):
            add(
                f"h{sender}-h{receiver}-{kind}",
                sender,
                receiver,
                options,
                payload_size=(48, 128, 512)[(sender + receiver) % 3],
            )
    for count in range(MAX_TRACES + 1):
        add(
            f"existing-{count}",
            options=int_option([(100 + i, 8191 - i, i + 1) for i in range(count)]),
        )
    add("options4", options=b"\x01" * 4)
    add("options40", options=b"\x01" * 40)
    add("nonleading-int", options=b"\x01" * 4 + int_option([]))
    add("copied-int", options=int_option([], copied=True))
    add("plain-first-fragment", options=b"", flags=0x2000)
    add("int-first-fragment", options=int_option([], copied=True), flags=0x2000)
    add("int-later-fragment", options=int_option([], copied=True), flags=1)
    add("ttl-last-hop-one", ttl=4)
    add("ttl-one-hop-two", sender=3, receiver=4, ttl=2)
    add("maximum-output-mtu", payload_size=1456)
    for options, name in ((b"", "plain"), (int_option([]), "int")):
        add(f"{name}-opaque-payload", options=options, transform=replace(23, b"\xfd"))
    for ttl in (0, 1, 3):
        add(f"expired-ttl-{ttl}", ttl=ttl, allowed=False)
    add(
        "unknown-route",
        sender=1,
        receiver=2,
        allowed=False,
        transform=replace(30, ipaddress.IPv4Address("192.0.2.1").packed),
    )
    add(
        "non-ipv4",
        allowed=False,
        transform=lambda frame: frame[:12] + b"\x88\xb5" + frame[14:],
    )
    add("bad-version", allowed=False, transform=replace(14, b"\x66"))
    add("short-ihl", allowed=False, transform=replace(14, b"\x44"))
    add("short-total", allowed=False, transform=replace(16, struct.pack("!H", 20)))
    add("long-total", allowed=False, transform=replace(16, struct.pack("!H", 600)))
    add("truncated-ip", allowed=False, transform=lambda frame: frame[:33])
    add(
        "truncated-options",
        options=int_option([(100, 1, 3)] * 3),
        allowed=False,
        transform=lambda frame: frame[:42],
    )
    add("bad-option-length", allowed=False, transform=replace(35, b"\x06"))
    add("bad-int-count", allowed=False, transform=replace(36, b"\0\x02"))
    add(
        "too-many-traces",
        options=int_option([(100, 1, 3)] * MAX_TRACES),
        allowed=False,
        transform=replace(36, b"\0\x0a"),
    )
    add("huge-int-count", allowed=False, transform=replace(36, b"\xff\xff"))
    add(
        "bad-ip-checksum",
        options=b"",
        allowed=False,
        transform=lambda frame: frame[:24] + bytes((frame[24] ^ 1,)) + frame[25:],
    )
    add(
        "bad-int-checksum",
        options=int_option([(100, 1, 3)]),
        allowed=False,
        transform=lambda frame: frame[:41] + bytes((frame[41] ^ 1,)) + frame[42:],
    )
    return probes


def parse_frame(frame: bytes) -> dict:
    if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
        raise RuntimeError("frame does not contain a complete IPv4 header")
    ihl = (frame[14] & 15) * 4
    total = int.from_bytes(frame[16:18], "big")
    if ihl < 20 or total < ihl or len(frame) != 14 + total:
        raise RuntimeError("IPv4 lengths do not match the complete frame")
    if checksum(frame[14 : 14 + ihl]):
        raise RuntimeError("invalid IPv4 header checksum")
    options = frame[34 : 14 + ihl]
    traces = None
    if options and options[0] & 0x7F == 0x1F:
        if len(options) < 4:
            raise RuntimeError("incomplete INT option")
        length, count = options[1], int.from_bytes(options[2:4], "big")
        if count > MAX_TRACES or length != 4 + 4 * count or length != len(options):
            raise RuntimeError("INT count, option length and IHL disagree")
        traces = []
        for offset in range(4, length, 4):
            value = int.from_bytes(options[offset : offset + 4], "big")
            traces.append((value >> 19, value >> 6 & 8191, value & 63))
    return {
        "ihl": ihl,
        "total": total,
        "options": options,
        "traces": traces,
        "payload": frame[14 + ihl :],
        "ttl": frame[22],
    }


def expected_trace_count(sent: bytes, path: list[tuple[int, int]]) -> int | None:
    original = parse_frame(sent)
    if original["traces"] is None:
        return None
    return min(
        MAX_TRACES,
        len(original["traces"]) + len(path),
        len(original["traces"]) + (65535 - original["total"]) // 4,
    )


def check_forwarded(sent: bytes, received: bytes, path: list[tuple[int, int]]) -> None:
    original, actual = parse_frame(sent), parse_frame(received)
    expected_count = expected_trace_count(sent, path)
    if expected_count is None:
        if actual["options"] != original["options"]:
            raise RuntimeError("ordinary IPv4 options changed during forwarding")
        new_options = original["options"]
    else:
        if actual["traces"] is None or len(actual["traces"]) != expected_count:
            raise RuntimeError("unexpected number of INT traces")
        inserted = expected_count - len(original["traces"])
        newest = actual["traces"][:inserted]
        if [(swid, port) for swid, _, port in newest] != list(
            reversed(path[:inserted])
        ):
            raise RuntimeError(
                "INT switch order or output port does not match the path"
            )
        if actual["traces"][inserted:] != original["traces"]:
            raise RuntimeError("existing INT traces were changed or lost")
        new_options = int_option(
            newest + original["traces"], bool(original["options"][0] & 128)
        )
    expected_ip = bytearray(sent[14:34] + new_options)
    expected_ip[0] = 0x45 + len(new_options) // 4
    expected_ip[2:4] = struct.pack(
        "!H", 20 + len(new_options) + len(original["payload"])
    )
    expected_ip[8] -= len(path)
    expected_ip[10:12] = b"\0\0"
    expected_ip[10:12] = struct.pack("!H", checksum(bytes(expected_ip)))
    source_mac = NEXT_HOPS[path[-2]] if len(path) > 1 else sent[:6]
    expected = (
        NEXT_HOPS[path[-1]]
        + source_mac
        + b"\x08\x00"
        + bytes(expected_ip)
        + original["payload"]
    )
    if received != expected:
        raise RuntimeError("routed frame contents, length, TTL or payload differ")
