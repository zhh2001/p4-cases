#!/usr/bin/env python3
"""Sniff on h2-eth0 for the INT UDP packet and report the parsed INT
stack. Exit 0 printing SUCCESS when the packet carries >= 2 INT
headers with swid == {1, 2} (s1 and s2 on the expected path)."""

from __future__ import annotations

import sys
import time

from scapy.fields import BitField, FieldLenField, PacketListField, ShortField
from scapy.layers.inet import IP, IPOption, _IPOption_HDR
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

IFACE = "h2-eth0"
TIMEOUT = 5.0


class SwitchTrace(Packet):
    fields_desc = [
        BitField("swid", 0, 13),
        BitField("qdepth", 0, 13),
        BitField("portid", 0, 6),
    ]

    def extract_padding(self, p):
        return b"", p


class IPOption_INT(IPOption):
    name = "INT"
    option = 31
    fields_desc = [
        _IPOption_HDR,
        FieldLenField("length", None, fmt="B",
                      length_of="int_headers",
                      adjust=lambda _, length: length * 2 + 4),
        ShortField("count", 0),
        PacketListField("int_headers", [], pkt_cls=SwitchTrace,
                        count_from=lambda pkt: pkt.count),
    ]


def has_udp_4321(pkt):
    return IP in pkt and pkt[IP].proto == 17 and bytes(pkt[IP].payload)[:2] == b"\x10\xe1"  # sport 4321


def main() -> int:
    sniffer = AsyncSniffer(iface=IFACE, filter="udp and port 4321",
                           count=1, timeout=TIMEOUT)
    sniffer.start()
    time.sleep(0.1)
    sniffer.join(timeout=TIMEOUT + 0.5)
    pkts = sniffer.results or []
    if not pkts:
        print(f"FAILURE: no UDP packet received on {IFACE} within {TIMEOUT}s")
        return 1

    pkt = pkts[0]
    print(f"received: src={pkt[Ether].src} dst={pkt[Ether].dst}")
    ip = pkt[IP]
    print(f"IP: {ip.src} -> {ip.dst} ihl={ip.ihl}")
    if ip.ihl <= 5 or not ip.options:
        print("FAILURE: packet has no IP options — switches did not append INT headers")
        return 1

    int_opt = next((o for o in ip.options if isinstance(o, IPOption_INT)), None)
    if int_opt is None:
        print("FAILURE: IP option is not INT")
        return 1

    print(f"INT count={int_opt.count}")
    for stanza in int_opt.int_headers:
        print(f"  swid={stanza.swid} qdepth={stanza.qdepth} portid={stanza.portid}")

    swids = [s.swid for s in int_opt.int_headers]
    if int_opt.count >= 2 and 1 in swids and 2 in swids:
        print("SUCCESS: INT stack carries s1 and s2 traces")
        return 0
    print(f"FAILURE: expected INT stack to include swid 1 and 2, got {swids}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
