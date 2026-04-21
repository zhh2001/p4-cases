#!/usr/bin/env python3
"""Send a single INT-capable UDP packet from h1 to h2.

Emits an IPv4 option (class=0, number=31) containing an INT header
with count=0 and an empty int_headers list. Each switch on the path
will append its own SwitchTrace stanza before the packet reaches h2.
"""

from __future__ import annotations

from scapy.fields import BitField, FieldLenField, PacketListField, ShortField
from scapy.layers.inet import IP, IPOption, UDP, _IPOption_HDR
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sendp

IFACE = "h1-eth0"
# The s1 LPM entry rewrites the dst MAC for 10.0.2.2/32 to this value
# before forwarding to port 2 (s2), so this is what h1 must send to so
# that s1 will match and forward (in L2 terms). On the wire s1 rewrites
# src_mac <- old_dst_mac and dst_mac <- LPM parameter, so even setting
# broadcast works — but the sniffer on h2 looks at the destination
# rewritten at the last hop, which is h2's real MAC.
DST_MAC = "ff:ff:ff:ff:ff:ff"
DST_IP = "10.0.2.2"


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


def main() -> int:
    pkt = (Ether(src="00:00:0a:00:01:01", dst=DST_MAC)
           / IP(dst=DST_IP, options=IPOption_INT(count=0, int_headers=[]))
           / UDP(dport=1234, sport=4321)
           / b"int-demo-payload")
    sendp(pkt, iface=IFACE, verbose=False)
    print("sent 1 INT-carrying UDP packet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
