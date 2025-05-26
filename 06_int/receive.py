import sys

from scapy.fields import BitField
from scapy.fields import FieldLenField
from scapy.fields import PacketListField
from scapy.fields import ShortField
from scapy.interfaces import get_if_list
from scapy.layers.inet import _IPOption_HDR
from scapy.layers.inet import IPOption
from scapy.packet import Packet
from scapy.sendrecv import sniff


def get_if():
    for _iface in get_if_list():
        if "eth0" in _iface:
            return _iface
    print("eth0 interface not found")
    exit(1)


class SwitchTrace(Packet):
    fields_desc = [
        BitField("swid", 0, 13),
        BitField("qdepth", 0, 13),
        BitField("portid", 0, 6),
    ]

    def extract_padding(self, p):
        return "", p


class IPOption_INT(IPOption):
    name = "INT"
    option = 31
    fields_desc = [
        _IPOption_HDR,
        FieldLenField("length", None, fmt="B",
                      length_of="int_headers",
                      adjust=lambda _, l: l * 2 + 4),
        ShortField("count", 0),
        PacketListField("int_headers",
                        [],
                        pkt_cls=SwitchTrace,
                        count_from=lambda pkt: (pkt.count * 1)),
    ]


def handle_pkt(pkt):
    print("收到一个数据包")
    pkt.show2()
    sys.stdout.flush()


if __name__ == '__main__':
    iface = 'h2-eth0'
    print(f"sniffing on {iface}")
    sys.stdout.flush()
    sniff(iface=iface,
          filter="udp and port 4321",
          prn=lambda x: handle_pkt(x))
