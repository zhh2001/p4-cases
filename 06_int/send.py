import sys
import socket
from time import sleep

from scapy.arch import get_if_hwaddr
from scapy.fields import BitField
from scapy.fields import FieldLenField
from scapy.fields import PacketListField
from scapy.fields import ShortField
from scapy.interfaces import get_if_list
from scapy.layers.inet import _IPOption_HDR
from scapy.layers.inet import IP
from scapy.layers.inet import IPOption
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sendp


def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
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
        FieldLenField(name="length",
                      default=None,
                      fmt="B",
                      length_of="int_headers",
                      adjust=lambda _, l: l * 2 + 4),
        ShortField("count", 0),
        PacketListField(name="int_headers",
                        default=[],
                        pkt_cls=SwitchTrace,
                        count_from=lambda pkt: (pkt.count * 1)),
    ]


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('传递 3 个参数: <目标地址> "<携带消息>" <发送数量>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
    pkt = pkt / IP(dst=addr, options=IPOption_INT(count=0, int_headers=[]))
    pkt = pkt / UDP(dport=1234, sport=4321)
    pkt = pkt / sys.argv[2]

    pkt.show2()

    try:
        for _ in range(int(sys.argv[3])):
            sendp(pkt, iface=iface)
            sleep(1.25)
    except KeyboardInterrupt:
        print('Keyboard Interrupt')
        exit(1)
