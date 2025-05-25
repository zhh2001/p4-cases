import random
import sys
import socket

from scapy.arch import get_if_hwaddr
from scapy.interfaces import get_if_list
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def get_if():
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if iface is None:
        exit("eth0 interface not found")
    return iface


def main():
    if not len(sys.argv) == 3:
        exit("缺少参数: [目的主机 IPv4 地址] [负载消息]")

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print(f"sending on interface {iface} to {addr}")
    pkt = Ether(src=get_if_hwaddr(iface),
                dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152, 65535)) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
