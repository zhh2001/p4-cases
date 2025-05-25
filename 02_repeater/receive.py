import os
import sys

from scapy.interfaces import get_if_list
from scapy.sendrecv import sniff
from scapy.utils import hexdump


def get_if():
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if iface is None:
        exit("eth0 interface not found")
    return iface


def handle_pkt(pkt):
    print("收到数据包")
    hexdump(pkt)
    pkt.show2()
    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print(f"sniffing on {iface}")
    sys.stdout.flush()
    sniff(iface=iface,
          filter="tcp",
          prn=handle_pkt)


if __name__ == '__main__':
    main()
