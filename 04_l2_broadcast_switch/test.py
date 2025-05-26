import time

from scapy.arch import get_if_hwaddr
from scapy.interfaces import get_if_list
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def send_packet(iface):
    data = input("请输入数据包携带的信息:")
    print(f"Sending on interface {iface}\n")
    pkt = Ether(src=get_if_hwaddr(iface),
                dst='ff:ff:ff:ff:ff:ff:ff')
    pkt = pkt / data
    sendp(pkt, iface=iface, verbose=False)


def get_if():
    for _iface in get_if_list():
        if "eth0" in _iface:
            return _iface
    exit("eth0 interface not found")


if __name__ == '__main__':
    iface = get_if()
    while True:
        send_packet(iface)
        time.sleep(0.25)
