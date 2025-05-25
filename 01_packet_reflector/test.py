import socket
import time
from threading import Event
from threading import Thread

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.data import ETH_P_ALL
from scapy.interfaces import get_if_list
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.sendrecv import sniff


class Sniffer(Thread):
    def __init__(self, interface="eth0"):
        super().__init__()

        self.interface = interface
        self.my_mac = get_if_hwaddr(interface)
        self.daemon = True
        self.socket = None
        self.stop_sniffer = Event()

    def isNotOutgoing(self, pkt) -> bool:
        return pkt[Ether].src != self.my_mac

    def run(self) -> None:
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter="ip",
        )
        sniff(
            lfilter=self.isNotOutgoing,
            opened_socket=self.socket,
            prn=self.print_packet,
            stop_filter=self.should_stop_sniffer,
        )

    def join(self, timeout=None) -> None:
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, _) -> bool:
        return self.stop_sniffer.is_set()

    @classmethod
    def print_packet(cls, pkt) -> None:
        print("[!] 数据包被交换机反射回来了: ")
        pkt.show()
        ether_layer = pkt.getlayer(Ether)
        print(f"[!] INFO: {ether_layer.src} -> {ether_layer.dst}\n")


def get_if() -> str:
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if iface is None:
        exit("eth0 interface not found")
    return iface


def send_packet(iface, addr) -> None:
    payload = input("请输入数据包要携带的信息：")
    print(f"Sending on interface {iface} to {addr}\n")
    pkt = Ether(src=get_if_hwaddr(iface), dst='00:01:02:03:04:05')
    pkt = pkt / IP(dst=addr) / payload
    sendp(pkt, iface=iface, verbose=False)


def main():
    addr = "10.0.0.2"
    addr = socket.gethostbyname(addr)
    iface = get_if()

    listener = Sniffer(iface)
    listener.start()

    try:
        while True:
            time.sleep(0.75)
            send_packet(iface, addr)

    except KeyboardInterrupt:
        print("[*] Stop sniffing")
        listener.join(2.0)

        if listener.is_alive():
            listener.socket.close()

    except Exception as ex:
        print(ex)


if __name__ == '__main__':
    main()
