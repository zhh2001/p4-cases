#!/usr/bin/env python3
"""Repeater verification helpers.

`test.py send` runs inside h1: sends a labelled Ethernet frame to h2's
MAC.

`test.py sniff` runs inside h2: listens on h2-eth0 for the labelled frame
and prints SUCCESS / FAILURE.
"""

from __future__ import annotations

import sys

from scapy.all import AsyncSniffer, Ether, get_if_hwaddr, sendp

H1_IFACE = "h1-eth0"
H2_IFACE = "h2-eth0"
H1_MAC = "00:00:00:00:00:01"
H2_MAC = "00:00:00:00:00:02"
PAYLOAD = b"hello-repeater"
TIMEOUT = 4.0


def run_send() -> int:
    frame = Ether(src=H1_MAC, dst=H2_MAC) / PAYLOAD
    sendp(frame, iface=H1_IFACE, verbose=False)
    print(f"SEND: {H1_MAC} -> {H2_MAC} payload={PAYLOAD!r}")
    return 0


def run_sniff() -> int:
    my_mac = get_if_hwaddr(H2_IFACE)
    sniffer = AsyncSniffer(
        iface=H2_IFACE,
        count=1,
        timeout=TIMEOUT,
        lfilter=lambda p: Ether in p and p[Ether].dst == my_mac and bytes(p[Ether].payload).startswith(PAYLOAD),
    )
    sniffer.start()
    sniffer.join(timeout=TIMEOUT + 0.5)
    pkts = sniffer.results or []

    if not pkts:
        print(f"FAILURE: no frame with payload {PAYLOAD!r} received on {H2_IFACE}")
        return 1
    pkt = pkts[0]
    print(f"SUCCESS: received src={pkt[Ether].src} dst={pkt[Ether].dst} payload={bytes(pkt[Ether].payload)!r}")
    return 0


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("send", "sniff"):
        print("usage: test.py send|sniff", file=sys.stderr)
        return 2
    return run_send() if sys.argv[1] == "send" else run_sniff()


if __name__ == "__main__":
    sys.exit(main())
