#!/usr/bin/env python3
"""Packet reflector verification.

Runs inside h1. Sends a raw Ethernet frame with a well-known payload and
waits for the switch to reflect the frame back with src/dst MACs swapped.
Prints SUCCESS and exits 0 on success, FAILURE and exits 1 otherwise.
"""

from __future__ import annotations

import sys
import time

from scapy.all import AsyncSniffer, Ether, get_if_hwaddr, sendp

IFACE = "h1-eth0"
TEST_MAC = "02:aa:bb:cc:dd:ee"
PAYLOAD = b"hello-reflector"
TIMEOUT = 3.0


def main() -> int:
    my_mac = get_if_hwaddr(IFACE)

    sniffer = AsyncSniffer(
        iface=IFACE,
        count=1,
        timeout=TIMEOUT,
        lfilter=lambda p: Ether in p and p[Ether].dst == my_mac and p[Ether].src == TEST_MAC,
    )
    sniffer.start()
    # Let the sniffer bind its raw socket before we send.
    time.sleep(0.5)

    frame = Ether(src=my_mac, dst=TEST_MAC) / PAYLOAD
    sendp(frame, iface=IFACE, verbose=False)

    sniffer.join(timeout=TIMEOUT + 0.5)
    pkts = sniffer.results or []

    if not pkts:
        print(f"FAILURE: no reflected packet seen within {TIMEOUT}s")
        return 1

    reflected = pkts[0]
    if reflected[Ether].src != TEST_MAC or reflected[Ether].dst != my_mac:
        print(f"FAILURE: MAC not swapped (got src={reflected[Ether].src} dst={reflected[Ether].dst})")
        return 1
    if bytes(reflected[Ether].payload) != PAYLOAD:
        print(f"FAILURE: payload corrupted (got {bytes(reflected[Ether].payload)!r})")
        return 1

    print(f"SUCCESS: packet reflected with MACs swapped "
          f"(src={reflected[Ether].src} dst={reflected[Ether].dst})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
