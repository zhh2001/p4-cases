#!/usr/bin/env python3
"""Runs inside h2. Waits for a VXLAN-over-UDP packet and prints a
machine-readable line `vni=<N> inner_dst=<MAC>` plus a plain count on
stdout so the driver can tell whether we saw anything.
"""
from __future__ import annotations

from scapy.all import AsyncSniffer, UDP

IFACE = "h2-eth0"
TIMEOUT = 4.0


def main() -> int:
    s = AsyncSniffer(
        iface=IFACE, count=1, timeout=TIMEOUT,
        lfilter=lambda p: UDP in p and p[UDP].dport == 4789,
    )
    s.start()
    s.join()
    pkts = s.results or []
    print(len(pkts))
    if not pkts:
        return 1
    raw = bytes(pkts[0])
    vxlan_off = 14 + 20 + 8     # outer eth + ipv4 + udp
    vni = int.from_bytes(raw[vxlan_off + 4 : vxlan_off + 7], "big")
    inner_dst = ":".join(f"{b:02x}" for b in raw[vxlan_off + 8 : vxlan_off + 14])
    print(f"vni={vni} inner_dst={inner_dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
