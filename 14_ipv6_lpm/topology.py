#!/usr/bin/env python3
"""Mininet topology for Case 14: IPv6 LPM routing.

Three hosts, each in their own /64. The switch routes between them via
an LPM table installed by the Go controller.

Test plan (scapy bypasses host kernel, so we don't have to wrestle
with Mininet's IPv6 routing tables):

  flow A: h1 -> 2001:db8:2::1   should reach h2 only       (/64 hit)
  flow B: h1 -> 2001:db8:3::1   should reach h3 only       (/128 wins)
  flow C: h1 -> 2001:db8:3::42  should reach h3 only       (/64 fallback)
  flow D: h1 -> 2001:db8:9::1   should reach nobody        (no entry -> drop)

Each received packet is also checked for hopLimit == 63 (was 64,
decremented once by ipv6_forward) and the dst-MAC rewritten to the
target host's MAC.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch  # noqa: E402


# Gateway MAC each host puts in the dst field of outgoing frames.
# The router rewrites src/dst MACs as part of forwarding.
GATEWAY_MAC = "00:00:00:00:0a:01"


class IPv6Topo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip=None, mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip=None, mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip=None, mac="00:00:00:00:00:03")
        self.addLink(h1, sw)
        self.addLink(h2, sw)
        self.addLink(h3, sw)


def configure_ipv6(net: Mininet) -> None:
    """Assign fixed IPv6 addresses; raw scapy bypasses kernel routes,
    but we still need each host to recognise its address so the
    interface comes up and we can sniff with the right filters."""
    plan = [
        ("h1", "h1-eth0", "2001:db8:1::1/64"),
        ("h2", "h2-eth0", "2001:db8:2::1/64"),
        ("h3", "h3-eth0", "2001:db8:3::1/64"),
    ]
    for hname, iface, addr in plan:
        h = net.get(hname)
        # Disable IPv6 DAD — it delays address availability by 1s+.
        h.cmd(f"sysctl -w net.ipv6.conf.{iface}.dad_transmits=0 >/dev/null")
        h.cmd(f"sysctl -w net.ipv6.conf.{iface}.accept_dad=0   >/dev/null")
        h.cmd(f"ip -6 addr add {addr} dev {iface}")
    # Give the interfaces a moment to settle.
    time.sleep(0.5)


def run_controller(controller_bin: str, p4info: str, config: str) -> subprocess.Popen:
    info("*** Launching Go controller\n")
    return subprocess.Popen(
        [controller_bin, "-addr", "127.0.0.1:9559", "-p4info", p4info, "-config", config],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )


def wait_ready(proc: subprocess.Popen, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else b""
        if not line:
            if proc.poll() is not None:
                return False
            time.sleep(0.05)
            continue
        decoded = line.decode(errors="replace").rstrip()
        info(f"    controller: {decoded}\n")
        if "ipv6 router ready" in decoded:
            return True
    return False


def probe(net: Mininet, dst_addr: str, target_iface: str, target_mac: str, n: int = 5) -> int:
    """h1 sends n IPv6 packets to dst_addr. Sniff on target_iface for
    packets that arrive with the expected dst MAC AND hopLimit==63
    (proves both rewrite and decrement happened)."""
    h1 = net.get("h1")
    target_host_name = {"h2-eth0": "h2", "h3-eth0": "h3"}.get(target_iface, "h1")
    target = net.get(target_host_name)

    sniff_script = (
        "from scapy.all import AsyncSniffer, IPv6, Ether\n"
        f"want_mac = '{target_mac}'\n"
        "def keep(p):\n"
        "    if not (Ether in p and IPv6 in p):\n"
        "        return False\n"
        "    if p[Ether].dst.lower() != want_mac.lower():\n"
        "        return False\n"
        "    return p[IPv6].hlim == 63\n"
        f"s = AsyncSniffer(iface='{target_iface}', count={n}, timeout=4, lfilter=keep)\n"
        "s.start(); s.join()\n"
        "print(len(s.results or []))\n"
    )
    rx = target.popen(["python3", "-c", sniff_script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(0.5)

    send_script = (
        "from scapy.all import Ether, IPv6, sendp\n"
        f"pkt = Ether(src='{h1.MAC()}', dst='{GATEWAY_MAC}')/"
        f"IPv6(src='2001:db8:1::1', dst='{dst_addr}', hlim=64)/b'ipv6-lpm-probe'\n"
        f"sendp([pkt]*{n}, iface='h1-eth0', verbose=False)\n"
    )
    h1.cmd(f"python3 -c \"{send_script}\"")

    try:
        out, _ = rx.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        rx.kill()
        out, _ = rx.communicate()

    for line in reversed((out or b"").decode(errors="replace").splitlines()):
        s = line.strip()
        if s.isdigit():
            return int(s)
    return 0


def probe_dropped(net: Mininet, dst_addr: str, n: int = 5) -> tuple[int, int]:
    """Send n packets to a no-route dst. Confirm neither h2 nor h3
    received any packet from this flow."""
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")

    def make_sniffer(host, iface):
        # Match anything from h1's IPv6 src — even if the router somehow
        # leaked the packet with wrong MAC, we'd still catch it.
        return host.popen(
            ["python3", "-c",
             "from scapy.all import AsyncSniffer, IPv6\n"
             f"s = AsyncSniffer(iface='{iface}', count={n}, timeout=3,\n"
             "    lfilter=lambda p: IPv6 in p and p[IPv6].src == '2001:db8:1::1')\n"
             "s.start(); s.join(); print(len(s.results or []))\n"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    rx2 = make_sniffer(h2, "h2-eth0")
    rx3 = make_sniffer(h3, "h3-eth0")
    time.sleep(0.5)

    send_script = (
        "from scapy.all import Ether, IPv6, sendp\n"
        f"pkt = Ether(src='{h1.MAC()}', dst='{GATEWAY_MAC}')/"
        f"IPv6(src='2001:db8:1::1', dst='{dst_addr}', hlim=64)/b'no-route'\n"
        f"sendp([pkt]*{n}, iface='h1-eth0', verbose=False)\n"
    )
    h1.cmd(f"python3 -c \"{send_script}\"")

    def harvest(p):
        try:
            out, _ = p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
        for line in reversed((out or b"").decode(errors="replace").splitlines()):
            s = line.strip()
            if s.isdigit():
                return int(s)
        return 0

    return harvest(rx2), harvest(rx3)


def run_test(net: Mininet) -> int:
    configure_ipv6(net)

    info("*** flow A: h1 -> 2001:db8:2::1 (h2 /64)\n")
    a = probe(net, "2001:db8:2::1", "h2-eth0", "00:00:00:00:00:02", n=5)
    info("*** flow B: h1 -> 2001:db8:3::1 (h3 /128, longer prefix)\n")
    b = probe(net, "2001:db8:3::1", "h3-eth0", "00:00:00:00:00:03", n=5)
    info("*** flow C: h1 -> 2001:db8:3::42 (h3 /64 fallback)\n")
    c = probe(net, "2001:db8:3::42", "h3-eth0", "00:00:00:00:00:03", n=5)
    info("*** flow D: h1 -> 2001:db8:9::1 (no route, expect drop)\n")
    d2, d3 = probe_dropped(net, "2001:db8:9::1", n=5)

    print(f"flow A  -> h2 received: {a}/5  (want 5, hop_limit=63, dst-MAC=h2)")
    print(f"flow B  -> h3 received: {b}/5  (want 5, /128 longer-prefix-wins)")
    print(f"flow C  -> h3 received: {c}/5  (want 5, /64 fallback)")
    print(f"flow D  -> h2 leaked:   {d2}/5  (want 0)")
    print(f"flow D  -> h3 leaked:   {d3}/5  (want 0)")

    if a == 5 and b == 5 and c == 5 and d2 == 0 and d3 == 0:
        print("SUCCESS: IPv6 LPM (longer-prefix wins, hop_limit decrement, dst-MAC rewrite) all working")
        return 0
    print("FAILURE: IPv6 LPM behaviour does not match expectations")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=IPv6Topo(), controller=None)
    net.start()

    ctrl = run_controller(args.controller, args.p4info, args.config)
    if not wait_ready(ctrl):
        print("!!! controller did not reach ready state")
        if ctrl.stdout:
            print(ctrl.stdout.read().decode(errors="replace"))
        net.stop()
        sys.exit(2)

    rc = 0
    try:
        if args.run_test:
            rc = run_test(net)
        else:
            configure_ipv6(net)
            CLI(net)
    finally:
        info("*** Stopping controller\n")
        if ctrl.poll() is None:
            ctrl.send_signal(signal.SIGTERM)
            try:
                ctrl.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ctrl.kill()
        net.stop()

    sys.exit(rc)


if __name__ == "__main__":
    main()
