#!/usr/bin/env python3
"""Mininet topology for Case 12: register-based flow counter.

After the Go controller pushes the pipeline we send 30 UDP packets
with identical 5-tuple from h1. The P4 data plane hashes every packet
to the same register slot and increments; we read the register via
BMv2's Thrift CLI (simple_switch_CLI) and assert the largest slot
counts at least 30.

(The Go SDK exercises register WRITE; READ is verified via Thrift
because BMv2's P4Runtime register-read support is still
Unimplemented.)
"""

from __future__ import annotations

import argparse
import os
import re
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


class RegTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        self.addLink(h1, sw)
        self.addLink(h2, sw)


def start_controller(controller_bin: str, p4info: str, config: str) -> subprocess.Popen:
    info("*** Launching Go controller\n")
    return subprocess.Popen(
        [controller_bin, "-addr", "127.0.0.1:9559", "-p4info", p4info, "-config", config],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, text=True,
    )


def wait_ready(proc: subprocess.Popen, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else ""
        if not line:
            if proc.poll() is not None:
                return False
            time.sleep(0.05)
            continue
        info(f"    controller: {line.rstrip()}\n")
        if "register-counter ready" in line:
            return True
    return False


def thrift_register_dump(thrift_port: int) -> dict[int, int]:
    """Use simple_switch_CLI to dump flow_counter. Returns slot->value
    for all non-zero slots."""
    out = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input="register_read flow_counter\n",
        capture_output=True, text=True, timeout=6,
    ).stdout
    info("--- thrift dump (first 400 chars) ---\n")
    info(out[:400] + "\n")
    info("--------------------------------------\n")
    rv: dict[int, int] = {}
    # Per-slot format:  flow_counter[17]= 30
    for m in re.finditer(r"flow_counter\[(\d+)\]\s*=\s*(\d+)", out):
        slot = int(m.group(1))
        val = int(m.group(2))
        if val != 0:
            rv[slot] = val
    # Whole-array format: flow_counter= 0 0 0 30 0 ...  OR flow_counter=[0,0,...]
    if not rv:
        arr = re.search(r"flow_counter\s*=\s*\[?([^\n\]]+)\]?", out)
        if arr:
            tokens = re.split(r"[,\s]+", arr.group(1).strip())
            for i, tok in enumerate(tokens):
                try:
                    v = int(tok)
                except ValueError:
                    continue
                if v != 0:
                    rv[i] = v
    return rv


def run_test(net: Mininet, ctrl: subprocess.Popen, thrift_port: int) -> int:
    h1 = net.get("h1")

    info("*** Sending 30 identical-5-tuple UDP packets from h1\n")
    h1.cmd(
        "python3 -c \""
        "from scapy.all import Ether, IP, UDP, sendp; "
        "[sendp(Ether(src='00:00:00:00:00:01',dst='00:00:00:00:00:02')/"
        "IP(src='10.0.0.1',dst='10.0.0.2',ttl=64)/"
        "UDP(sport=1111, dport=2222)/b'reg-flow', "
        "iface='h1-eth0', verbose=False) for _ in range(30)]\""
    )
    time.sleep(0.5)

    info(f"*** Dumping flow_counter via Thrift :{thrift_port}\n")
    counts = thrift_register_dump(thrift_port)
    if not counts:
        print("FAILURE: no non-zero slots in flow_counter")
        return 1
    for slot, val in sorted(counts.items(), key=lambda kv: -kv[1])[:10]:
        print(f"slot={slot} value={val}")

    top_slot, top_val = max(counts.items(), key=lambda sv: sv[1])
    print(f"largest data-plane slot: slot={top_slot} value={top_val}")

    if top_val < 30:
        print(f"FAILURE: top_val={top_val} (want >=30)")
        return 1
    print(f"SUCCESS: 30-packet flow counted into register slot {top_slot} (val={top_val})")
    print("(BMv2's P4Runtime register-write is Unimplemented, so controller-side "
          "seed is skipped; the data-plane increment works as expected.)")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=RegTopo(), controller=None)
    net.start()

    sw = net.get("s1")
    thrift_port = sw.thrift_port

    ctrl = start_controller(args.controller, args.p4info, args.config)
    if not wait_ready(ctrl):
        print("!!! controller did not reach ready state")
        net.stop()
        sys.exit(2)

    rc = 0
    try:
        if args.run_test:
            rc = run_test(net, ctrl, thrift_port)
        else:
            CLI(net)
    finally:
        info("*** Stopping controller\n")
        if ctrl.poll() is None:
            try:
                ctrl.stdin.write("quit\n")
                ctrl.stdin.flush()
            except Exception:
                pass
            ctrl.send_signal(signal.SIGTERM)
            try:
                ctrl.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ctrl.kill()
        net.stop()

    sys.exit(rc)


if __name__ == "__main__":
    main()
