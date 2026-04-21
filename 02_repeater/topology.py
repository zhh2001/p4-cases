#!/usr/bin/env python3
"""Mininet topology for Case 02: port repeater.

Single switch with two hosts. Packets from h1 (port 1) exit on port 2
to h2 and vice versa. The P4 program hard-codes this mapping so the
controller only pushes the pipeline — no table writes.
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


class RepeaterTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        # Port order: h1 gets port 1, h2 gets port 2.
        self.addLink(h1, sw)
        self.addLink(h2, sw)


def run_controller(controller_bin: str, p4info: str, config: str) -> subprocess.Popen:
    info("*** Launching Go controller to push pipeline\n")
    return subprocess.Popen(
        [
            controller_bin,
            "-addr", "127.0.0.1:9559",
            "-p4info", p4info,
            "-config", config,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def wait_controller_ready(proc: subprocess.Popen, timeout: float = 10.0) -> bool:
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
        if "repeater ready" in decoded:
            return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    net = Mininet(topo=RepeaterTopo(), controller=None)
    net.start()

    ctrl = run_controller(args.controller, args.p4info, args.config)
    if not wait_controller_ready(ctrl):
        print("!!! controller did not reach ready state")
        if ctrl.stdout:
            print(ctrl.stdout.read().decode(errors="replace"))
        net.stop()
        sys.exit(2)

    rc = 0
    try:
        if args.run_test:
            h1 = net.get("h1")
            h2 = net.get("h2")
            info("*** Starting sniffer on h2\n")
            sniff = h2.popen(
                ["python3", f"{HERE}/test.py", "sniff"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            # Give the sniffer a second to bind its socket.
            time.sleep(1.0)
            info("*** Sending test frame from h1\n")
            send_out = h1.cmd(f"python3 {HERE}/test.py send")
            info("    " + send_out.strip() + "\n")

            try:
                out, _ = sniff.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                sniff.kill()
                out, _ = sniff.communicate()
            sys.stdout.write(out.decode(errors="replace"))
            rc = 0 if b"SUCCESS" in out else 1
        else:
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
