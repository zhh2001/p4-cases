#!/usr/bin/env python3
"""Mininet topology for Case 10: Firewall ACL.

Single switch, two hosts (h1 = 10.0.0.1, h2 = 10.0.0.2). Tests drive
flows with and without IPv4 options, malformed headers and fragments:

  1. h1 -> h2  TCP/80    (allowed by rule 2 at prio 90)
  2. h1 -> h2  TCP/22    (denied by rule 1 at prio 100)
  3. h1 -> h2  UDP/5000  (denied by rule 3 at prio 80)
  4. h1 -> h2  UDP/1234  (allowed — no rule matches, default action)
"""

from __future__ import annotations

import argparse
from collections import Counter
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from common.p4switch import P4RuntimeSwitch  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402

packets = importlib.import_module("10_firewall_acl.packets")


class ACLTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        self.addLink(h1, sw)
        self.addLink(h2, sw)


def run_controller(
    runtime: NetworkRuntime, controller_bin: str, p4info: str, config: str
) -> Controller:
    info("*** Launching Go controller\n")
    return runtime.start_controller(
        [
            controller_bin,
            "-addr",
            "127.0.0.1:9559",
            "-p4info",
            p4info,
            "-config",
            config,
        ],
    )


def wait_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("firewall ready", timeout)


def test_vectors(prefix: bytes) -> list[dict]:
    """Build independently labelled packets for each expected ACL decision."""
    if len(prefix) != 4:
        raise ValueError("test prefix must contain four MAC bytes")
    probes = []
    sequence = 0

    def add(
        name,
        sender,
        proto,
        dport,
        options=b"",
        allowed=True,
        fault="",
        flags=0,
        offset=0,
    ):
        nonlocal sequence
        receiver = "h2" if sender == "h1" else "h1"
        src_ip = "10.0.0.1" if sender == "h1" else "10.0.0.2"
        dst_ip = "10.0.0.2" if receiver == "h2" else "10.0.0.1"
        dst_mac = bytes.fromhex("000000000002" if receiver == "h2" else "000000000001")
        frames = []
        for _ in range(5):
            sequence += 1
            frames.append(
                packets.make_frame(
                    prefix + sequence.to_bytes(2, "big"),
                    dst_mac,
                    src_ip,
                    dst_ip,
                    proto,
                    dport,
                    options,
                    sequence,
                    fault,
                    flags,
                    offset,
                )
            )
        probes.append(
            {
                "name": name,
                "sender": sender,
                "receiver": receiver,
                "allowed": allowed,
                "frames": frames,
            }
        )

    flows = [
        ("TCP", 80, True),
        ("TCP", 22, False),
        ("UDP", 5000, False),
        ("UDP", 1234, True),
    ]
    for proto, port, allowed in flows:
        misleading = (
            22
            if proto == "TCP" and allowed
            else 80 if proto == "TCP" else 5000 if allowed else 1234
        )
        shapes = [
            ("plain", b""),
            ("options4", b"\x01" * 4),
            ("options40", b"\x01" * 40),
            ("port-like-options", b"\x94\x04" + misleading.to_bytes(2, "big")),
        ]
        for shape, options in shapes:
            add(
                f"h1-{proto.lower()}{port}-{shape}", "h1", proto, port, options, allowed
            )
        for shape, options in (("plain", b""), ("options40", b"\x01" * 40)):
            add(f"h2-{proto.lower()}{port}-{shape}", "h2", proto, port, options)
    add("icmp-plain", "h1", "ICMP", 0)
    add("icmp-options40", "h1", "ICMP", 0, b"\x01" * 40)
    add("arp", "h1", "ARP", 0)
    add("tcp-dont-fragment", "h1", "TCP", 80, flags=2)
    for fault in (
        "bad-version",
        "short-ihl",
        "short-total",
        "long-total",
        "truncated-ip",
        "truncated-options",
        "short-tcp",
        "short-udp",
    ):
        proto = "UDP" if fault == "short-udp" else "TCP"
        options = b"\x01" * 40 if fault in ("short-total", "truncated-options") else b""
        add(fault, "h1", proto, 1234 if proto == "UDP" else 80, options, False, fault)
    for proto, port in (("TCP", 80), ("UDP", 1234)):
        add(
            f"{proto.lower()}-first-fragment", "h1", proto, port, allowed=False, flags=1
        )
        add(
            f"{proto.lower()}-later-fragment",
            "h1",
            proto,
            port,
            allowed=False,
            offset=1,
        )
    return probes


def read_probe(proc: subprocess.Popen, timeout: float = 6) -> dict:
    output, error = proc.communicate(timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"packet probe failed: {output.strip()} {error.strip()}")
    try:
        reply = json.loads(output)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("packet probe returned invalid JSON") from exc
    if not isinstance(reply, dict):
        raise RuntimeError("packet probe reply must be an object")
    return reply


def frame_list(reply: dict) -> list[bytes]:
    frames = reply.get("frames")
    if not isinstance(frames, list) or any(
        not isinstance(frame, str) for frame in frames
    ):
        raise RuntimeError("capture reply must contain a frame list")
    try:
        return [bytes.fromhex(frame) for frame in frames]
    except ValueError as exc:
        raise RuntimeError("capture reply contains invalid frame bytes") from exc


def check_delivery(probes: list[dict], received: dict[str, list[bytes]]) -> None:
    errors = []
    for host in ("h1", "h2"):
        actual = received.get(host)
        if not isinstance(actual, list):
            raise RuntimeError(f"missing capture from {host}")
        expected = [
            frame
            for probe in probes
            if probe["receiver"] == host and probe["allowed"]
            for frame in probe["frames"]
        ]
        if Counter(actual) != Counter(expected):
            errors.append(
                f"{host} received {len(actual)} frames, expected {len(expected)} with exact contents"
            )
    for probe in probes:
        sources = {frame[6:12] for frame in probe["frames"]}
        observed = [
            frame for frame in received[probe["receiver"]] if frame[6:12] in sources
        ]
        wanted = len(probe["frames"]) if probe["allowed"] else 0
        print(
            f"{probe['name']}: received={len(observed)}/{len(probe['frames'])}, expected={wanted}"
        )
        if len(observed) != wanted:
            errors.append(
                f"{probe['name']} received {len(observed)}, expected {wanted}"
            )
    if errors:
        raise RuntimeError("ACL delivery differs: " + ", ".join(errors))


def stop_probe(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


def run_test(net: Mininet, ctrl: Controller | None = None) -> int:
    procs = []
    try:
        prefix = b"\x02" + uuid.uuid4().bytes[:3]
        probes = test_vectors(prefix)
        info(f"*** Checking {len(probes)} ACL scenarios with five frames each\n")
        with tempfile.TemporaryDirectory(prefix="p4-acl-") as directory:
            receivers = {}
            for name in ("h1", "h2"):
                host = net.get(name)
                ready = Path(directory) / f"{name}-ready"
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/test.py",
                        "receive",
                        "--iface",
                        host.defaultIntf().name,
                        "--prefix",
                        prefix.hex(),
                        "--ready",
                        str(ready),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                procs.append(proc)
                receivers[name] = (proc, ready)
            deadline = time.monotonic() + 3
            while not all(
                ready.exists() and ready.read_text() == "ready\n"
                for _, ready in receivers.values()
            ):
                if time.monotonic() >= deadline or any(
                    proc.poll() is not None for proc, _ in receivers.values()
                ):
                    raise RuntimeError("packet receivers did not become ready")
                time.sleep(0.02)
            for name in ("h1", "h2"):
                host = net.get(name)
                frames = [
                    frame
                    for probe in probes
                    if probe["sender"] == name
                    for frame in probe["frames"]
                ]
                manifest = Path(directory) / f"{name}-frames.json"
                manifest.write_text(json.dumps([frame.hex() for frame in frames]))
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/test.py",
                        "send",
                        "--iface",
                        host.defaultIntf().name,
                        "--frames",
                        str(manifest),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                procs.append(proc)
                reply = read_probe(proc, timeout=5)
                if type(reply.get("sent")) is not int or reply["sent"] != len(frames):
                    raise RuntimeError("sender did not confirm all test frames")
            received = {
                name: frame_list(read_probe(proc))
                for name, (proc, _) in receivers.items()
            }
            check_delivery(probes, received)
            if ctrl is not None and ctrl.proc.poll() is not None:
                raise RuntimeError("controller exited during the ACL test")
    except (
        RuntimeError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        TypeError,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    finally:
        for proc in procs:
            stop_probe(proc)
    print(
        "SUCCESS: ACL decisions, IPv4 options and rejected packets match expectations"
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()

    setLogLevel("info")
    with NetworkRuntime(ACLTopo()) as runtime:
        net = runtime.net

        ctrl = run_controller(runtime, args.controller, args.p4info, args.config)
        if not wait_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)

        rc = 0
        if args.run_test:
            rc = run_test(net, ctrl)
        else:
            CLI(net)

    sys.exit(rc)


if __name__ == "__main__":
    main()
