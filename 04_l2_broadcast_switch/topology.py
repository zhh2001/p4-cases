#!/usr/bin/env python3
"""Validate complete unicast and flooding without returning frames to ingress."""

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
from common.p4switch import P4RuntimeSwitch, reset_port_allocators  # noqa: E402
from common.runtime import Controller, NetworkRuntime  # noqa: E402

packets = importlib.import_module("04_l2_broadcast_switch.packets")


def host_ip(number: int) -> str:
    return packets.host_ip(number) + "/24"


def host_mac(number: int) -> str:
    return packets.host_mac(number)


class BroadcastTopo(Topo):
    def build(self, n_hosts: int = 4, **_opts) -> None:
        packets.validate_host_count(n_hosts)
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        for number in range(1, n_hosts + 1):
            host = self.addHost(f"h{number}", ip=host_ip(number), mac=host_mac(number))
            self.addLink(host, sw)


def configure_test_interfaces(net: Mininet, n_hosts: int) -> None:
    for name in (*[f"h{number}" for number in range(1, n_hosts + 1)], "s1"):
        node = net.get(name)
        settings = [
            f"net.ipv6.conf.{intf.name}.disable_ipv6=1"
            for intf in node.intfList()
            if intf.name != "lo"
        ]
        output, error, code = node.pexec(["sysctl", "-q", "-w", *settings])
        if code:
            raise RuntimeError(
                f"interface command failed: {output.strip()} {error.strip()}"
            )


def run_controller(
    runtime: NetworkRuntime, controller_bin: str, p4info: str, config: str, hosts: int
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
            "-hosts",
            str(hosts),
        ]
    )


def wait_controller_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("broadcast-switch ready", timeout)


def read_probe(proc: subprocess.Popen, timeout: float = 4) -> dict:
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
        raise RuntimeError("capture reply must contain frame hex strings")
    try:
        return [bytes.fromhex(frame) for frame in frames]
    except ValueError as exc:
        raise RuntimeError("capture reply contains invalid frame bytes") from exc


def check_delivery(
    probes: list[dict], received: dict[str, list[bytes]], n_hosts: int = 4
) -> None:
    if set(received) != {f"h{number}" for number in range(1, n_hosts + 1)}:
        raise RuntimeError("capture replies must include every host")
    for name, frames in received.items():
        expected = [item["frame"] for item in probes if name in item["receivers"]]
        if (
            not isinstance(frames, list)
            or any(not isinstance(frame, bytes) for frame in frames)
            or Counter(frames) != Counter(expected)
        ):
            raise RuntimeError(
                f"{name} did not receive exactly the expected complete frames"
            )


def stop_probe(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


def run_probes(
    net: Mininet, ctrl: Controller, prefix: bytes, probes: list[dict], n_hosts: int = 4
) -> None:
    if ctrl.proc.poll() is not None:
        raise RuntimeError("controller exited before the L2 broadcast test")
    packets.validate_host_count(n_hosts)
    duration = 2 + 0.2 * max(0, n_hosts - 4)
    names = [f"h{number}" for number in range(1, n_hosts + 1)]
    procs = []
    try:
        with tempfile.TemporaryDirectory(prefix="p4-broadcast-l2-") as directory:
            receivers = {}
            for name in names:
                host = net.get(name)
                ready = Path(directory) / f"{name}-ready"
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/probe.py",
                        "receive",
                        "--iface",
                        host.defaultIntf().name,
                        "--prefix",
                        prefix.hex(),
                        "--seconds",
                        str(duration),
                        "--ready",
                        str(ready),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                procs.append(proc)
                receivers[name] = (proc, ready)
            deadline = time.monotonic() + 2 + 0.05 * max(0, n_hosts - 4)
            while not all(
                ready.exists() and ready.read_text() == "ready\n"
                for _, ready in receivers.values()
            ):
                if time.monotonic() >= deadline or any(
                    proc.poll() is not None for proc, _ in receivers.values()
                ):
                    raise RuntimeError("packet receivers did not become ready")
                time.sleep(0.02)
            senders = []
            for name in names:
                frames = [item["frame"] for item in probes if item["sender"] == name]
                if not frames:
                    continue
                manifest = Path(directory) / f"{name}.json"
                manifest.write_text(json.dumps([frame.hex() for frame in frames]))
                host = net.get(name)
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/probe.py",
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
                senders.append((proc, len(frames)))
            for proc, count in senders:
                reply = read_probe(proc)
                if type(reply.get("sent")) is not int or reply["sent"] != count:
                    raise RuntimeError("sender did not confirm all test frames")
            captured = {
                name: frame_list(read_probe(proc, timeout=duration + 5))
                for name, (proc, _) in receivers.items()
            }
        check_delivery(probes, captured, n_hosts)
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited during the L2 broadcast test")
    finally:
        for proc in procs:
            stop_probe(proc)


def check_arp(net: Mininet, n_hosts: int) -> None:
    for number in range(1, n_hosts + 1):
        host = net.get(f"h{number}")
        iface = host.defaultIntf().name
        output, error, code = host.pexec(["ip", "-j", "neigh", "show"])
        if code:
            raise RuntimeError(f"ARP read failed: {output.strip()} {error.strip()}")
        try:
            entries = json.loads(output)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("ARP read returned invalid JSON") from exc
        if not isinstance(entries, list) or any(
            not isinstance(item, dict) for item in entries
        ):
            raise RuntimeError("ARP read must contain neighbour records")
        expected = {
            packets.host_ip(peer): host_mac(peer)
            for peer in range(1, n_hosts + 1)
            if peer != number
        }
        observed = {}
        for item in entries:
            if not isinstance(item.get("dst"), str):
                raise RuntimeError("ARP read contains an invalid destination address")
            if item.get("dst") not in expected:
                continue
            if item["dst"] in observed:
                raise RuntimeError("ARP read contains duplicate neighbour records")
            states = item.get("state")
            mac = item.get("lladdr")
            if (
                item.get("dev") != iface
                or not isinstance(mac, str)
                or not isinstance(states, list)
                or not states
                or any(
                    state not in ("REACHABLE", "STALE", "DELAY", "PROBE")
                    for state in states
                )
            ):
                raise RuntimeError("ARP neighbour is missing, invalid or not dynamic")
            observed[item["dst"]] = mac.lower()
        if observed != expected:
            raise RuntimeError(
                f"h{number} did not resolve every peer to its configured MAC"
            )


def run_test(net: Mininet, ctrl: Controller, n_hosts: int = 4) -> int:
    try:
        packets.validate_host_count(n_hosts)
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited before the L2 broadcast test")
        configure_test_interfaces(net, n_hosts)
        for number in range(1, n_hosts + 1):
            host = net.get(f"h{number}")
            output, error, code = host.pexec(
                ["ip", "neigh", "flush", "dev", host.defaultIntf().name]
            )
            if code:
                raise RuntimeError(
                    f"ARP flush failed: {output.strip()} {error.strip()}"
                )
        if n_hosts > 1:
            dropped = net.pingAll(timeout="3")
            if type(dropped) not in (int, float) or dropped != 0:
                raise RuntimeError(
                    f"pingAll returned a nonzero or invalid drop ratio: {dropped}"
                )
            check_arp(net, n_hosts)
            print(f"ping drop ratio: {dropped}%")
        else:
            print("pingAll skipped: single-host topology")
        prefix = b"\x02" + uuid.uuid4().bytes[:3]
        probes = packets.make_probes(prefix, n_hosts)
        run_probes(net, ctrl, prefix, probes, n_hosts)
        if ctrl.proc.poll() is not None:
            raise RuntimeError("controller exited during the L2 broadcast test")
    except (
        RuntimeError,
        OSError,
        ValueError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    copies = sum(len(item["receivers"]) for item in probes)
    dropped = sum(not item["receivers"] for item in probes)
    print(f"L2 probes: sent={len(probes)} delivered={copies} dropped={dropped}")
    print("SUCCESS: L2 unicast, flooding and dynamic ARP validated")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--n-hosts", type=int, default=4)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()
    try:
        packets.validate_host_count(args.n_hosts)
    except ValueError as exc:
        parser.error(str(exc))

    setLogLevel("info")
    reset_port_allocators()
    with NetworkRuntime(BroadcastTopo(n_hosts=args.n_hosts)) as runtime:
        net = runtime.net
        ctrl = run_controller(
            runtime, args.controller, args.p4info, args.config, args.n_hosts
        )
        if not wait_controller_ready(ctrl):
            print("!!! controller did not reach ready state")
            sys.exit(2)
        rc = 0
        if args.run_test:
            rc = run_test(net, ctrl, args.n_hosts)
        else:
            CLI(net)
    sys.exit(rc)


if __name__ == "__main__":
    main()
