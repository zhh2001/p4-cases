#!/usr/bin/env python3
"""Mininet topology for Case 09: ECMP hash.

One switch, three hosts. Validate TCP and UDP flow affinity, direct
routes, fragment affinity, IPv4 options, full packet contents and drops.
"""

from __future__ import annotations

import argparse
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

packets = importlib.import_module("09_ecmp_hash.packets")


def host_ip(n: int) -> str:
    return f"10.0.0.{n}/24"


def host_mac(n: int) -> str:
    return f"00:00:00:00:00:{n:02d}"


class EcmpTopo(Topo):
    def build(self, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        for i in range(1, 4):
            self.addHost(f"h{i}", ip=host_ip(i), mac=host_mac(i))
            self.addLink(f"h{i}", sw)


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
    return proc.wait_ready("ecmp ready", timeout)


def populate_arp(net: Mininet) -> None:
    for i in range(1, 4):
        host = net.get(f"h{i}")
        for j in range(1, 4):
            if j == i:
                continue
            output, error, code = host.pexec(
                [
                    "ip",
                    "neigh",
                    "replace",
                    f"10.0.0.{j}",
                    "lladdr",
                    host_mac(j),
                    "nud",
                    "permanent",
                    "dev",
                    host.defaultIntf().name,
                ]
            )
            if code:
                raise RuntimeError(f"cannot configure h{i}: {output} {error}")


def read_probe(proc: subprocess.Popen, timeout: float = 7) -> dict:
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


def check_delivery(probes: list[dict], received: dict[str, list[bytes]]) -> None:
    if set(received) != {"h1", "h2", "h3"}:
        raise RuntimeError("capture replies must include all three hosts")
    identities = {packets.identity(item["frame"]): item for item in probes}
    if len(identities) != len(probes):
        raise RuntimeError("test packets must have unique identities")
    arrivals = {key: [] for key in identities}
    for host, frames in received.items():
        if not isinstance(frames, list):
            raise RuntimeError("capture replies must contain frame lists")
        for frame in frames:
            key = packets.identity(frame)
            if key not in identities:
                raise RuntimeError("capture contains an unrecognised frame")
            arrivals[key].append((host, frame))
    distribution = {protocol: {"h2": 0, "h3": 0} for protocol in (17, 6)}
    for key, item in identities.items():
        actual = arrivals[key]
        expected = 1 if item["allowed"] else 0
        if len(actual) != expected:
            raise RuntimeError(
                f"{item['name']} received {len(actual)} frames, expected {expected}"
            )
        if actual:
            host, frame = actual[0]
            if host != item["receiver"]:
                raise RuntimeError(
                    f"{item['name']} arrived at the wrong ECMP or direct host"
                )
            packets.check_forwarded(item["frame"], frame, host)
            for protocol, counts in distribution.items():
                if item["name"].startswith(f"ecmp-{protocol}-"):
                    counts[host] += 1
    for protocol, counts in distribution.items():
        if sum(counts.values()):
            if not all(counts.values()):
                raise RuntimeError(f"protocol {protocol} did not use both ECMP members")
            print(f"protocol={protocol}: h2={counts['h2']} h3={counts['h3']}")


def run_test(net: Mininet, controller: Controller, n_flows: int = 20) -> int:
    procs = []
    try:
        if controller.proc.poll() is not None:
            raise RuntimeError("controller exited before the ECMP test")
        prefix = bytes((198, 18)) + uuid.uuid4().bytes[:1]
        probes = packets.make_probes(prefix, n_flows)
        with tempfile.TemporaryDirectory(prefix="p4-ecmp-") as directory:
            receivers = {}
            for number in (1, 2, 3):
                name = f"h{number}"
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
            for number in (1, 2, 3):
                name = f"h{number}"
                sent = [item["frame"] for item in probes if item["sender"] == name]
                manifest = Path(directory) / f"{name}.json"
                manifest.write_text(json.dumps([frame.hex() for frame in sent]))
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
                reply = read_probe(proc)
                if type(reply.get("sent")) is not int or reply["sent"] != len(sent):
                    raise RuntimeError("sender did not confirm all test frames")
            captured = {
                name: frame_list(read_probe(proc))
                for name, (proc, _) in receivers.items()
            }
        check_delivery(probes, captured)
        if controller.proc.poll() is not None:
            raise RuntimeError("controller exited during the ECMP test")
    except (
        RuntimeError,
        OSError,
        ValueError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    finally:
        for proc in procs:
            stop_probe(proc)
    print(
        f"SUCCESS: {len(probes)} ECMP and IPv4 packets follow expected paths and contents"
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
    reset_port_allocators()
    with NetworkRuntime(EcmpTopo()) as runtime:
        net = runtime.net
        populate_arp(net)

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
