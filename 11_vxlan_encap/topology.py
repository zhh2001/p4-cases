#!/usr/bin/env python3
"""Mininet topology for Case 11: VXLAN encap.

h1 sends a plain Ethernet frame to a synthetic inner MAC; h2 receives
the frame wrapped in VXLAN over UDP and verifies the outer stack +
lengths, checksum, VNI and the complete inner frame.
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

packets = importlib.import_module("11_vxlan_encap.packets")


class VxlanTopo(Topo):
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
    return proc.wait_ready("vxlan ready", timeout)


def configure_mtu(net: Mininet) -> None:
    for link in net.links:
        interfaces = (link.intf1, link.intf2)
        mtu = 1500 if any(intf.node.name == "h1" for intf in interfaces) else 1600
        for intf in interfaces:
            output, error, code = intf.node.pexec(
                ["ip", "link", "set", "dev", intf.name, "mtu", str(mtu)]
            )
            if code:
                raise RuntimeError(
                    f"cannot configure {intf.name} MTU: {output} {error}"
                )


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
    expected = [
        packets.encapsulate(frame)
        for item in probes
        if item["allowed"]
        for frame in item["frames"]
    ]
    errors = []
    for host, wanted in (("h1", []), ("h2", expected)):
        actual = received.get(host)
        if not isinstance(actual, list):
            raise RuntimeError(f"missing capture from {host}")
        if Counter(actual) != Counter(wanted):
            errors.append(
                f"{host} received {len(actual)} frames, expected {len(wanted)} with exact contents"
            )
            if host == "h2":
                originals = {
                    frame[6:12]: frame for item in probes for frame in item["frames"]
                }
                for frame in actual:
                    inner = originals.get(frame[56:62])
                    if (
                        inner is not None
                        and len(frame) >= 42
                        and frame != packets.encapsulate(inner)
                    ):
                        errors.append(
                            f"outer lengths IPv4={int.from_bytes(frame[16:18], 'big')} UDP={int.from_bytes(frame[38:40], 'big')}, "
                            f"expected IPv4={len(inner) + 36} UDP={len(inner) + 16}"
                        )
                        break
    for item in probes:
        sources = {frame[6:12] for frame in item["frames"]}
        observed = sum(
            frame[56:62] in sources or frame[6:12] in sources
            for host in ("h1", "h2")
            for frame in received[host]
        )
        wanted = len(item["frames"]) if item["allowed"] else 0
        print(
            f"{item['name']}: received={observed}/{len(item['frames'])}, expected={wanted}"
        )
        if observed != wanted:
            errors.append(f"{item['name']} received {observed}, expected {wanted}")
    if errors:
        raise RuntimeError("VXLAN delivery differs: " + ", ".join(errors))


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
        probes = packets.make_probes(prefix)
        info(f"*** Checking {len(probes)} VXLAN scenarios with five frames each\n")
        with tempfile.TemporaryDirectory(prefix="p4-vxlan-") as directory:
            receivers = {}
            for name in ("h1", "h2"):
                host = net.get(name)
                ready = Path(directory) / f"{name}-ready"
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/test_sniff.py",
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
            deadline = time.monotonic() + 2
            while not all(
                ready.exists() and ready.read_text() == "ready\n"
                for _, ready in receivers.values()
            ):
                if time.monotonic() >= deadline or any(
                    proc.poll() is not None for proc, _ in receivers.values()
                ):
                    raise RuntimeError("packet receivers did not become ready")
                time.sleep(0.02)
            frames = [frame for item in probes for frame in item["frames"]]
            manifest = Path(directory) / "frames.json"
            manifest.write_text(json.dumps([frame.hex() for frame in frames]))
            h1 = net.get("h1")
            proc = h1.popen(
                [
                    "python3",
                    f"{HERE}/test_sniff.py",
                    "send",
                    "--iface",
                    h1.defaultIntf().name,
                    "--frames",
                    str(manifest),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(proc)
            reply = read_probe(proc, timeout=4)
            if type(reply.get("sent")) is not int or reply["sent"] != len(frames):
                raise RuntimeError("sender did not confirm all test frames")
            received = {
                name: frame_list(read_probe(proc, timeout=5))
                for name, (proc, _) in receivers.items()
            }
            check_delivery(probes, received)
            if ctrl is not None and ctrl.proc.poll() is not None:
                raise RuntimeError("controller exited during the VXLAN test")
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
        "SUCCESS: VXLAN lengths, checksum, outer headers and inner frames match expectations"
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
    with NetworkRuntime(VxlanTopo()) as runtime:
        net = runtime.net

        configure_mtu(net)
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
