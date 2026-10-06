#!/usr/bin/env python3
"""Mininet topology for Case 05: L2 learning switch (digest variant).

The test checks unknown-destination flooding, reads back learned MAC
entries and observes learned unicast delivery on every host port.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
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


def host_ip(n: int) -> str:
    return f"10.0.0.{n}/24"


def host_mac(n: int) -> str:
    return f"00:00:00:00:00:{n:02x}"


class LearningTopo(Topo):
    def build(self, n_hosts: int = 4, **_opts) -> None:
        sw = self.addSwitch("s1", cls=P4RuntimeSwitch, device_id=1)
        for i in range(1, n_hosts + 1):
            self.addHost(f"h{i}", ip=host_ip(i), mac=host_mac(i))
            self.addLink(f"h{i}", sw)


def run_controller(
    runtime: NetworkRuntime, controller_bin: str, p4info: str, config: str, ports: int
) -> Controller:
    info("*** Launching Go controller (digest learner)\n")
    return runtime.start_controller(
        [
            controller_bin,
            "-addr",
            "127.0.0.1:9559",
            "-p4info",
            p4info,
            "-config",
            config,
            "-ports",
            str(ports),
        ],
    )


def wait_controller_ready(proc: Controller, timeout: float = 15.0) -> bool:
    return proc.wait_ready("learning-switch ready", timeout)


def drain_controller(proc: Controller, seconds: float) -> None:
    """Allow a bounded grace window for controller output."""
    for _line in proc.lines_for(seconds):
        pass


def parse_learning_table(output: str, source: bool) -> dict[str, int | None]:
    """Read explicit entries and reject unsuccessful or malformed CLI output."""
    if "TABLE ENTRIES" not in output or "Dumping default entry" not in output:
        raise RuntimeError("incomplete learning-table dump")
    if re.search(r"\b(?:Error|Exception|Traceback)\b", output):
        raise RuntimeError(f"learning-table read failed: {output.strip()}")
    entries: dict[str, int | None] = {}
    field = "srcAddr" if source else "dstAddr"
    for block in re.findall(
        r"Dumping entry .*?(?=Dumping entry |Dumping default entry)", output, re.S
    ):
        key = re.search(
            rf"(?:hdr\.)?ethernet\.{field}\s*:\s*EXACT\s+([0-9a-fA-F]+)", block
        )
        action = re.search(r"Action entry:[ \t]*(\S+)[ \t]*-[ \t]*([^\n]*)", block)
        if key is None or len(key[1]) != 12 or action is None:
            raise RuntimeError("malformed learning-table entry")
        mac = bytes.fromhex(key[1]).hex(":")
        if mac in entries:
            raise RuntimeError(f"duplicate learning-table entry for {mac}")
        if source:
            if action[1] != "NoAction" or action[2].strip():
                raise RuntimeError(f"unexpected smac action for {mac}")
            entries[mac] = None
        else:
            if action[1] != "MyIngress.forward" or not re.fullmatch(
                r"(?:[0-9a-fA-F]{2}|[0-9a-fA-F]{4})", action[2].strip()
            ):
                raise RuntimeError(f"unexpected dmac action for {mac}")
            port = int(action[2], 16)
            if not 1 <= port <= 511:
                raise RuntimeError(f"invalid dmac port for {mac}")
            entries[mac] = port
    return entries


def read_learning_tables(thrift_port: int, timeout: float = 3) -> tuple[dict, dict]:
    tables = []
    deadline = time.monotonic() + timeout
    for table in ("smac", "dmac"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("learning-table read timed out")
        result = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=f"table_dump MyIngress.{table}\n",
            capture_output=True,
            text=True,
            timeout=remaining,
        )
        if result.returncode:
            raise RuntimeError(f"{table} read failed: {result.stdout}{result.stderr}")
        tables.append(parse_learning_table(result.stdout, source=table == "smac"))
    return tables[0], tables[1]


def wait_learning(net: Mininet, timeout: float = 5.0) -> None:
    expected = {host.MAC().lower(): int(host.name[1:]) for host in net.hosts}
    deadline = time.monotonic() + timeout
    smac, dmac = {}, {}
    while (remaining := deadline - time.monotonic()) > 0:
        smac, dmac = read_learning_tables(net.get("s1").thrift_port, min(3, remaining))
        if all(mac in smac and dmac.get(mac) == port for mac, port in expected.items()):
            print(
                f"Learned tables: {len(expected)} host MACs mapped to their ingress ports"
            )
            return
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    missing = {
        mac: port
        for mac, port in expected.items()
        if mac not in smac or dmac.get(mac) != port
    }
    raise RuntimeError(f"host MAC learning did not complete: {missing}")


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


def read_probe(proc: subprocess.Popen, timeout: float = 5) -> dict:
    output, error = proc.communicate(timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"packet probe failed: {output.strip()} {error.strip()}")
    try:
        data = json.loads(output)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"packet probe returned invalid JSON: {output!r}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("packet probe reply must be an object")
    return data


def check_delivery(
    packets: dict[str, list], src: str, dst: str, expected: set[str], count: int
) -> None:
    if not expected.issubset(packets):
        raise RuntimeError("missing capture results for a destination host")
    for host, received in packets.items():
        if not isinstance(received, list):
            raise RuntimeError(f"invalid packet list from {host}")
        wanted = list(range(count)) if host in expected else []
        for packet in received:
            if (
                not isinstance(packet, dict)
                or packet.get("src") != src
                or packet.get("dst") != dst
            ):
                raise RuntimeError(f"unexpected Ethernet header received by {host}")
            if type(packet.get("sequence")) is not int:
                raise RuntimeError(f"invalid packet sequence received by {host}")
        if sorted(packet.get("sequence") for packet in received) != wanted:
            raise RuntimeError(f"unexpected delivery to {host}: {received}")


def probe_forwarding(
    net: Mininet, sender_name: str, dst: str, expected: set[str]
) -> None:
    """Require successful capture on every host, including zero-packet ports."""
    sender = net.get(sender_name)
    token = uuid.uuid4().hex
    count = 3
    procs = []
    with tempfile.TemporaryDirectory(prefix="p4-learning-") as directory:
        captures = {}
        try:
            for host in net.hosts:
                ready = Path(directory) / host.name
                proc = host.popen(
                    [
                        "python3",
                        f"{HERE}/test.py",
                        "receive",
                        "--iface",
                        host.defaultIntf().name,
                        "--token",
                        token,
                        "--ready",
                        str(ready),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                procs.append(proc)
                captures[host.name] = (proc, ready)
            deadline = time.monotonic() + 3
            while not all(
                ready.exists() and ready.read_text() == "ready\n"
                for _, ready in captures.values()
            ):
                if time.monotonic() >= deadline or any(
                    proc.poll() is not None for proc, _ in captures.values()
                ):
                    raise RuntimeError("packet receivers did not become ready")
                time.sleep(0.02)
            tx = sender.popen(
                [
                    "python3",
                    f"{HERE}/test.py",
                    "send",
                    "--iface",
                    sender.defaultIntf().name,
                    "--src",
                    sender.MAC(),
                    "--dst",
                    dst,
                    "--token",
                    token,
                    "--count",
                    str(count),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(tx)
            if read_probe(tx).get("sent") != count:
                raise RuntimeError("packet sender did not confirm all frames")
            packets = {
                name: read_probe(proc).get("packets")
                for name, (proc, _) in captures.items()
            }
            check_delivery(packets, sender.MAC().lower(), dst.lower(), expected, count)
            print(
                f"Delivery {sender_name} -> {dst}: "
                + ", ".join(f"{name}={len(frames)}" for name, frames in packets.items())
            )
        finally:
            for proc in procs:
                stop_probe(proc)


def run_test(net: Mininet, ctrl: Controller) -> int:
    try:
        info("*** Checking unknown-destination flooding\n")
        probe_forwarding(
            net,
            "h1",
            "02:ff:ff:ff:ff:fe",
            {host.name for host in net.hosts if host.name != "h1"},
        )
        info("*** Running pingAll to learn host MACs\n")
        if net.pingAll(timeout="3") != 0:
            raise RuntimeError("initial pingAll lost packets")
        wait_learning(net)
        info("*** Running pingAll with learned destinations\n")
        if net.pingAll(timeout="3") != 0:
            raise RuntimeError("learned pingAll lost packets")
        info("*** Checking learned unicast without flooding\n")
        probe_forwarding(net, "h1", net.get("h2").MAC(), {"h2"})
        probe_forwarding(net, "h2", net.get("h1").MAC(), {"h1"})
        drain_controller(ctrl, 0.1)
    except (
        RuntimeError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        TypeError,
    ) as exc:
        print(f"FAILURE: {exc}")
        return 1
    print("SUCCESS: host MACs learned and unicast delivered without flooding")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--p4info", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--n-hosts", type=int, default=4)
    parser.add_argument("--run-test", action="store_true")
    args = parser.parse_args()
    if not 2 <= args.n_hosts <= 254:
        parser.error("--n-hosts must be between 2 and 254")

    setLogLevel("info")
    with NetworkRuntime(LearningTopo(n_hosts=args.n_hosts)) as runtime:
        net = runtime.net

        ctrl = run_controller(
            runtime, args.controller, args.p4info, args.config, args.n_hosts
        )
        if not wait_controller_ready(ctrl):
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
