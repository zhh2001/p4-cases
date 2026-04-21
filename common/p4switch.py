"""Mininet helpers for spawning BMv2 simple_switch_grpc instances.

The cases in this repository use pure Mininet (no p4utils, no p4app). The
P4RuntimeSwitch class defined here is the minimum glue needed: it launches
simple_switch_grpc with a sensible command line, wires Mininet-owned
veth interfaces to BMv2 port numbers, and tears everything down cleanly
on stop.

Every switch is started with --no-p4, meaning the pipeline is pushed by
an external P4Runtime controller (the Go binary in controller/). That
matches how production SDN controllers operate and exercises the Go SDK
end-to-end.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time

from mininet.log import info, warn
from mininet.node import Switch


DEFAULT_SWITCH_PATH = "/usr/local/bin/simple_switch_grpc"
DEFAULT_GRPC_BASE_PORT = 9559
DEFAULT_THRIFT_BASE_PORT = 9090
DEFAULT_CPU_PORT = 510


class P4RuntimeSwitch(Switch):
    """Mininet Switch that runs BMv2 simple_switch_grpc under the hood.

    Port numbering: mininet links are numbered 1..N in the order they are
    added. We pass `-i N@ifname` to simple_switch_grpc so BMv2 exposes
    ports with the same indices the controller will reference.
    """

    next_grpc_port = DEFAULT_GRPC_BASE_PORT
    next_thrift_port = DEFAULT_THRIFT_BASE_PORT

    def __init__(
        self,
        name: str,
        device_id: int = 1,
        grpc_port: int | None = None,
        thrift_port: int | None = None,
        cpu_port: int | None = None,
        sw_path: str = DEFAULT_SWITCH_PATH,
        log_file: str | None = None,
        pcap_dir: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(name, **kwargs)
        self.device_id = device_id
        self.grpc_port = grpc_port or self._alloc_grpc_port()
        self.thrift_port = thrift_port or self._alloc_thrift_port()
        self.cpu_port = cpu_port
        self.sw_path = sw_path
        self.log_file = log_file or f"/tmp/{name}.log"
        self.pcap_dir = pcap_dir
        self.proc: subprocess.Popen | None = None

    @classmethod
    def _alloc_grpc_port(cls) -> int:
        p = cls.next_grpc_port
        cls.next_grpc_port += 1
        return p

    @classmethod
    def _alloc_thrift_port(cls) -> int:
        p = cls.next_thrift_port
        cls.next_thrift_port += 1
        return p

    def start(self, _controllers) -> None:  # type: ignore[override]
        """Launch simple_switch_grpc after the veth pairs are up."""
        if not os.path.exists(self.sw_path):
            raise RuntimeError(
                f"simple_switch_grpc not found at {self.sw_path}. Install "
                "behavioral-model, or set P4_SWITCH_PATH in the env."
            )

        # Build -i N@ifname mappings in port order.
        iface_args: list[str] = []
        for port, intf in self.intfs.items():
            # Mininet exposes intf 0 as loopback; real links start at 1.
            if port == 0:
                continue
            iface_args.extend(["-i", f"{port}@{intf.name}"])

        cmd = [
            self.sw_path,
            "--no-p4",
            "--log-file", self.log_file,
            "--log-flush",
            "--device-id", str(self.device_id),
            "--thrift-port", str(self.thrift_port),
            *iface_args,
        ]
        if self.pcap_dir:
            os.makedirs(self.pcap_dir, exist_ok=True)
            cmd.extend(["--pcap", self.pcap_dir])
        # Separator between BMv2 core args and simple_switch_grpc target args.
        cmd.append("--")
        cmd.extend([
            "--grpc-server-addr", f"0.0.0.0:{self.grpc_port}",
        ])
        if self.cpu_port is not None:
            cmd.extend(["--cpu-port", str(self.cpu_port)])

        info(f"*** Starting BMv2 for {self.name} on :{self.grpc_port}\n")
        info("     " + " ".join(cmd) + "\n")
        log_fd = open(self.log_file + ".stderr", "wb")
        # Detach into its own process group so SIGINT on mininet does not
        # race us; we manage lifecycle in stop().
        self.proc = subprocess.Popen(
            cmd,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )

        # Wait for gRPC to be accepting connections (up to 10 s).
        if not self._wait_tcp_open("127.0.0.1", self.grpc_port, timeout=10.0):
            self.stop()
            raise RuntimeError(
                f"{self.name}: simple_switch_grpc gRPC port {self.grpc_port} "
                f"never opened; see {self.log_file} and {self.log_file}.stderr"
            )

    def stop(self, deleteIntfs: bool = True) -> None:  # type: ignore[override]
        if self.proc and self.proc.poll() is None:
            info(f"*** Stopping BMv2 for {self.name} (pid {self.proc.pid})\n")
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                self.proc.wait(timeout=3)
            except Exception as exc:  # pragma: no cover
                warn(f"!!! {self.name}: graceful stop failed ({exc}); SIGKILL\n")
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.proc = None
        super().stop(deleteIntfs=deleteIntfs)

    @staticmethod
    def _wait_tcp_open(host: str, port: int, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.2)
        return False


def reset_port_allocators() -> None:
    """Call at the top of each topology script if you launch multiple
    independent networks in the same Python process."""
    P4RuntimeSwitch.next_grpc_port = DEFAULT_GRPC_BASE_PORT
    P4RuntimeSwitch.next_thrift_port = DEFAULT_THRIFT_BASE_PORT
