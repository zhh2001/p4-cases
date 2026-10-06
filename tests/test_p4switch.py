"""Check switch path selection, startup failure and owned-process teardown."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from common.p4switch import DEFAULT_SWITCH_PATH, P4RuntimeSwitch


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class SwitchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for target in (
            "common.p4switch.Switch.__init__",
            "common.p4switch.Switch.stop",
            "common.p4switch.info",
        ):
            mocked = patch(target, return_value=None)
            mocked.start()
            self.addCleanup(mocked.stop)

    def switch(self, **kwargs):
        switch = P4RuntimeSwitch(
            "test-switch",
            grpc_port=free_port(),
            thrift_port=free_port(),
            log_file=str(Path(self.temp.name) / "switch.log"),
            **kwargs,
        )
        switch.name = "test-switch"
        switch.intfs = {}
        self.addCleanup(switch.stop)
        return switch

    def test_path_uses_environment_and_explicit_argument(self):
        with patch.dict(os.environ, {"P4_SWITCH_PATH": "/custom/switch"}):
            self.assertEqual(self.switch().sw_path, "/custom/switch")
            self.assertEqual(
                self.switch(sw_path="/explicit/switch").sw_path, "/explicit/switch"
            )
        with patch.dict(os.environ, {"P4_SWITCH_PATH": ""}):
            self.assertEqual(self.switch().sw_path, DEFAULT_SWITCH_PATH)

    def test_missing_binary_has_actionable_message(self):
        switch = self.switch(sw_path="/missing/simple_switch_grpc")
        with self.assertRaisesRegex(RuntimeError, "P4_SWITCH_PATH"):
            switch.start([])
        self.assertIsNone(switch.proc)

    def test_occupied_ports_are_rejected_without_stopping_listener(self):
        for attr in ("grpc_port", "thrift_port"):
            with self.subTest(port=attr), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                switch = self.switch(sw_path=sys.executable)
                setattr(switch, attr, listener.getsockname()[1])
                with self.assertRaisesRegex(RuntimeError, "already in use"):
                    switch.start([])
                self.assertIsNone(switch.proc)
                with socket.create_connection(listener.getsockname(), timeout=1):
                    pass

    def test_early_exit_is_reported_and_reaped(self):
        # Python rejects BMv2 arguments immediately, simulating startup failure.
        switch = self.switch(sw_path=sys.executable)
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "did not open gRPC port"):
            switch.start([])
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertIsNone(switch.proc)
        self.assertIn("unknown option", Path(switch.log_file + ".stderr").read_text())

    def test_parent_log_descriptor_is_closed_and_child_is_reaped(self):
        binary = Path(self.temp.name) / "simple_switch_grpc"
        binary.write_text(
            "#!/usr/bin/env python3\n"
            "import socket, sys, time\n"
            "port = int(sys.argv[sys.argv.index('--grpc-server-addr') + 1].rsplit(':', 1)[1])\n"
            "listener = socket.socket()\n"
            "listener.bind(('127.0.0.1', port))\n"
            "listener.listen()\n"
            "time.sleep(60)\n"
        )
        binary.chmod(0o755)
        switch = self.switch(sw_path=str(binary))
        real_spawn = subprocess.Popen
        descriptors = []

        def spawn(*args, **kwargs):
            descriptors.append(kwargs["stdout"])
            return real_spawn(*args, **kwargs)

        with patch("common.p4switch.subprocess.Popen", side_effect=spawn):
            switch.start([])
        self.assertTrue(descriptors[0].closed)
        child = switch.proc
        self.assertIsNone(child.poll())
        switch.stop()
        self.assertIsNotNone(child.returncode)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", switch.grpc_port), timeout=0.2)

    def test_wait_for_port_obeys_deadline(self):
        switch = self.switch()
        switch.proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        started = time.monotonic()
        self.assertFalse(switch._wait_tcp_open("127.0.0.1", switch.grpc_port, 0.1))
        self.assertLess(time.monotonic() - started, 0.6)


if __name__ == "__main__":
    unittest.main()
