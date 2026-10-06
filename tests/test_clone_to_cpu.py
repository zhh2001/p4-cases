"""Verify clone correlation and reject false success from background traffic."""

import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from common.runtime import Controller


CASE = Path(__file__).resolve().parents[1] / "13_clone_to_cpu"


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, CASE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


topology = load_module("clone_topology", "topology.py")
probe = load_module("clone_probe", "test.py")
SRC = "00:00:00:00:00:01"
DST = "00:00:00:00:00:02"
TOKEN = "correlation-test"


def frames(count=10):
    return [probe.make_frame(SRC, DST, TOKEN, sequence) for sequence in range(count)]


def cpu_copy(frame, port=1):
    return frame[:12] + b"\x10\x10" + struct.pack("!H", port) + frame[14:]


def packet_line(frame, port=1):
    return f"packet-in #1 ingress_port={port} payload={cpu_copy(frame, port).hex()}"


class CorrelationTests(unittest.TestCase):
    def controller(self, lines):
        controller = Mock()
        controller.lines_for.return_value = iter(lines)
        return controller

    def test_background_packets_do_not_count(self):
        background = probe.make_frame(SRC, DST, "background", 0)
        ctrl = self.controller([packet_line(background)] * 30)
        copies = topology.packet_ins(ctrl, TOKEN, seconds=0.1)
        self.assertEqual(copies, [])
        with self.assertRaisesRegex(RuntimeError, "CPU copies differ"):
            topology.check_copies(frames(), frames(), copies, 1)

    def test_matching_packets_remain_distinct_from_background(self):
        expected = frames()
        background = probe.make_frame(SRC, DST, "background", 0)
        ctrl = self.controller(
            [packet_line(background)] + [packet_line(frame) for frame in expected]
        )
        copies = topology.packet_ins(ctrl, TOKEN, seconds=0.1)
        self.assertEqual(len(copies), 10)
        topology.check_copies(expected, expected[::-1], copies[::-1], 1)

    def test_missing_duplicate_and_corrupted_clones_are_rejected(self):
        expected = frames()
        copies = [(1, cpu_copy(frame)) for frame in expected]
        corrupted = copies[:-1] + [(1, copies[-1][1][:-1] + b"x")]
        for actual in ([], copies[:-1], copies + copies[:1], corrupted):
            with self.subTest(actual=actual), self.assertRaises(RuntimeError):
                topology.check_copies(expected, expected, actual, 1)

    def test_original_forwarding_is_required(self):
        expected = frames()
        copies = [(1, cpu_copy(frame)) for frame in expected]
        for received in (
            [],
            expected[:-1],
            expected + expected[:1],
            [cpu_copy(frame) for frame in expected],
        ):
            with self.subTest(received=received), self.assertRaisesRegex(
                RuntimeError, "forwarded frames differ"
            ):
                topology.check_copies(expected, received, copies, 1)

    def test_reported_port_and_cpu_header_must_both_match(self):
        expected = frames()
        for copies in (
            [(2, cpu_copy(frame)) for frame in expected],
            [(1, cpu_copy(frame, 2)) for frame in expected],
            [
                (1, frame[:12] + b"\x08\x00" + cpu_copy(frame)[14:])
                for frame in expected
            ],
        ):
            with self.subTest(copies=copies), self.assertRaises(RuntimeError):
                topology.check_copies(expected, expected, copies, 1)

    def test_truncated_controller_logs_cannot_prove_clone_delivery(self):
        ctrl = self.controller(
            [
                f"packet-in #1 ingress_port=1 payload={cpu_copy(frame)[:24].hex()}"
                for frame in frames()
            ]
        )
        copies = topology.packet_ins(ctrl, TOKEN, seconds=0.1)
        with self.assertRaises(RuntimeError):
            topology.check_copies(frames(), frames(), copies, 1)

    def test_malformed_packet_logs_are_rejected(self):
        for line in (
            "packet-in #1 ingress_port=1 payload=oops",
            "packet-in #1 ingress_port=1 payload=123",
        ):
            with self.subTest(line=line), self.assertRaises((RuntimeError, ValueError)):
                topology.packet_ins(self.controller([line]), TOKEN, seconds=0.1)

    def test_observation_window_ends_when_controller_is_silent(self):
        with patch("common.runtime.info"):
            ctrl = Controller([sys.executable, "-c", "import time; time.sleep(60)"])
            try:
                started = time.monotonic()
                self.assertEqual(topology.packet_ins(ctrl, TOKEN, seconds=0.1), [])
                self.assertLess(time.monotonic() - started, 0.6)
            finally:
                ctrl.close()


class ProbeTests(unittest.TestCase):
    def test_sender_confirmations_require_unique_frames_and_headers(self):
        expected = frames()
        valid = {"sent": 10, "frames": [frame.hex() for frame in expected]}
        self.assertEqual(topology.check_sent(valid, SRC, DST, TOKEN, 10), expected)
        for reply in (
            {**valid, "sent": 0},
            {**valid, "frames": valid["frames"][:-1]},
            {**valid, "frames": [valid["frames"][0]] * 10},
            {
                **valid,
                "frames": [
                    probe.make_frame(DST, SRC, TOKEN, n).hex() for n in range(10)
                ],
            },
            {
                **valid,
                "frames": [
                    probe.make_frame(SRC, DST, "other", n).hex() for n in range(10)
                ],
            },
        ):
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                topology.check_sent(reply, SRC, DST, TOKEN, 10)

    def test_failed_sender_cannot_return_successful_counts(self):
        proc = Mock(returncode=1)
        proc.communicate.return_value = ('{"sent": 10}', "SyntaxError")
        with self.assertRaisesRegex(RuntimeError, "packet probe failed"):
            topology.read_probe(proc)

    def test_missing_or_malformed_probe_replies_are_rejected(self):
        for output in ("", "null", "[]", "not JSON"):
            proc = Mock(returncode=0)
            proc.communicate.return_value = (output, "")
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                topology.read_probe(proc)
        for reply in ({}, {"frames": None}, {"frames": [0]}, {"frames": ["xyz"]}):
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                topology.frame_list(reply)

    def test_probe_timeout_is_propagated(self):
        proc = Mock()
        proc.communicate.side_effect = subprocess.TimeoutExpired("probe", 5)
        with self.assertRaises(subprocess.TimeoutExpired):
            topology.read_probe(proc)

    def test_failed_probes_make_case_fail(self):
        for failure in (
            RuntimeError("clones absent"),
            OSError("capture failed"),
            subprocess.TimeoutExpired("sender", 5),
        ):
            with self.subTest(failure=failure):
                with patch.object(topology, "check_direction", side_effect=failure):
                    self.assertEqual(topology.run_test(Mock(), Mock()), 1)

    def test_probe_cleanup_reaps_process_after_term_timeout(self):
        proc = Mock()
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired("probe", 1), 0]
        topology.stop_probe(proc)
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()
        self.assertEqual(proc.wait.call_count, 2)
        proc.stdout.close.assert_called_once()
        proc.stderr.close.assert_called_once()

    def test_sender_does_not_accept_zero_count(self):
        with self.assertRaises(ValueError):
            probe.send_frames("missing", SRC, DST, TOKEN, 0)

    def test_frame_sequence_and_minimum_ethernet_length(self):
        frame = probe.make_frame(SRC, DST, "short", 42)
        self.assertEqual(
            frame[:14],
            bytes.fromhex(DST.replace(":", "") + SRC.replace(":", "")) + b"\x88\xb5",
        )
        offset = 14 + len(probe.PREFIX) + len("short:")
        self.assertEqual(struct.unpack("!I", frame[offset : offset + 4])[0], 42)
        self.assertGreaterEqual(len(frame), 60)
        self.assertEqual(len(set(frames())), 10)


if __name__ == "__main__":
    unittest.main()
