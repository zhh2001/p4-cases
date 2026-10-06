"""Validate meter test evidence and process failures without a switch."""

import importlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


topology = importlib.import_module("07_meter.topology")
spec = importlib.util.spec_from_file_location(
    "meter_probe", Path(topology.HERE) / "test.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.frames = topology.make_frames(topology.METERED_MAC, bytes(8), 1, 30)
        self.sent = {"sent": 30, "started": 100.0, "finished": 100.001}

    def capture(self, frames, at=100.002):
        return {"frames": [{"frame": frame.hex(), "at": at} for frame in frames]}

    def test_burst_frames_have_distinct_sequences_and_multiple_sizes(self):
        self.assertEqual(len(set(self.frames)), 30)
        self.assertEqual({len(frame) for frame in self.frames}, {60, 80, 100, 120})
        other = topology.make_frames(topology.METERED_MAC, bytes(8), 2, 30)
        self.assertFalse(set(self.frames).intersection(other))
        self.assertTrue(
            all(frame[6:12] == bytes.fromhex("aaaaaaaaaaaa") for frame in self.frames)
        )

    def test_complete_allowed_delivery_is_independent_of_order(self):
        topology.check_burst(
            self.frames, self.sent, self.capture(self.frames[::-1]), False
        )

    def test_limited_burst_accepts_the_committed_tokens_and_small_refill(self):
        for count in (5, 6):
            topology.check_burst(
                self.frames, self.sent, self.capture(self.frames[:count]), True
            )

    def test_meter_bypass_and_excess_green_delivery_are_rejected(self):
        for count in (7, 30):
            with self.subTest(count=count), self.assertRaisesRegex(
                RuntimeError, "meter delivered"
            ):
                topology.check_burst(
                    self.frames, self.sent, self.capture(self.frames[:count]), True
                )

    def test_elapsed_time_limits_refill_without_accepting_a_slow_burst(self):
        topology.check_burst(
            self.frames, self.sent, self.capture(self.frames[:8], 100.21), True
        )
        for frames in (self.frames, self.frames[:5]):
            with self.assertRaisesRegex(RuntimeError, "timing budget"):
                topology.check_burst(
                    self.frames,
                    self.sent,
                    self.capture(frames, 100.6),
                    len(frames) != 30,
                )

    def test_empty_capture_and_fixed_source_denial_cannot_pass(self):
        for limited in (False, True):
            with self.subTest(limited=limited), self.assertRaises(RuntimeError):
                topology.check_burst(self.frames, self.sent, self.capture([]), limited)
        with self.assertRaisesRegex(RuntimeError, "initial committed burst"):
            topology.check_burst(
                self.frames, self.sent, self.capture(self.frames[1:6]), True
            )

    def test_loss_duplicates_and_changed_content_cannot_pass(self):
        changed = self.frames[0][:-1] + bytes([self.frames[0][-1] ^ 1])
        for frames in (
            self.frames[:-1],
            self.frames + self.frames[:1],
            [changed] + self.frames[1:],
        ):
            with self.subTest(frames=len(frames)), self.assertRaises(RuntimeError):
                topology.check_burst(
                    self.frames, self.sent, self.capture(frames), False
                )
        with self.assertRaises(RuntimeError):
            topology.check_burst(
                self.frames,
                self.sent,
                self.capture(self.frames[:5] + self.frames[:1]),
                True,
            )

    def test_recovery_requires_all_committed_burst_frames(self):
        frames = self.frames[:5]
        sent = {**self.sent, "sent": 5}
        topology.check_burst(frames, sent, self.capture(frames), False)
        with self.assertRaises(RuntimeError):
            topology.check_burst(frames, sent, self.capture(frames[:4]), False)

    def test_sender_count_must_be_an_exact_integer(self):
        for count in (None, 0, 29, True, "30"):
            with self.subTest(count=count), self.assertRaises(RuntimeError):
                topology.check_burst(
                    self.frames,
                    {**self.sent, "sent": count},
                    self.capture(self.frames),
                    False,
                )

    def test_invalid_timestamps_cannot_change_the_meter_budget(self):
        for value in (None, True, -1, "100", float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                topology.check_burst(
                    self.frames,
                    {**self.sent, "finished": value},
                    self.capture(self.frames),
                    False,
                )
        with self.assertRaisesRegex(RuntimeError, "out of order"):
            topology.check_burst(
                self.frames,
                {**self.sent, "finished": 99},
                self.capture(self.frames),
                False,
            )
        with self.assertRaisesRegex(RuntimeError, "before this burst"):
            topology.check_burst(
                self.frames, self.sent, self.capture(self.frames, 99), False
            )

    def test_invalid_capture_replies_are_rejected(self):
        for capture in (
            {},
            {"frames": None},
            {"frames": [None]},
            {"frames": [{"frame": "zz", "at": 100.1}]},
        ):
            with self.subTest(capture=capture), self.assertRaises(RuntimeError):
                topology.check_burst(self.frames, self.sent, capture, False)


class ProcessTests(unittest.TestCase):
    def test_nonzero_probe_exit_cannot_be_zero_delivery(self):
        child = Mock(returncode=1)
        child.communicate.return_value = ('{"frames": []}', "capture failure")
        with self.assertRaisesRegex(RuntimeError, "packet probe failed"):
            topology.read_probe(child)

    def test_invalid_json_and_timeouts_are_reported(self):
        for output in ("", "[]", "null", "bad JSON"):
            child = Mock(returncode=0)
            child.communicate.return_value = (output, "")
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                topology.read_probe(child)
        child.communicate.side_effect = subprocess.TimeoutExpired("probe", 4)
        with self.assertRaises(subprocess.TimeoutExpired):
            topology.read_probe(child)

    def test_stuck_process_is_killed_and_reaped(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("probe", 1), 0]
        topology.stop_probe(child)
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_empty_manifest_and_invalid_source_are_rejected_before_socket_use(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frames.json"
            path.write_text("[]")
            with self.assertRaises(ValueError):
                probe.send_frames("missing", str(path))
        with self.assertRaises(ValueError):
            probe.receive_frames("missing", "aa", 1.5, "absent")

    def test_process_launch_failure_makes_the_case_fail(self):
        net = Mock()
        net.get.return_value.popen.side_effect = OSError("capture launch failed")
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net), 1)

    def test_controller_exit_cannot_pass(self):
        ctrl = Mock()
        ctrl.proc.poll.return_value = 1
        with patch("sys.stdout", new=io.StringIO()), patch.object(
            topology, "run_burst"
        ) as burst:
            self.assertEqual(topology.run_test(Mock(), ctrl), 1)
            burst.assert_not_called()


if __name__ == "__main__":
    unittest.main()
