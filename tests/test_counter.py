"""Reject incomplete counter and forwarding evidence without a switch."""

import copy
import importlib
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


topology = importlib.import_module("08_counter.topology")
probe = importlib.import_module("08_counter.probe")
PREFIX = bytes.fromhex("02aabbcc")


class CounterEvidenceTests(unittest.TestCase):
    def setUp(self):
        quiet = patch("sys.stdout", new=io.StringIO())
        quiet.start()
        self.addCleanup(quiet.stop)
        self.frames = {1: topology.make_frames(PREFIX, 1)}
        self.before = {1: {"packets": 7, "bytes": 701}, 2: {"packets": 9, "bytes": 902}}
        self.after = copy.deepcopy(self.before)
        self.after[1]["packets"] += len(self.frames[1])
        self.after[1]["bytes"] += sum(map(len, self.frames[1]))

    def test_frames_have_multiple_lengths_and_unique_labels_in_both_directions(self):
        other = topology.make_frames(PREFIX, 2)
        self.assertEqual(len(self.frames[1]), 30)
        self.assertEqual(sum(map(len, self.frames[1])), 18890)
        self.assertEqual(
            {len(frame) for frame in self.frames[1]}, {60, 64, 128, 512, 1500, 1514}
        )
        self.assertEqual(len(set(self.frames[1] + other)), 60)
        self.assertEqual(
            {frame[:6] for frame in self.frames[1]}, {bytes.fromhex("000000000002")}
        )
        self.assertEqual(
            {frame[:6] for frame in other}, {bytes.fromhex("000000000001")}
        )

    def test_both_counters_use_deltas_from_nonzero_snapshots(self):
        topology.check_counters(self.before, self.after, self.frames)
        other = topology.make_frames(PREFIX, 2)
        after = copy.deepcopy(self.before)
        after[2]["packets"] += len(other)
        after[2]["bytes"] += sum(map(len, other))
        topology.check_counters(self.before, after, {2: other})

    def test_idle_requires_both_counters_to_remain_unchanged(self):
        topology.check_counters(self.before, self.before, {})
        for port in (1, 2):
            changed = copy.deepcopy(self.before)
            changed[port]["packets"] += 1
            with self.assertRaises(RuntimeError):
                topology.check_counters(self.before, changed, {})

    def test_packet_and_byte_under_or_overcounts_are_rejected(self):
        for field in ("packets", "bytes"):
            for delta in (-1, 1, 1000):
                with self.subTest(field=field, delta=delta):
                    changed = copy.deepcopy(self.after)
                    changed[1][field] += delta
                    with self.assertRaises(RuntimeError):
                        topology.check_counters(self.before, changed, self.frames)

    def test_activity_on_the_other_ingress_port_is_rejected(self):
        for field in ("packets", "bytes"):
            changed = copy.deepcopy(self.after)
            changed[2][field] += 1
            with self.assertRaises(RuntimeError):
                topology.check_counters(self.before, changed, self.frames)

    def test_missing_or_invalid_snapshot_fields_are_rejected(self):
        for invalid in (None, {}, {1: self.before[1]}, {1: None, 2: self.before[2]}):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                topology.check_counters(invalid, self.after, self.frames)
        for value in (True, -1, "7", None):
            changed = copy.deepcopy(self.before)
            changed[1]["packets"] = value
            with self.assertRaises(RuntimeError):
                topology.check_counters(changed, self.after, self.frames)

    def test_forwarding_checks_full_contents_and_all_hosts(self):
        topology.check_delivery(self.frames, {"h1": [], "h2": self.frames[1][::-1]})
        changed = self.frames[1][0][:-1] + bytes([self.frames[1][0][-1] ^ 1])
        for frames in (
            [],
            self.frames[1][:-1],
            self.frames[1] + self.frames[1][:1],
            [changed] + self.frames[1][1:],
        ):
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.frames, {"h1": [], "h2": frames})
        with self.assertRaises(RuntimeError):
            topology.check_delivery(
                self.frames, {"h1": self.frames[1][:1], "h2": self.frames[1]}
            )
        with self.assertRaises(RuntimeError):
            topology.check_delivery(self.frames, {"h2": self.frames[1]})

    def test_frame_labels_require_a_valid_port_and_prefix(self):
        for prefix, port in ((b"bad", 1), (PREFIX, 0), (PREFIX, 3)):
            with self.assertRaises(ValueError):
                topology.make_frames(prefix, port)


class CounterReplyTests(unittest.TestCase):
    def controller(self, lines):
        proc = Mock()
        proc.lines_for.return_value = iter(lines)
        return proc

    def test_complete_zero_samples_and_reversed_port_order_are_valid(self):
        proc = self.controller(
            ["port=2 packets=0 bytes=0", "port=1 packets=0 bytes=0", "dump-done"]
        )
        self.assertEqual(
            topology.dump_counters(proc),
            {1: {"packets": 0, "bytes": 0}, 2: {"packets": 0, "bytes": 0}},
        )
        proc.send.assert_called_once_with("dump")

    def test_missing_ports_errors_duplicates_and_malformed_samples_are_rejected(self):
        first = "port=1 packets=7 bytes=70"
        for lines in (
            ["dump-done"],
            [first, "dump-done"],
            [first, first, "dump-done"],
            ["ERR port 1: counter unavailable", "dump-done"],
            ["port=3 packets=7 bytes=70", "dump-done"],
            ["port=1 packets=-1 bytes=70", "dump-done"],
            ["port=1 packets=7", "dump-done"],
            ["port=1 packets=7 bytes=bad", "dump-done"],
        ):
            with self.subTest(lines=lines), self.assertRaises(RuntimeError):
                topology.dump_counters(self.controller(lines))


class CounterProcessTests(unittest.TestCase):
    def test_process_errors_and_invalid_json_cannot_be_empty_captures(self):
        child = Mock(returncode=1)
        child.communicate.return_value = ('{"frames": []}', "capture failed")
        with self.assertRaises(RuntimeError):
            topology.read_probe(child)
        child.returncode = 0
        for output in ("", "bad JSON", "[]", "null"):
            child.communicate.return_value = (output, "")
            with self.assertRaises(RuntimeError):
                topology.read_probe(child)
        child.communicate.side_effect = subprocess.TimeoutExpired("probe", 4)
        with self.assertRaises(subprocess.TimeoutExpired):
            topology.read_probe(child)

    def test_invalid_capture_replies_are_rejected(self):
        for reply in (
            {},
            {"frames": None},
            {"frames": [True]},
            {"frames": ["not-hex"]},
        ):
            with self.assertRaises(RuntimeError):
                topology.frame_list(reply)

    def test_stuck_process_is_killed_reaped_and_closed(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("probe", 1), 0]
        topology.stop_probe(child)
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_failed_capture_launch_fails_the_case(self):
        ctrl = Mock()
        ctrl.proc.poll.return_value = None
        net = Mock()
        net.get.return_value.popen.side_effect = OSError("capture launch failed")
        with patch.object(topology, "dump_counters", return_value={}), patch(
            "sys.stdout", new=io.StringIO()
        ):
            self.assertEqual(topology.run_test(net, ctrl), 1)

    def test_controller_exit_and_burst_errors_fail_the_case(self):
        ctrl = Mock()
        ctrl.proc.poll.return_value = 1
        with patch.object(topology, "run_burst") as burst, patch(
            "sys.stdout", new=io.StringIO()
        ):
            self.assertEqual(topology.run_test(Mock(), ctrl), 1)
            burst.assert_not_called()
        ctrl.proc.poll.return_value = None
        for error in (
            RuntimeError("counter read failed"),
            subprocess.TimeoutExpired("sender", 4),
        ):
            with patch.object(topology, "run_burst", side_effect=error), patch(
                "sys.stdout", new=io.StringIO()
            ):
                self.assertEqual(topology.run_test(Mock(), ctrl), 1)

    def test_host_configuration_failure_is_reported(self):
        net = Mock()
        net.get.return_value.intfList.return_value = [Mock(name="h1-eth0")]
        net.get.return_value.pexec.return_value = ("", "denied", 1)
        with self.assertRaises(RuntimeError):
            topology.configure_test_interfaces(net)

    def test_ipv6_configuration_only_changes_interfaces_owned_by_the_topology(self):
        nodes = {}
        for name, interfaces in (
            ("h1", ["h1-eth0"]),
            ("h2", ["h2-eth0"]),
            ("s1", ["lo", "s1-eth1", "s1-eth2"]),
        ):
            node = Mock()
            node.intfList.return_value = []
            for iface in interfaces:
                intf = Mock()
                intf.name = iface
                node.intfList.return_value.append(intf)
            node.pexec.return_value = ("", "", 0)
            nodes[name] = node
        net = Mock()
        net.get.side_effect = nodes.__getitem__
        topology.configure_test_interfaces(net)
        for name, node in nodes.items():
            expected = [
                f"net.ipv6.conf.{intf.name}.disable_ipv6=1"
                for intf in node.intfList.return_value
                if intf.name != "lo"
            ]
            node.pexec.assert_called_once_with(["sysctl", "-q", "-w", *expected])


class CounterProbeTests(unittest.TestCase):
    def test_invalid_manifests_are_rejected_before_opening_a_socket(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            path = Path(directory) / "frames.json"
            for values in ([], {}, [True], ["bad"], ["00"]):
                path.write_text(json.dumps(values))
                with self.assertRaises(ValueError):
                    probe.send_frames("absent", str(path))
            factory.assert_not_called()

    def test_partial_sends_do_not_report_success(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            frame = topology.make_frames(PREFIX, 1)[0]
            path = Path(directory) / "frames.json"
            path.write_text(json.dumps([frame.hex()]))
            factory.return_value.__enter__.return_value.send.return_value = (
                len(frame) - 1
            )
            with self.assertRaises(RuntimeError):
                probe.send_frames("absent", str(path))

    def test_capture_filters_outgoing_and_unlabelled_frames_and_signals_readiness(self):
        frame = topology.make_frames(PREFIX, 1)[0]
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            ready = Path(directory) / "ready"
            sock = factory.return_value.__enter__.return_value
            sock.recvfrom.side_effect = [
                (frame, ("iface", 0, socket.PACKET_OUTGOING)),
                (bytes(len(frame)), ("iface", 0, socket.PACKET_HOST)),
                (frame, ("iface", 0, socket.PACKET_HOST)),
                socket.timeout(),
            ]
            output = io.StringIO()
            with patch("sys.stdout", new=output):
                probe.receive_frames("iface", PREFIX.hex(), 2, str(ready))
            self.assertEqual(ready.read_text(), "ready\n")
            self.assertEqual(json.loads(output.getvalue()), {"frames": [frame.hex()]})


if __name__ == "__main__":
    unittest.main()
