"""Check INT wire layouts, complete routing evidence and probe failures."""

import copy
import importlib
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


packets = importlib.import_module("06_int.packets")
topology = importlib.import_module("06_int.topology")
sender = importlib.import_module("06_int.test_send")
receiver = importlib.import_module("06_int.test_receive")
PREFIX = bytes((198, 18, 1))


def routed(item):
    sent = item["frame"]
    original = packets.parse_frame(sent)
    options = original["options"]
    if original["traces"] is not None:
        traces = list(original["traces"])
        length = original["total"]
        for swid, port in item["path"]:
            if len(traces) < 9 and length <= 65531:
                traces.insert(0, (swid, 7, port))
                length += 4
        options = packets.int_option(traces, bool(options[0] & 128))
    header = bytearray(sent[14:34] + options)
    header[0] = 0x45 + len(options) // 4
    header[2:4] = struct.pack("!H", len(header) + len(original["payload"]))
    header[8] -= len(item["path"])
    path = item["path"]
    source_mac = packets.NEXT_HOPS[path[-2]] if len(path) > 1 else sent[:6]
    frame = (
        packets.NEXT_HOPS[path[-1]]
        + source_mac
        + b"\x08\x00"
        + bytes(header)
        + original["payload"]
    )
    return packets.recalculate_checksum(frame)


class INTWireTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)
        self.named = {item["name"]: item for item in self.probes}

    def test_trace_and_option_have_known_wire_bytes(self):
        self.assertEqual(packets.int_option([(1, 0, 2)]).hex(), "1f08000100080002")
        self.assertEqual(packets.trace_bytes((8191, 8191, 63)), b"\xff" * 4)
        self.assertEqual(packets.int_option([]), b"\x1f\x04\0\0")
        self.assertEqual(packets.int_option([], copied=True), b"\x9f\x04\0\0")

    def test_option_lengths_cover_every_supported_count(self):
        for count in range(10):
            item = self.named[f"existing-{count}"]
            data = packets.parse_frame(item["frame"])
            self.assertEqual(len(data["traces"]), count)
            self.assertEqual(data["ihl"], 24 + 4 * count)
            self.assertEqual(data["options"][1], 4 + 4 * count)
            packets.check_forwarded(item["frame"], routed(item), item["path"])

    def test_full_stack_preserves_every_original_record(self):
        item = self.named["existing-9"]
        before = packets.parse_frame(item["frame"])
        after = packets.parse_frame(routed(item))
        self.assertEqual(before["options"], after["options"])
        self.assertEqual(after["ihl"], 60)
        self.assertEqual(after["total"], before["total"])
        self.assertEqual(after["ttl"], before["ttl"] - 3)

    def test_partial_capacity_only_records_the_first_hops(self):
        for count, expected in ((7, [(1, 3), (2, 2)]), (8, [(2, 2)])):
            data = packets.parse_frame(routed(self.named[f"existing-{count}"]))
            self.assertEqual(
                [(swid, port) for swid, _, port in data["traces"][: 9 - count]],
                expected,
            )

    def test_invalid_field_widths_and_option_sizes_are_rejected(self):
        for trace in ((-1, 0, 0), (8192, 0, 0), (0, 8192, 0), (0, 0, 64)):
            with self.assertRaises(ValueError):
                packets.trace_bytes(trace)
        with self.assertRaises(ValueError):
            packets.int_option([(1, 0, 1)] * 10)
        for options in (b"x", b"x" * 44):
            with self.assertRaises(ValueError):
                packets.make_frame(PREFIX + b"\x01", 1, 2, options)
        with self.assertRaises(ValueError):
            packets.make_probes(b"short")

    def test_known_checksum_and_odd_padding(self):
        self.assertEqual(packets.checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)
        self.assertEqual(packets.checksum(b"\x01"), 0xFEFF)

    def test_all_inputs_have_unique_labels_and_cover_all_directions(self):
        self.assertEqual(len(self.probes), 63)
        self.assertEqual(len({item["frame"][26:30] for item in self.probes}), 63)
        self.assertEqual(len(packets.PATHS), 12)
        for pair in packets.PATHS:
            for kind in ("plain", "int"):
                self.assertIn(f"h{pair[0]}-h{pair[1]}-{kind}", self.named)

    def test_allowed_packets_have_valid_ip_and_udp_checksums(self):
        for item in self.probes:
            if not item["allowed"]:
                continue
            frame = item["frame"]
            data = packets.parse_frame(frame)
            if frame[23] == 17:
                pseudo = frame[26:34] + struct.pack("!BBH", 0, 17, len(data["payload"]))
                self.assertEqual(packets.checksum(pseudo + data["payload"]), 0)
            packets.check_forwarded(frame, routed(item), item["path"])
        self.assertEqual(
            packets.parse_frame(routed(self.named["maximum-output-mtu"]))["total"], 1500
        )

    def test_malformed_lengths_and_checksums_are_rejected(self):
        for name in (
            "bad-version",
            "short-ihl",
            "short-total",
            "long-total",
            "truncated-ip",
            "truncated-options",
            "bad-option-length",
            "bad-int-count",
            "too-many-traces",
            "huge-int-count",
            "bad-ip-checksum",
            "bad-int-checksum",
        ):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                packets.parse_frame(self.named[name]["frame"])

    def test_order_ports_existing_traces_and_payload_must_remain_exact(self):
        item = self.named["existing-7"]
        correct = routed(item)
        mutations = [
            correct[:6] + bytes(6) + correct[12:],
            correct[:-1] + bytes((correct[-1] ^ 1,)),
            packets.recalculate_checksum(
                correct[:22] + bytes((correct[22] + 1,)) + correct[23:]
            ),
            packets.recalculate_checksum(
                correct[:38] + packets.trace_bytes((3, 7, 3)) + correct[42:]
            ),
            packets.recalculate_checksum(
                correct[:42] + packets.trace_bytes((2, 7, 1)) + correct[46:]
            ),
            packets.recalculate_checksum(
                correct[:46] + packets.trace_bytes((999, 1, 2)) + correct[50:]
            ),
        ]
        for frame in mutations:
            with self.assertRaises(RuntimeError):
                packets.check_forwarded(item["frame"], frame, item["path"])

    def test_ipv4_length_headroom_limits_trace_count(self):
        for total, extra in ((65527, 2), (65531, 1), (65532, 0), (65535, 0)):
            frame = packets.make_frame(
                PREFIX + b"\x01", 2, 4, packets.int_option([]), payload_size=total - 32
            )
            self.assertEqual(
                packets.expected_trace_count(frame, packets.PATHS[2, 4]), extra
            )


class INTDeliveryTests(unittest.TestCase):
    def setUp(self):
        quiet = patch("sys.stdout", new=io.StringIO())
        quiet.start()
        self.addCleanup(quiet.stop)
        self.probes = packets.make_probes(PREFIX)
        self.captured = {name: [] for name in ("h1", "h2", "h3", "h4")}
        for item in self.probes:
            if item["allowed"]:
                self.captured[item["receiver"]].append(routed(item))

    def test_complete_delivery_is_independent_of_capture_order(self):
        topology.check_delivery(
            self.probes, {name: frames[::-1] for name, frames in self.captured.items()}
        )

    def test_missing_duplicate_and_wrong_host_delivery_fail(self):
        for mode in ("missing", "duplicate", "wrong-host"):
            received = copy.deepcopy(self.captured)
            frame = received["h2"].pop()
            if mode == "duplicate":
                received["h2"].extend([frame, frame])
            elif mode == "wrong-host":
                received["h1"].append(frame)
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)

    def test_dropped_packets_and_unknown_frames_cannot_be_received(self):
        for name in (
            "expired-ttl-0",
            "bad-int-count",
            "too-many-traces",
            "bad-int-checksum",
        ):
            received = copy.deepcopy(self.captured)
            received["h4"].append(
                next(item["frame"] for item in self.probes if item["name"] == name)
            )
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)
        received = copy.deepcopy(self.captured)
        received["h4"].append(bytes(34))
        with self.assertRaises(RuntimeError):
            topology.check_delivery(self.probes, received)

    def test_empty_incomplete_or_invalid_captures_fail(self):
        for received in (
            {},
            {name: [] for name in self.captured},
            {**self.captured, "h1": None},
        ):
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)


class INTProcessTests(unittest.TestCase):
    def test_probe_error_json_and_timeout_are_reported(self):
        child = Mock(returncode=1)
        child.communicate.return_value = ('{"frames": []}', "failed")
        with self.assertRaises(RuntimeError):
            topology.read_probe(child)
        child.returncode = 0
        for output in ("", "[]", "null", "not JSON"):
            child.communicate.return_value = (output, "")
            with self.assertRaises(RuntimeError):
                topology.read_probe(child)
        child.communicate.side_effect = subprocess.TimeoutExpired("probe", 6)
        with self.assertRaises(subprocess.TimeoutExpired):
            topology.read_probe(child)
        for reply in (
            {},
            {"frames": None},
            {"frames": [False]},
            {"frames": ["bad-hex"]},
        ):
            with self.assertRaises(RuntimeError):
                topology.frame_list(reply)

    def test_capture_launch_failure_stops_an_already_started_receiver(self):
        child, controller = Mock(), Mock()
        child.poll.return_value = None
        controller.proc.poll.return_value = None
        net = Mock()
        net.get.return_value.popen.side_effect = [
            child,
            OSError("capture launch failed"),
        ]
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, [controller]), 1)
        child.terminate.assert_called_once()
        child.wait.assert_called_once()
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_stuck_capture_is_killed_and_reaped(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("probe", 1), 0]
        topology.stop_probe(child)
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)

    def test_controller_exit_fails_before_starting_probes(self):
        controller, net = Mock(), Mock()
        controller.proc.poll.return_value = 1
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, [controller]), 1)
        net.get.assert_not_called()

    def test_host_routes_and_neighbours_are_checked(self):
        net = Mock()
        net.get.return_value.pexec.return_value = ("", "denied", 1)
        with self.assertRaises(RuntimeError):
            topology.populate_arp(net)
        net.get.return_value.defaultIntf.return_value.name = "host-eth0"
        net.get.return_value.pexec.return_value = ("", "", 0)
        net.get.return_value.pexec.reset_mock()
        topology.populate_arp(net)
        self.assertEqual(net.get.return_value.pexec.call_count, 16)
        self.assertEqual(
            net.get.return_value.pexec.call_args_list[0].args[0],
            ["ip", "route", "replace", "default", "dev", "host-eth0"],
        )

    def test_sender_rejects_invalid_manifests_and_partial_writes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            sender.socket, "socket"
        ) as factory:
            path = Path(directory) / "frames.json"
            for values in ([], {}, [True], ["bad-hex"], ["00"]):
                path.write_text(json.dumps(values))
                with self.assertRaises(ValueError):
                    sender.send_frames("missing", str(path))
            factory.assert_not_called()
            frame = packets.make_probes(PREFIX)[0]["frame"]
            path.write_text(json.dumps([frame.hex()]))
            factory.return_value.__enter__.return_value.send.return_value = (
                len(frame) - 1
            )
            with self.assertRaises(RuntimeError):
                sender.send_frames("iface", str(path))

    def test_receiver_prefix_readiness_and_outgoing_filter(self):
        frame = packets.make_probes(PREFIX)[0]["frame"]
        with tempfile.TemporaryDirectory() as directory, patch.object(
            receiver.socket, "socket"
        ) as factory:
            ready = Path(directory) / "ready"
            with self.assertRaises(ValueError):
                receiver.receive_frames("iface", "00", 4, str(ready))
            factory.assert_not_called()
            sock = factory.return_value.__enter__.return_value
            sock.recvfrom.side_effect = [
                (frame, ("iface", 0, socket.PACKET_OUTGOING)),
                (bytes(len(frame)), ("iface", 0, socket.PACKET_HOST)),
                (frame, ("iface", 0, socket.PACKET_HOST)),
                socket.timeout(),
            ]
            self.assertEqual(
                receiver.receive_frames("iface", PREFIX.hex(), 4, str(ready)), [frame]
            )
            self.assertEqual(ready.read_text(), "ready\n")


if __name__ == "__main__":
    unittest.main()
