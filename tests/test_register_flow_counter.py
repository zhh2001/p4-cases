"""Reject incomplete register snapshots, forwarding evidence and probe errors."""

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


packets = importlib.import_module("12_register_flow_counter.packets")
topology = importlib.import_module("12_register_flow_counter.topology")
probe = importlib.import_module("12_register_flow_counter.probe")
PREFIX = bytes.fromhex("02aabbcc")


def array_output(values, separator=", ", brackets=False):
    body = separator.join(map(str, values))
    if brackets:
        body = "[" + body + "]"
    return "RuntimeCmd: MyIngress.flow_counter= " + body + "\nRuntimeCmd: "


class RegisterSnapshotTests(unittest.TestCase):
    def test_complete_array_formats_and_zero_values_are_valid(self):
        values = [0] * 1024
        values[0], values[1023] = 42, (1 << 32) - 1
        for separator, brackets in ((", ", False), (",", True), (" ", False)):
            self.assertEqual(
                topology.parse_register_dump(array_output(values, separator, brackets)),
                values,
            )
        self.assertEqual(
            topology.parse_register_dump(array_output([0] * 1024)), [0] * 1024
        )

    def test_indexed_dump_requires_all_slots_and_accepts_reversed_order(self):
        output = "\n".join(
            f"flow_counter[{slot}]= {slot}" for slot in reversed(range(1024))
        )
        self.assertEqual(topology.parse_register_dump(output), list(range(1024)))
        for invalid in (
            output.split("\n", 1)[1],
            output + "\nflow_counter[0]= 0",
            output + "\nflow_counter[1024]= 0",
            output + "\nflow_counter= 1",
        ):
            with self.assertRaises(RuntimeError):
                topology.parse_register_dump(invalid)

    def test_incomplete_malformed_and_error_replies_are_rejected(self):
        valid = array_output([0] * 1024)
        invalid = [
            "",
            "RuntimeCmd: ",
            array_output([0] * 1023),
            array_output([0] * 1025),
            valid + valid,
            valid + "\nflow_counter[-1]= 0",
            valid + "\nflow_counter[bad]= 0",
            valid + "\nError: read failed",
            valid.replace("MyIngress.flow_counter", "another.flow_counter"),
            valid.replace("0, 0", "0,,0", 1),
            valid.replace("0, 0", "0, nope", 1),
            valid.replace("0, 0", "0, -1", 1),
            valid.replace("0, 0", "0, 4294967296", 1),
            valid.replace("0, 0", "0, 1.5", 1),
            valid.replace("0, 0", "0, True", 1),
        ]
        for output in invalid:
            with self.subTest(output=output[:60]), self.assertRaises(RuntimeError):
                topology.parse_register_dump(output)

    def test_thrift_errors_and_timeouts_cannot_be_valid_samples(self):
        result = Mock(
            returncode=0,
            stdout=array_output([0] * 1024),
            stderr="register index omitted, reading entire array\n",
        )
        with patch.object(topology.subprocess, "run", return_value=result) as run:
            self.assertEqual(topology.thrift_register_dump(9090), [0] * 1024)
            self.assertEqual(
                run.call_args.kwargs["input"], "register_read MyIngress.flow_counter\n"
            )
            for code, output, error in (
                (1, result.stdout, ""),
                (0, "", "Error: failed"),
                (0, "Error: unknown register", ""),
            ):
                result.returncode, result.stdout, result.stderr = code, output, error
                with self.assertRaises(RuntimeError):
                    topology.thrift_register_dump(9090)
        with patch.object(
            topology.subprocess, "run", side_effect=subprocess.TimeoutExpired("cli", 6)
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                topology.thrift_register_dump(9090)
        for port in (0, 65536, True):
            with self.assertRaises(ValueError):
                topology.thrift_register_dump(port)

    def test_seed_requires_exact_readback_and_unchanged_other_slots(self):
        before = [17] * 1024
        after = before.copy()
        after[1023] = 42
        with patch.object(
            topology, "thrift_register_dump", return_value=before
        ), patch.object(topology, "thrift_command", return_value=array_output(after)):
            self.assertEqual(topology.seed_register(9090, 1023, 42), after)
        for invalid in (before, [42] * 1024):
            with patch.object(
                topology, "thrift_register_dump", return_value=before
            ), patch.object(
                topology, "thrift_command", return_value=array_output(invalid)
            ):
                with self.assertRaises(RuntimeError):
                    topology.seed_register(9090, 1023, 42)
        for slot, value in (
            (-1, 0),
            (1024, 0),
            (True, 0),
            (0, -1),
            (0, 1 << 32),
            (0, False),
        ):
            with self.assertRaises(ValueError):
                topology.seed_register(9090, slot, value)


class RegisterPacketTests(unittest.TestCase):
    def setUp(self):
        self.batches = dict(packets.make_batches(PREFIX))

    def test_crc_and_original_udp_flow_have_known_results(self):
        self.assertEqual(packets.crc16(b"123456789"), 0xBB3D)
        self.assertEqual(packets.hash_slot("10.0.0.1", "10.0.0.2", 1111, 2222), 986)

    def test_both_directions_options_and_boundary_slots_are_covered(self):
        items = [item for values in self.batches.values() for item in values]
        self.assertEqual(len(items), 216)
        self.assertEqual(sum(p["allowed"] for p in items), 192)
        self.assertEqual(sum(p["counted"] for p in items), 168)
        self.assertEqual(len({p["frame"][6:12] for p in items}), 216)
        self.assertEqual({p["sender"] for p in items}, {"h1", "h2"})
        self.assertTrue(all(not p["counted"] for p in items if not p["allowed"]))
        self.assertEqual(
            {packets.flow_slot(p["frame"]) for p in self.batches["collisions"]},
            {0, 1023},
        )
        self.assertEqual(
            {packets.flow_slot(p["frame"]) for p in self.batches["wraparound"]}, {0}
        )
        for sender, wanted in ((1, 986), (2, 906)):
            repeated = [
                p for p in items if p["name"].startswith(f"h{sender}-repeated-")
            ]
            self.assertEqual(
                {packets.flow_slot(p["frame"]) for p in repeated}, {wanted}
            )
            self.assertEqual({p["frame"][14] & 15 for p in repeated}, {5, 6, 15})

    def test_valid_ipv4_and_transport_headers_have_complete_checksums(self):
        for items in self.batches.values():
            for item in items:
                frame = item["frame"]
                if not item["allowed"] or frame[12:14] != b"\x08\x00":
                    continue
                start = 14 + (frame[14] & 15) * 4
                self.assertEqual(packets.checksum(frame[14:start]), 0, item["name"])
                if (
                    frame[23] not in (6, 17)
                    or int.from_bytes(frame[20:22], "big") & 0x3FFF
                ):
                    continue
                transport = frame[start : 14 + int.from_bytes(frame[16:18], "big")]
                if "zero-checksum" in item["name"]:
                    self.assertEqual(transport[6:8], bytes(2))
                    continue
                pseudo = (
                    frame[26:34]
                    + bytes((0, frame[23]))
                    + len(transport).to_bytes(2, "big")
                )
                self.assertEqual(packets.checksum(pseudo + transport), 0, item["name"])

    def test_fragment_groups_reassemble_and_are_never_counted(self):
        for sender in (1, 2):
            for protocol in (17, 6):
                pieces = [
                    p
                    for p in self.batches["excluded-and-malformed"]
                    if p["name"].startswith(f"h{sender}-fragment-{protocol}-")
                ]
                self.assertEqual(len(pieces), 3)
                self.assertTrue(all(p["allowed"] and not p["counted"] for p in pieces))
                self.assertEqual(len({p["frame"][18:20] for p in pieces}), 1)
                datagram = b"".join(p["frame"][38:54] for p in pieces)
                pseudo = pieces[0]["frame"][26:34] + bytes((0, protocol)) + b"\0\x30"
                self.assertEqual(packets.checksum(pseudo + datagram), 0)

    def test_collision_finder_validates_indices_and_finds_distinct_ports(self):
        for slot in (0, 1023):
            ports = packets.ports_for_slot("10.0.0.1", "10.0.0.2", slot)
            self.assertNotEqual(*ports)
            self.assertEqual(
                {
                    packets.hash_slot("10.0.0.1", "10.0.0.2", port, 2222)
                    for port in ports
                },
                {slot},
            )
        for slot in (-1, 1024, False):
            with self.assertRaises(ValueError):
                packets.ports_for_slot("10.0.0.1", "10.0.0.2", slot)
        with self.assertRaises(ValueError):
            packets.make_batches(b"short")


class RegisterEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.items = dict(packets.make_batches(PREFIX))["udp-flows"]
        self.before = [42 + slot for slot in range(1024)]
        self.after = self.before.copy()
        for item in self.items:
            self.after[packets.flow_slot(item["frame"])] += 1
        self.captured = {
            name: [p["frame"] for p in self.items if p["receiver"] == name]
            for name in ("h1", "h2")
        }

    def test_exact_deltas_from_nonzero_state_and_idle_samples_pass(self):
        topology.check_counts(self.before, self.after, self.items)
        topology.check_counts(self.before, self.before, [])
        topology.check_delivery(
            self.items, {name: values[::-1] for name, values in self.captured.items()}
        )

    def test_seeded_large_slot_cannot_replace_packet_increments(self):
        with self.assertRaises(RuntimeError):
            topology.check_counts(self.before, self.before, self.items)

    def test_missing_extra_wrong_slot_and_idle_activity_are_rejected(self):
        for slot, delta in ((986, -1), (986, 1), (1023, 1), (0, 1)):
            changed = self.after.copy()
            changed[slot] += delta
            with self.assertRaises(RuntimeError):
                topology.check_counts(self.before, changed, self.items)
        changed = self.before.copy()
        changed[1023] += 1
        with self.assertRaises(RuntimeError):
            topology.check_counts(self.before, changed, [])

    def test_collisions_sum_exactly_and_wraparound_uses_uint32(self):
        batches = dict(packets.make_batches(PREFIX))
        before, after = [0] * 1024, [0] * 1024
        after[0], after[1023] = 14, 18
        topology.check_counts(before, after, batches["collisions"])
        before[0], after[0], after[1023] = (1 << 32) - 2, 30, 0
        topology.check_counts(before, after, batches["wraparound"])
        after[0] = 31
        with self.assertRaises(RuntimeError):
            topology.check_counts(before, after, batches["wraparound"])

    def test_snapshot_shape_types_and_width_are_checked(self):
        for values in (
            None,
            {},
            [0] * 1023,
            [0] * 1025,
            [True] + [0] * 1023,
            [-1] + [0] * 1023,
            [1 << 32] + [0] * 1023,
        ):
            with self.assertRaises(RuntimeError):
                topology.check_counts(values, self.after, self.items)
            with self.assertRaises(RuntimeError):
                topology.check_counts(self.before, values, self.items)

    def test_missing_duplicate_modified_and_wrong_host_frames_are_rejected(self):
        for mutation in ("missing", "duplicate", "modified", "wrong-host"):
            captured = copy.deepcopy(self.captured)
            original = captured["h2"][0]
            if mutation == "missing":
                captured["h2"].pop(0)
            elif mutation == "duplicate":
                captured["h2"].append(original)
            elif mutation == "modified":
                captured["h2"][0] = original[:-1] + bytes((original[-1] ^ 1,))
            else:
                captured["h2"].pop(0)
                captured["h1"].append(original)
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.items, captured)
        for captured in ({}, {"h1": []}, {**self.captured, "h1": [False]}):
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.items, captured)

    def test_any_malformed_delivery_or_excluded_packet_increment_fails(self):
        items = dict(packets.make_batches(PREFIX))["excluded-and-malformed"]
        captured = {
            name: [p["frame"] for p in items if p["allowed"] and p["receiver"] == name]
            for name in ("h1", "h2")
        }
        topology.check_delivery(items, captured)
        topology.check_counts(self.before, self.before, items)
        for item in items:
            if not item["allowed"]:
                leaked = copy.deepcopy(captured)
                leaked[item["receiver"]].append(item["frame"])
                with self.assertRaises(RuntimeError):
                    topology.check_delivery(items, leaked)
        changed = self.before.copy()
        changed[986] += 1
        with self.assertRaises(RuntimeError):
            topology.check_counts(self.before, changed, items)


class RegisterProcessTests(unittest.TestCase):
    def test_probe_errors_bad_json_and_timeouts_are_reported(self):
        child = Mock(returncode=1)
        child.communicate.return_value = ('{"frames": []}', "failed")
        with self.assertRaises(RuntimeError):
            topology.read_probe(child)
        child.returncode = 0
        for output in ("", "[]", "null", "not JSON"):
            child.communicate.return_value = (output, "")
            with self.assertRaises(RuntimeError):
                topology.read_probe(child)
        child.communicate.side_effect = subprocess.TimeoutExpired("probe", 4)
        with self.assertRaises(subprocess.TimeoutExpired):
            topology.read_probe(child)
        for reply in (
            {},
            {"frames": None},
            {"frames": [True]},
            {"frames": ["bad-hex"]},
        ):
            with self.assertRaises(RuntimeError):
                topology.frame_list(reply)

    def test_capture_launch_failure_stops_started_receivers(self):
        net, ctrl, child = Mock(), Mock(), Mock()
        ctrl.proc.poll.return_value = None
        child.poll.return_value = None
        net.get.return_value.popen.side_effect = [child, OSError("launch failed")]
        with patch.object(topology, "thrift_register_dump", return_value=[0] * 1024):
            with self.assertRaises(OSError):
                topology.run_batch(net, ctrl, 9090, PREFIX, [])
        child.terminate.assert_called_once()
        child.wait.assert_called_once()
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_stuck_probe_is_killed_reaped_and_closed(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("probe", 1), 0]
        topology.stop_probe(child)
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)

    def test_controller_exit_and_thrift_failure_fail_the_test(self):
        net, ctrl = Mock(), Mock()
        ctrl.proc.poll.return_value = 1
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl, 9090), 1)
        net.get.assert_not_called()
        ctrl.proc.poll.return_value = None
        with patch.object(topology, "configure_test_interfaces"), patch.object(
            topology, "seed_register", side_effect=RuntimeError("write failed")
        ), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl, 9090), 1)

    def test_interface_configuration_is_checked_and_local_to_case_interfaces(self):
        net = Mock()
        nodes = {}
        for name in ("h1", "h2", "s1"):
            node = Mock()
            node.intfList.return_value = []
            for iface in ("lo", f"{name}-eth0"):
                intf = Mock()
                intf.name = iface
                node.intfList.return_value.append(intf)
            node.pexec.return_value = ("", "", 0)
            nodes[name] = node
        net.get.side_effect = nodes.__getitem__
        topology.configure_test_interfaces(net)
        for name, node in nodes.items():
            node.pexec.assert_called_once_with(
                ["sysctl", "-q", "-w", f"net.ipv6.conf.{name}-eth0.disable_ipv6=1"]
            )
        nodes["h1"].pexec.return_value = ("", "denied", 1)
        with self.assertRaises(RuntimeError):
            topology.configure_test_interfaces(net)

    def test_sender_rejects_bad_manifests_and_partial_writes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            path = Path(directory) / "frames.json"
            for values in ([], {}, [True], ["bad-hex"], ["00"]):
                path.write_text(json.dumps(values))
                with self.assertRaises(ValueError):
                    probe.send_frames("iface", str(path))
            factory.assert_not_called()
            frame = packets.make_frame(PREFIX, 1)
            path.write_text(json.dumps([frame.hex()]))
            factory.return_value.__enter__.return_value.send.return_value = (
                len(frame) - 1
            )
            with self.assertRaises(RuntimeError):
                probe.send_frames("iface", str(path))

    def test_receiver_marks_readiness_and_ignores_outgoing_frames(self):
        frame = packets.make_frame(PREFIX, 1)
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            ready = Path(directory) / "ready"
            with self.assertRaises(ValueError):
                probe.receive_frames("iface", "00", 2, str(ready))
            factory.assert_not_called()
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
            self.assertEqual(json.loads(output.getvalue()), {"frames": [frame.hex()]})
            self.assertEqual(ready.read_text(), "ready\n")


if __name__ == "__main__":
    unittest.main()
