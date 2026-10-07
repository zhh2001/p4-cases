"""Check ECMP packet evidence and helper failures without live switches."""

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


packets = importlib.import_module("09_ecmp_hash.packets")
topology = importlib.import_module("09_ecmp_hash.topology")
probe = importlib.import_module("09_ecmp_hash.probe")
PREFIX = bytes((198, 18, 19))


class ECMPPacketTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)

    def test_crc_matches_standard_arc_vector_and_empty_input(self):
        self.assertEqual(packets.crc16(b"123456789"), 0xBB3D)
        self.assertEqual(packets.crc16(b""), 0)

    def test_probes_include_unique_identities_and_both_ecmp_protocols(self):
        self.assertEqual(len(self.probes), 243)
        self.assertEqual(sum(item["allowed"] for item in self.probes), 223)
        self.assertEqual(len({packets.identity(p["frame"]) for p in self.probes}), 243)
        for protocol in (17, 6):
            flows = [
                p for p in self.probes if p["name"].startswith(f"ecmp-{protocol}-")
            ]
            self.assertEqual(len(flows), 60)
            self.assertEqual({p["receiver"] for p in flows}, {"h2", "h3"})
            for flow in range(20):
                repeats = [
                    p for p in flows if p["name"].startswith(f"ecmp-{protocol}-{flow}-")
                ]
                self.assertEqual(len(repeats), 3)
                self.assertEqual(
                    len({packets.hash_input(p["frame"]) for p in repeats}), 1
                )
                self.assertEqual(len({p["receiver"] for p in repeats}), 1)
                self.assertEqual({p["sender"] for p in repeats}, {"h1", "h2", "h3"})

    def test_each_tuple_field_is_exercised_for_tcp_and_udp(self):
        for protocol in (17, 6):
            for field in ("source", "destination", "sport", "dport"):
                items = [
                    p
                    for p in self.probes
                    if p["name"].startswith(f"tuple-{protocol}-{field}-")
                ]
                self.assertEqual(len(items), 8)
                self.assertEqual(
                    len({packets.hash_input(p["frame"]) for p in items}), 8
                )
                self.assertEqual({p["receiver"] for p in items}, {"h2", "h3"})

    def test_transport_and_ipv4_checksums_cover_options_and_payload(self):
        for item in self.probes:
            if not item["allowed"]:
                continue
            frame = item["frame"]
            end = 14 + (frame[14] & 15) * 4
            self.assertEqual(packets.checksum(frame[14:end]), 0, item["name"])
            if frame[23] not in (6, 17) or int.from_bytes(frame[20:22], "big") & 0x3FFF:
                continue
            total = int.from_bytes(frame[16:18], "big")
            transport = frame[end : 14 + total]
            if item["name"] == "udp-no-checksum":
                self.assertEqual(transport[6:8], b"\0\0")
                continue
            pseudo = (
                frame[26:34] + b"\0" + frame[23:24] + len(transport).to_bytes(2, "big")
            )
            self.assertEqual(packets.checksum(pseudo + transport), 0, item["name"])

    def test_all_fragment_pieces_use_zero_ports_and_keep_one_path(self):
        for protocol in (17, 6):
            for destination in ("10.0.0.2", "10.0.0.100"):
                pieces = [
                    p
                    for p in self.probes
                    if p["name"].startswith(f"fragment-{protocol}-{destination}-")
                ]
                self.assertEqual(len(pieces), 3)
                self.assertEqual(len({p["frame"][18:20] for p in pieces}), 1)
                self.assertEqual(len({p["receiver"] for p in pieces}), 1)
                self.assertEqual(
                    len({packets.hash_input(p["frame"]) for p in pieces}), 1
                )
                self.assertTrue(
                    all(packets.hash_input(p["frame"])[-4:] == bytes(4) for p in pieces)
                )
                reassembled = b"".join(p["frame"][38:54] for p in pieces)
                pseudo = pieces[0]["frame"][26:34] + bytes((0, protocol)) + b"\0\x30"
                self.assertEqual(len(reassembled), 48)
                self.assertEqual(packets.checksum(pseudo + reassembled), 0)

    def test_unknown_protocol_payload_and_options_do_not_change_hash(self):
        for protocol in (1, 253):
            items = [
                p for p in self.probes if p["name"].startswith(f"opaque-{protocol}-")
            ]
            self.assertEqual(len({packets.hash_input(p["frame"]) for p in items}), 1)
            self.assertEqual(len({p["receiver"] for p in items}), 1)
            self.assertTrue(
                all(packets.hash_input(p["frame"])[-4:] == bytes(4) for p in items)
            )

    def test_direct_routes_take_precedence_over_ecmp(self):
        direct = [p for p in self.probes if p["name"].startswith("direct-")]
        self.assertEqual(len(direct), 12)
        for item in direct:
            self.assertEqual(item["receiver"], "h" + str(item["frame"][33]))

    def test_expected_frames_preserve_transport_options_and_padding(self):
        for item in self.probes:
            if not item["allowed"]:
                continue
            sent = item["frame"]
            result = packets.expected_frame(sent)
            end = 14 + (sent[14] & 15) * 4
            self.assertEqual(len(result), len(sent))
            self.assertEqual(result[:6], packets.HOST_MACS[int(item["receiver"][1:])])
            self.assertEqual(result[6:12], sent[:6])
            self.assertEqual(result[22], sent[22] - 1)
            self.assertEqual(packets.checksum(result[14:end]), 0)
            self.assertEqual(result[34:], sent[34:])

    def test_packet_inputs_and_flow_count_are_validated(self):
        for prefix, flows in ((b"", 20), (PREFIX, 1), (PREFIX, 101), (PREFIX, True)):
            with self.assertRaises(ValueError):
                packets.make_probes(prefix, flows)
        for kwargs in ({"options": b"x"}, {"tcp_options": b"x"}, {"payload_size": -1}):
            with self.assertRaises(ValueError):
                packets.make_frame(PREFIX + b"\x01", "10.0.0.2", 1, 1, **kwargs)


class ECMPEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)
        self.captured = {name: [] for name in ("h1", "h2", "h3")}
        for item in self.probes:
            if item["allowed"]:
                self.captured[item["receiver"]].append(
                    packets.expected_frame(item["frame"])
                )
        quiet = patch("sys.stdout", new=io.StringIO())
        quiet.start()
        self.addCleanup(quiet.stop)

    def test_complete_out_of_order_evidence_is_accepted(self):
        topology.check_delivery(
            self.probes, {name: frames[::-1] for name, frames in self.captured.items()}
        )

    def test_missing_duplicate_and_extra_packets_are_rejected(self):
        for operation in ("missing", "duplicate", "unknown"):
            captures = copy.deepcopy(self.captured)
            if operation == "missing":
                captures["h2"].pop()
            elif operation == "duplicate":
                captures["h2"].append(captures["h2"][0])
            else:
                frame = bytearray(captures["h2"][0])
                frame[18:20] = b"\xff\xff"
                captures["h2"].append(bytes(frame))
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captures)

    def test_wrong_host_and_split_flow_are_rejected(self):
        item = next(p for p in self.probes if p["name"] == "ecmp-17-0-1")
        captures = copy.deepcopy(self.captured)
        frame = packets.expected_frame(item["frame"])
        captures[item["receiver"]].remove(frame)
        other = "h3" if item["receiver"] == "h2" else "h2"
        captures[other].append(packets.expected_frame(item["frame"], other))
        with self.assertRaisesRegex(RuntimeError, "wrong ECMP or direct host"):
            topology.check_delivery(self.probes, captures)

    def test_mac_ttl_checksum_options_and_payload_changes_are_rejected(self):
        item = next(p for p in self.probes if p["name"] == "ecmp-6-0-2")
        original = packets.expected_frame(item["frame"])
        for offset in (0, 6, 22, 24, 34, 80, len(original) - 1):
            captures = copy.deepcopy(self.captured)
            index = captures[item["receiver"]].index(original)
            changed = bytearray(original)
            changed[offset] ^= 1
            captures[item["receiver"]][index] = bytes(changed)
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captures)

    def test_delivery_of_any_drop_vector_is_rejected(self):
        for item in self.probes:
            if item["allowed"]:
                continue
            captures = copy.deepcopy(self.captured)
            captures["h2"].append(item["frame"])
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captures)

    def test_missing_hosts_invalid_frames_and_duplicate_probe_ids_are_rejected(self):
        for captures in (
            {},
            {"h1": [], "h2": []},
            {**self.captured, "h1": None},
            {**self.captured, "h1": [False]},
            {**self.captured, "h1": [b"short"]},
        ):
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captures)
        with self.assertRaises(RuntimeError):
            topology.check_delivery(self.probes + self.probes[:1], self.captured)


class ECMPProcessTests(unittest.TestCase):
    def simulated_run(self, sender_reply=None, controller_exit=False):
        items = packets.make_probes(PREFIX, 2)
        captured = {name: [] for name in ("h1", "h2", "h3")}
        for item in items:
            if item["allowed"]:
                captured[item["receiver"]].append(
                    packets.expected_frame(item["frame"]).hex()
                )
        children = []

        def launch(arguments, **_kwargs):
            child = Mock(returncode=0)
            child.poll.return_value = 0
            if "receive" in arguments:
                ready = Path(arguments[arguments.index("--ready") + 1])
                name = ready.name.split("-")[0]
                ready.write_text("ready\n")
                reply = {"frames": captured[name]}
            else:
                manifest = Path(arguments[arguments.index("--frames") + 1])
                reply = {"sent": len(json.loads(manifest.read_text()))}
                if sender_reply is not None:
                    reply = sender_reply
            child.communicate.return_value = (json.dumps(reply), "")
            children.append(child)
            return child

        controller, net = Mock(), Mock()
        controller.proc.poll.side_effect = [None, 1 if controller_exit else None]
        net.get.return_value.popen.side_effect = launch
        with patch.object(topology.packets, "make_probes", return_value=items), patch(
            "sys.stdout", new=io.StringIO()
        ):
            result = topology.run_test(net, controller)
        for child in children:
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()
        return result

    def test_complete_capture_and_sender_confirmations_pass(self):
        self.assertEqual(self.simulated_run(), 0)

    def test_sender_evidence_must_confirm_exact_integer_counts(self):
        for reply in ({}, {"sent": True}, {"sent": 0}, {"sent": "10"}):
            with self.subTest(reply=reply):
                self.assertEqual(self.simulated_run(sender_reply=reply), 1)

    def test_controller_exit_during_capture_rejects_valid_packet_evidence(self):
        self.assertEqual(self.simulated_run(controller_exit=True), 1)

    def test_errors_invalid_json_and_timeouts_are_reported(self):
        child = Mock(returncode=1)
        child.communicate.return_value = ('{"frames": []}', "failed")
        with self.assertRaises(RuntimeError):
            topology.read_probe(child)
        child.returncode = 0
        for output in ("", "[]", "null", "not JSON"):
            child.communicate.return_value = (output, "")
            with self.assertRaises(RuntimeError):
                topology.read_probe(child)
        child.communicate.side_effect = subprocess.TimeoutExpired("probe", 7)
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

    def test_capture_launch_failure_stops_an_existing_receiver(self):
        child, controller, net = Mock(), Mock(), Mock()
        child.poll.return_value = None
        controller.proc.poll.return_value = None
        net.get.return_value.popen.side_effect = [child, OSError("launch failed")]
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, controller), 1)
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

    def test_controller_exit_prevents_probe_start(self):
        controller, net = Mock(), Mock()
        controller.proc.poll.return_value = 1
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, controller), 1)
        net.get.assert_not_called()

    def test_receiver_exit_before_readiness_fails_the_case(self):
        controller, net, child = Mock(), Mock(), Mock()
        controller.proc.poll.return_value = None
        child.poll.return_value = 1
        net.get.return_value.popen.return_value = child
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, controller), 1)
        self.assertEqual(child.stdout.close.call_count, 3)

    def test_static_neighbour_configuration_checks_command_status(self):
        net = Mock()
        net.get.return_value.pexec.return_value = ("", "denied", 1)
        with self.assertRaises(RuntimeError):
            topology.populate_arp(net)
        net.get.return_value.pexec.return_value = ("", "", 0)
        net.get.return_value.pexec.reset_mock()
        topology.populate_arp(net)
        self.assertEqual(net.get.return_value.pexec.call_count, 6)

    def test_sender_rejects_invalid_manifests_and_partial_sends(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            path = Path(directory) / "frames.json"
            for values in ([], {}, [True], ["bad-hex"], ["00"]):
                path.write_text(json.dumps(values))
                with self.assertRaises(ValueError):
                    probe.send_frames("missing", str(path))
            factory.assert_not_called()
            frame = packets.make_probes(PREFIX)[0]["frame"]
            path.write_text(json.dumps([frame.hex()]))
            factory.return_value.__enter__.return_value.send.return_value = (
                len(frame) - 1
            )
            with self.assertRaises(RuntimeError):
                probe.send_frames("iface", str(path))

    def test_receiver_readiness_prefix_and_outgoing_filter(self):
        frame = packets.make_probes(PREFIX)[0]["frame"]
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            ready = Path(directory) / "ready"
            for prefix, seconds in (("00", 5), (PREFIX.hex(), 0)):
                with self.assertRaises(ValueError):
                    probe.receive_frames("iface", prefix, seconds, str(ready))
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
                probe.receive_frames("iface", PREFIX.hex(), 5, str(ready))
            self.assertEqual(json.loads(output.getvalue()), {"frames": [frame.hex()]})
            self.assertEqual(ready.read_text(), "ready\n")


if __name__ == "__main__":
    unittest.main()
