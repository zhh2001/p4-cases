"""Check IPv6 routing evidence and failures without starting a switch."""

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


packets = importlib.import_module("14_ipv6_lpm.packets")
topology = importlib.import_module("14_ipv6_lpm.topology")
probe = importlib.import_module("14_ipv6_lpm.probe")
PREFIX = bytes.fromhex("02aabbcc")


class IPv6PacketTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)

    def test_matrix_covers_three_hosts_with_unique_complete_frames(self):
        self.assertEqual(len(self.probes), 228)
        self.assertEqual(sum(p["allowed"] for p in self.probes), 159)
        self.assertEqual({p["sender"] for p in self.probes}, {"h1", "h2", "h3"})
        expected = [
            packets.expected_frame(p["frame"], p["receiver"])
            for p in self.probes
            if p["allowed"]
        ]
        self.assertEqual(len(set(expected)), 159)
        for name, wanted in (("h1", 18), ("h2", 78), ("h3", 63)):
            self.assertEqual(sum(p["receiver"] == name for p in self.probes), wanted)

    def test_host_route_and_adjacent_addresses_have_distinct_next_hops(self):
        for destination, wanted in (
            ("2001:db8:3::42", "h2"),
            ("2001:db8:3::41", "h3"),
            ("2001:db8:3::43", "h3"),
            ("2001:db8:3::1", "h3"),
            ("2001:db8:3:1::42", None),
        ):
            self.assertEqual(packets.expected_host(destination), wanted)
        for number, subnet in packets.SUBNETS.items():
            for address in (subnet.network_address, subnet.broadcast_address):
                self.assertEqual(packets.expected_host(str(address)), f"h{number}")

    def test_transport_checksums_and_extension_chain_are_complete(self):
        for item in self.probes:
            frame = item["frame"]
            if not item["allowed"]:
                continue
            protocol, start = frame[20], 54
            if protocol == 0:
                self.assertEqual(
                    frame[54:70],
                    bytes((60, 0, 1, 4, 0, 0, 0, 0, 17, 0, 1, 4, 0, 0, 0, 0)),
                )
                protocol, start = 17, 70
            if protocol not in (6, 17, 58):
                continue
            segment = frame[start : 54 + int.from_bytes(frame[18:20], "big")]
            pseudo = frame[22:54] + struct.pack("!I3xB", len(segment), protocol)
            self.assertEqual(packets.checksum(pseudo + segment), 0, item["name"])
            if protocol == 17:
                self.assertNotEqual(segment[6:8], bytes(2))

    def test_fragments_include_complete_transport_headers_and_reassemble(self):
        for sender in (1, 2, 3):
            for destination in ("2001:db8:3::42", "2001:db8:3::43"):
                for protocol in (6, 17):
                    pieces = [
                        p
                        for p in self.probes
                        if p["name"].startswith(
                            f"fragment-{sender}-{destination}-{protocol}-"
                        )
                    ]
                    self.assertEqual(len(pieces), 3)
                    self.assertEqual(len({p["frame"][58:62] for p in pieces}), 1)
                    self.assertEqual(len({p["receiver"] for p in pieces}), 1)
                    datagram = b""
                    for index, item in enumerate(pieces):
                        frame = item["frame"]
                        offset = int.from_bytes(frame[56:58], "big")
                        self.assertEqual((offset >> 3) * 8, len(datagram))
                        self.assertEqual(offset & 1, index < 2)
                        body = frame[62 : 54 + int.from_bytes(frame[18:20], "big")]
                        if index == 0:
                            self.assertGreaterEqual(
                                len(body), 20 if protocol == 6 else 8
                            )
                        datagram += body
                    pseudo = pieces[0]["frame"][22:54] + struct.pack(
                        "!I3xB", 48, protocol
                    )
                    self.assertEqual(len(datagram), 48)
                    self.assertEqual(packets.checksum(pseudo + datagram), 0)

    def test_hop_mtu_empty_payload_and_padding_boundaries_are_present(self):
        frames = [p["frame"] for p in self.probes if p["allowed"]]
        self.assertEqual({frame[21] for frame in frames}, {2, 64, 255})
        self.assertTrue(any(len(frame) == 1514 for frame in frames))
        empty = [frame for frame in frames if frame[18:20] == bytes(2)]
        self.assertEqual(len(empty), 3)
        self.assertTrue(
            all(frame[20] == 59 and frame[54:] == b"\xa5" * 6 for frame in empty)
        )

    def test_prediction_changes_only_macs_and_hop_limit(self):
        for item in self.probes:
            if not item["allowed"]:
                continue
            sent = item["frame"]
            received = packets.expected_frame(sent, item["receiver"])
            self.assertEqual(len(sent), len(received))
            self.assertEqual(received[6:12], sent[:6])
            self.assertEqual(received[12:21], sent[12:21])
            self.assertEqual(received[21], sent[21] - 1)
            self.assertEqual(received[22:], sent[22:])

    def test_packet_inputs_do_not_allow_invalid_identities_or_oversize_frames(self):
        for prefix, identification, kwargs in (
            (b"short", 1, {}),
            (b"\xff" * 4, 1, {}),
            (PREFIX, True, {}),
            (PREFIX, 65536, {}),
            (PREFIX, 1, {"sender": 4}),
            (PREFIX, 1, {"payload_size": -1}),
            (PREFIX, 1, {"protocol": 6, "payload_size": 1452}),
            (PREFIX, 1, {"flow_label": 1 << 20}),
        ):
            with self.assertRaises(ValueError):
                packets.make_frame(prefix, identification, **kwargs)
        for limit in (0, 1):
            with self.assertRaises(ValueError):
                packets.expected_frame(
                    packets.make_frame(PREFIX, 1, hop_limit=limit), "h2"
                )


class IPv6EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)
        self.captured = {name: [] for name in ("h1", "h2", "h3")}
        for item in self.probes:
            if item["allowed"]:
                self.captured[item["receiver"]].append(
                    packets.expected_frame(item["frame"], item["receiver"])
                )

    def test_complete_out_of_order_delivery_passes(self):
        topology.check_delivery(
            self.probes, {name: frames[::-1] for name, frames in self.captured.items()}
        )

    def test_missing_duplicate_wrong_host_and_reflected_frames_fail(self):
        for mode in ("missing", "duplicate", "wrong-host", "reflected"):
            captured = copy.deepcopy(self.captured)
            frame = captured["h2"][0]
            if mode == "duplicate":
                captured["h2"].append(frame)
            else:
                captured["h2"].pop(0)
                if mode == "wrong-host":
                    captured["h3"].append(frame)
                elif mode == "reflected":
                    captured["h1"].append(frame)
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)

    def test_macs_base_header_transport_and_padding_are_checked(self):
        frame = self.captured["h2"][0]
        for offset in (0, 6, 12, 14, 18, 20, 21, 22, 38, 54, len(frame) - 1):
            captured = copy.deepcopy(self.captured)
            changed = bytearray(frame)
            changed[offset] ^= 1
            captured["h2"][0] = bytes(changed)
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)

    def test_host_route_and_subnet_cannot_use_each_others_next_hop(self):
        for destination, wanted, wrong in (
            ("2001:db8:3::42", "h2", "h3"),
            ("2001:db8:3::43", "h3", "h2"),
        ):
            item = next(
                p for p in self.probes if p["name"] == f"lpm-1-{destination}-17"
            )
            captured = copy.deepcopy(self.captured)
            captured[wanted].remove(packets.expected_frame(item["frame"], wanted))
            captured[wrong].append(packets.expected_frame(item["frame"], wrong))
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)

    def test_each_dropped_packet_leak_is_rejected(self):
        for item in self.probes:
            if item["allowed"]:
                continue
            captured = copy.deepcopy(self.captured)
            captured["h2"].append(item["frame"])
            with self.subTest(name=item["name"]), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)

    def test_all_hosts_and_frame_types_are_required(self):
        for captured in ({}, {"h2": []}, {**self.captured, "h1": [False]}):
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)


class IPv6ProcessTests(unittest.TestCase):
    def test_failed_probes_bad_replies_and_timeouts_cannot_mean_zero_packets(self):
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

    def test_receiver_launch_failure_reaps_started_processes(self):
        net, ctrl, child = Mock(), Mock(), Mock()
        ctrl.proc.poll.return_value = None
        child.poll.return_value = None
        net.get.return_value.popen.side_effect = [child, OSError("launch failed")]
        with self.assertRaises(OSError):
            topology.run_probes(net, ctrl, PREFIX, [])
        child.terminate.assert_called_once()
        child.wait.assert_called_once()
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_stuck_probe_is_killed_and_reaped(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("probe", 1), 0]
        topology.stop_probe(child)
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)

    def test_dead_receiver_prevents_sending_and_closes_all_receivers(self):
        net, ctrl = Mock(), Mock()
        ctrl.proc.poll.return_value = None
        children = [Mock() for _ in range(3)]
        for child in children:
            child.poll.return_value = 1
        net.get.return_value.popen.side_effect = children
        with self.assertRaisesRegex(RuntimeError, "did not become ready"):
            topology.run_probes(net, ctrl, PREFIX, [])
        self.assertEqual(net.get.return_value.popen.call_count, 3)
        for child in children:
            child.stdout.close.assert_called_once()

    def test_full_probe_flow_checks_sender_counts_and_capture_before_sending(self):
        all_probes = packets.make_probes(PREFIX)
        items = [
            next(p for p in all_probes if p["sender"] == f"h{number}" and p["allowed"])
            for number in (1, 2, 3)
        ]
        for sent in (1, 0, True):
            net, ctrl = Mock(), Mock()
            ctrl.proc.poll.return_value = None
            hosts = {name: Mock() for name in ("h1", "h2", "h3")}
            net.get.side_effect = hosts.__getitem__
            events, children = [], []

            def launch(name, command, **kwargs):
                mode = command[2]
                events.append(mode)
                child = Mock(returncode=0)
                child.poll.return_value = 0
                if mode == "receive":
                    Path(command[command.index("--ready") + 1]).write_text("ready\n")
                    frames = [
                        packets.expected_frame(p["frame"], name).hex()
                        for p in items
                        if p["receiver"] == name
                    ]
                    reply = {"frames": frames}
                else:
                    reply = {"sent": sent}
                child.communicate.return_value = (json.dumps(reply), "")
                children.append(child)
                return child

            for name, host in hosts.items():
                host.defaultIntf.return_value.name = f"{name}-eth0"
                host.popen.side_effect = lambda command, name=name, **kwargs: launch(
                    name, command, **kwargs
                )
            if type(sent) is int and sent == 1:
                topology.run_probes(net, ctrl, PREFIX, items)
            else:
                with self.assertRaisesRegex(RuntimeError, "did not confirm"):
                    topology.run_probes(net, ctrl, PREFIX, items)
            self.assertEqual(events, ["receive"] * 3 + ["send"] * 3)
            for child in children:
                child.stdout.close.assert_called_once()

    def test_controller_exit_configuration_failure_and_timeout_fail_the_test(self):
        net, ctrl = Mock(), Mock()
        ctrl.proc.poll.return_value = 1
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl), 1)
        net.get.assert_not_called()
        ctrl.proc.poll.return_value = None
        with patch.object(topology, "configure_test_interfaces"), patch.object(
            topology, "run_probes", side_effect=subprocess.TimeoutExpired("probe", 4)
        ), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl), 1)

    def test_interface_configuration_is_checked_and_local_to_case_interfaces(self):
        net = Mock()
        nodes = {name: Mock() for name in ("h1", "h2", "h3", "s1")}
        net.get.side_effect = nodes.__getitem__
        for name, node in nodes.items():
            interfaces = [Mock(), Mock()]
            interfaces[0].name, interfaces[1].name = "lo", f"{name}-eth0"
            node.intfList.return_value = interfaces
            node.defaultIntf.return_value.name = f"{name}-eth0"
            node.pexec.return_value = ("", "", 0)
        topology.configure_test_interfaces(net)
        for name, node in nodes.items():
            node.pexec.assert_called_once_with(
                ["sysctl", "-q", "-w", f"net.ipv6.conf.{name}-eth0.disable_ipv6=1"]
            )
        topology.configure_ipv6(net)
        for number in (1, 2, 3):
            nodes[f"h{number}"].pexec.assert_called_with(
                [
                    "ip",
                    "-6",
                    "addr",
                    "replace",
                    f"2001:db8:{number}::1/64",
                    "dev",
                    f"h{number}-eth0",
                ]
            )
        nodes["h1"].pexec.return_value = ("", "denied", 1)
        with self.assertRaises(RuntimeError):
            topology.configure_ipv6(net)
        with self.assertRaises(RuntimeError):
            topology.configure_test_interfaces(net)

    def test_sender_rejects_bad_manifests_and_partial_sends(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            path = Path(directory) / "frames.json"
            for value in ([], {}, [True], ["bad-hex"], ["00"]):
                path.write_text(json.dumps(value))
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

    def test_receiver_marks_ready_and_captures_only_incoming_marked_frames(self):
        frame = packets.expected_frame(packets.make_frame(PREFIX, 1), "h2")
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
            with patch("sys.stdout", new=io.StringIO()) as output:
                probe.receive_frames("iface", PREFIX.hex(), 2, str(ready))
            self.assertEqual(ready.read_text(), "ready\n")
            self.assertEqual(json.loads(output.getvalue()), {"frames": [frame.hex()]})


if __name__ == "__main__":
    unittest.main()
