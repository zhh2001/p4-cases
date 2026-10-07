"""Check static L2 packet evidence, VLAN capture and process failures."""

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

packets = importlib.import_module("03_l2_forwarding_switch.packets")
topology = importlib.import_module("03_l2_forwarding_switch.topology")
probe = importlib.import_module("03_l2_forwarding_switch.probe")
PREFIX = bytes.fromhex("02aabbcc")


class StaticL2PacketTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)

    def test_all_pairs_and_content_variants_have_exact_counts(self):
        self.assertEqual(len(self.probes), 124)
        self.assertEqual(sum(p["allowed"] for p in self.probes), 80)
        self.assertEqual(len({p["frame"] for p in self.probes}), 124)
        for sender in range(1, 5):
            for receiver in range(1, 5):
                if sender != receiver:
                    self.assertEqual(
                        sum(
                            p["name"].startswith(f"pair-{sender}-{receiver}-")
                            for p in self.probes
                        ),
                        3,
                    )
            self.assertEqual(
                sum(p["receiver"] == f"h{sender}" for p in self.probes), 20
            )

    def test_host_addresses_are_valid_hex_and_subnet_addresses(self):
        self.assertEqual(packets.host_mac(10), "00:00:00:00:00:0a")
        self.assertEqual(packets.host_mac(100), "00:00:00:00:00:64")
        self.assertEqual(packets.host_mac(254), "00:00:00:00:00:fe")
        for number in range(1, 255):
            self.assertEqual(
                bytes.fromhex(packets.host_mac(number).replace(":", ""))[-1], number
            )
            self.assertEqual(packets.host_ip(number), f"10.0.0.{number}")
        for invalid in (-1, 0, 255, 256, True, "4"):
            with self.assertRaises(ValueError):
                packets.make_probes(PREFIX, invalid)
            with self.assertRaises(ValueError):
                topology.host_mac(invalid)

    def test_inner_checksums_and_vlan_headers_are_complete(self):
        for item in self.probes:
            frame = item["frame"]
            if not item["name"].startswith("content-"):
                continue
            kind, start = int.from_bytes(frame[12:14], "big"), 14
            if kind == 0x8100:
                self.assertEqual(frame[14:18], bytes.fromhex("a0070800"))
                kind, start = 0x0800, 18
            elif kind == 0x88A8:
                self.assertEqual(frame[14:22], bytes.fromhex("002a8100000786dd"))
                kind, start = 0x86DD, 22
            if kind == 0x0800:
                actual = packets.checksum(frame[start : start + 20])
                self.assertEqual(actual == 0, "bad-ipv4-checksum" not in item["name"])
                segment = frame[
                    start
                    + 20 : start
                    + int.from_bytes(frame[start + 2 : start + 4], "big")
                ]
                pseudo = frame[start + 12 : start + 20] + struct.pack(
                    "!BBH", 0, 17, len(segment)
                )
            elif kind == 0x86DD:
                segment = frame[
                    start
                    + 40 : start
                    + 40
                    + int.from_bytes(frame[start + 4 : start + 6], "big")
                ]
                pseudo = frame[start + 8 : start + 40] + struct.pack(
                    "!I3xB", len(segment), 17
                )
            else:
                continue
            self.assertEqual(packets.checksum(pseudo + segment), 0)

    def test_minimum_mtu_same_port_and_unmatched_destinations_are_covered(self):
        for item in self.probes:
            self.assertEqual(item["frame"][6:10], PREFIX)
            if item["name"].endswith("-mtu"):
                self.assertEqual(len(item["frame"]), 1514)
            if item["name"].endswith("-empty"):
                self.assertEqual(item["frame"][14:], b"\xa5" * 46)
            if item["name"].startswith(("same-port-", "unmatched-")):
                self.assertFalse(item["allowed"])
                self.assertIsNone(item["receiver"])

    def test_single_host_and_larger_topologies_have_consistent_delivery(self):
        one = packets.make_probes(PREFIX, 1)
        self.assertEqual(len(one), 22)
        self.assertFalse(any(p["allowed"] for p in one))
        large = packets.make_probes(PREFIX, 12)
        self.assertEqual(len(large), 396)
        self.assertEqual(sum(p["allowed"] for p in large), 264)
        self.assertEqual(sum(p["receiver"] == "h12" for p in large), 22)


class StaticL2EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)
        self.captured = {
            f"h{number}": [
                p["frame"]
                for p in self.probes
                if p["allowed"] and p["receiver"] == f"h{number}"
            ]
            for number in range(1, 5)
        }

    def test_complete_reordered_frames_pass(self):
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
                if mode in ("wrong-host", "reflected"):
                    captured["h3" if mode == "wrong-host" else "h1"].append(frame)
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)

    def test_macs_ether_type_payload_and_padding_changes_fail(self):
        frame = self.captured["h2"][0]
        for offset in (0, 6, 12, 14, 20, len(frame) - 1):
            captured = copy.deepcopy(self.captured)
            modified = bytearray(frame)
            modified[offset] ^= 1
            captured["h2"][0] = bytes(modified)
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)

    def test_every_dropped_packet_and_missing_host_reply_fail(self):
        for item in self.probes:
            if not item["allowed"]:
                captured = copy.deepcopy(self.captured)
                captured["h2"].append(item["frame"])
                with self.assertRaises(RuntimeError):
                    topology.check_delivery(self.probes, captured)
        for captured in ({}, {"h2": []}, {**self.captured, "h1": [False]}):
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)


class StaticL2CaptureTests(unittest.TestCase):
    def aux(self, status, tci, tpid):
        data = probe.AUXDATA.pack(status, 60, 60, 0, 14, tci, tpid)
        return [(probe.SOL_PACKET, probe.PACKET_AUXDATA, data)]

    def test_vlan_metadata_restores_zero_tci_and_both_tag_types(self):
        for kind, tci, status in (
            (0x8100, 0, 16),
            (0x8100, 0xA007, 80),
            (0x88A8, 42, 80),
        ):
            frame = packets.make_frame(PREFIX, 1, bytes.fromhex("000000000002"))
            expected = frame[:12] + struct.pack("!HH", kind, tci) + frame[12:]
            self.assertEqual(
                probe.restore_vlan(frame, self.aux(status, tci, kind), 0), expected
            )

    def test_untagged_data_and_existing_inner_tag_are_preserved(self):
        frame = next(
            p["frame"]
            for p in packets.make_probes(PREFIX)
            if p["name"] == "content-1-qinq"
        )
        untagged = frame[:12] + frame[16:]
        self.assertEqual(
            probe.restore_vlan(untagged, self.aux(80, 42, 0x88A8), 0), frame
        )
        self.assertEqual(probe.restore_vlan(frame, [], 0), frame)
        self.assertEqual(probe.restore_vlan(frame, self.aux(0, 0, 0), 0), frame)

    def test_truncated_or_malformed_capture_metadata_fails(self):
        frame = bytes(60)
        for ancillary, flags in (
            ([], socket.MSG_TRUNC),
            ([], socket.MSG_CTRUNC),
            ([(probe.SOL_PACKET, 8, b"bad")], 0),
            (self.aux(80, 1, 0x8100) * 2, 0),
        ):
            with self.assertRaises(RuntimeError):
                probe.restore_vlan(frame, ancillary, flags)
        with self.assertRaises(RuntimeError):
            probe.restore_vlan(bytes(13), self.aux(80, 1, 0x8100), 0)

    def test_receiver_marks_ready_and_ignores_outgoing_and_unmarked_frames(self):
        frame = packets.make_probes(PREFIX)[0]["frame"]
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            ready = Path(directory) / "ready"
            sock = factory.return_value.__enter__.return_value
            sock.recvmsg.side_effect = [
                (frame, [], 0, ("iface", 0, socket.PACKET_OUTGOING)),
                (bytes(60), [], 0, ("iface", 0, socket.PACKET_HOST)),
                (frame, [], 0, ("iface", 0, socket.PACKET_HOST)),
                socket.timeout(),
            ]
            with patch("sys.stdout", new=io.StringIO()) as output:
                probe.receive_frames("iface", PREFIX.hex(), 2, str(ready))
            self.assertEqual(ready.read_text(), "ready\n")
            self.assertEqual(json.loads(output.getvalue()), {"frames": [frame.hex()]})
            sock.setsockopt.assert_called_once_with(probe.SOL_PACKET, 8, 1)


class StaticL2ProcessTests(unittest.TestCase):
    def test_all_receivers_start_before_sending_and_send_counts_are_required(self):
        probes = packets.make_probes(PREFIX)
        for mode in ("complete", "short", "extra", "boolean", "missing", "exited"):
            with self.subTest(mode=mode):
                net, ctrl = Mock(), Mock()
                ctrl.proc.poll.side_effect = [None, 1 if mode == "exited" else None]
                events, children = [], []

                def launch(command, **_opts):
                    role = command[2]
                    name = command[command.index("--iface") + 1].split("-")[0]
                    events.append(role)
                    child = Mock(returncode=0)
                    child.poll.return_value = 0
                    if role == "receive":
                        Path(command[command.index("--ready") + 1]).write_text(
                            "ready\n"
                        )
                        reply = {
                            "frames": [
                                item["frame"].hex()
                                for item in probes
                                if item["allowed"] and item["receiver"] == name
                            ]
                        }
                    else:
                        count = sum(item["sender"] == name for item in probes)
                        sent = {
                            "short": count - 1,
                            "extra": count + 1,
                            "boolean": True,
                        }.get(mode, count)
                        reply = {} if mode == "missing" else {"sent": sent}
                    child.communicate.return_value = (json.dumps(reply), "")
                    children.append(child)
                    return child

                nodes = {f"h{number}": Mock() for number in range(1, 5)}
                net.get.side_effect = nodes.__getitem__
                for name, node in nodes.items():
                    node.defaultIntf.return_value.name = f"{name}-eth0"
                    node.popen.side_effect = launch
                if mode == "complete":
                    topology.run_probes(net, ctrl, PREFIX, probes)
                else:
                    with self.assertRaises(RuntimeError):
                        topology.run_probes(net, ctrl, PREFIX, probes)
                self.assertEqual(events, ["receive"] * 4 + ["send"] * 4)
                for child in children:
                    child.stdout.close.assert_called_once()
                    child.stderr.close.assert_called_once()

    def test_receiver_exit_before_readiness_prevents_sending(self):
        net, ctrl, child = Mock(), Mock(), Mock(returncode=9)
        ctrl.proc.poll.return_value = None
        child.poll.return_value = 9
        net.get.return_value.popen.return_value = child
        with self.assertRaisesRegex(RuntimeError, "receivers did not become ready"):
            topology.run_probes(net, ctrl, PREFIX, packets.make_probes(PREFIX))
        self.assertEqual(net.get.return_value.popen.call_count, 4)
        self.assertEqual(child.stdout.close.call_count, 4)

    def test_failed_probes_bad_json_and_timeouts_cannot_mean_zero_packets(self):
        child = Mock(returncode=1)
        child.communicate.return_value = ('{"frames":[]}', "failed")
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

    def test_receiver_launch_failure_stops_started_children(self):
        net, ctrl, child = Mock(), Mock(), Mock()
        ctrl.proc.poll.return_value = None
        child.poll.return_value = None
        net.get.return_value.popen.side_effect = [child, OSError("launch failed")]
        with self.assertRaises(OSError):
            topology.run_probes(net, ctrl, PREFIX, [])
        child.terminate.assert_called_once()
        child.wait.assert_called_once()
        child.stdin.close.assert_called_once()
        child.stdout.close.assert_called_once()

    def test_stuck_process_is_killed_and_reaped(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("probe", 1), 0]
        topology.stop_probe(child)
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)

    def test_static_arp_batch_is_checked_and_uses_hex_macs(self):
        net, child = Mock(), Mock(returncode=0)
        child.poll.return_value = 0
        child.communicate.return_value = ("", "")
        net.get.return_value.popen.return_value = child
        net.get.return_value.defaultIntf.return_value.name = "host-eth0"
        topology.populate_arp(net, 4)
        self.assertEqual(net.get.return_value.popen.call_count, 4)
        text = child.communicate.call_args_list[0].kwargs["input"]
        self.assertEqual(len(text.splitlines()), 3)
        self.assertIn(
            "neigh replace 10.0.0.2 lladdr 00:00:00:00:00:02 nud permanent dev host-eth0\n",
            text,
        )
        self.assertNotIn("10.0.0.1 ", text)
        net.reset_mock()
        topology.populate_arp(net, 1)
        net.get.return_value.popen.assert_not_called()
        child.returncode = 1
        with self.assertRaises(RuntimeError):
            topology.populate_arp(net, 4)
        child.communicate.side_effect = subprocess.TimeoutExpired("ip", 5)
        child.poll.return_value = None
        with self.assertRaises(subprocess.TimeoutExpired):
            topology.populate_arp(net, 4)
        child.terminate.assert_called_once()

    def test_controller_exit_ping_loss_and_invalid_ping_result_fail(self):
        net, ctrl = Mock(), Mock()
        ctrl.proc.poll.return_value = 1
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl), 1)
        net.get.assert_not_called()
        ctrl.proc.poll.return_value = None
        for dropped in (0, 0.1, False, None, float("nan"), float("inf")):
            net.pingAll.return_value = dropped
            with patch.object(topology, "configure_test_interfaces"), patch.object(
                topology, "run_probes"
            ), patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(
                    topology.run_test(net, ctrl),
                    0 if type(dropped) is int and dropped == 0 else 1,
                )
        net.reset_mock()
        with patch.object(topology, "configure_test_interfaces"), patch.object(
            topology, "run_probes"
        ), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl, 1), 0)
        net.pingAll.assert_not_called()

    def test_interface_changes_are_checked_and_exclude_loopback(self):
        net = Mock()
        nodes = {name: Mock() for name in ("h1", "h2", "h3", "h4", "s1")}
        net.get.side_effect = nodes.__getitem__
        for name, node in nodes.items():
            interfaces = [Mock(), Mock()]
            interfaces[0].name, interfaces[1].name = "lo", f"{name}-eth0"
            node.intfList.return_value = interfaces
            node.pexec.return_value = ("", "", 0)
        topology.configure_test_interfaces(net, 4)
        for name, node in nodes.items():
            node.pexec.assert_called_once_with(
                ["sysctl", "-q", "-w", f"net.ipv6.conf.{name}-eth0.disable_ipv6=1"]
            )
        nodes["h1"].pexec.return_value = ("", "denied", 1)
        with self.assertRaises(RuntimeError):
            topology.configure_test_interfaces(net, 4)

    def test_bad_manifests_and_partial_sends_fail(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            path = Path(directory) / "frames.json"
            for value in ([], {}, [True], ["bad-hex"], ["00"]):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    probe.send_frames("iface", str(path))
            factory.assert_not_called()
            frame = packets.make_probes(PREFIX)[0]["frame"]
            path.write_text(json.dumps([frame.hex()]))
            factory.return_value.__enter__.return_value.send.return_value = (
                len(frame) - 1
            )
            with self.assertRaises(RuntimeError):
                probe.send_frames("iface", str(path))


if __name__ == "__main__":
    unittest.main()
