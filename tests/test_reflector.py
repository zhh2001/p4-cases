"""Check reflected MACs, complete frame evidence and probe lifecycles."""

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

packets = importlib.import_module("01_packet_reflector.packets")
topology = importlib.import_module("01_packet_reflector.topology")
probe = importlib.import_module("01_packet_reflector.test")
PREFIX = bytes.fromhex("02aabbcc")


class ReflectorPacketTests(unittest.TestCase):
    def test_all_destinations_and_content_variants_are_reflected(self):
        probes = packets.make_probes(PREFIX)
        self.assertEqual(len(probes), 92)
        self.assertEqual(len({p["frame"] for p in probes}), 90)
        for sender in (1,):
            selected = [p for p in probes if p["sender"] == f"h{sender}"]
            self.assertEqual(len(selected), 92)
            self.assertTrue(all(p["receiver"] == f"h{sender}" for p in selected))
            for destination in (
                "peer",
                "self",
                "unknown",
                "zero",
                "broadcast",
                "ipv4-multicast",
                "ipv6-multicast",
            ):
                self.assertEqual(
                    sum(
                        p["name"].startswith(f"{sender}-{destination}-")
                        for p in selected
                    ),
                    12,
                )
            repeats = [p["frame"] for p in selected if "-repeat-" in p["name"]]
            self.assertEqual(repeats, [repeats[0]] * 3)

    def test_minimum_mtu_and_distinct_addresses_are_preserved(self):
        probes = packets.make_probes(PREFIX)
        for item in probes:
            frame = item["frame"]
            self.assertTrue(frame[:4] == PREFIX or frame[6:10] == PREFIX)
            self.assertGreaterEqual(len(frame), 60)
            if item["name"].endswith("-mtu"):
                self.assertEqual(len(frame), 1514)
            if item["name"].endswith("-empty"):
                self.assertEqual(frame[14:], b"\xa5" * 46)
            if "-self-" in item["name"]:
                self.assertEqual(
                    frame[:6], bytes(5) + bytes((int(item["sender"][1:]),))
                )

    def test_ipv4_ipv6_vlan_checksums_and_opaque_ttl_values(self):
        for item in packets.make_probes(PREFIX):
            frame = item["frame"]
            kind, start = int.from_bytes(frame[12:14], "big"), 14
            if kind == 0x8100:
                self.assertEqual(frame[14:18], bytes.fromhex("a0070800"))
                kind, start = 0x0800, 18
            elif kind == 0x88A8:
                self.assertEqual(frame[14:22], bytes.fromhex("002a8100000786dd"))
                kind, start = 0x86DD, 22
            if kind == 0x0800:
                valid = packets.checksum(frame[start : start + 20]) == 0
                self.assertEqual(valid, "bad-ipv4-checksum" not in item["name"])
                if item["name"].endswith("ttl-zero"):
                    self.assertEqual(frame[start + 8], 0)
                if item["name"].endswith("ttl-one"):
                    self.assertEqual(frame[start + 8], 1)
                segment = frame[
                    start
                    + 20 : start
                    + int.from_bytes(frame[start + 2 : start + 4], "big")
                ]
                pseudo = frame[start + 12 : start + 20] + struct.pack(
                    "!BBH", 0, 17, len(segment)
                )
            elif kind == 0x86DD:
                if item["name"].endswith("hop-zero"):
                    self.assertEqual(frame[start + 7], 0)
                length = int.from_bytes(frame[start + 4 : start + 6], "big")
                segment = frame[start + 40 : start + 40 + length]
                pseudo = frame[start + 8 : start + 40] + struct.pack(
                    "!I3xB", len(segment), 17
                )
            else:
                continue
            self.assertEqual(packets.checksum(pseudo + segment), 0)

    def test_arp_probes_do_not_address_host_ips(self):
        for item in packets.make_probes(PREFIX):
            if not item["name"].endswith("-arp"):
                continue
            frame = item["frame"]
            self.assertEqual(frame[20:22], b"\x00\x01")
            self.assertEqual(frame[28:31], bytes((198, 18, 0)))
            self.assertEqual(frame[32:38], bytes(6))
            self.assertEqual(frame[38:41], bytes((198, 18, 1)))

    def test_invalid_markers_and_identities_cannot_build_probe_frames(self):
        for prefix in (b"", bytes(3), bytes(5), bytes.fromhex("01aabbcc")):
            with self.assertRaises(ValueError):
                packets.make_probes(prefix)
        for ident in (-1, 0, 65536, True):
            with self.assertRaises(ValueError):
                packets.make_frame(PREFIX, ident, bytes(6))

    def test_reflections_change_only_the_two_mac_fields(self):
        for item in packets.make_probes(PREFIX, 3):
            original = item["frame"]
            reflected = packets.reflect_frame(original)
            self.assertEqual(reflected[:6], original[6:12])
            self.assertEqual(reflected[6:12], original[:6])
            self.assertEqual(reflected[12:], original[12:])
        for frame in (bytes(13), bytearray(60), None):
            with self.assertRaises(ValueError):
                packets.reflect_frame(frame)

    def test_multiple_hosts_have_distinct_frames_and_valid_hex_addresses(self):
        for number in (1, 3, 12, 254):
            probes = packets.make_probes(PREFIX, number)
            self.assertEqual(len(probes), 92 * number)
            self.assertEqual(len({p["frame"] for p in probes}), 90 * number)
            for sender in range(1, number + 1):
                selected = [p for p in probes if p["sender"] == f"h{sender}"]
                self.assertEqual(len(selected), 92)
                self.assertTrue(all(p["receiver"] == f"h{sender}" for p in selected))
        self.assertEqual(packets.host_mac(12), "00:00:00:00:00:0c")
        self.assertEqual(packets.host_mac(254), "00:00:00:00:00:fe")
        for number in (0, 255, True, "3"):
            with self.assertRaises(ValueError):
                packets.make_probes(PREFIX, number)


class ReflectorEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX, 3)
        self.captured = {
            name: [
                packets.reflect_frame(p["frame"])
                for p in self.probes
                if p["receiver"] == name
            ]
            for name in ("h1", "h2", "h3")
        }

    def test_reordered_complete_frames_and_expected_repetitions_pass(self):
        topology.check_delivery(
            self.probes,
            {name: frames[::-1] for name, frames in self.captured.items()},
            3,
        )

    def test_missing_duplicate_wrong_port_and_unswapped_frames_fail(self):
        for mode in ("missing", "duplicate", "wrong-port", "unswapped"):
            captured = copy.deepcopy(self.captured)
            frame = captured["h1"][0]
            if mode == "duplicate":
                captured["h1"].append(frame)
            else:
                captured["h1"].pop(0)
                if mode == "wrong-port":
                    captured["h2"].append(frame)
                elif mode == "unswapped":
                    captured["h1"].append(packets.reflect_frame(frame))
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured, 3)

    def test_one_sided_swap_and_content_changes_fail(self):
        original = self.probes[0]["frame"]
        for replacement in (
            original[:6] + original[:6] + original[12:],
            original[6:12] + original[6:12] + original[12:],
        ):
            captured = copy.deepcopy(self.captured)
            captured["h1"][0] = replacement
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured, 3)
        frame = self.captured["h1"][0]
        for offset in (0, 6, 12, 14, 20, len(frame) - 1):
            captured = copy.deepcopy(self.captured)
            modified = bytearray(frame)
            modified[offset] ^= 1
            captured["h1"][0] = bytes(modified)
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured, 3)

    def test_vlan_tags_truncation_and_extra_bytes_fail(self):
        for kind in ("vlan", "qinq", "mtu"):
            captured = copy.deepcopy(self.captured)
            frame = next(
                packets.reflect_frame(p["frame"])
                for p in self.probes
                if p["name"] == f"1-peer-{kind}"
            )
            index = captured["h1"].index(frame)
            for replacement in (frame[:12] + frame[16:], frame[:-1], frame + b"x"):
                damaged = copy.deepcopy(captured)
                damaged["h1"][index] = replacement
                with self.assertRaises(RuntimeError):
                    topology.check_delivery(self.probes, damaged, 3)

    def test_missing_host_invalid_values_and_repeat_counts_fail(self):
        for captured in (
            {},
            {"h1": []},
            {**self.captured, "h1": [False]},
            {**self.captured, "h4": []},
        ):
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured, 3)
        for count in (2, 4):
            captured = copy.deepcopy(self.captured)
            frame = next(
                packets.reflect_frame(p["frame"])
                for p in self.probes
                if p["name"] == "1-repeat-0"
            )
            captured["h1"] = [f for f in captured["h1"] if f != frame] + [frame] * count
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured, 3)


class ReflectorCaptureTests(unittest.TestCase):
    def test_invalid_capture_parameters_fail_before_opening_socket(self):
        with patch.object(probe.socket, "socket") as factory:
            for prefix, seconds in (
                ("", 2),
                ("bad-hex", 2),
                (PREFIX.hex(), 0),
                (PREFIX.hex(), -1),
                (PREFIX.hex(), float("nan")),
                (PREFIX.hex(), float("inf")),
            ):
                with self.assertRaises(ValueError):
                    probe.receive_frames("iface", prefix, seconds, "unused")
            factory.assert_not_called()

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
            if p["name"] == "1-peer-qinq"
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

    def test_receiver_captures_markers_in_either_mac_and_excludes_outgoing(self):
        frame = packets.make_probes(PREFIX)[0]["frame"]
        reflected = packets.reflect_frame(frame)
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe.socket, "socket"
        ) as factory:
            ready = Path(directory) / "ready"
            sock = factory.return_value.__enter__.return_value
            sock.recvmsg.side_effect = [
                (frame, [], 0, ("iface", 0, socket.PACKET_OUTGOING)),
                (reflected, [], 0, ("iface", 0, socket.PACKET_OUTGOING)),
                (bytes(60), [], 0, ("iface", 0, socket.PACKET_HOST)),
                (frame, [], 0, ("iface", 0, socket.PACKET_HOST)),
                (reflected, [], 0, ("iface", 0, socket.PACKET_HOST)),
                socket.timeout(),
            ]
            with patch("sys.stdout", new=io.StringIO()) as output:
                probe.receive_frames("iface", PREFIX.hex(), 2, str(ready))
            self.assertEqual(ready.read_text(), "ready\n")
            self.assertEqual(
                json.loads(output.getvalue()),
                {"frames": [frame.hex(), reflected.hex()]},
            )
            sock.setsockopt.assert_called_once_with(probe.SOL_PACKET, 8, 1)


class ReflectorProcessTests(unittest.TestCase):
    def test_all_receivers_start_before_sending_and_send_counts_are_required(self):
        probes = packets.make_probes(PREFIX, 3)
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
                                packets.reflect_frame(item["frame"]).hex()
                                for item in probes
                                if name == item["receiver"]
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

                nodes = {f"h{number}": Mock() for number in range(1, 4)}
                net.get.side_effect = nodes.__getitem__
                for name, node in nodes.items():
                    node.defaultIntf.return_value.name = f"{name}-eth0"
                    node.popen.side_effect = launch
                if mode == "complete":
                    topology.run_probes(net, ctrl, PREFIX, probes, 3)
                else:
                    with self.assertRaises(RuntimeError):
                        topology.run_probes(net, ctrl, PREFIX, probes, 3)
                self.assertEqual(events, ["receive"] * 3 + ["send"] * 3)
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
        self.assertEqual(net.get.return_value.popen.call_count, 1)
        self.assertEqual(child.stdout.close.call_count, 1)

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
            topology.run_probes(net, ctrl, PREFIX, [], 3)
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

    def test_controller_exit_and_invalid_host_counts_fail(self):
        net, ctrl = Mock(), Mock()
        ctrl.proc.poll.return_value = 1
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl), 1)
        net.get.assert_not_called()
        ctrl.proc.poll.return_value = None
        for number in (0, 255, True, "3"):
            with patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(topology.run_test(net, ctrl, number), 1)
        with patch.object(topology, "configure_test_interfaces"), patch.object(
            topology, "run_probes"
        ), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl), 0)
            net.pingAll.assert_not_called()
            ctrl.proc.poll.side_effect = [None, 1]
            self.assertEqual(topology.run_test(net, ctrl), 1)

    def test_failed_interface_command_and_probe_prevent_success(self):
        net, ctrl = Mock(), Mock()
        ctrl.proc.poll.return_value = None
        for failure in (
            OSError("socket failed"),
            RuntimeError("probe failed"),
            subprocess.TimeoutExpired("probe", 4),
        ):
            with patch.object(topology, "configure_test_interfaces"), patch.object(
                topology, "run_probes", side_effect=failure
            ), patch("sys.stdout", new=io.StringIO()) as output:
                self.assertEqual(topology.run_test(net, ctrl), 1)
                self.assertNotIn("SUCCESS:", output.getvalue())
                net.pingAll.assert_not_called()
        net.get.return_value.intfList.return_value = []
        net.get.return_value.pexec.return_value = ("", "denied", 1)
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl), 1)
        net.pingAll.assert_not_called()

    def test_interface_changes_are_checked_and_exclude_loopback(self):
        net = Mock()
        nodes = {name: Mock() for name in ("h1", "h2", "s1")}
        net.get.side_effect = nodes.__getitem__
        for name, node in nodes.items():
            interfaces = [Mock(), Mock()]
            interfaces[0].name, interfaces[1].name = "lo", f"{name}-eth0"
            node.intfList.return_value = interfaces
            node.pexec.return_value = ("", "", 0)
        topology.configure_test_interfaces(net, 2)
        for name, node in nodes.items():
            node.pexec.assert_called_once_with(
                ["sysctl", "-q", "-w", f"net.ipv6.conf.{name}-eth0.disable_ipv6=1"]
            )
        nodes["h1"].pexec.return_value = ("", "denied", 1)
        with self.assertRaises(RuntimeError):
            topology.configure_test_interfaces(net, 2)

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
