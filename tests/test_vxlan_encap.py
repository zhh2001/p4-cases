"""Check VXLAN frame expectations and reject incomplete test evidence."""

import importlib
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


topology = importlib.import_module("11_vxlan_encap.topology")
packets = importlib.import_module("11_vxlan_encap.packets")
spec = importlib.util.spec_from_file_location(
    "vxlan_probe", Path(topology.HERE) / "test_sniff.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
PREFIX = bytes.fromhex("02aabbcc")


def received_frames(probes):
    return {
        "h1": [],
        "h2": [
            packets.encapsulate(frame)
            for item in probes
            if item["allowed"]
            for frame in item["frames"]
        ],
    }


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)

    def test_cases_include_multiple_lengths_protocols_and_unique_sources(self):
        self.assertEqual(len(self.probes), 11)
        frames = [frame for item in self.probes for frame in item["frames"]]
        self.assertEqual(len(frames), 55)
        self.assertEqual(len({frame[6:12] for frame in frames}), 55)
        self.assertEqual(
            {len(frame) for frame in frames}, {60, 64, 128, 512, 1500, 1514}
        )
        self.assertEqual(
            {frame[12:14] for frame in frames},
            {b"\x88\xb5", b"\x81\x00", b"\x08\x00", b"\x08\x06"},
        )
        self.assertTrue(all(frame[6:10] == PREFIX for frame in frames))

    def test_outer_lengths_include_the_whole_inner_frame(self):
        for item in self.probes:
            for inner in item["frames"]:
                raw = packets.encapsulate(inner)
                self.assertEqual(len(raw), len(inner) + 50)
                self.assertEqual(struct.unpack("!H", raw[16:18])[0], len(inner) + 36)
                self.assertEqual(struct.unpack("!H", raw[38:40])[0], len(inner) + 16)
                self.assertEqual(raw[50:], inner)

    def test_outer_checksum_and_all_fixed_fields(self):
        raw = packets.encapsulate(self.probes[0]["frames"][0])
        self.assertEqual(packets.checksum(raw[14:34]), 0)
        self.assertEqual(raw[:14], bytes.fromhex("000000000002000000dead010800"))
        self.assertEqual(raw[14:16], b"\x45\0")
        self.assertEqual(raw[18:24], bytes.fromhex("000000004011"))
        self.assertEqual(raw[26:34], bytes.fromhex("c0a80101c0a80102"))
        self.assertEqual(raw[34:38], struct.pack("!HH", 12345, 4789))
        self.assertEqual(raw[40:50], bytes.fromhex("00000800000000138800"))

    def test_checksum_uses_known_bytes_and_odd_padding(self):
        self.assertEqual(packets.checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)
        self.assertEqual(packets.checksum(b"\x01"), 0xFEFF)

    def test_ipv4_limit_is_checked_before_encoding_length_fields(self):
        raw = packets.encapsulate(bytes(65499))
        self.assertEqual(struct.unpack("!H", raw[16:18])[0], 65535)
        self.assertEqual(struct.unpack("!H", raw[38:40])[0], 65515)
        for size in (13, 65500):
            with self.subTest(size=size), self.assertRaises(ValueError):
                packets.encapsulate(bytes(size))

    def test_inner_vlan_and_ipv4_are_preserved_as_bytes(self):
        named = {item["name"]: item for item in self.probes}
        vlan = named["vlan"]["frames"][0]
        self.assertEqual(vlan[12:18], bytes.fromhex("8100006488b5"))
        ipv4 = named["ipv4"]["frames"][0]
        self.assertEqual(packets.checksum(ipv4[14:34]), 0)
        self.assertEqual(int.from_bytes(ipv4[16:18], "big"), len(ipv4) - 14)
        for inner in (vlan, ipv4):
            self.assertEqual(packets.encapsulate(inner)[50:], inner)

    def test_prefix_validation_rejects_ambiguous_identifiers(self):
        with self.assertRaises(ValueError):
            packets.make_probes(b"aa")


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)
        quiet = patch("sys.stdout", new=io.StringIO())
        quiet.start()
        self.addCleanup(quiet.stop)

    def test_expected_delivery_passes_independently_of_order(self):
        received = received_frames(self.probes)
        received["h2"].reverse()
        topology.check_delivery(self.probes, received)

    def test_old_fixed_lengths_cannot_pass_with_matching_vni_and_mac(self):
        received = received_frames(self.probes)
        raw = bytearray(received["h2"][0])
        raw[16:18], raw[38:40] = struct.pack("!H", 50), struct.pack("!H", 30)
        raw[24:26] = b"\0\0"
        raw[24:26] = struct.pack("!H", packets.checksum(bytes(raw[14:34])))
        received["h2"][0] = bytes(raw)
        with self.assertRaisesRegex(RuntimeError, "IPv4=50 UDP=30"):
            topology.check_delivery(self.probes, received)

    def test_outer_fields_checksum_and_inner_payload_changes_are_rejected(self):
        for offset in (
            0,
            6,
            12,
            14,
            15,
            16,
            18,
            20,
            22,
            23,
            24,
            26,
            30,
            34,
            36,
            38,
            40,
            42,
            43,
            46,
            49,
            50,
            56,
            62,
            75,
        ):
            received = received_frames(self.probes)
            raw = bytearray(received["h2"][0])
            raw[offset] ^= 1
            received["h2"][0] = bytes(raw)
            with self.subTest(offset=offset), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)

    def test_missing_duplicate_truncated_or_wrong_host_delivery_is_rejected(self):
        for mode in ("missing", "duplicate", "truncated", "wrong-host"):
            received = received_frames(self.probes)
            if mode == "missing":
                received["h2"].pop()
            elif mode == "duplicate":
                received["h2"].append(received["h2"][0])
            elif mode == "truncated":
                received["h2"][0] = received["h2"][0][:-1]
            else:
                received["h1"].append(received["h2"].pop())
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)

    def test_unmatched_plain_or_encapsulated_frames_are_rejected(self):
        item = next(item for item in self.probes if not item["allowed"])
        for raw in (item["frames"][0], packets.encapsulate(item["frames"][0])):
            received = received_frames(self.probes)
            received["h2"].append(raw)
            with self.subTest(raw=len(raw)), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)

    def test_empty_and_missing_captures_cannot_pass(self):
        for received in ({}, {"h1": [], "h2": []}, {"h1": None, "h2": []}):
            with self.subTest(received=received), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)


class ProcessTests(unittest.TestCase):
    def test_probe_errors_invalid_replies_and_timeouts_are_reported(self):
        child = Mock(returncode=1)
        child.communicate.return_value = ('{"frames": []}', "capture failed")
        with self.assertRaisesRegex(RuntimeError, "packet probe failed"):
            topology.read_probe(child)
        child.returncode = 0
        for output in ("", "[]", "null", "invalid JSON"):
            child.communicate.return_value = (output, "")
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                topology.read_probe(child)
        child.communicate.side_effect = subprocess.TimeoutExpired("probe", 5)
        with self.assertRaises(subprocess.TimeoutExpired):
            topology.read_probe(child)

    def test_malformed_capture_cannot_mean_zero_delivery(self):
        for reply in ({}, {"frames": None}, {"frames": [1]}, {"frames": ["zz"]}):
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                topology.frame_list(reply)

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

    def test_empty_manifest_and_invalid_prefix_fail_before_socket_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frames.json"
            path.write_text("[]")
            with self.assertRaises(ValueError):
                probe.send_frames("missing", str(path))
        with self.assertRaises(ValueError):
            probe.receive_frames("missing", "02", 3, "absent")

    def test_launch_failure_makes_the_case_fail(self):
        net = Mock()
        net.get.return_value.popen.side_effect = OSError("capture launch failed")
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net), 1)

    def test_mtu_configuration_failure_is_not_ignored(self):
        intf1, intf2 = Mock(), Mock()
        intf1.node.name = "h1"
        intf2.node.name = "s1"
        intf1.node.pexec.return_value = ("", "permission denied", 1)
        net = Mock(links=[Mock(intf1=intf1, intf2=intf2)])
        with self.assertRaisesRegex(RuntimeError, "MTU"):
            topology.configure_mtu(net)


if __name__ == "__main__":
    unittest.main()
