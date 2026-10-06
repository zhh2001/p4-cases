"""Check ACL test evidence, packet layouts and child-process failures."""

import importlib
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


topology = importlib.import_module("10_firewall_acl.topology")
packets = importlib.import_module("10_firewall_acl.packets")
spec = importlib.util.spec_from_file_location(
    "acl_probe", Path(topology.HERE) / "test.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
PREFIX = bytes.fromhex("02aabbcc")


def received_frames(probes):
    return {
        host: [
            frame
            for item in probes
            if item["receiver"] == host and item["allowed"]
            for frame in item["frames"]
        ]
        for host in ("h1", "h2")
    }


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.probes = topology.test_vectors(PREFIX)
        self.named = {item["name"]: item for item in self.probes}

    def test_checksum_known_bytes_and_odd_padding(self):
        self.assertEqual(packets.checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)
        self.assertEqual(packets.checksum(b"\x01"), 0xFEFF)
        self.assertEqual(
            packets.checksum(bytes.fromhex("45000073000040004011b861c0a80001c0a800c7")),
            0,
        )

    def test_cases_have_unique_packet_sources(self):
        self.assertEqual(len(self.probes), 40)
        frames = [frame for item in self.probes for frame in item["frames"]]
        self.assertEqual(len(frames), 200)
        self.assertEqual(len({frame[6:12] for frame in frames}), 200)
        self.assertTrue(all(frame[6:10] == PREFIX for frame in frames))

    def test_options_and_transport_ports_use_the_declared_offset(self):
        for name in ("h1-tcp22-options4", "h1-tcp22-options40", "h1-udp5000-options40"):
            frame = self.named[name]["frames"][0]
            ihl = (frame[14] & 15) * 4
            port = struct.unpack("!H", frame[14 + ihl + 2 : 14 + ihl + 4])[0]
            self.assertEqual(port, 22 if "tcp" in name else 5000)
            self.assertEqual(frame[34 : 14 + ihl], b"\x01" * (ihl - 20))
        tcp = self.named["h1-tcp80-port-like-options"]["frames"][0]
        self.assertEqual(tcp[34:38], bytes.fromhex("94040016"))
        self.assertEqual(struct.unpack("!H", tcp[40:42])[0], 80)

    def test_valid_headers_and_transport_checksums(self):
        invalid = {
            "bad-version",
            "short-ihl",
            "short-total",
            "long-total",
            "truncated-ip",
            "truncated-options",
            "short-tcp",
            "short-udp",
        }
        for item in self.probes:
            if item["name"] in invalid or item["name"] == "arp":
                continue
            for frame in item["frames"]:
                ihl = (frame[14] & 15) * 4
                total = struct.unpack("!H", frame[16:18])[0]
                self.assertEqual(packets.checksum(frame[14 : 14 + ihl]), 0)
                transport = frame[14 + ihl : 14 + total]
                proto = frame[23]
                pseudo = (
                    frame[26:34] + struct.pack("!BBH", 0, proto, len(transport))
                    if proto != 1
                    else b""
                )
                self.assertEqual(packets.checksum(pseudo + transport), 0)

    def test_fragment_flags_and_offsets_include_df_control(self):
        for name in ("tcp-first-fragment", "udp-first-fragment"):
            frame = self.named[name]["frames"][0]
            self.assertEqual(struct.unpack("!H", frame[20:22])[0], 0x2000)
            total = struct.unpack("!H", frame[16:18])[0]
            self.assertEqual((total - 20) % 8, 0)
        for name in ("tcp-later-fragment", "udp-later-fragment"):
            self.assertEqual(self.named[name]["frames"][0][20:22], b"\0\x01")
        self.assertEqual(self.named["tcp-dont-fragment"]["frames"][0][20:22], b"\x40\0")

    def test_truncated_inputs_keep_the_capture_identifier(self):
        for name, size in (("truncated-ip", 26), ("truncated-options", 36)):
            frame = self.named[name]["frames"][0]
            self.assertEqual(len(frame), size)
            self.assertEqual(frame[6:10], PREFIX)

    def test_invalid_option_sizes_are_rejected(self):
        for options in (b"x", b"x" * 44):
            with self.subTest(options=options), self.assertRaises(ValueError):
                packets.make_frame(
                    bytes(6), bytes(6), "10.0.0.1", "10.0.0.2", "TCP", 80, options, 1
                )


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.probes = topology.test_vectors(PREFIX)
        self.quiet = patch("sys.stdout", new=io.StringIO())
        self.quiet.start()
        self.addCleanup(self.quiet.stop)

    def test_expected_delivery_passes_independently_of_order(self):
        received = received_frames(self.probes)
        topology.check_delivery(
            self.probes, {host: frames[::-1] for host, frames in received.items()}
        )

    def test_allowed_flow_loss_or_duplicate_is_rejected(self):
        for mode in ("missing", "duplicate", "changed"):
            received = received_frames(self.probes)
            if mode == "missing":
                received["h2"].pop()
            elif mode == "duplicate":
                received["h2"].append(received["h2"][0])
            else:
                frame = received["h2"][0]
                received["h2"][0] = frame[:-1] + bytes([frame[-1] ^ 1])
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)

    def test_denied_and_malformed_forwarding_is_rejected(self):
        for name in (
            "h1-tcp22-options4",
            "h1-udp5000-options40",
            "truncated-ip",
            "tcp-first-fragment",
            "udp-later-fragment",
        ):
            received = received_frames(self.probes)
            item = next(item for item in self.probes if item["name"] == name)
            received["h2"].append(item["frames"][0])
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)

    def test_empty_or_missing_captures_cannot_prove_denial(self):
        for received in ({}, {"h1": [], "h2": []}, {"h1": None, "h2": []}):
            with self.subTest(received=received), self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, received)


class ProcessTests(unittest.TestCase):
    def test_failed_capture_cannot_be_zero_delivery(self):
        child = Mock(returncode=1)
        child.communicate.return_value = ('{"frames": []}', "capture failed")
        with self.assertRaisesRegex(RuntimeError, "packet probe failed"):
            topology.read_probe(child)

    def test_invalid_process_replies_are_rejected(self):
        for output in ("", "[]", "null", "not JSON"):
            child = Mock(returncode=0)
            child.communicate.return_value = (output, "")
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                topology.read_probe(child)
        for reply in ({}, {"frames": None}, {"frames": [1]}, {"frames": ["zz"]}):
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                topology.frame_list(reply)

    def test_probe_timeout_is_reported(self):
        child = Mock()
        child.communicate.side_effect = subprocess.TimeoutExpired("probe", 6)
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

    def test_empty_manifest_cannot_confirm_sending(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frames.json"
            path.write_text("[]")
            with self.assertRaises(ValueError):
                probe.send_frames("missing", str(path))

    def test_capture_prefix_is_validated_before_socket_creation(self):
        with self.assertRaises(ValueError):
            probe.receive_frames("missing", "02", 5, "absent")

    def test_network_process_launch_errors_make_case_fail(self):
        with patch("sys.stdout", new=io.StringIO()):
            net = Mock()
            net.get.return_value.popen.side_effect = OSError("capture launch failed")
            self.assertEqual(topology.run_test(net), 1)


if __name__ == "__main__":
    unittest.main()
