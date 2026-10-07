"""Check exact flooded copies, dynamic ARP and packet probe failures."""

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

packets = importlib.import_module("04_l2_broadcast_switch.packets")
topology = importlib.import_module("04_l2_broadcast_switch.topology")
probe = importlib.import_module("04_l2_broadcast_switch.probe")
PREFIX = bytes.fromhex("02aabbcc")


class BroadcastL2PacketTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)

    def test_all_pairs_and_content_variants_have_exact_counts(self):
        self.assertEqual(len(self.probes), 300)
        self.assertEqual(sum(len(p["receivers"]) for p in self.probes), 692)
        self.assertEqual(len({p["frame"] for p in self.probes}), 300)
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
                sum(f"h{sender}" in p["receivers"] for p in self.probes), 173
            )

    def test_host_addresses_are_valid_hex_and_subnet_addresses(self):
        self.assertEqual(packets.host_mac(10), "00:00:00:00:00:0a")
        self.assertEqual(packets.host_mac(100), "00:00:00:00:00:64")
        self.assertEqual(packets.host_mac(128), "00:00:00:00:00:80")
        for number in range(1, 129):
            self.assertEqual(
                bytes.fromhex(packets.host_mac(number).replace(":", ""))[-1], number
            )
            self.assertEqual(packets.host_ip(number), f"10.0.0.{number}")
        for invalid in (-1, 0, 129, 254, True, "4"):
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
            if item["name"].startswith("same-port-"):
                self.assertEqual(item["receivers"], [])
            if item["flooded"]:
                self.assertEqual(len(item["receivers"]), 3)
                self.assertNotIn(item["sender"], item["receivers"])

    def test_single_host_and_larger_topologies_have_consistent_delivery(self):
        one = packets.make_probes(PREFIX, 1)
        self.assertEqual(len(one), 66)
        self.assertFalse(any(p["receivers"] for p in one))
        large = packets.make_probes(PREFIX, 12)
        self.assertEqual(len(large), 924)
        self.assertEqual(sum(len(p["receivers"]) for p in large), 6996)
        self.assertEqual(sum("h12" in p["receivers"] for p in large), 583)

    def test_flooded_arp_requests_do_not_use_host_ip_addresses(self):
        frames = [
            item["frame"]
            for item in self.probes
            if item["name"].startswith("flood-") and item["name"].endswith("-arp")
        ]
        self.assertEqual(len(frames), 16)
        for frame in frames:
            self.assertEqual(frame[12:14], b"\x08\x06")
            self.assertEqual(frame[20:22], b"\x00\x01")
            self.assertEqual(frame[28:31], bytes((198, 18, 0)))
            self.assertEqual(frame[32:38], bytes(6))
            self.assertEqual(frame[38:41], bytes((198, 18, 1)))


class BroadcastL2EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.probes = packets.make_probes(PREFIX)
        self.captured = {
            f"h{number}": [
                p["frame"] for p in self.probes if f"h{number}" in p["receivers"]
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
            if not item["receivers"]:
                captured = copy.deepcopy(self.captured)
                captured["h2"].append(item["frame"])
                with self.assertRaises(RuntimeError):
                    topology.check_delivery(self.probes, captured)
        for captured in ({}, {"h2": []}, {**self.captured, "h1": [False]}):
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)

    def test_every_flood_requires_one_copy_on_each_other_host(self):
        for item in self.probes:
            if not item["flooded"]:
                continue
            for receiver in item["receivers"]:
                captured = copy.deepcopy(self.captured)
                captured[receiver].remove(item["frame"])
                with self.assertRaises(RuntimeError):
                    topology.check_delivery(self.probes, captured)
            captured = copy.deepcopy(self.captured)
            captured[item["sender"]].append(item["frame"])
            with self.assertRaises(RuntimeError):
                topology.check_delivery(self.probes, captured)


class BroadcastL2ARPTests(unittest.TestCase):
    def setUp(self):
        self.net = Mock()
        self.nodes = {f"h{number}": Mock() for number in range(1, 5)}
        self.net.get.side_effect = self.nodes.__getitem__
        self.entries = {}
        for number in range(1, 5):
            name = f"h{number}"
            self.nodes[name].defaultIntf.return_value.name = f"{name}-eth0"
            self.entries[name] = [
                {
                    "dst": packets.host_ip(peer),
                    "lladdr": packets.host_mac(peer),
                    "dev": f"{name}-eth0",
                    "state": ["REACHABLE"],
                }
                for peer in range(1, 5)
                if peer != number
            ]
        self.set_replies()

    def set_replies(self):
        for name, entries in self.entries.items():
            self.nodes[name].pexec.return_value = (json.dumps(entries), "", 0)

    def test_every_dynamic_peer_is_required_with_its_mac_and_interface(self):
        for state in ("REACHABLE", "STALE", "DELAY", "PROBE"):
            for entries in self.entries.values():
                for item in entries:
                    item["state"] = [state]
                    item["lladdr"] = item["lladdr"].upper()
            self.set_replies()
            topology.check_arp(self.net, 4)
        for node in self.nodes.values():
            node.pexec.assert_called_with(["ip", "-j", "neigh", "show"])

    def test_missing_duplicate_or_invalid_neighbours_fail(self):
        pristine = copy.deepcopy(self.entries)
        for mode in (
            "missing",
            "duplicate",
            "mac",
            "interface",
            "permanent",
            "failed",
            "incomplete",
            "state-type",
            "no-state",
            "bad-destination",
        ):
            with self.subTest(mode=mode):
                self.entries = copy.deepcopy(pristine)
                first = self.entries["h1"][0]
                if mode == "missing":
                    self.entries["h1"].pop(0)
                elif mode == "duplicate":
                    self.entries["h1"].append(first.copy())
                else:
                    key, value = {
                        "mac": ("lladdr", "00:00:00:00:00:7f"),
                        "interface": ("dev", "lo"),
                        "permanent": ("state", ["PERMANENT"]),
                        "failed": ("state", ["FAILED"]),
                        "incomplete": ("state", ["INCOMPLETE"]),
                        "state-type": ("state", "REACHABLE"),
                        "no-state": ("state", []),
                        "bad-destination": ("dst", []),
                    }[mode]
                    first[key] = value
                self.set_replies()
                with self.assertRaises(RuntimeError):
                    topology.check_arp(self.net, 4)

    def test_failed_commands_and_invalid_json_fail(self):
        for output, code in (
            ("[]", 1),
            ("", 0),
            ("{}", 0),
            ("null", 0),
            ("[false]", 0),
            ("invalid", 0),
        ):
            self.nodes["h1"].pexec.return_value = (output, "", code)
            with self.assertRaises(RuntimeError):
                topology.check_arp(self.net, 4)

    def test_arp_is_flushed_before_ping_and_read_before_raw_probes(self):
        ctrl = Mock()
        ctrl.proc.poll.return_value = None
        events = []
        for node in self.nodes.values():
            node.pexec.side_effect = lambda command: (
                events.append("flush") or "",
                "",
                0,
            )
        self.net.pingAll.side_effect = lambda **_opts: events.append("ping") or 0
        with patch.object(topology, "configure_test_interfaces"), patch.object(
            topology, "check_arp", side_effect=lambda *_args: events.append("arp")
        ), patch.object(
            topology, "run_probes", side_effect=lambda *_args: events.append("probes")
        ), patch(
            "sys.stdout", new=io.StringIO()
        ):
            self.assertEqual(topology.run_test(self.net, ctrl), 0)
        self.assertEqual(events, ["flush"] * 4 + ["ping", "arp", "probes"])

    def test_failed_flush_or_arp_validation_prevents_probe_success(self):
        ctrl = Mock()
        ctrl.proc.poll.return_value = None
        self.nodes["h1"].pexec.return_value = ("", "denied", 1)
        with patch.object(topology, "configure_test_interfaces"), patch.object(
            topology, "run_probes"
        ) as run, patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(self.net, ctrl), 1)
            run.assert_not_called()
        for node in self.nodes.values():
            node.pexec.return_value = ("", "", 0)
        self.net.pingAll.return_value = 0
        with patch.object(topology, "configure_test_interfaces"), patch.object(
            topology, "check_arp", side_effect=RuntimeError("ARP incomplete")
        ), patch.object(topology, "run_probes") as run, patch(
            "sys.stdout", new=io.StringIO()
        ):
            self.assertEqual(topology.run_test(self.net, ctrl), 1)
            run.assert_not_called()


class BroadcastL2CaptureTests(unittest.TestCase):
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


class BroadcastL2ProcessTests(unittest.TestCase):
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
                                if name in item["receivers"]
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

    def test_controller_exit_ping_loss_and_invalid_ping_result_fail(self):
        net, ctrl = Mock(), Mock()
        ctrl.proc.poll.return_value = 1
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(topology.run_test(net, ctrl), 1)
        net.get.assert_not_called()
        ctrl.proc.poll.return_value = None
        net.get.return_value.pexec.return_value = ("", "", 0)
        for dropped in (0, 0.1, False, None, float("nan"), float("inf")):
            net.pingAll.return_value = dropped
            with patch.object(topology, "configure_test_interfaces"), patch.object(
                topology, "run_probes"
            ), patch.object(topology, "check_arp"), patch(
                "sys.stdout", new=io.StringIO()
            ):
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
