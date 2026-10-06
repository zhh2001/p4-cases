"""Check learning readback and packet evidence without requiring root."""

import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


CASE = Path(__file__).resolve().parents[1] / "05_l2_learning_switch"


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, CASE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


topology = load_module("learning_topology", "topology.py")
probe = load_module("learning_probe", "test.py")
SRC = "00:00:00:00:00:01"
DST = "00:00:00:00:00:02"


def table_dump(source, entries=()):
    field = "srcAddr" if source else "dstAddr"
    blocks = []
    for number, (mac, port) in enumerate(entries):
        action = "NoAction - " if source else f"MyIngress.forward - {port}"
        blocks.append(
            f"Dumping entry 0x{number:x}\nMatch key:\n"
            f"* ethernet.{field} : EXACT {mac.replace(':', '')}\n"
            f"Action entry: {action}\n**********\n"
        )
    return (
        "Obtaining JSON from switch...\nDone\nRuntimeCmd: ==========\n"
        "TABLE ENTRIES\n**********\n"
        + "".join(blocks)
        + "==========\nDumping default entry\nAction entry: "
        + ("MyIngress.mac_learn - " if source else "NoAction - ")
        + "\n==========\nRuntimeCmd: "
    )


def network():
    hosts = [
        SimpleNamespace(name="h1", MAC=lambda: SRC),
        SimpleNamespace(name="h2", MAC=lambda: DST),
    ]
    return SimpleNamespace(
        hosts=hosts, get=lambda name: SimpleNamespace(thrift_port=9090)
    )


class LearningTableTests(unittest.TestCase):
    def test_native_cli_entries_and_canonical_ports(self):
        self.assertEqual(
            topology.parse_learning_table(table_dump(True, [(SRC, None)]), True),
            {SRC: None},
        )
        for port in ("02", "0002"):
            self.assertEqual(
                topology.parse_learning_table(table_dump(False, [(DST, port)]), False),
                {DST: 2},
            )
        self.assertEqual(topology.parse_learning_table(table_dump(False), False), {})

    def test_malformed_and_failed_reads_are_rejected(self):
        valid = table_dump(False, [(DST, "02")])
        for output in (
            "",
            valid.replace("TABLE ENTRIES", ""),
            valid + "\nError: unavailable",
            valid.replace("MyIngress.forward - 02", "NoAction - "),
            valid.replace("000000000002", "0002"),
            table_dump(False, [(DST, "00")]),
            table_dump(False, [(DST, "0200")]),
            table_dump(False, [(DST, "02"), (DST, "03")]),
        ):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                topology.parse_learning_table(output, False)

    def test_source_action_must_suppress_learning(self):
        for action in ("MyIngress.mac_learn - ", "NoAction - 01"):
            output = table_dump(True, [(SRC, None)]).replace("NoAction - ", action)
            with self.subTest(action=action), self.assertRaises(RuntimeError):
                topology.parse_learning_table(output, True)

    def test_cli_process_failure_cannot_return_empty_tables(self):
        result = subprocess.CompletedProcess([], 1, "", "connection refused")
        with patch.object(topology.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "smac read failed"):
                topology.read_learning_tables(9090)

    def test_missing_or_wrong_bindings_do_not_pass(self):
        for tables in (({}, {}), ({SRC: None, DST: None}, {SRC: 2, DST: 1})):
            with self.subTest(tables=tables):
                with patch.object(
                    topology, "read_learning_tables", return_value=tables
                ):
                    with self.assertRaisesRegex(RuntimeError, "did not complete"):
                        topology.wait_learning(network(), timeout=0.02)

    def test_matching_bindings_pass_with_unrelated_entries(self):
        tables = ({SRC: None, DST: None, "02:aa:bb:cc:dd:ee": None}, {SRC: 1, DST: 2})
        with patch.object(topology, "read_learning_tables", return_value=tables):
            topology.wait_learning(network(), timeout=0.1)

    def test_successful_ping_does_not_replace_learning_evidence(self):
        net = Mock()
        net.hosts = network().hosts
        net.pingAll.return_value = 0
        with patch.object(topology, "probe_forwarding"), patch.object(
            topology,
            "wait_learning",
            side_effect=RuntimeError("missing learned entries"),
        ):
            self.assertEqual(topology.run_test(net, Mock()), 1)
        net.pingAll.assert_called_once()

    def test_host_mac_uses_hexadecimal_octets(self):
        self.assertEqual(topology.host_mac(10), "00:00:00:00:00:0a")
        self.assertEqual(topology.host_mac(100), "00:00:00:00:00:64")
        self.assertEqual(topology.host_mac(254), "00:00:00:00:00:fe")


class DeliveryTests(unittest.TestCase):
    def packets(self):
        return [{"src": SRC, "dst": DST, "sequence": n} for n in range(3)]

    def test_unicast_and_flooding_have_distinct_delivery(self):
        packets = {"h1": [], "h2": self.packets(), "h3": []}
        topology.check_delivery(packets, SRC, DST, {"h2"}, 3)
        packets["h3"] = self.packets()
        with self.assertRaises(RuntimeError):
            topology.check_delivery(packets, SRC, DST, {"h2"}, 3)
        topology.check_delivery(packets, SRC, DST, {"h2", "h3"}, 3)

    def test_capture_loss_duplicates_headers_and_types_are_rejected(self):
        for received in (
            [],
            self.packets()[:2],
            self.packets() + self.packets()[:1],
            None,
            [{"src": DST, "dst": DST, "sequence": n} for n in range(3)],
            [{"src": SRC, "dst": DST, "sequence": str(n)} for n in range(3)],
        ):
            with self.subTest(received=received), self.assertRaises(RuntimeError):
                topology.check_delivery({"h2": received}, SRC, DST, {"h2"}, 3)
        with self.assertRaises(RuntimeError):
            topology.check_delivery({}, SRC, DST, {"h2"}, 3)

    def test_failed_capture_is_not_zero_packet_delivery(self):
        proc = Mock(returncode=1)
        proc.communicate.return_value = ('{"packets": []}', "interface unavailable")
        with self.assertRaisesRegex(RuntimeError, "packet probe failed"):
            topology.read_probe(proc)

    def test_invalid_capture_reply_is_rejected(self):
        for output in ("", "[]", "null", "not JSON"):
            proc = Mock(returncode=0)
            proc.communicate.return_value = (output, "")
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                topology.read_probe(proc)

    def test_capture_failure_makes_case_fail(self):
        with patch.object(
            topology, "probe_forwarding", side_effect=RuntimeError("capture failed")
        ):
            self.assertEqual(topology.run_test(network(), Mock()), 1)

    def test_probe_process_is_reaped_after_term_timeout(self):
        proc = Mock()
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired("probe", 1), 0]
        topology.stop_probe(proc)
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()
        self.assertEqual(proc.wait.call_count, 2)
        proc.stdout.close.assert_called_once()
        proc.stderr.close.assert_called_once()


class ProbeFrameTests(unittest.TestCase):
    def test_frame_round_trip_and_filtering(self):
        frame = probe.make_frame(SRC, DST, "sample", 2)
        self.assertGreaterEqual(len(frame), 60)
        self.assertEqual(
            probe.decode_frame(frame, "sample"), {"src": SRC, "dst": DST, "sequence": 2}
        )
        self.assertIsNone(probe.decode_frame(frame, "other"))
        self.assertIsNone(probe.decode_frame(frame[:10], "sample"))
        self.assertIsNone(
            probe.decode_frame(frame[:12] + b"\x08\x00" + frame[14:], "sample")
        )

    def test_malformed_matching_payload_is_not_ignored(self):
        frame = probe.make_frame(SRC, DST, "sample", 0)
        frame = frame[:14] + probe.PREFIX + b"sample:invalid"
        with self.assertRaises(ValueError):
            probe.decode_frame(frame, "sample")


if __name__ == "__main__":
    unittest.main()
