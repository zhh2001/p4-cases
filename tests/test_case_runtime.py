"""Check that every case uses the shared bounded output readers."""

import importlib.util
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock, patch

from common.runtime import Controller


ROOT = Path(__file__).resolve().parents[1]


def load_case(case):
    path = next(ROOT.glob(f"{case:02d}_*/topology.py"))
    spec = importlib.util.spec_from_file_location(f"case_{case}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CaseRuntimeTests(unittest.TestCase):
    def setUp(self):
        quiet = patch("common.runtime.info")
        quiet.start()
        self.addCleanup(quiet.stop)

    def controller(self, script, **kwargs):
        controller = Controller([sys.executable, "-u", "-c", script], **kwargs)
        self.addCleanup(controller.close)
        return controller

    def test_all_fourteen_readiness_helpers_obey_deadlines(self):
        for case in range(1, 15):
            with self.subTest(case=case):
                module = load_case(case)
                controller = self.controller("import time; time.sleep(60)")
                helper = next(
                    getattr(module, name)
                    for name in (
                        "wait_controller_ready",
                        "wait_ready",
                        "wait_all_ready",
                    )
                    if hasattr(module, name)
                )
                arg = [controller] if case == 6 else controller
                started = time.monotonic()
                self.assertFalse(helper(arg, timeout=0.05))
                self.assertLess(time.monotonic() - started, 0.5)
                controller.close()

    def test_learning_grace_window_and_packet_in_window_end_in_silence(self):
        controller = self.controller("import time; time.sleep(60)")
        started = time.monotonic()
        load_case(5).drain_controller(controller, 0.1)
        self.assertEqual(load_case(13).count_packet_ins(controller, 0.1), 0)
        self.assertLess(time.monotonic() - started, 0.7)

    def test_counter_and_register_controllers_keep_stdin_open(self):
        for case in (8, 12):
            with self.subTest(case=case):
                runtime = Mock()
                load_case(case).start_controller(
                    runtime, "controller", "info", "config"
                )
                self.assertTrue(
                    runtime.start_controller.call_args.kwargs["interactive"]
                )

    def test_counter_dump_requires_terminator(self):
        controller = self.controller(
            "import sys; sys.stdin.readline(); print('port=1 packets=7 bytes=70')",
            interactive=True,
        )
        with self.assertRaisesRegex(RuntimeError, "did not complete"):
            load_case(8).dump_counters(controller)

    def test_counter_dump_parses_complete_reply(self):
        controller = self.controller(
            "import sys; sys.stdin.readline(); "
            "print('port=1 packets=7 bytes=70'); print('dump-done')",
            interactive=True,
        )
        self.assertEqual(
            load_case(8).dump_counters(controller),
            {1: {"packets": 7, "bytes": 70}},
        )

    def test_counter_dump_times_out_on_silent_controller(self):
        controller = self.controller("import time; time.sleep(60)", interactive=True)
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "within 4s"):
            load_case(8).dump_counters(controller)
        self.assertLess(time.monotonic() - started, 4.8)


if __name__ == "__main__":
    unittest.main()
