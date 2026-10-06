"""Exercise controller deadlines and cleanup using real subprocesses."""

import os
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from common.runtime import Controller, NetworkRuntime, stop_process


class ControllerTests(unittest.TestCase):
    def setUp(self):
        quiet = patch("common.runtime.info")
        quiet.start()
        self.addCleanup(quiet.stop)

    def controller(self, script, **kwargs):
        controller = Controller([sys.executable, "-u", "-c", script], **kwargs)
        self.addCleanup(controller.close)
        return controller

    def test_silent_controller_obeys_deadline(self):
        controller = self.controller("import time; time.sleep(60)")
        started = time.monotonic()
        self.assertFalse(controller.wait_ready("ready", timeout=0.1))
        self.assertLess(time.monotonic() - started, 0.6)
        self.assertIsNone(controller.proc.poll())

    def test_partial_line_does_not_block_deadline(self):
        controller = self.controller(
            "import time; print('ready', end='', flush=True); time.sleep(60)"
        )
        started = time.monotonic()
        self.assertFalse(controller.wait_ready("ready", timeout=0.1))
        self.assertLess(time.monotonic() - started, 0.6)

    def test_stderr_blank_lines_and_final_unterminated_line(self):
        controller = self.controller(
            "import sys; print(); print('ready', file=sys.stderr); "
            "print('last', end='', flush=True)"
        )
        self.assertEqual(controller.readline(2), "")
        self.assertTrue(controller.wait_ready("ready", timeout=2))
        self.assertEqual(list(controller.lines_for(2)), ["last"])

    def test_early_exit_returns_without_waiting_for_timeout(self):
        controller = self.controller("raise SystemExit(7)")
        started = time.monotonic()
        self.assertFalse(controller.wait_ready("ready", timeout=5))
        self.assertEqual(controller.proc.wait(timeout=2), 7)
        self.assertLess(time.monotonic() - started, 1)

    def test_output_is_consumed_after_readiness(self):
        controller = self.controller(
            "import time; print('ready', flush=True); time.sleep(0.2); "
            "[print('x'*100) for _ in range(10000)]"
        )
        self.assertTrue(controller.wait_ready("ready", timeout=2))
        # More than a pipe's capacity must not stall a controller in CLI mode.
        self.assertEqual(controller.proc.wait(timeout=3), 0)
        controller._reader.join(timeout=1)
        with self.assertRaisesRegex(RuntimeError, "unread output exceeded"):
            controller.readline(0.1)

    def test_interactive_commands_and_close_are_supported(self):
        controller = self.controller(
            "import sys; print('ready', flush=True); "
            "\nfor line in sys.stdin:\n"
            " if line.strip() == 'quit': break\n"
            " print(line.strip() + '-done', flush=True)\n",
            interactive=True,
        )
        self.assertTrue(controller.wait_ready("ready", timeout=2))
        controller.send("dump")
        self.assertEqual(controller.readline(2), "dump-done")
        controller.close()
        controller.close()
        self.assertIsNotNone(controller.proc.returncode)
        self.assertFalse(controller._reader.is_alive())
        self.assertTrue(controller.proc.stdout.closed)
        self.assertTrue(controller.proc.stdin.closed)

    def test_close_after_child_closed_stdin(self):
        controller = self.controller("raise SystemExit(0)", interactive=True)
        controller.proc.wait(timeout=2)
        controller.close()
        self.assertTrue(controller.proc.stdout.closed)

    def test_force_stop_reaps_a_process_ignoring_term(self):
        controller = self.controller(
            "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); time.sleep(60)"
        )
        self.assertTrue(controller.wait_ready("ready", timeout=2))
        with patch("common.runtime.warn"):
            stop_process(controller.proc, timeout=0.1)
        self.assertEqual(controller.proc.returncode, -signal.SIGKILL)

    def test_thread_start_failure_stops_child(self):
        children = []

        real_spawn = subprocess.Popen

        def tracked_spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            children.append(child)
            return child

        with patch("common.runtime.threading.Thread.start", side_effect=RuntimeError):
            with patch("common.runtime.subprocess.Popen", side_effect=tracked_spawn):
                with self.assertRaises(RuntimeError):
                    Controller([sys.executable, "-c", "import time; time.sleep(60)"])
                self.assertIsNotNone(children[0].returncode)


class NetworkRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.handlers = {
            signum: signal.getsignal(signum)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }
        net_patch = patch("common.runtime.Mininet")
        self.network = net_patch.start().return_value
        self.addCleanup(net_patch.stop)
        self.addCleanup(self.assert_handlers_restored)

    def assert_handlers_restored(self):
        for signum, handler in self.handlers.items():
            self.assertEqual(signal.getsignal(signum), handler)

    def test_build_and_start_errors_stop_network(self):
        for method in ("build", "start"):
            with self.subTest(method=method):
                self.network.reset_mock()
                getattr(self.network, method).side_effect = RuntimeError(method)
                with self.assertRaisesRegex(RuntimeError, method):
                    with NetworkRuntime(object()):
                        self.fail("startup should fail")
                self.network.stop.assert_called_once()
                getattr(self.network, method).side_effect = None
                self.assert_handlers_restored()

    def test_later_controller_launch_error_stops_previous_controller(self):
        first = Mock(label="first")
        with patch("common.runtime.Controller", side_effect=[first, OSError("launch")]):
            with self.assertRaisesRegex(OSError, "launch"):
                with NetworkRuntime(object()) as runtime:
                    runtime.start_controller(["first"])
                    runtime.start_controller(["second"])
        first.close.assert_called_once()
        self.network.stop.assert_called_once()

    def test_body_error_stops_all_controllers_even_if_one_close_fails(self):
        first, second = Mock(label="first"), Mock(label="second")
        second.close.side_effect = RuntimeError("close")
        with patch("common.runtime.Controller", side_effect=[first, second]):
            with patch("common.runtime.warn"):
                with self.assertRaisesRegex(ValueError, "test"):
                    with NetworkRuntime(object()) as runtime:
                        runtime.start_controller(["first"])
                        runtime.start_controller(["second"])
                        raise ValueError("test")
        first.close.assert_called_once()
        second.close.assert_called_once()
        self.network.stop.assert_called_once()

    def test_signal_exits_through_cleanup(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                self.network.reset_mock()
                with self.assertRaises(SystemExit) as caught:
                    with NetworkRuntime(object()):
                        os.kill(os.getpid(), signum)
                self.assertEqual(caught.exception.code, 128 + signum)
                self.network.stop.assert_called_once()
                self.assert_handlers_restored()

    def test_stop_error_still_restores_signal_handlers(self):
        self.network.stop.side_effect = RuntimeError("stop")
        with self.assertRaisesRegex(RuntimeError, "stop"):
            with NetworkRuntime(object()):
                pass


if __name__ == "__main__":
    unittest.main()
