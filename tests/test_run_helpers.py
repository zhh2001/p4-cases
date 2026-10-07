"""Exercise shell exit status, stdin and cleanup of the owned topology."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "common/run_helpers.sh"


class RunHelpersTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def topology(self, code):
        path = self.directory / "topology.py"
        path.write_text(code)
        return path

    def command(self, topology):
        return [
            "bash",
            "-c",
            'source "$1"; trap_cleanup; start_topology "$2"',
            "test",
            str(HELPERS),
            str(topology),
        ]

    def test_topology_exit_code_is_preserved(self):
        for status in (0, 7):
            with self.subTest(status=status):
                result = subprocess.run(
                    self.command(self.topology(f"raise SystemExit({status})\n")),
                    capture_output=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, status)

    def test_cli_stdin_reaches_topology(self):
        result = subprocess.run(
            self.command(self.topology("print(input())\n")),
            input="nodes\n",
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "nodes")

    def test_meter_and_counter_runs_use_fresh_matching_artifacts(self):
        fixture = self.directory / "repo"
        (fixture / "common").mkdir(parents=True)
        # The isolated fixture needs no real network or elevated privileges.
        (fixture / "common/run_helpers.sh").write_text(
            HELPERS.read_text() + "\nrequire_root() { :; }\n"
        )
        commands = self.directory / "commands"
        commands.mkdir()
        fake_compiler = commands / "p4c"
        fake_compiler.write_text(
            f"#!{sys.executable}\n"
            "from pathlib import Path\nimport sys\n"
            "args = sys.argv[1:]\n"
            "source = Path(args[-1])\n"
            "info = Path(args[args.index('--p4runtime-files') + 1])\n"
            "config = Path(args[args.index('-o') + 1]) / (source.stem + '.json')\n"
            "info.write_text(source.read_text())\n"
            "config.write_text(source.read_text())\n"
        )
        fake_topology = commands / "python3"
        fake_topology.write_text(
            f"#!{sys.executable}\n"
            "from pathlib import Path\nimport sys\n"
            "args = sys.argv[1:]\n"
            "info = Path(args[args.index('--p4info') + 1])\n"
            "config = Path(args[args.index('--config') + 1])\n"
            "assert info.read_text() == config.read_text()\n"
            "print(config.name + ':' + config.read_text())\n"
        )
        fake_compiler.chmod(0o755)
        fake_topology.chmod(0o755)
        environment = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}")
        for case, stem, options in (
            ("07_meter", "indirect_meter", []),
            ("08_counter", "indirect_counter", []),
            ("08_counter", "direct_counter", ["test", "direct"]),
        ):
            with self.subTest(case=case, stem=stem):
                directory = fixture / case
                (directory / "build").mkdir(parents=True, exist_ok=True)
                script = directory / "run.sh"
                script.write_text((ROOT / case / "run.sh").read_text())
                (directory / "build/main.json").write_text("stale pipeline")
                for content in ("first pipeline", "second pipeline"):
                    (directory / f"{stem}.p4").write_text(content)
                    result = subprocess.run(
                        [
                            "bash",
                            "-c",
                            'go() { : > "$3"; }; export -f go; exec bash "$@"',
                            "test",
                            str(script),
                            *options,
                        ],
                        env=environment,
                        text=True,
                        capture_output=True,
                        timeout=5,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), f"{stem}.json:{content}")
                    self.assertEqual(
                        (directory / "build/main.json").read_text(), "stale pipeline"
                    )

    def test_term_and_int_stop_only_owned_topology(self):
        sentinel = subprocess.Popen(
            [
                "python3",
                "-c",
                "import time; time.sleep(60)",
                "simple_switch_grpc",
            ]
        )
        self.addCleanup(sentinel.wait)
        self.addCleanup(sentinel.terminate)
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signum=signum):
                ready = self.directory / f"ready-{signum}"
                cleaned = self.directory / f"cleaned-{signum}"
                topology = self.topology(
                    "import os, signal, time\n"
                    "from pathlib import Path\n"
                    "def stop(signum, frame):\n"
                    f" Path({str(cleaned)!r}).write_text('stopped')\n"
                    " raise SystemExit(128 + signum)\n"
                    "signal.signal(signal.SIGTERM, stop)\n"
                    "signal.signal(signal.SIGINT, stop)\n"
                    f"Path({str(ready)!r}).write_text(str(os.getpid()))\n"
                    "time.sleep(60)\n"
                )
                shell = subprocess.Popen(
                    self.command(topology),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(ready.exists())
                    child_pid = int(ready.read_text())
                    shell.send_signal(signum)
                    self.assertEqual(shell.wait(timeout=5), 128 + signum)
                    self.assertTrue(cleaned.exists())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
                    self.assertIsNone(sentinel.poll())
                finally:
                    if shell.poll() is None:
                        os.killpg(shell.pid, signal.SIGKILL)
                        shell.wait()


if __name__ == "__main__":
    unittest.main()
