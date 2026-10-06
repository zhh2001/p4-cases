"""Controller output and network lifecycles shared by the case topologies."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator, Sequence
import os
import signal
import subprocess
import threading
import time

from mininet.log import info, warn
from mininet.net import Mininet


def stop_process(proc: subprocess.Popen, timeout: float = 3.0) -> None:
    """Stop and reap a process launched with start_new_session=True."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        warn(f"!!! Process {proc.pid} did not stop within {timeout:g}s\n")
    finally:
        # Also stop descendants if the parent exited before its children.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()


class Controller:
    """Consume logs continuously and expose reads with a real deadline."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        label: str = "controller",
        interactive: bool = False,
    ) -> None:
        self.label = label
        self._lines: deque[str] = deque(maxlen=4096)
        self._condition = threading.Condition()
        self._eof = False
        self._overflow = False
        self._error: Exception | None = None
        self._closed = False
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            start_new_session=True,
        )
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        try:
            self._reader.start()
        except BaseException:
            self.close()
            raise

    def _read_output(self) -> None:
        try:
            for line in self.proc.stdout:
                line = line.rstrip("\r\n")
                with self._condition:
                    if len(self._lines) == self._lines.maxlen:
                        self._overflow = True
                    self._lines.append(line)
                    self._condition.notify_all()
                info(f"    {self.label}: {line}\n")
        except Exception as exc:
            self._error = exc
        finally:
            with self._condition:
                self._eof = True
                self._condition.notify_all()

    def readline(self, timeout: float) -> str | None:
        """Return the next line, or None on EOF or timeout."""
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                if self._overflow:
                    raise RuntimeError(
                        f"{self.label}: unread output exceeded 4096 lines"
                    )
                if self._error:
                    raise RuntimeError(
                        f"{self.label}: output reader failed"
                    ) from self._error
                if self._lines:
                    return self._lines.popleft()
                if self._eof:
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)

    def lines_for(self, seconds: float) -> Iterator[str]:
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            line = self.readline(remaining)
            if line is None:
                break
            yield line

    def wait_ready(self, banner: str, timeout: float = 15.0) -> bool:
        return any(banner in line for line in self.lines_for(timeout))

    def send(self, command: str) -> None:
        if self.proc.stdin is None:
            raise RuntimeError(f"{self.label}: stdin commands are disabled")
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.proc.stdin is not None:
                try:
                    self.send("quit")
                    self.proc.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
        finally:
            stop_process(self.proc)
            if self._reader.ident is not None:
                self._reader.join(timeout=1)
            if self.proc.stdin is not None:
                try:
                    self.proc.stdin.close()
                except BrokenPipeError:
                    pass
            self.proc.stdout.close()


class NetworkRuntime:
    """Clean up this network and its controllers, including failed startup."""

    def __init__(self, topo) -> None:
        self.net = Mininet(topo=topo, controller=None, build=False)
        self._controllers: list[Controller] = []
        self._handlers: dict[int, object] = {}
        self._closed = False

    @staticmethod
    def _interrupt(signum, _frame) -> None:
        raise SystemExit(128 + signum)

    def __enter__(self) -> NetworkRuntime:
        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                self._handlers[signum] = signal.signal(signum, self._interrupt)
            self.net.build()
            self.net.start()
        except BaseException:
            self.close()
            raise
        return self

    def start_controller(self, command: Sequence[str], **kwargs) -> Controller:
        controller = Controller(command, **kwargs)
        self._controllers.append(controller)
        return controller

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # A second signal must not interrupt network teardown.
        for signum in self._handlers:
            signal.signal(signum, signal.SIG_IGN)
        try:
            for controller in reversed(self._controllers):
                try:
                    controller.close()
                except Exception as exc:
                    warn(f"!!! {controller.label}: cleanup failed: {exc}\n")
            self.net.stop()
        finally:
            for signum, handler in self._handlers.items():
                signal.signal(signum, handler)

    def __exit__(self, _exc_type, _exc_value, _traceback) -> None:
        self.close()
