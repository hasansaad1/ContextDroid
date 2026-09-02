"""Shared subprocess helpers with hard timeout and process-group teardown."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
from typing import Optional


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=2)
    except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired, OSError):
        pass
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def run_subprocess_with_timeout(
    cmd: list[str],
    *,
    check: bool = False,
    text: bool = True,
    timeout_sec: Optional[float] = None,
) -> subprocess.CompletedProcess:
    """Run a command; on timeout kill the process group so hung adb clients cannot linger."""
    if timeout_sec is None:
        return subprocess.run(cmd, check=check, text=text, capture_output=text)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired as exc:
        logging.warning("Command timed out after %.1fs: %s", timeout_sec, " ".join(cmd))
        _terminate_process_tree(proc)
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="ignore")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="ignore")
        if not str(stderr).strip():
            stderr = f"timeout after {timeout_sec}s"
        result = subprocess.CompletedProcess(cmd, 124, stdout, stderr)
        if check:
            raise subprocess.CalledProcessError(result.returncode, cmd, output=stdout, stderr=stderr)
        return result

    result = subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=stdout, stderr=stderr)
    return result
