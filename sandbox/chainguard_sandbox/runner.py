"""Host side of the sandbox: create a private job dir, launch the worker in an
isolated child, enforce wall-clock / memory / output limits, collect the result,
clean up.  This is the only module that knows *how* isolation is done; swap
`NamespaceBackend` for a Docker/gVisor backend with the same `run()` contract.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import toolchain

REPO_ROOT = toolchain.SANDBOX_DIR.parent
VENV_DIR = Path(os.environ.get("CHAINGUARD_SANDBOX_VENV", REPO_ROOT / ".venv"))
VENV_PY = VENV_DIR / "bin" / "python"
JOB_BASE = Path(os.environ.get("CHAINGUARD_SANDBOX_JOBDIR", Path(tempfile.gettempdir()) / "chainguard-jobs"))

# Host paths hidden from the worker (tmpfs mounted over them inside the sandbox).
COVER = ["/tmp", "/var/tmp", "/run", "/home", "/root", "/workspace", "/opt", "/uk",
         "/srv", "/media", "/dev/shm", "/var/run"]
# Outputs larger than these are truncated / treated as failure.
MAX_RESULT_BYTES = 48 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024


@dataclass
class Limits:
    wall_s: float = 60.0
    cpu_s: int = 60
    mem_mb: int = 2048             # RSS of the whole process tree (watchdog)
    as_soft_mb: int = 3072         # RLIMIT_AS soft limit (see nsinit.apply_rlimits)
    fsize_mb: int = 64             # max size of any single file written
    nproc: int = 128               # processes+threads inside the sandbox user ns
    nofile: int = 256


@dataclass
class RunResult:
    ok: bool
    result: Optional[dict]
    error: Optional[str]
    killed_reason: Optional[str]   # "timeout" | "memory" | "output" | None
    exit_code: Optional[int]
    wall_s: float
    max_rss_mb: float
    stderr_tail: str = ""
    jobdir_removed: bool = True
    extra: dict = field(default_factory=dict)


def isolation_available() -> tuple[bool, str]:
    if not shutil.which("unshare"):
        return False, "util-linux `unshare` not found"
    try:
        r = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
                            "--mount", "true"], capture_output=True, timeout=10, env={})
    except Exception as e:  # pragma: no cover
        return False, f"unshare failed: {e}"
    if r.returncode != 0:
        return False, "unprivileged user namespaces unavailable: " + r.stderr.decode(errors="replace")[:300]
    return True, "ok"


def _tree_rss_kb(root_pid: int) -> int:
    """Sum VmRSS of root_pid and all descendants (host view of /proc)."""
    children: dict[int, list[int]] = {}
    rss: dict[int, int] = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat", "rb") as fh:
                st = fh.read().decode(errors="replace")
            ppid = int(st.rsplit(")", 1)[1].split()[1])
            children.setdefault(ppid, []).append(int(d))
            with open(f"/proc/{d}/statm") as fh:
                rss[int(d)] = int(fh.read().split()[1]) * (os.sysconf("SC_PAGE_SIZE") // 1024)
        except (OSError, ValueError, IndexError):
            continue
    total, stack = 0, [root_pid]
    seen = set()
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        total += rss.get(p, 0)
        stack.extend(children.get(p, []))
    return total


def _read_capped(path: Path, cap: int) -> str:
    try:
        with open(path, "rb") as fh:
            data = fh.read(cap + 1)
    except OSError:
        return ""
    s = data[:cap].decode(errors="replace")
    return s + ("\n...[truncated]" if len(data) > cap else "")


def _tail(path: Path, cap: int) -> str:
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            fh.seek(max(0, size - cap))
            return fh.read().decode(errors="replace")
    except OSError:
        return ""


class NamespaceBackend:
    """unshare(1) user+net+pid+mount namespaces + rlimits + RSS watchdog."""

    name = "linux-userns"

    def run(self, mode: str, request: dict, files: dict[str, bytes], limits: Limits,
            keep_jobdir: bool = False) -> RunResult:
        JOB_BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(JOB_BASE, 0o700)
        jobdir = Path(tempfile.mkdtemp(prefix="job-", dir=JOB_BASE))
        os.chmod(jobdir, 0o700)
        t0 = time.monotonic()
        max_rss_kb = 0
        killed = None
        proc = None
        try:
            for sub in ("in", "out", "work", "home", "tmp"):
                (jobdir / sub).mkdir(mode=0o700)
            for name, data in files.items():  # names are pre-sanitised by api.py
                (jobdir / "in" / name).write_bytes(data)
            (jobdir / "in" / "request.json").write_text(json.dumps({"mode": mode, **request}))
            env = {
                "PATH": f"{toolchain.FOUNDRY_BIN}:/usr/local/bin:/usr/bin:/bin",
                "HOME": str(jobdir / "home"),
                "TMPDIR": str(jobdir / "tmp"),
                "LANG": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "CHAINGUARD_JOBDIR": str(jobdir),
                "CHAINGUARD_TOOLCHAIN": str(toolchain.TOOLCHAIN_DIR),
                "FOUNDRY_OFFLINE": "true",
                "NO_COLOR": "1",
            }
            cfg = {
                "jobdir": str(jobdir),
                "cwd": str(jobdir / "work"),
                "keep_ro": [str(VENV_DIR.resolve()), str(toolchain.PKG_DIR), str(toolchain.TOOLCHAIN_DIR)],
                "cover": COVER,
                "stage": "/mnt",
                "rlimits": {
                    "cpu_s": int(limits.cpu_s),
                    "fsize_b": limits.fsize_mb * 1024 * 1024,
                    "nproc": limits.nproc,
                    "nofile": limits.nofile,
                    "core": 0,
                    "as_soft_b": limits.as_soft_mb * 1024 * 1024,
                },
                "argv": [str(VENV_PY), "-I", "-B", str(toolchain.PKG_DIR / "worker.py"), str(jobdir)],
                "env": env,
            }
            cfg_path = jobdir / "nsinit.json"
            cfg_path.write_text(json.dumps(cfg))
            os.chmod(cfg_path, 0o400)
            cmd = ["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork", "--mount",
                   "--kill-child", "--", str(VENV_PY), "-I", "-B", str(toolchain.PKG_DIR / "nsinit.py"),
                   str(cfg_path)]
            with open(jobdir / "stdout.log", "wb") as so, open(jobdir / "stderr.log", "wb") as se:
                proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                        env={"PATH": "/usr/bin:/bin"}, cwd=str(jobdir),
                                        start_new_session=True, close_fds=True)
                deadline = t0 + limits.wall_s
                while proc.poll() is None:
                    now = time.monotonic()
                    rss = _tree_rss_kb(proc.pid)
                    max_rss_kb = max(max_rss_kb, rss)
                    if rss > limits.mem_mb * 1024:
                        killed = "memory"
                    elif now > deadline:
                        killed = "timeout"
                    else:
                        for lg in (jobdir / "stdout.log", jobdir / "stderr.log"):
                            try:
                                if lg.stat().st_size > limits.fsize_mb * 1024 * 1024:
                                    killed = "output"
                            except OSError:
                                pass
                    if killed:
                        self._kill(proc)
                        break
                    time.sleep(0.05)
                proc.wait(timeout=10)
            wall = time.monotonic() - t0
            code = proc.returncode
            stderr_tail = _tail(jobdir / "stderr.log", 4000)
            if code is not None and code < 0 and -code == signal.SIGXFSZ and not killed:
                killed = "output"
            if code == 128 + signal.SIGXFSZ and not killed:
                killed = "output"
            if code == 128 + signal.SIGXCPU or code == 128 + signal.SIGKILL and "CPU" in stderr_tail:
                killed = killed or "cpu"
            result = None
            rpath = jobdir / "out" / "result.json"
            if not killed and rpath.exists():
                if rpath.stat().st_size > MAX_RESULT_BYTES:
                    killed = "output"
                else:
                    try:
                        result = json.loads(rpath.read_text())
                    except (ValueError, UnicodeDecodeError) as e:
                        result = None
                        stderr_tail += f"\n[runner] result.json unreadable: {e}"
            err = None
            if killed:
                err = {"timeout": f"sandbox wall-clock limit exceeded ({limits.wall_s:.0f}s); process tree killed",
                       "memory": f"sandbox memory limit exceeded ({limits.mem_mb} MB RSS); process tree killed",
                       "output": f"sandbox output/file-size limit exceeded ({limits.fsize_mb} MB)",
                       "cpu": f"sandbox CPU-time limit exceeded ({limits.cpu_s}s)"}[killed]
            elif result is None:
                err = f"sandbox worker exited with code {code} and no result"
                if "nsinit:" in stderr_tail:
                    err += ": " + stderr_tail.split("nsinit:", 1)[1].strip()[:500]
            return RunResult(ok=result is not None and not killed, result=result, error=err,
                             killed_reason=killed, exit_code=code, wall_s=round(wall, 3),
                             max_rss_mb=round(max_rss_kb / 1024, 1), stderr_tail=stderr_tail[-2000:],
                             extra={"jobdir": str(jobdir)})
        finally:
            if proc is not None and proc.poll() is None:
                self._kill(proc)
            removed = True
            if not keep_jobdir:
                shutil.rmtree(jobdir, ignore_errors=True)
                removed = not jobdir.exists()
            # stash for tests
            NamespaceBackend.last_jobdir = str(jobdir)
            NamespaceBackend.last_jobdir_removed = removed

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        # unshare is the session/group leader; --kill-child makes the namespace's
        # PID 1 die with it, and the kernel then SIGKILLs every process in the
        # PID namespace (even ones that setsid()'d away from our process group).
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            pass


BACKEND = NamespaceBackend()
