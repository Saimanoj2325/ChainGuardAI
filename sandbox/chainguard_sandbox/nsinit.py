"""In-namespace init for a sandbox job.  Runs as PID 1 of a fresh
user+net+pid+mount namespace (started by runner.py via `unshare`).

Steps (each failure is fatal: we never run the worker half-isolated):
  1. make all mounts private, so nothing propagates back to the host
  2. hide host data: tmpfs over /tmp /run /home /root /workspace /opt /uk ...
     then bind back ONLY the paths the worker needs (venv, sandbox package,
     toolchain, the job dir)
  3. remount every mount read-only except the job dir
  4. mount a fresh /proc for the new PID namespace (host processes invisible)
  5. apply rlimits, chdir into the job dir, exec the worker with a scrubbed env

Invoked as:  python -I nsinit.py <config.json>
The config is written by the host (runner.py) and is trusted.
"""
from __future__ import annotations

import ctypes
import json
import os
import resource
import sys

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_NOATIME = 1024
MS_NODIRATIME = 2048
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_RELATIME = 1 << 21
MS_STRICTATIME = 1 << 24

ST_TO_MS = {2: MS_NOSUID, 4: MS_NODEV, 8: MS_NOEXEC, 1024: MS_NOATIME, 2048: MS_NODIRATIME, 4096: MS_RELATIME}

_libc = ctypes.CDLL(None, use_errno=True)
_libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]


def die(msg: str) -> None:
    sys.stderr.write("nsinit: " + msg + "\n")
    sys.stderr.flush()
    os._exit(97)


def mount(src, target, fstype, flags, data=None, check=True) -> int:
    r = _libc.mount(src.encode() if src else None, target.encode(),
                    fstype.encode() if fstype else None, flags,
                    data.encode() if data else None)
    if r != 0:
        e = ctypes.get_errno()
        if check:
            die(f"mount({src!r},{target!r},{fstype!r},{flags:#x}) failed: {os.strerror(e)}")
        return e
    return 0


def locked_flags(path: str) -> int:
    f = os.statvfs(path).f_flag
    out = 0
    for st, ms in ST_TO_MS.items():
        if f & st:
            out |= ms
    return out


def mountpoints() -> list[str]:
    pts = []
    with open("/proc/self/mountinfo") as fh:
        for line in fh:
            mp = line.split()[4].encode().decode("unicode_escape")
            pts.append(mp)
    return pts


def under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def setup_mounts(cfg: dict) -> None:
    jobdir = cfg["jobdir"]
    keep_ro = [p for p in cfg["keep_ro"] if os.path.exists(p)]
    cover = [p for p in cfg["cover"] if os.path.isdir(p) and not os.path.islink(p)]
    stage = cfg.get("stage", "/mnt")

    mount(None, "/", None, MS_REC | MS_PRIVATE)
    # 1) staging tmpfs; bind every kept path into it before hiding its parent
    mount("tmpfs", stage, "tmpfs", MS_NOSUID | MS_NODEV, "size=1m,mode=0755")
    keep = [(p, True) for p in keep_ro] + [(jobdir, False)]
    staged = []
    for i, (p, ro) in enumerate(keep):
        s = os.path.join(stage, str(i))
        if os.path.isdir(p):
            os.mkdir(s)
        else:
            open(s, "w").close()
        mount(p, s, None, MS_BIND | MS_REC)
        staged.append((s, p, ro))
    # 2) hide host data
    for c in cover:
        if c == stage:
            continue
        mount("tmpfs", c, "tmpfs", MS_NOSUID | MS_NODEV, "size=4m,mode=0755")
    # 3) move kept paths back to their original locations
    for s, p, ro in staged:
        if os.path.isdir(s):
            os.makedirs(p, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if not os.path.exists(p):
                open(p, "w").close()
        mount(s, p, None, MS_MOVE)
    # 4) fresh /proc for this PID namespace
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    # 5) read-only everything except the job dir (and /proc, /dev nodes stay usable)
    for mp in sorted(set(mountpoints()), key=len):
        if under(mp, jobdir) or under(mp, "/proc"):
            continue
        try:
            flags = locked_flags(mp)
        except OSError:
            continue
        e = mount(None, mp, None, MS_REMOUNT | MS_BIND | MS_RDONLY | flags, check=False)
        if e and cfg.get("strict_ro", True) and not under(mp, "/sys") and not under(mp, "/dev"):
            die(f"could not remount {mp} read-only: {os.strerror(e)}")
    # the job dir: rw but nosuid/nodev
    mount(None, jobdir, None, MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV | locked_flags(jobdir), check=False)


def apply_rlimits(lim: dict) -> None:
    table = {
        "cpu_s": resource.RLIMIT_CPU,
        "fsize_b": resource.RLIMIT_FSIZE,
        "nproc": resource.RLIMIT_NPROC,
        "nofile": resource.RLIMIT_NOFILE,
        "core": resource.RLIMIT_CORE,
    }
    for k, r in table.items():
        if k in lim:
            resource.setrlimit(r, (lim[k], lim[k]))
    if lim.get("as_soft_b"):
        # Soft AS only: the wasm solc (node/V8) needs a huge virtual reservation and
        # raises its own soft limit. The hard memory backstop is the host-side RSS
        # watchdog in runner.py.
        resource.setrlimit(resource.RLIMIT_AS, (lim["as_soft_b"], resource.RLIM_INFINITY))


def main() -> None:
    with open(sys.argv[1]) as fh:
        cfg = json.load(fh)
    if os.getpid() != 1:
        die("expected to be PID 1 of a new pid namespace")
    setup_mounts(cfg)
    os.chdir(cfg["cwd"])
    os.umask(0o077)
    apply_rlimits(cfg["rlimits"])
    argv = cfg["argv"]
    env = cfg["env"]
    # PID 1 must reap; fork the worker and wait so zombies don't accumulate and
    # our exit status mirrors the worker's.
    pid = os.fork()
    if pid == 0:
        try:
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    status = 0
    while True:
        try:
            p, st = os.wait()
        except ChildProcessError:
            break
        if p == pid:
            status = st
    if os.WIFSIGNALED(status):
        os._exit(128 + os.WTERMSIG(status))
    os._exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)


if __name__ == "__main__":
    main()
