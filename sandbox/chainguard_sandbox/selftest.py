"""Fixed isolation probes run INSIDE the sandbox by the security tests.
Not reachable through api.analyze/validate (no arbitrary code execution);
runner.BACKEND.run("selftest", {"probe": name}) only.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path


def _try(fn):
    try:
        return {"ok": True, "value": fn()}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def probe_network(jobdir, req):
    out = {}
    def tcp(host, port):
        s = socket.create_connection((host, port), timeout=3)
        s.close()
        return "connected"
    out["tcp_1.1.1.1_443"] = _try(lambda: tcp("1.1.1.1", 443))
    out["dns_example.com"] = _try(lambda: socket.gethostbyname("example.com"))
    out["tcp_api.instabox.sh_443"] = _try(lambda: tcp("api.instabox.sh", 443))
    out["ifaces"] = _try(lambda: sorted(os.listdir("/sys/class/net")))
    out["proc_net_dev"] = _try(lambda: [l.split(":")[0].strip() for l in open("/proc/net/dev").read().splitlines()[2:]])
    return out


def probe_env(jobdir, req):
    environ = None
    try:
        environ = open("/proc/1/environ", "rb").read().decode(errors="replace")
    except OSError as e:
        environ = f"unreadable: {e}"
    return {"env": dict(os.environ), "proc1_environ": environ,
            "pids_visible": sorted(int(p) for p in os.listdir("/proc") if p.isdigit())}


def probe_fs(jobdir, req):
    res = {}
    for target in req.get("write_targets", []):
        def w(t=target):
            Path(t).write_text("pwned")
            return "written"
        res[target] = _try(w)
    for target in req.get("read_targets", []):
        res["read:" + target] = _try(lambda t=target: (os.listdir(t) if os.path.isdir(t) else Path(t).read_text()[:100]))
    res["inside_jobdir"] = _try(lambda: (Path(os.environ["TMPDIR"]) / "ok.txt").write_text("ok"))
    return res


def probe_cpu(jobdir, req):
    while True:
        pass


def probe_memory(jobdir, req):
    # bypass the RLIMIT_AS soft limit like the wasm compiler does, then allocate
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    blocks = []
    while True:
        blocks.append(bytearray(64 * 1024 * 1024))
        for i in range(0, len(blocks[-1]), 4096):
            blocks[-1][i] = 1


def probe_memory_rlimit(jobdir, req):
    blocks = []
    try:
        while True:
            blocks.append(bytearray(256 * 1024 * 1024))
    except MemoryError:
        return {"memory_error_after_mb": 256 * len(blocks)}


def probe_output(jobdir, req):
    chunk = "A" * (1024 * 1024)
    while True:
        sys.stdout.write(chunk)


def probe_bigfile(jobdir, req):
    with open(Path(os.environ["TMPDIR"]) / "big.bin", "wb") as fh:
        while True:
            fh.write(b"\0" * (1024 * 1024))


def probe_fork(jobdir, req):
    n, err = 0, None
    procs = []
    try:
        for _ in range(req.get("max", 10000)):
            procs.append(subprocess.Popen(["sleep", "30"]))
            n += 1
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    for p in procs:
        p.kill()
    return {"spawned": n, "error": err}


def probe_escape_setsid(jobdir, req):
    # a grandchild that leaves our process group and sleeps forever
    subprocess.Popen(["setsid", "sleep", "1000"], start_new_session=True)
    while True:
        pass


PROBES = {k[6:]: v for k, v in globals().items() if k.startswith("probe_")}


def run(jobdir, req):
    fn = PROBES.get(req.get("probe"))
    if not fn:
        return {"ok": False, "error": "unknown probe"}
    return {"ok": True, "probe": req["probe"], "data": fn(jobdir, req)}
