"""Download solc binaries for the current platform (Windows / Linux) into sandbox/.toolchain/solc/native."""
import json
import os
import platform
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TC = HERE / ".toolchain"
NATIVE_DIR = TC / "solc" / "native"
NATIVE_DIR.mkdir(parents=True, exist_ok=True)

WANTED = ["0.8.24", "0.8.20", "0.6.12", "0.4.26", "0.7.6", "0.5.17"]

system = platform.system().lower()
if system == "windows":
    plat = "windows-amd64"
    ext = ".exe"
elif system == "darwin":
    plat = "macosx-amd64"
    ext = ""
else:
    plat = "linux-amd64"
    ext = ""

print(f"Configuring toolchain for platform {plat}...")
list_url = f"https://binaries.soliditylang.org/{plat}/list.json"
req = urllib.request.Request(list_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    releases = data.get("releases", {})
    (NATIVE_DIR / "list.json").write_text(json.dumps(data))
    
    for v in WANTED:
        target = NATIVE_DIR / f"solc-{v}{ext}"
        if target.exists() and target.stat().st_size > 1000:
            print(f"  solc {v} already present at {target.name}")
            continue
        rel_path = releases.get(v)
        if not rel_path:
            print(f"  solc {v} not available in {plat} releases")
            continue
        url = f"https://binaries.soliditylang.org/{plat}/{rel_path}"
        print(f"  Downloading solc {v} from {url}...")
        tmp = target.with_suffix(".tmp")
        req_bin = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req_bin, timeout=45) as b_resp, open(tmp, "wb") as fh:
            fh.write(b_resp.read())
        if tmp.exists():
            if target.exists():
                target.unlink()
            tmp.rename(target)
            if ext == "":
                os.chmod(target, 0o755)
            print(f"  solc {v} installed successfully ({target.stat().st_size // 1024} KB)")
except Exception as e:
    print(f"Notice: Failed to download online solc: {e}")

print("Toolchain setup finished.")
