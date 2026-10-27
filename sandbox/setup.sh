#!/usr/bin/env bash
# ChainGuard sandbox toolchain setup. Runs on the HOST with network access.
# Everything is installed under sandbox/.toolchain (gitignored); the no-network
# sandbox never downloads anything.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TC="$HERE/.toolchain"
ROOT="$(cd "$HERE/.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
mkdir -p "$TC/solc/native" "$TC/solc/wasm" "$TC/bin" "$TC/node"

echo "[1/4] python deps"
"$PY" -m pip install -q -r "$HERE/requirements.txt"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) SOLC_PLAT=linux-amd64; FOUNDRY_PLAT=linux_amd64 ;;
  aarch64|arm64) SOLC_PLAT=linux-arm64; FOUNDRY_PLAT=linux_arm64 ;;
  *) echo "unsupported arch $ARCH"; exit 1 ;;
esac
BASE=https://binaries.soliditylang.org

# Native binaries where the platform publishes them; otherwise the official
# emscripten (soljson) build run through node via bin/solc-wasm.
NATIVE_WANT="${SOLC_NATIVE:-0.4.26 0.5.17 0.6.12 0.7.6 0.8.19 0.8.26 0.8.30 0.8.31 0.8.38}"
WASM_WANT="${SOLC_WASM:-0.4.24 0.4.26 0.5.16 0.5.17 0.6.12 0.7.6 0.8.0 0.8.4 0.8.17 0.8.19 0.8.20 0.8.21 0.8.24 0.8.25 0.8.26 0.8.27 0.8.28 0.8.29 0.8.30}"

echo "[2/4] solc ($SOLC_PLAT)"
curl -fsSL "$BASE/$SOLC_PLAT/list.json" -o "$TC/solc/native/list.json"
curl -fsSL "$BASE/wasm/list.json" -o "$TC/solc/wasm/list.json"
for v in $NATIVE_WANT; do
  p=$("$PY" -c "import json,sys;print(json.load(open('$TC/solc/native/list.json'))['releases'].get('$v',''))")
  [ -z "$p" ] && { echo "  native $v not published for $SOLC_PLAT"; continue; }
  [ -x "$TC/solc/native/solc-$v" ] || { curl -fsSL "$BASE/$SOLC_PLAT/$p" -o "$TC/solc/native/solc-$v.tmp" && chmod +x "$TC/solc/native/solc-$v.tmp" && mv "$TC/solc/native/solc-$v.tmp" "$TC/solc/native/solc-$v"; }
  echo "  native $v ok"
done
for v in $WASM_WANT; do
  [ -x "$TC/solc/native/solc-$v" ] && continue
  p=$("$PY" -c "import json;print(json.load(open('$TC/solc/wasm/list.json'))['releases'].get('$v',''))")
  [ -z "$p" ] && { echo "  wasm $v missing"; continue; }
  [ -f "$TC/solc/wasm/soljson-$v.js" ] || curl -fsSL "$BASE/wasm/$p" -o "$TC/solc/wasm/soljson-$v.js"
  echo "  wasm $v ok"
done
# solc-js wrapper (handles old/new soljson APIs) for the wasm shim
if command -v npm >/dev/null; then
  if [ ! -d "$TC/node/node_modules/solc" ]; then
    echo '{"name":"cg-toolchain","private":true}' > "$TC/node/package.json"
    npm install --prefix "$TC/node" --cache "$TC/.npmcache" --no-audit --no-fund solc@0.8.26 >/dev/null
  fi
fi

echo "[3/4] foundry ($FOUNDRY_PLAT)"
FV="${FOUNDRY_VERSION:-v1.8.6}"
if [ ! -x "$TC/bin/forge" ]; then
  if curl -fsSL "https://github.com/foundry-rs/foundry/releases/download/$FV/foundry_${FV}_${FOUNDRY_PLAT}.tar.gz" -o "$TC/foundry.tgz"; then
    tar -xzf "$TC/foundry.tgz" -C "$TC/bin" && rm -f "$TC/foundry.tgz"
  else
    echo "  foundry download failed (validate() will report error/not_applicable)"
  fi
fi
[ -x "$TC/bin/forge" ] && "$TC/bin/forge" --version | head -1 || true

echo "[4/4] forge-std (vendored offline copy)"
if [ ! -d "$TC/forge-std" ]; then
  git clone -q --depth 1 --branch v1.9.7 https://github.com/foundry-rs/forge-std "$TC/forge-std" || echo "  forge-std clone failed"
fi
echo "done: $TC"
