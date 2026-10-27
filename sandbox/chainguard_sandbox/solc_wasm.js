#!/usr/bin/env node
// Minimal native-solc-compatible CLI over the official soljson (emscripten) build.
// Supports only: `--version` and `--standard-json` (stdin -> stdout). Other flags
// such as --allow-paths/--base-path are accepted and ignored. Imports are NOT
// resolved from disk only inside $CHAINGUARD_JOBDIR/in (the uploaded file
// itself, which crytic-compile passes by URL); anything else is refused.
// Usage: node solc_wasm.js <soljson.js> <node_modules dir> [solc args...]
'use strict';
const path = require('path');
const [soljsonPath, nodeModules, ...args] = process.argv.slice(2);
const wrapper = require(path.join(nodeModules, 'solc', 'wrapper.js'));
const solc = wrapper(require(soljsonPath));
if (args.includes('--version')) {
  process.stdout.write('solc, the solidity compiler commandline interface\nVersion: ' + solc.version() + '\n');
  process.exitCode = 0;
}
else if (args.includes('--standard-json')) {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => { input += c; });
  process.stdin.on('end', () => {
    const fs = require('fs');
    const jd = process.env.CHAINGUARD_JOBDIR;
    const root = jd ? fs.realpathSync(path.join(jd, 'in')) + path.sep : null;
    const importer = (p) => {
      try {
        const rp = fs.realpathSync(path.resolve(p));
        if (root && rp.startsWith(root)) return { contents: fs.readFileSync(rp, 'utf8') };
      } catch (e) { /* fallthrough */ }
      return { error: 'imports outside the uploaded file are disabled in the ChainGuard sandbox: ' + p };
    };
    const out = solc.compile(input, { import: importer });
    // never process.exit() here: it can truncate a large piped stdout
    process.stdout.write(out, () => { process.exitCode = 0; });
  });
} else {
  process.stderr.write('solc_wasm shim: only --version and --standard-json are supported\n');
  process.exit(2);
}
