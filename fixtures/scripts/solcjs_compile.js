// Compile one Solidity file with a given soljson build via the npm `solc` wrapper.
// usage: node solcjs_compile.js <soljson.js> <file.sol>   (NODE_PATH must contain the `solc` package)
const fs = require('fs');
const path = require('path');
const wrapper = require('solc/wrapper');
const solc = wrapper(require(path.resolve(process.argv[2])));
const file = process.argv[3];
const input = {
  language: 'Solidity',
  sources: { [path.basename(file)]: { content: fs.readFileSync(file, 'utf8') } },
  settings: { outputSelection: { '*': { '*': ['abi'] } } },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (out.errors || []).filter(e => e.severity === 'error');
const warnings = (out.errors || []).filter(e => e.severity === 'warning');
process.stdout.write(JSON.stringify({
  version: solc.version(),
  ok: errors.length === 0,
  errors: errors.map(e => e.formattedMessage || e.message),
  warnings: warnings.length,
  contracts: Object.values(out.contracts || {}).flatMap(c => Object.keys(c)),
}));
