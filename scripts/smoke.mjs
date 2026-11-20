// ESM smoke test: import the package the way an ES module consumer would
// and check one basic redaction works.
//
// src/index.js is CommonJS (module.exports, no "type": "module" in
// package.json), so there are no named ESM exports to import. A default
// import gives the whole module.exports object, and `redact` is taken
// from that. A named import (`import { redact } from ...`) would not be
// reliable here, so this file deliberately uses the default import.

import pkg from '../src/index.js';

const { redact } = pkg;

const input = 'Contact ana@example.com please';
const expected = 'Contact [EMAIL] please';
const actual = redact(input);

if (actual !== expected) {
  console.error('ESM smoke test FAILED');
  console.error(`  input:    ${input}`);
  console.error(`  expected: ${expected}`);
  console.error(`  actual:   ${actual}`);
  process.exit(1);
}

console.log('ESM smoke test passed: import loads the package and email redaction works.');
