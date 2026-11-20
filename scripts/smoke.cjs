'use strict';

// CJS smoke test: require() the package the way a CommonJS consumer would
// and check one basic redaction works.

const { redact } = require('../src/index.js');

const input = 'Contact ana@example.com please';
const expected = 'Contact [EMAIL] please';
const actual = redact(input);

if (actual !== expected) {
  console.error('CJS smoke test FAILED');
  console.error(`  input:    ${input}`);
  console.error(`  expected: ${expected}`);
  console.error(`  actual:   ${actual}`);
  process.exit(1);
}

console.log('CJS smoke test passed: require() loads the package and email redaction works.');
