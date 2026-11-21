'use strict';

// Benchmark for redact-sensitive: times redact() and findSensitive() over a
// large synthetic log built in memory. Run with `npm run bench`.
//
// NOTE: the synthetic log uses placeholders only (user@example.com,
// sk_live_..., AIza...). Never put a realistic-looking secret in here —
// GitHub secret scanning would flag it.

const { redact, findSensitive } = require('../src/index.js');

const LINE_COUNT = 10000;

// A small pool of line templates, mixed so the log looks like real app logs.
// All "secrets" below are truncated placeholders, not real values.
const templates = [
  (i) => `2026-11-21T06:00:${String(i % 60).padStart(2, '0')}Z INFO user${i}@example.com logged in from 203.0.113.${i % 250}`,
  (i) => `2026-11-21T06:00:${String(i % 60).padStart(2, '0')}Z DEBUG request ${i} completed in ${i % 400}ms`,
  (i) => `2026-11-21T06:00:${String(i % 60).padStart(2, '0')}Z WARN retrying payment for order-${i} card 4111 1111 1111 1111`,
  (i) => `2026-11-21T06:00:${String(i % 60).padStart(2, '0')}Z ERROR api key sk_live_... rejected for service-${i}`,
  (i) => `2026-11-21T06:00:${String(i % 60).padStart(2, '0')}Z INFO google key AIza... used by worker-${i}`,
  (i) => `2026-11-21T06:00:${String(i % 60).padStart(2, '0')}Z DEBUG cache hit for user${i}@example.com session ${i}`,
  (i) => `2026-11-21T06:00:${String(i % 60).padStart(2, '0')}Z INFO user ${i} signed up with phone 555-123-${String(1000 + (i % 9000))}`,
  (i) => `2026-11-21T06:00:${String(i % 60).padStart(2, '0')}Z TRACE heartbeat ${i} ok, no sensitive data here`,
];

function buildLog(lineCount) {
  const lines = new Array(lineCount);
  for (let i = 0; i < lineCount; i++) {
    lines[i] = templates[i % templates.length](i);
  }
  return lines.join('\n');
}

function time(label, fn, lineCount) {
  const start = process.hrtime.bigint();
  const result = fn();
  const end = process.hrtime.bigint();
  const ms = Number(end - start) / 1e6;
  const linesPerSecond = Math.round(lineCount / (ms / 1000));
  console.log(
    `${label}: ${ms.toFixed(1)} ms (${linesPerSecond.toLocaleString('en-US')} lines/sec)`,
  );
  return result;
}

function main() {
  const log = buildLog(LINE_COUNT);
  console.log(`Benchmarking over ${LINE_COUNT.toLocaleString('en-US')} lines (${log.length.toLocaleString('en-US')} chars)`);
  const redacted = time('redact()', () => redact(log), LINE_COUNT);
  const found = time('findSensitive()', () => findSensitive(log), LINE_COUNT);
  console.log(`redact() output: ${redacted.length.toLocaleString('en-US')} chars`);
  console.log(`findSensitive() matches: ${found.length}`);
}

main();
