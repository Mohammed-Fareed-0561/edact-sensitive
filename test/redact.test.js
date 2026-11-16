'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { redact, redactObject, findSensitive } = require('../src/index.js');

test('redacts an email address', () => {
  assert.equal(redact('Contact ana@example.com please'), 'Contact [EMAIL] please');
});

test('redacts a phone number', () => {
  assert.equal(redact('Call 555-123-4567'), 'Call [PHONE]');
});

test('redacts a valid credit card but keeps a random 16-digit number that fails Luhn', () => {
  assert.equal(redact('Card 4111 1111 1111 1111'), 'Card [CARD]');
  assert.equal(redact('Order 1234567890123456'), 'Order 1234567890123456');
});

test('redacts GitHub, OpenAI and AWS-style keys', () => {
  assert.equal(redact('token ghp_abcdefghij1234567890'), 'token [TOKEN]');
  assert.equal(redact('key sk-abcdefghij1234567890abcd'), 'key [API_KEY]');
  assert.equal(redact('key AKIAIOSFODNN7EXAMPLE'), 'key [AWS_KEY]');
});

test('redacts a password inside a URL only, keeping the rest', () => {
  assert.equal(
    redact('https://user:hunter2@example.com/x'),
    'https://user:[PASSWORD]@example.com/x'
  );
});

test('redacts nested values in objects and arrays', () => {
  assert.deepEqual(redactObject({ user: { email: 'a@b.com' }, tags: ['x@y.com'] }), {
    user: { email: '[EMAIL]' },
    tags: ['[EMAIL]'],
  });
});

test('redacts an Indian PAN number', () => {
  assert.equal(redact('PAN ABCDE1234F on file'), 'PAN [PAN] on file');
});

test('keeps text that only looks like an Indian PAN number', () => {
  assert.equal(redact('code ABCDE1234'), 'code ABCDE1234');
  assert.equal(redact('ref ABCDE1234FG'), 'ref ABCDE1234FG');
  assert.equal(redact('pan abcde1234f'), 'pan abcde1234f');
});

test('findSensitive lists what was found', () => {
  const found = findSensitive('mail a@b.com, card 4111111111111111');
  assert.deepEqual(
    found.map((f) => f.type).sort(),
    ['creditCard', 'email']
  );
});

test('options.only limits redaction to one type', () => {
  assert.equal(redact('a@b.com 555-123-4567', { only: ['email'] }), '[EMAIL] 555-123-4567');
});

test('custom patterns are applied', () => {
  assert.equal(
    redact('order #12345', { custom: [{ pattern: '#\\d+', replacement: '[ORDER]' }] }),
    'order [ORDER]'
  );
});

test('leaves plain text untouched', () => {
  assert.equal(redact('Hello, world. No secrets here.'), 'Hello, world. No secrets here.');
});
