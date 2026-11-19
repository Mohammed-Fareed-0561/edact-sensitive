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

test('redacts a valid IBAN but keeps an IBAN-shaped string that fails the checksum', () => {
  // Public example IBANs from ISO 13616 / bank documentation, not real accounts.
  assert.equal(redact('Pay to DE89 3704 0044 0532 0130 00 today'), 'Pay to [IBAN] today');
  assert.equal(redact('IBAN: GB82WEST12345698765432'), 'IBAN: [IBAN]');
  assert.equal(redact('Product code AB12 CDEF GHIJ KLMN'), 'Product code AB12 CDEF GHIJ KLMN');
});

test('IBAN match stops at the country length, so a following word is not pulled in', () => {
  assert.equal(redact('BE68 5390 0754 7034 CODE'), '[IBAN] CODE');
  assert.equal(redact('NO93 8601 1117 947 ok'), '[IBAN] ok');
});

test('IBAN with an unknown country code is not reported, even with a valid checksum', () => {
  // XX is not an IBAN country; check digits 46 make the mod-97 sum valid.
  assert.deepEqual(findSensitive('XX46370400440532013000'), []);
});

test('redacts GitHub, OpenAI and AWS-style keys', () => {
  assert.equal(redact('token ghp_abcdefghij1234567890'), 'token [TOKEN]');
  assert.equal(redact('key sk-abcdefghij1234567890abcd'), 'key [API_KEY]');
  assert.equal(redact('key AKIAIOSFODNN7EXAMPLE'), 'key [AWS_KEY]');
});

test('redacts Stripe secret keys but not publishable keys', () => {
  // Built at runtime so no key-shaped literal is committed (secret scanners flag those).
  const body = 'a'.repeat(24);
  assert.equal(redact(`key sk_live_${body}`), 'key [API_KEY]');
  assert.equal(redact(`key sk_test_${body}`), 'key [API_KEY]');
  assert.equal(redact(`key pk_live_${body}`), `key pk_live_${body}`);
  assert.equal(redact('key sk_live_short'), 'key sk_live_short');
});

test('redacts ENCRYPTED PRIVATE KEY blocks', () => {
  assert.equal(
    redact('-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBvTCCAUY=\n-----END ENCRYPTED PRIVATE KEY-----'),
    '[PRIVATE_KEY]'
  );
});

test('redacts a truncated private key block that has no END line', () => {
  assert.equal(
    redact('key dump:\n-----BEGIN PRIVATE KEY-----\nMIIBvTCCAUYgAwIBAgI='),
    'key dump:\n[PRIVATE_KEY]'
  );
  assert.equal(
    redact('-----BEGIN RSA PRIVATE KEY-----\nMIIBvTCCAUYgAwIBAgIMIIBvTCCAUYgAwIBAgI\nMIIBvTCCAUYgAwIBAgIMIIBvTCCAUYgAwIBAgI'),
    '[PRIVATE_KEY]'
  );
});

test('a truncated private key block does not swallow the text after it', () => {
  assert.equal(
    redact('-----BEGIN PRIVATE KEY-----\nMIIBvTCCAUYgAwIBAgI=\nnext log line'),
    '[PRIVATE_KEY]\nnext log line'
  );
});

test('two complete private key blocks are redacted separately', () => {
  assert.equal(
    redact('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\nkeep\n-----BEGIN EC PRIVATE KEY-----\nBBBB\n-----END EC PRIVATE KEY-----'),
    '[PRIVATE_KEY]\nkeep\n[PRIVATE_KEY]'
  );

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

// --- Issue #25: findSensitive returns matches in text order and honours options ---

test('findSensitive returns matches in text order with their index', () => {
  const found = findSensitive('card 4111111111111111 then mail a@b.com then phone 555-123-4567');
  assert.deepEqual(found, [
    { type: 'creditCard', value: '4111111111111111', index: 5 },
    { type: 'email', value: 'a@b.com', index: 32 },
    { type: 'phone', value: '555-123-4567', index: 51 },
  ]);
});

test('findSensitive honours options.only', () => {
  const found = findSensitive('mail a@b.com, card 4111111111111111', { only: ['email'] });
  assert.deepEqual(found, [{ type: 'email', value: 'a@b.com', index: 5 }]);
});

test('findSensitive honours options.except', () => {
  const found = findSensitive('mail a@b.com, card 4111111111111111', { except: ['email'] });
  assert.deepEqual(found, [{ type: 'creditCard', value: '4111111111111111', index: 19 }]);
});

test('findSensitive reports custom patterns as type custom', () => {
  const found = findSensitive('order #12345 and a@b.com', { custom: [{ pattern: '#\\d+' }] });
  assert.deepEqual(found, [
    { type: 'custom', value: '#12345', index: 6 },
    { type: 'email', value: 'a@b.com', index: 17 },
  ]);
});

test('findSensitive rejects unknown names in only', () => {
  assert.throws(() => findSensitive('a@b.com', { only: ['emial'] }), RangeError);
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

test('redacts values stored under sensitive key names', () => {
  assert.deepEqual(
    redactObject({ password: 'hunter2', apiKey: 'abc123secret', user: 'ana' }),
    { password: '[PASSWORD]', apiKey: '[API_KEY]', user: 'ana' }
  );
});

test('sensitive key matching is case-insensitive and ignores separators', () => {
  assert.deepEqual(
    redactObject({ PASSWORD: 'x', Api_Key: 'y', 'access-key': 'z' }),
    { PASSWORD: '[PASSWORD]', Api_Key: '[API_KEY]', 'access-key': '[API_KEY]' }
  );
});

test('redacts sensitive keys nested in objects', () => {
  assert.deepEqual(
    redactObject({ config: { credentials: { token: 'tok123', host: 'example.com' } } }),
    { config: { credentials: { token: '[TOKEN]', host: 'example.com' } } }
  );
});

test('redacts sensitive keys inside arrays of objects', () => {
  assert.deepEqual(
    redactObject({ users: [{ name: 'ana', password: 'hunter2' }, { name: 'bob' }] }),
    { users: [{ name: 'ana', password: '[PASSWORD]' }, { name: 'bob' }] }
  );
});

test('non-sensitive keys keep their values (pattern redaction still applies)', () => {
  assert.deepEqual(
    redactObject({ user: 'ana', note: 'mail a@b.com', count: 3 }),
    { user: 'ana', note: 'mail [EMAIL]', count: 3 }
  );
});

test('redacts non-string values under sensitive keys', () => {
  assert.deepEqual(
    redactObject({ password: 12345, token: true, secret: null, apiKey: 0 }),
    { password: '[PASSWORD]', token: '[TOKEN]', secret: '[SECRET]', apiKey: '[API_KEY]' }
  );
});

test('options.sensitiveKeys extends the default sensitive key list', () => {
  assert.deepEqual(
    redactObject({ mySecretPhrase: 'shh', user: 'ana' }, { sensitiveKeys: ['mySecretPhrase'] }),
    { mySecretPhrase: '[REDACTED]', user: 'ana' }
  );
});

test('preserves a Date value inside an object while redacting a sibling email', () => {
  const created = new Date('2026-11-17T09:00:00.000Z');
  const out = redactObject({ created, email: 'a@b.com' });
  assert.ok(out.created instanceof Date);
  assert.equal(out.created.getTime(), created.getTime());
  assert.equal(out.email, '[EMAIL]');
});

test('returns a top-level Date unchanged', () => {
  const date = new Date('2026-11-17T09:00:00.000Z');
  assert.equal(redactObject(date), date);
});

test('preserves a RegExp value inside an object', () => {
  const pattern = /foo\d+/gi;
  const out = redactObject({ pattern });
  assert.equal(out.pattern, pattern);
  assert.equal(out.pattern.source, 'foo\\d+');
});

test('plain-object redaction still works after the non-plain fix', () => {
  assert.deepEqual(
    redactObject({ user: { email: 'a@b.com' }, tags: ['x@y.com'], when: new Date('2026-01-01T00:00:00.000Z') }),
    {
      user: { email: '[EMAIL]' },
      tags: ['[EMAIL]'],
      when: new Date('2026-01-01T00:00:00.000Z'),
    }
  );
});

// --- Issue #13: secrets in URL query strings ---

test('redacts only the value of sensitive query params, keeping other params', () => {
  assert.equal(
    redact('GET https://example.com/callback?token=abc123&user=ana&page=2'),
    'GET https://example.com/callback?token=[TOKEN]&user=ana&page=2'
  );
  assert.equal(
    redact('https://example.com/x?access_token=zzz&auth=yyy&lang=en'),
    'https://example.com/x?access_token=[TOKEN]&auth=[TOKEN]&lang=en'
  );
});

test('query param labels follow the param name', () => {
  assert.equal(redact('?api_key=abcdef0123'), '?api_key=[API_KEY]');
  assert.equal(redact('?client_secret=s3cr3tvalue'), '?client_secret=[SECRET]');
  assert.equal(redact('?password=hunter2'), '?password=[PASSWORD]');
  assert.equal(redact('?refresh_token=tok123'), '?refresh_token=[TOKEN]');
  assert.equal(redact('?sessionid=abc123'), '?sessionid=[TOKEN]');
  assert.equal(redact('?apiKey=abcdef0123'), '?apiKey=[API_KEY]');
});

test('query secret redaction is case-insensitive and stops at a fragment', () => {
  assert.equal(redact('?TOKEN=abc123'), '?TOKEN=[TOKEN]');
  assert.equal(redact('?token=abc123#section'), '?token=[TOKEN]#section');
});

test('query secret redaction works inside longer log lines and object values', () => {
  assert.equal(
    redact('200 GET /cb?token=abc123 HTTP/1.1'),
    '200 GET /cb?token=[TOKEN] HTTP/1.1'
  );
  assert.deepEqual(
    redactObject({ url: 'https://example.com/cb?token=abc123&user=ana' }),
    { url: 'https://example.com/cb?token=[TOKEN]&user=ana' }
  );
});

test('query secret redaction respects only / except / keepLabels', () => {
  assert.equal(redact('?token=abc123', { only: ['email'] }), '?token=abc123');
  assert.equal(redact('?token=abc123', { except: ['urlQuerySecret'] }), '?token=abc123');
  assert.equal(redact('?token=abc123', { keepLabels: false, replacement: '***' }), '?token=***');
  assert.equal(redact('?token=abc123', { labels: { urlQuerySecret: '[Q]' } }), '?token=[Q]');
});

test('query secret false positives stay untouched', () => {
  assert.equal(redact('?user=ana&page=2'), '?user=ana&page=2');
  // The param name must match exactly: longer names are not secrets.
  assert.equal(redact('?mytoken=abc123'), '?mytoken=abc123');
  assert.equal(redact('?tokenized=abc123'), '?tokenized=abc123');
  // An empty value has nothing to leak.
  assert.equal(redact('?token='), '?token=');
  // 'token' as a bare word in prose is not a query param.
  assert.equal(redact('your token is abc123'), 'your token is abc123');
});

// --- Issue #6: per-type custom replacement labels ---

test('options.labels overrides one pattern label at a time', () => {
  assert.equal(
    redact('a@b.com 555-123-4567', { labels: { email: '[E-MAIL]', phone: '[TEL]' } }),
    '[E-MAIL] [TEL]'
  );
  // A label for one type leaves every other type on its default label.
  assert.equal(redact('a@b.com', { labels: { phone: '[TEL]' } }), '[EMAIL]');
  assert.equal(redact('Call 555-123-4567', { labels: { email: '[E-MAIL]' } }), 'Call [PHONE]');
});

test('keepLabels: false wins over per-type labels', () => {
  assert.equal(
    redact('a@b.com', { labels: { email: '[E-MAIL]' }, keepLabels: false, replacement: '***' }),
    '***'
  );
});

test('options.labels works through redactObject, including sensitive keys', () => {
  assert.deepEqual(
    redactObject({ note: 'mail a@b.com' }, { labels: { email: '[E-MAIL]' } }),
    { note: 'mail [E-MAIL]' }
  );
  assert.deepEqual(
    redactObject({ password: 'hunter2' }, { labels: { password: '[PWD]' } }),
    { password: '[PWD]' }
  );
});

test('options.labels applies to urlPassword and genericApiKey too', () => {
  assert.equal(
    redact('https://user:hunter2@example.com/x', { labels: { urlPassword: '[PW]' } }),
    'https://user:[PW]@example.com/x'
  );
  assert.equal(
    redact('https://user:hunter2@example.com/x', { keepLabels: false, replacement: '***' }),
    'https://user:***@example.com/x'
  );
  assert.equal(
    redact('api_key = abcdefgh12345678', { labels: { genericApiKey: '[KEY]' } }),
    'api_key = [KEY]'
  );
});

// --- Authorization header values in log text ---

test('redacts Bearer and Basic credentials, keeping header name and scheme', () => {
  assert.equal(redact('Authorization: Bearer abc123opaque'), 'Authorization: Bearer [TOKEN]');
  assert.equal(redact('Authorization: Basic dXNlcjpwYXNz'), 'Authorization: Basic [CREDENTIALS]');
});

test('auth header redaction is case-insensitive and covers Proxy-Authorization', () => {
  assert.equal(redact('authorization: Bearer xyz'), 'authorization: Bearer [TOKEN]');
  assert.equal(redact('Proxy-Authorization: Basic dXNlcjpwYXNz'), 'Proxy-Authorization: Basic [CREDENTIALS]');
});

test('auth header redaction works inside longer log lines', () => {
  assert.equal(
    redact('request headers: Authorization: Bearer abc123, Content-Type: text/plain'),
    'request headers: Authorization: Bearer [TOKEN], Content-Type: text/plain'
  );
});

test('auth header redaction respects only / except / keepLabels', () => {
  assert.equal(redact('Authorization: Bearer abc', { only: ['email'] }), 'Authorization: Bearer abc');
  assert.equal(redact('Authorization: Bearer abc', { except: ['authHeader'] }), 'Authorization: Bearer abc');
  assert.equal(
    redact('Authorization: Bearer abc', { keepLabels: false, replacement: '***' }),
    'Authorization: Bearer ***'
  );
});

test('other auth schemes are left alone', () => {
  // Deliberate choice: only Bearer (reusable opaque token) and Basic
  // (base64 username:password) are redacted. Negotiate, Digest and friends
  // carry session-bound challenge responses, not static credentials, so
  // they are not treated as secrets here.
  assert.equal(redact('Authorization: Negotiate YIIabc123'), 'Authorization: Negotiate YIIabc123');
  assert.equal(redact('Authorization: Digest username="ana"'), 'Authorization: Digest username="ana"');
  // A scheme with no credential has nothing to leak.
  assert.equal(redact('Authorization: Bearer'), 'Authorization: Bearer');
});

test('findSensitive reports the new pattern types', () => {
  const found = findSensitive('?token=abc123 and Authorization: Bearer xyz');
  assert.deepEqual(
    found.map((f) => f.type).sort(),
    ['authHeader', 'urlQuerySecret']
  );
});

// Unknown option names must not silently disable or change redaction.
for (const option of ['only', 'except', 'labels']) {
  test(`rejects unknown names in ${option}`, () => {
    const options = { [option]: option === 'labels' ? { emial: '[MAIL]' } : ['emial'] };
    for (const input of ['a@example.com', '', null, 42]) {
      assert.throws(() => redact(input, options), (error) => {
        assert.ok(error instanceof RangeError);
        assert.match(error.message, new RegExp(option));
        assert.match(error.message, /emial/);
        assert.match(error.message, /email/);
        return true;
      });
    }
    for (const input of [{}, [], { password: 'synthetic' }]) {
      assert.throws(() => redactObject(input, options), RangeError);
    }
  });
}

test('accepts all current pattern names and sensitive-key labels', () => {
  const { PATTERNS, SENSITIVE_KEYS } = require('../src');
  const names = PATTERNS.map((pattern) => pattern.name);
  assert.equal(redact('a@example.com', { only: names }), '[EMAIL]');
  assert.equal(redact('a@example.com', { except: names }), 'a@example.com');
  assert.equal(redact('a@example.com', { only: [] }), 'a@example.com');
  const labels = Object.fromEntries([...names, ...SENSITIVE_KEYS.keys()].map((name) => [name, '[CUSTOM]']));
  assert.deepEqual(redactObject({ password: 'synthetic', note: 'a@example.com' }, { labels }), {
    password: '[CUSTOM]', note: '[CUSTOM]',
  });
});

test('sensitive key names are not accepted as pattern filters', () => {
  assert.throws(() => redact('text', { only: ['password'] }), RangeError);
  assert.throws(() => redact('text', { except: ['password'] }), RangeError);
});

test('every PATTERNS entry matches the exported TypeScript shape', () => {
  const { PATTERNS } = require('../src');
  assert.ok(Array.isArray(PATTERNS));
  assert.ok(PATTERNS.length > 0);
  for (const pattern of PATTERNS) {
    assert.equal(typeof pattern.name, 'string');
    assert.equal(typeof pattern.label, 'string');
    assert.ok(pattern.regex instanceof RegExp);
    if (pattern.replacement !== undefined) {
      assert.ok(typeof pattern.replacement === 'string' || typeof pattern.replacement === 'function');
    }
    if (pattern.labelFor !== undefined) assert.equal(typeof pattern.labelFor, 'function');
    if (pattern.validate !== undefined) assert.equal(typeof pattern.validate, 'function');
  }
  // Spot-check the specialised entries the type has to cover.
  const byName = Object.fromEntries(PATTERNS.map((p) => [p.name, p]));
  assert.equal(typeof byName.urlPassword.replacement, 'string');
  assert.equal(typeof byName.genericApiKey.replacement, 'function');
  assert.equal(typeof byName.urlQuerySecret.labelFor, 'function');
  assert.equal(typeof byName.authHeader.labelFor, 'function');
  assert.equal(typeof byName.iban.validate, 'function');
});

// --- Issue #22: redactObject crashes on circular references and very deep nesting ---

test('redactObject replaces a self-reference with [Circular] instead of throwing', () => {
  const c = { name: 'ana' };
  c.self = c;
  assert.deepEqual(redactObject(c), { name: 'ana', self: '[Circular]' });
});

test('redactObject replaces a mutual two-object cycle with [Circular]', () => {
  const a = { name: 'ana' };
  const b = { name: 'bob', back: a };
  a.other = b;
  const out = redactObject(a);
  assert.equal(out.name, 'ana');
  assert.equal(out.other.name, 'bob');
  assert.equal(out.other.back, '[Circular]');
});

test('redactObject replaces a self-referencing array with [Circular]', () => {
  const arr = ['a@b.com'];
  arr.push(arr);
  assert.deepEqual(redactObject(arr), ['[EMAIL]', '[Circular]']);
});

test('redactObject does not mistake a shared non-circular object for a cycle', () => {
  const shared = { email: 'a@b.com' };
  assert.deepEqual(redactObject({ first: shared, second: shared }), {
    first: { email: '[EMAIL]' },
    second: { email: '[EMAIL]' },
  });
});

test('redactObject does not throw on a 5,000-deep object and caps it with a placeholder', () => {
  let deep = { leaf: 'a@b.com' };
  for (let i = 0; i < 5000; i++) deep = { next: deep };
  let out;
  assert.doesNotThrow(() => {
    out = redactObject(deep);
  });
  // Walk down until the depth cap: the value there is the placeholder.
  let cur = out;
  let steps = 0;
  while (typeof cur === 'object' && cur !== null) {
    cur = cur.next;
    steps++;
  }
  assert.equal(cur, '[DEPTH_LIMIT]');
  assert.ok(steps <= 101, `depth cap reached after ${steps} levels`);
});

test('redactObject honours options.maxDepth', () => {
  const value = { a: { b: { c: { d: 'x' } } } };
  assert.deepEqual(redactObject(value, { maxDepth: 2 }), {
    a: { b: { c: '[DEPTH_LIMIT]' } },
  });
});

test('redaction still works inside nested objects and arrays after the circular/depth fix', () => {
  assert.deepEqual(
    redactObject({
      user: { email: 'a@b.com', password: 'hunter2' },
      tags: ['x@y.com', { note: 'mail a@b.com' }],
    }),
    {
      user: { email: '[EMAIL]', password: '[PASSWORD]' },
      tags: ['[EMAIL]', { note: 'mail [EMAIL]' }],
    }
  );
});

// --- Issue #24: email regex was quadratic on long digit-dash runs ---

test('email pattern stays fast on a long digit-dash run with no @', () => {
  const input = '1-'.repeat(40000); // 80k chars
  const start = process.hrtime.bigint();
  const out = redact(input, { only: ['email'] });
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.equal(out, input);
  // Was several seconds before the fix; generous bound to avoid CI flakiness.
  assert.ok(ms < 1000, `redaction took ${ms.toFixed(0)} ms`);
});

test('a real email at the end of a long digit-dash run is still redacted', () => {
  assert.equal(
    redact('1-'.repeat(1000) + 'ana@example.com', { only: ['email'] }),
    '[EMAIL]'
  );
  assert.equal(redact('id 1-2-3 mail ana-b@example.com', { only: ['email'] }), 'id 1-2-3 mail [EMAIL]');
});

// --- Issue #20: AWS-style compound secret key names ---

test('genericApiKey redacts aws_secret_access_key and secret_access_key values', () => {
  const value = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  assert.equal(redact(`aws_secret_access_key = ${value}`), 'aws_secret_access_key = [API_KEY]');
  assert.equal(redact(`secret_access_key = ${value}`), 'secret_access_key = [API_KEY]');
  assert.equal(redact(`AWS_SECRET_ACCESS_KEY=${value}`), 'AWS_SECRET_ACCESS_KEY=[API_KEY]');
  assert.equal(redact(`aws-secret-access-key: ${value}`), 'aws-secret-access-key: [API_KEY]');
  assert.equal(redact(`SecretAccessKey = "${value}"`), 'SecretAccessKey = "[API_KEY]"');
});

test('plain secret = ... still works and unrelated compound names are untouched', () => {
  assert.equal(redact('secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), 'secret = [API_KEY]');
  assert.equal(redact('secret_access_key_id = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), 'secret_access_key_id = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
});
