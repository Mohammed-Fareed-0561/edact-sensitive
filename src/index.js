'use strict';

/**
 * redact-sensitive
 *
 * Redact sensitive data from text and logs before it leaves your app.
 * Zero dependencies. Works in Node.js and browsers (via bundlers).
 *
 *   const { redact } = require('redact-sensitive');
 *   redact('Contact me at ana@example.com or 555-123-4567');
 *   // 'Contact me at [EMAIL] or [PHONE]'
 */

const DEFAULT_REPLACEMENT = '[REDACTED]';

function luhnValid(digits) {
  let sum = 0;
  let doubleIt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (doubleIt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    doubleIt = !doubleIt;
  }
  return digits.length >= 13 && sum % 10 === 0;
}

// IBAN length for each country in the SWIFT IBAN registry.
const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AX: 18, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22,
  BI: 27, BR: 29, BY: 28, CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DJ: 27, DK: 18,
  DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FK: 18, FO: 18, FR: 27, GB: 22, GE: 22,
  GF: 27, GI: 23, GL: 18, GP: 27, GR: 27, GT: 28, HN: 28, HR: 21, HU: 28, IE: 22,
  IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21,
  LT: 20, LU: 20, LV: 21, LY: 25, MC: 27, MD: 24, ME: 22, MF: 27, MK: 19, MN: 20,
  MQ: 27, MR: 27, MT: 31, MU: 30, NC: 27, NI: 28, NL: 18, NO: 15, OM: 23, PF: 27,
  PK: 24, PL: 28, PM: 27, PS: 29, PT: 25, QA: 29, RE: 27, RO: 24, RS: 22, RU: 33,
  SA: 24, SC: 31, SD: 18, SE: 24, SI: 19, SK: 24, SM: 27, SO: 23, ST: 25, SV: 28,
  TF: 27, TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, WF: 27, XK: 20, YE: 30,
  YT: 27,
};

// Build one alternative per length so a match stops exactly where the IBAN
// ends. E.g. for 16 (BE): BE\d{2}(?: ?[A-Z0-9]{4}){3}, so in
// "BE68 5390 0754 7034 CODE" the following word is never pulled in.
function buildIbanRegex() {
  const countriesByLength = {};
  for (const [country, length] of Object.entries(IBAN_LENGTHS)) {
    (countriesByLength[length] = countriesByLength[length] || []).push(country);
  }
  const alternatives = Object.entries(countriesByLength).map(([length, countries]) => {
    const rest = Number(length) - 4;
    const fullGroups = Math.floor(rest / 4);
    const remainder = rest % 4;
    return (
      `(?:${countries.join('|')})\\d{2}(?: ?[A-Z0-9]{4}){${fullGroups}}` +
      (remainder ? `(?: ?[A-Z0-9]{${remainder}})` : '')
    );
  });
  return new RegExp(`\\b(?:${alternatives.join('|')})\\b`, 'g');
}

// ISO 13616 mod-97 check: move the first 4 chars to the end, turn letters
// into numbers (A=10 ... Z=35), and the result mod 97 must equal 1.
function ibanValid(match) {
  const iban = match.replace(/ /g, '');
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const value = ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of value) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }
  return remainder === 1;
}

const PATTERNS = [
  {
    name: 'urlPassword',
    label: '[PASSWORD]',
    // https://user:password@host — redact only the password part.
    regex: /(\/\/[^/\s:@]+:)([^/\s@]+)(@)/g,
    replacement: '$1[PASSWORD]$3',
  },
  {
    name: 'email',
    label: '[EMAIL]',
    regex: /(?<![A-Za-z0-9._%+\[\]])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  },
  {
    name: 'awsAccessKey',
    label: '[AWS_KEY]',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    name: 'githubToken',
    label: '[TOKEN]',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: 'slackToken',
    label: '[TOKEN]',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    name: 'openaiKey',
    label: '[API_KEY]',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: 'privateKey',
    label: '[PRIVATE_KEY]',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    name: 'jwt',
    label: '[TOKEN]',
    regex: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  {
    name: 'iban',
    label: '[IBAN]',
    // DE89 3704 0044 0532 0130 00 or DE89370400440532013000. Exact length per
    // country, then mod-97 checked below.
    // Runs before creditCard and phone so their patterns don't grab the digit groups.
    regex: buildIbanRegex(),
    validate: ibanValid,
  },
  {
    name: 'creditCard',
    label: '[CARD]',
    // 13-19 digits, optionally grouped with spaces or dashes. Luhn-checked below.
    regex: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: (match) => luhnValid(match.replace(/[ -]/g, '')),
  },
  {
    name: 'ssn',
    label: '[SSN]',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    name: 'indianPan',
    label: '[PAN]',
    // Indian Permanent Account Number: five letters, four digits, one letter.
    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
  },
  {
    name: 'phone',
    label: '[PHONE]',
    // +1 555-123-4567, (555) 123-4567, 555-123-4567, +91 98765 43210
    regex: /(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?|\d{2,4}[\s-])?\d{3,4}[\s-]\d{4}\b/g,
    validate: (match) => match.replace(/\D/g, '').length >= 7,
  },
  {
    name: 'ipv4',
    label: '[IP]',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    validate: (match) =>
      match.split('.').every((part) => {
        const n = Number(part);
        return n >= 0 && n <= 255 && String(n) === part;
      }),
  },
  {
    name: 'genericApiKey',
    label: '[API_KEY]',
    regex: /\b(?:api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*['"]?([A-Za-z0-9_\-./]{8,})['"]?/gi,
    replacement: (match) => match.replace(/([:=]\s*['"]?)[A-Za-z0-9_\-./]{8,}(['"]?)/, '$1[API_KEY]$2'),
  },
];

function redact(input, options = {}) {
  if (input === null || input === undefined) return input;
  if (typeof input !== 'string') return input;

  const replacement = options.replacement || DEFAULT_REPLACEMENT;
  const enabled = new Set(options.only || PATTERNS.map((p) => p.name));
  const disabled = new Set(options.except || []);
  let out = input;

  for (const pattern of PATTERNS) {
    if (!enabled.has(pattern.name) || disabled.has(pattern.name)) continue;
    const label = options.keepLabels === false ? replacement : pattern.label;
    if (typeof pattern.replacement === 'function') {
      out = out.replace(pattern.regex, pattern.replacement);
    } else if (typeof pattern.replacement === 'string') {
      out = out.replace(pattern.regex, pattern.replacement);
    } else if (pattern.validate) {
      out = out.replace(pattern.regex, (match) => (pattern.validate(match) ? label : match));
    } else {
      out = out.replace(pattern.regex, label);
    }
  }

  for (const custom of options.custom || []) {
    const regex = custom instanceof RegExp ? custom : new RegExp(custom.pattern, custom.flags || 'g');
    out = out.replace(regex, custom.replacement || replacement);
  }

  return out;
}

function redactObject(value, options = {}) {
  if (typeof value === 'string') return redact(value, options);
  if (Array.isArray(value)) return value.map((item) => redactObject(item, options));
  if (isPlainObject(value)) {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      // A value stored under a sensitive key name is a secret, whatever
      // its type — replace it outright instead of recursing into it.
      const label = sensitiveKeyLabel(key, options);
      out[key] = label !== null ? label : redactObject(val, options);
    }
    return out;
  }
  return value;
}

// Only plain objects (created with {} or Object.create(null)) are safe
// to rebuild key by key. Anything else — Date, RegExp, Buffer, class
// instances — keeps its own internal state, which Object.entries would
// not preserve, so it is passed through unchanged.
function isPlainObject(value) {
  if (!value || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// Key names whose values are always secrets. Matching is case-insensitive
// and ignores '_'/'-' separators, so `apiKey`, `api_key` and `API-KEY`
// all match. Contributors: extend this map to cover new key names.
const SENSITIVE_KEYS = new Map([
  ['password', '[PASSWORD]'],
  ['passwd', '[PASSWORD]'],
  ['pwd', '[PASSWORD]'],
  ['secret', '[SECRET]'],
  ['apikey', '[API_KEY]'],
  ['accesskey', '[API_KEY]'],
  ['token', '[TOKEN]'],
  ['auth', '[TOKEN]'],
  ['authorization', '[TOKEN]'],
  ['privatekey', '[PRIVATE_KEY]'],
  ['clientsecret', '[SECRET]'],
]);

function normalizeKeyName(key) {
  return String(key).toLowerCase().replace(/[_-]/g, '');
}

// Returns the replacement label for a sensitive key name, or null if the
// key is not sensitive. `options.sensitiveKeys` adds extra key names
// (matched the same way) that are replaced with '[REDACTED]'.
function sensitiveKeyLabel(key, options = {}) {
  const name = normalizeKeyName(key);
  if (SENSITIVE_KEYS.has(name)) {
    return options.keepLabels === false
      ? options.replacement || DEFAULT_REPLACEMENT
      : SENSITIVE_KEYS.get(name);
  }
  const extra = (options.sensitiveKeys || []).map(normalizeKeyName);
  if (extra.includes(name)) return options.replacement || DEFAULT_REPLACEMENT;
  return null;
}

function findSensitive(input) {
  if (typeof input !== 'string') return [];
  const found = [];
  for (const pattern of PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(input)) !== null) {
      if (pattern.validate && !pattern.validate(match[0])) continue;
      found.push({ type: pattern.name, value: match[0] });
      if (match[0].length === 0) regex.lastIndex++;
    }
  }
  return found;
}

module.exports = { redact, redactObject, findSensitive, PATTERNS, SENSITIVE_KEYS };
