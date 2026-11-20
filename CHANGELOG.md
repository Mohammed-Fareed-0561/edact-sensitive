# Changelog

All notable changes to redact-sensitive are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Stripe secret keys (`sk_live_...`, `sk_test_...`) are now redacted as
  `[API_KEY]` ([#17](https://github.com/sharkohark1234/redact-sensitive/issues/17)).
- `aws_secret_access_key` and `secret_access_key` values are now redacted by
  the `key = value` pattern
  ([#20](https://github.com/sharkohark1234/redact-sensitive/issues/20)).
- `ENCRYPTED PRIVATE KEY` blocks and truncated PEM blocks with no `END` line
  are now redacted as `[PRIVATE_KEY]`
  ([#21](https://github.com/sharkohark1234/redact-sensitive/issues/21)).
- Passwords in database, cache and queue connection strings (`mongodb://`,
  `mongodb+srv://`, `postgres://`, `mysql://`, `redis://`, `amqp://`) are
  now redacted as `[PASSWORD]`, keeping the scheme, user and host readable.
  This covers the no-username form (`redis://:pass@host`) and passwords
  containing `@` or other special characters.
- Sentry DSNs are now redacted as `[DSN]` (only the public key; the ingest
  host and project id stay readable) instead of being mangled by the email
  pattern ([#55](https://github.com/sharkohark1234/redact-sensitive/issues/55)).
- GitHub fine-grained personal access tokens (`github_pat_...`) are now
  redacted as `[TOKEN]`
  ([#36](https://github.com/sharkohark1234/redact-sensitive/issues/36)).
- Slack incoming webhook URLs (`https://hooks.slack.com/services/...`,
  including GovSlack) are now redacted as `[WEBHOOK]`
  ([#52](https://github.com/sharkohark1234/redact-sensitive/issues/52)).
- Session cookie values in `Cookie` / `Set-Cookie` headers are now redacted
  as `[TOKEN]` for known session cookie names only
  ([#56](https://github.com/sharkohark1234/redact-sensitive/issues/56)).

### Fixed

- The API-key patterns now cover newer token formats: Stripe restricted keys
  (`rk_live_...`, `rk_test_...`), OpenAI service account keys (`sk-svcacct-...`),
  Slack `xoxe-...` tokens and AWS temporary session keys (`ASIA...`)
  ([#37](https://github.com/sharkohark1234/redact-sensitive/issues/37)).
- The email pattern no longer stalls on long digit-dash runs with no `@`
  (quadratic-time behaviour)
  ([#24](https://github.com/sharkohark1234/redact-sensitive/issues/24)).
- The `key = value` pattern now redacts base64 secret values in full: a
  `+` or `=` inside the value no longer leaves the tail unredacted
  ([#35](https://github.com/sharkohark1234/redact-sensitive/issues/35)).
- `redactObject` no longer drops symbol-keyed properties: enumerable
  symbol keys are carried over, and a value stored under a symbol whose
  description is a sensitive name (for example `Symbol('password')`) is
  redacted outright
  ([#23](https://github.com/sharkohark1234/redact-sensitive/issues/23)).

## [0.1.0]

### Added

- Initial release: redaction for emails, phone numbers, credit cards (Luhn),
  IBAN, GitHub/OpenAI/AWS/Slack API keys, JWTs, private-key blocks, SSNs,
  Indian PANs, IPv4 addresses, URL passwords, URL query-string secrets,
  `Authorization` headers, and `key = value` secrets.
- `redact()`, `redactObject()` and `findSensitive()`, with `only` / `except` /
  `labels` / `custom` options and TypeScript types.

