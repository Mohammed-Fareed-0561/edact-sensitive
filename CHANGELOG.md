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

### Fixed

- The API-key patterns now cover newer token formats: Stripe restricted keys
  (`rk_live_...`, `rk_test_...`), OpenAI service account keys (`sk-svcacct-...`),
  Slack `xoxe-...` tokens and AWS temporary session keys (`ASIA...`)
  ([#37](https://github.com/sharkohark1234/redact-sensitive/issues/37)).
- The email pattern no longer stalls on long digit-dash runs with no `@`
  (quadratic-time behaviour)
  ([#24](https://github.com/sharkohark1234/redact-sensitive/issues/24)).

## [0.1.0]

### Added

- Initial release: redaction for emails, phone numbers, credit cards (Luhn),
  IBAN, GitHub/OpenAI/AWS/Slack API keys, JWTs, private-key blocks, SSNs,
  Indian PANs, IPv4 addresses, URL passwords, URL query-string secrets,
  `Authorization` headers, and `key = value` secrets.
- `redact()`, `redactObject()` and `findSensitive()`, with `only` / `except` /
  `labels` / `custom` options and TypeScript types.
