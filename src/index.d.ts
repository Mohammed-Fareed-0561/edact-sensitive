export interface RedactOptions {
  replacement?: string;
  /** Pattern names to include. Unknown names throw RangeError. */
  only?: string[];
  /** Pattern names to exclude. Unknown names throw RangeError. */
  except?: string[];
  keepLabels?: boolean;
  /** Replacement labels, keyed by pattern name or normalized sensitive key name. For example, `{ email: '[E-MAIL]' }`. Unknown names throw RangeError. `keepLabels: false` still wins over these. */
  labels?: Record<string, string>;
  custom?: Array<{ pattern: string | RegExp; flags?: string; replacement?: string }>;
  /** Extra object key names whose values redactObject should replace outright. */
  sensitiveKeys?: string[];
}

export interface SensitiveMatch {
  type: string;
  value: string;
}

/** Default sensitive key names (normalised, lower-case) mapped to their label. */
export const SENSITIVE_KEYS: Map<string, string>;

/**
 * One built-in redaction pattern. `name` is the stable identifier used by
 * `options.only` / `options.except` / `options.labels`, `label` is the
 * default replacement text, and `regex` is the pattern to match.
 * The optional members cover the specialised entries:
 * - `replacement`: a string with `$1`-style back-references, or a function
 *   like a `String.replace` callback (it receives the effective label as an
 *   extra final argument).
 * - `labelFor`: for patterns whose label depends on what matched (e.g. the
 *   URL query parameter name, or the auth scheme); returns
 *   `[textToKeep, labelForTheSecret]`.
 * - `validate`: an extra check on a match; only validated matches are redacted.
 */
export interface RedactPattern {
  name: string;
  label: string;
  regex: RegExp;
  replacement?: string | ((...args: any[]) => string);
  labelFor?: (match: string, groups: string[]) => [string, string];
  validate?: (match: string) => boolean;
}

/** The built-in patterns, in the order they are applied. */
export const PATTERNS: RedactPattern[];

export function redact(input: string, options?: RedactOptions): string;
export function redactObject<T>(value: T, options?: RedactOptions): T;
export function findSensitive(input: string): SensitiveMatch[];
