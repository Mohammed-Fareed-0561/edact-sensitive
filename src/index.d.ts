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

export function redact(input: string, options?: RedactOptions): string;
export function redactObject<T>(value: T, options?: RedactOptions): T;
export function findSensitive(input: string): SensitiveMatch[];
