export interface RedactOptions {
  replacement?: string;
  only?: string[];
  except?: string[];
  keepLabels?: boolean;
  /** Per-pattern replacement labels, keyed by pattern name, e.g. `{ email: '[E-MAIL]' }`. `keepLabels: false` still wins over these. */
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
