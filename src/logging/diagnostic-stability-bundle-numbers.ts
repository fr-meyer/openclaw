/** Numeric validation for untrusted persisted stability bundles. */
export function readRequiredNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`Invalid stability bundle: ${label} must be a finite number`);
  }
  return value;
}

export function readOptionalPositiveInteger(value: unknown, label: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const parsed = readRequiredNumber(value, label);
  return parsed >= 0 ? Math.floor(parsed) : undefined;
}

export function readTimestampMs(value: unknown, label: string): number {
  const timestamp = readRequiredNumber(value, label);
  if (Number.isNaN(new Date(timestamp).getTime())) {
    throw new Error(`Invalid stability bundle: ${label} must be a valid timestamp`);
  }
  return timestamp;
}

export function readOptionalNumber(value: unknown, label: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  return readRequiredNumber(value, label);
}
