export type RetiredIntegrationSentinelOptions = {
  id: string;
  reason: string;
  exitCode?: number;
  replacement?: string;
};

export type RetiredIntegrationStatus = {
  id: string;
  status: "retired";
  reason: string;
  exitCode: number;
  replacement?: string;
};

const INTEGRATION_ID_RE = /^[a-z0-9][a-z0-9._-]{0,79}$/;
const CONTROL_CHARACTER_RE = /[\u0000-\u001f\u007f]/u;

export function resolveRetiredIntegrationStatus(
  options: RetiredIntegrationSentinelOptions,
): RetiredIntegrationStatus {
  if (!INTEGRATION_ID_RE.test(options.id)) {
    throw new Error("integration id must be a lowercase stable identifier");
  }
  const reason = options.reason.trim();
  if (!reason || reason.length > 500 || CONTROL_CHARACTER_RE.test(reason)) {
    throw new Error("retirement reason must contain between 1 and 500 safe characters");
  }
  const exitCode = options.exitCode ?? 64;
  if (!Number.isInteger(exitCode) || exitCode < 1 || exitCode > 255) {
    throw new Error("exitCode must be an integer between 1 and 255");
  }
  const replacement = options.replacement?.trim();
  if (
    replacement !== undefined &&
    (!replacement || replacement.length > 300 || CONTROL_CHARACTER_RE.test(replacement))
  ) {
    throw new Error("replacement must contain between 1 and 300 safe characters");
  }
  return {
    id: options.id,
    status: "retired",
    reason,
    exitCode,
    ...(replacement === undefined ? {} : { replacement }),
  };
}

export function formatRetiredIntegrationNotice(status: RetiredIntegrationStatus): string {
  const replacement = status.replacement ? `; replacement: ${status.replacement}` : "";
  return `blocked: integration ${status.id} is retired; reason: ${status.reason}${replacement}`;
}

export function runRetiredIntegrationSentinel(options: {
  sentinel: RetiredIntegrationSentinelOptions;
  argv?: readonly string[];
  writeError: (message: string) => void;
}): number {
  const status = resolveRetiredIntegrationStatus(options.sentinel);
  void options.argv;
  options.writeError(`${formatRetiredIntegrationNotice(status)}\n`);
  return status.exitCode;
}
