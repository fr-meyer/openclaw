import type { AgentHarnessCompactResult } from "openclaw/plugin-sdk/agent-harness-runtime";

export function failedCompaction(reason: string, rawError?: string): AgentHarnessCompactResult {
  return {
    ok: false,
    compacted: false,
    reason,
    failure: { reason, ...(rawError === undefined ? {} : { rawError }) },
  };
}
