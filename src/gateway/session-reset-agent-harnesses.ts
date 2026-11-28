import { resolveAgentDir } from "../agents/agent-scope.js";
import { resetRegisteredAgentHarnessSessions } from "../agents/harness/registry.js";
import { acquireAgentRuntimeCleanupRegistries } from "../agents/prepared-model-runtime.js";
import type { SessionEntry } from "../config/sessions.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type { GatewaySessionStoreTarget } from "./session-utils-store.types.js";

export async function resetSessionAgentHarnesses(params: {
  cfg: OpenClawConfig;
  target: Pick<GatewaySessionStoreTarget, "agentId" | "canonicalKey">;
  entry: SessionEntry;
  reason: "reset" | "deleted";
  assertCurrent?: () => void;
}): Promise<void> {
  const { agentId, canonicalKey: sessionKey } = params.target;
  params.assertCurrent?.();
  await using owners = await acquireAgentRuntimeCleanupRegistries(
    resolveAgentDir(params.cfg, agentId),
  );
  params.assertCurrent?.();
  await resetRegisteredAgentHarnessSessions(
    {
      agentId,
      sessionId: params.entry.sessionId,
      sessionKey,
      sessionFile: sessionKey,
      reason: params.reason,
    },
    owners.registries,
  );
  params.assertCurrent?.();
}
