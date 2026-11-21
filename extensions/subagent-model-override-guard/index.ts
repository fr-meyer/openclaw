import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { evaluateSessionsSpawnOverride, resolvePluginConfig, toolNameOf } from "./policy.js";

const PLUGIN_ID = "subagent-model-override-guard";
const POLICY_ID = "deny-sessions-spawn-model-override";

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "Subagent Model Override Guard",
  description: "Blocks explicit per-call sessions_spawn model overrides.",
  register(api) {
    api.registerTrustedToolPolicy({
      id: POLICY_ID,
      description: "Deny sessions_spawn calls that include an explicit model override.",
      async evaluate(event, context) {
        const config = resolvePluginConfig(api.pluginConfig);
        const decision = evaluateSessionsSpawnOverride(event, context, config);
        if (decision.outcome !== "deny") {
          return undefined;
        }
        api.logger.warn(
          `blocked ${toolNameOf(event) ?? "unknown_tool"}: ${decision.code} agent=${context.agentId ?? "unknown"}`,
        );
        return {
          allow: false,
          reason: `${PLUGIN_ID}:${decision.reason}`,
        };
      },
    });
  },
});
