export const DEFAULT_MESSAGE =
  "sessions_spawn model overrides are disabled by policy; omit model so the configured subagent default chain is used.";
export const THINKING_MESSAGE =
  "sessions_spawn thinking overrides are disabled by policy; omit thinking so configured subagent defaults are used.";

export type OverrideGuardConfig = {
  enabled: boolean;
  agentIds: string[];
  blockThinkingOverride: boolean;
  message: string;
};

export type OverrideGuardDecision =
  | { outcome: "pass" }
  | {
      outcome: "deny";
      code: "model_override_denied" | "thinking_override_denied";
      reason: string;
    };

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function resolvePluginConfig(apiConfig: unknown): OverrideGuardConfig {
  const raw = isRecord(apiConfig) ? apiConfig : {};
  const configuredAgentIds = Array.isArray(raw.agentIds)
    ? raw.agentIds.filter(
        (value): value is string => typeof value === "string" && value.trim().length > 0,
      )
    : [];

  return {
    enabled: raw.enabled !== false,
    agentIds: configuredAgentIds.length > 0 ? configuredAgentIds : ["*"],
    blockThinkingOverride: raw.blockThinkingOverride === true,
    message:
      typeof raw.message === "string" && raw.message.trim().length > 0
        ? raw.message.trim()
        : DEFAULT_MESSAGE,
  };
}

function appliesToAgent(config: OverrideGuardConfig, context: unknown): boolean {
  if (config.agentIds.includes("*")) {
    return true;
  }
  const agentId = isRecord(context) && typeof context.agentId === "string" ? context.agentId : "";
  return agentId.length > 0 && config.agentIds.includes(agentId);
}

export function toolNameOf(event: unknown): string | undefined {
  if (!isRecord(event)) {
    return undefined;
  }
  if (typeof event.toolName === "string") {
    return event.toolName;
  }
  if (typeof event.name === "string") {
    return event.name;
  }
  return isRecord(event.tool) && typeof event.tool.name === "string" ? event.tool.name : undefined;
}

function paramsOf(event: unknown): Record<string, unknown> {
  if (!isRecord(event)) {
    return {};
  }
  if (isRecord(event.params)) {
    return event.params;
  }
  return isRecord(event.arguments) ? event.arguments : {};
}

function hasPresentOverride(value: unknown): boolean {
  return typeof value === "string"
    ? value.trim().length > 0
    : value !== undefined && value !== null;
}

export function evaluateSessionsSpawnOverride(
  event: unknown,
  context: unknown,
  config: OverrideGuardConfig,
): OverrideGuardDecision {
  if (!config.enabled || !appliesToAgent(config, context)) {
    return { outcome: "pass" };
  }
  if (toolNameOf(event) !== "sessions_spawn") {
    return { outcome: "pass" };
  }

  const params = paramsOf(event);
  if (hasPresentOverride(params.model)) {
    return {
      outcome: "deny",
      code: "model_override_denied",
      reason: config.message,
    };
  }
  if (config.blockThinkingOverride && hasPresentOverride(params.thinking)) {
    return {
      outcome: "deny",
      code: "thinking_override_denied",
      reason: THINKING_MESSAGE,
    };
  }
  return { outcome: "pass" };
}
