import { describe, expect, it, vi } from "vitest";
import plugin from "./index.js";
import { evaluateSessionsSpawnOverride } from "./policy.js";

const baseConfig = {
  enabled: true,
  agentIds: ["*"],
  blockThinkingOverride: false,
  message: "blocked model override",
};

type PluginApi = Parameters<typeof plugin.register>[0];
type TrustedPolicy = Parameters<PluginApi["registerTrustedToolPolicy"]>[0];

describe("subagent model override policy", () => {
  it("denies sessions_spawn with an explicit model", () => {
    const decision = evaluateSessionsSpawnOverride(
      { toolName: "sessions_spawn", params: { task: "summarize", model: "provider/model" } },
      { agentId: "coordinator" },
      baseConfig,
    );

    expect(decision).toEqual({
      outcome: "deny",
      code: "model_override_denied",
      reason: "blocked model override",
    });
  });

  it("allows sessions_spawn when model is omitted or blank", () => {
    expect(
      evaluateSessionsSpawnOverride(
        { toolName: "sessions_spawn", params: { task: "summarize" } },
        { agentId: "coordinator" },
        baseConfig,
      ),
    ).toEqual({ outcome: "pass" });
    expect(
      evaluateSessionsSpawnOverride(
        { toolName: "sessions_spawn", params: { task: "summarize", model: "  " } },
        { agentId: "coordinator" },
        baseConfig,
      ),
    ).toEqual({ outcome: "pass" });
  });

  it("allows unrelated tools", () => {
    expect(
      evaluateSessionsSpawnOverride(
        { toolName: "read", params: { model: "provider/model" } },
        { agentId: "coordinator" },
        baseConfig,
      ),
    ).toEqual({ outcome: "pass" });
  });

  it("can scope the policy to selected coordinator agents", () => {
    expect(
      evaluateSessionsSpawnOverride(
        { toolName: "sessions_spawn", params: { model: "provider/model" } },
        { agentId: "unscoped-agent" },
        { ...baseConfig, agentIds: ["coordinator"] },
      ),
    ).toEqual({ outcome: "pass" });
  });

  it("optionally denies explicit thinking overrides", () => {
    expect(
      evaluateSessionsSpawnOverride(
        { toolName: "sessions_spawn", params: { task: "summarize", thinking: "high" } },
        { agentId: "coordinator" },
        { ...baseConfig, blockThinkingOverride: true },
      ),
    ).toEqual({
      outcome: "deny",
      code: "thinking_override_denied",
      reason:
        "sessions_spawn thinking overrides are disabled by policy; omit thinking so configured subagent defaults are used.",
    });
  });

  it("registers and enforces the declared trusted policy", async () => {
    const registered: TrustedPolicy[] = [];
    const warn = vi.fn();
    plugin.register({
      pluginConfig: baseConfig,
      logger: { warn },
      registerTrustedToolPolicy(policy) {
        registered.push(policy);
      },
    } as PluginApi);

    expect(registered).toHaveLength(1);
    expect(registered[0]?.id).toBe("deny-sessions-spawn-model-override");
    await expect(
      registered[0]?.evaluate(
        { toolName: "sessions_spawn", params: { model: "provider/model" } },
        { agentId: "coordinator", toolName: "sessions_spawn" },
      ),
    ).resolves.toEqual({
      allow: false,
      reason: "subagent-model-override-guard:blocked model override",
    });
    expect(warn).toHaveBeenCalledOnce();
  });
});
