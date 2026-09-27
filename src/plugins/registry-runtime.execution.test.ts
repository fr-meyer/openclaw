import { describe, expect, it, vi } from "vitest";
import { createPluginRecord } from "./loader-records.js";
import { createRuntimeTestRegistry } from "./registry-runtime.test-helpers.js";
import { getPluginRuntimeGatewayRequestScope } from "./runtime/gateway-request-scope.js";
import { createPluginRuntime } from "./runtime/index.js";
import type { PluginRuntime } from "./runtime/types.js";

describe("retained plugin execution observation", () => {
  it("rejects a retained method after its registration is revoked", async () => {
    let observedPlugin: string | undefined;
    const observeSettlement = vi.fn(() => {
      observedPlugin = getPluginRuntimeGatewayRequestScope()?.pluginId;
      return "settled" as const;
    });
    const subagent: PluginRuntime["subagent"] = {
      complete: async () => ({ text: "" }),
      run: async () => ({ runId: "owned-run", execution: { observeSettlement } }),
      waitForRun: async () => ({ status: "pending" }),
      getSessionMessages: async () => ({ messages: [] }),
      deleteSession: async () => {},
    };
    const runtime = createPluginRuntime({ subagent });
    runtime.config.current = () => ({});
    runtime.agent.session.getSessionEntry = () => undefined;
    runtime.agent.session.listSessionEntries = () => [];
    const builder = createRuntimeTestRegistry(runtime);
    const record = createPluginRecord({
      id: "execution-owner",
      source: "/plugins/execution-owner/index.js",
      origin: "bundled",
      enabled: true,
      configSchema: false,
    });
    const api = builder.createApi(record, { config: {} });
    const result = await api.runtime.subagent.run({
      sessionKey: "agent:main:worker",
      message: "worker",
    });
    const retained = result.execution!.observeSettlement;
    expect(retained()).toBe("settled");
    expect(observedPlugin).toBe("execution-owner");
    builder.rollbackPluginGlobalSideEffects(record.id, record);
    expect(() => retained()).toThrow("no longer active");
    expect(observeSettlement).toHaveBeenCalledOnce();
  });
});
