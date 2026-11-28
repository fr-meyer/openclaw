import { createHash } from "node:crypto";
import { resolveSessionAgentIdStrict } from "openclaw/plugin-sdk/agent-scope-runtime";
import {
  getAgentWorkspaceAccess,
  WorkspaceAccessUnavailableError,
} from "openclaw/plugin-sdk/agent-workspace-runtime";
import { resolveAgentWorkspaceDir } from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import { jsonResult } from "openclaw/plugin-sdk/memory-core-host-runtime-core";
import type { AnyAgentTool, OpenClawPluginToolContext } from "openclaw/plugin-sdk/plugin-entry";
import { withBoundedOwnerCleanup } from "./bounded-admission-cleanup.js";
import { openBoundedMemoryWorkerOwner } from "./bounded-admission-worker-owner.js";
import type { BoundedAllocation } from "./bounded-admission-worker-task.js";
import {
  requireBoundedMemoryAdmission,
  boundedMemoryAdmissionActive,
  installBoundedMemoryAdmission,
  validateBoundedMemoryPolicy,
  type BoundedMemoryPolicy,
} from "./bounded-admission.js";
import { MemoryIndexManager, getMemoryIndexManagerRegistry } from "./manager.js";

// This is an out-of-band owner binding, never model-supplied policy/allocation.
export type BoundedOwnerBinding = {
  agentId: string;
  sessionKey: string;
  sessionId: string;
  policySha256: string;
  policy: BoundedMemoryPolicy;
  allocation: Record<"forward" | "recovery", BoundedAllocation>;
  // Supplied by the approved native funding owner, not a boolean tool argument.
  assertFinancialAdmissionCurrent(): void;
  assertSelectedIndexRecoveryPrepared(): void;
};
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isAllocation(value: unknown): value is BoundedAllocation {
  return (
    isRecord(value) &&
    typeof value.calls === "number" &&
    typeof value.mass === "number" &&
    typeof value.money === "number"
  );
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return isRecord(value) && Object.values(value).every((pin) => typeof pin === "string");
}

function isBoundedOwnerBinding(value: unknown): value is BoundedOwnerBinding {
  if (!isRecord(value)) {
    return false;
  }
  const policy = value.policy;
  const allocation = value.allocation;
  if (!isRecord(policy) || !isRecord(allocation)) {
    return false;
  }
  const provider = policy.provider;
  const cohort = policy.cohort;
  return (
    typeof value.agentId === "string" &&
    typeof value.sessionKey === "string" &&
    typeof value.sessionId === "string" &&
    typeof value.policySha256 === "string" &&
    typeof value.assertFinancialAdmissionCurrent === "function" &&
    typeof value.assertSelectedIndexRecoveryPrepared === "function" &&
    typeof policy.agent === "string" &&
    typeof policy.operation === "string" &&
    typeof policy.expiresAt === "number" &&
    typeof policy.moneyPerUnit === "number" &&
    isRecord(provider) &&
    typeof provider.id === "string" &&
    typeof provider.model === "string" &&
    typeof provider.key === "string" &&
    isRecord(cohort) &&
    isStringRecord(cohort.forward) &&
    isStringRecord(cohort.recovery) &&
    isAllocation(allocation.forward) &&
    isAllocation(allocation.recovery)
  );
}

export function createBoundedMemoryOwnerTool(
  ctx: OpenClawPluginToolContext<2>,
): AnyAgentTool | null {
  if (
    ctx.senderIsOwner !== true ||
    !ctx.sessionKey ||
    !ctx.sessionId ||
    !ctx.requesterSenderId ||
    typeof ctx.assertInvocationCurrent !== "function"
  ) {
    return null;
  }
  const binding = ctx.toolBindings?.["memory-core.bounded-owner"];
  if (!isBoundedOwnerBinding(binding)) {
    return null;
  }
  const cfg = ctx.getRuntimeConfig?.() ?? ctx.runtimeConfig ?? ctx.config;
  if (!cfg) {
    return null;
  }
  const agentId = resolveSessionAgentIdStrict({
    sessionKey: ctx.sessionKey,
    config: cfg,
    agentId: ctx.agentId,
  });
  const policy = structuredClone(binding.policy),
    allocation = structuredClone(binding.allocation);
  const pin = createHash("sha256").update(JSON.stringify({ policy, allocation })).digest("hex");
  const assertCurrent = () => {
    ctx.assertInvocationCurrent();
    if (
      ctx.senderIsOwner !== true ||
      binding.agentId !== agentId ||
      policy.agent !== agentId ||
      binding.sessionKey !== ctx.sessionKey ||
      binding.sessionId !== ctx.sessionId ||
      pin !== binding.policySha256
    ) {
      throw new Error("Bounded owner identity/policy mismatch");
    }
    binding.assertFinancialAdmissionCurrent();
    binding.assertSelectedIndexRecoveryPrepared();
  };
  return {
    name: "memory_bounded_control",
    label: "Bounded Memory Control",
    description:
      "Run exactly the prebound owner-approved native memory cohort. Requires current native funding admission; does not accept policy or budgets from model arguments.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: { action: { type: "string", enum: ["forward"] } },
      required: ["action"],
    },
    async execute(_callId, raw, signal) {
      assertCurrent();
      if (!isRecord(raw) || raw.action !== "forward") {
        throw new Error("Unsupported bounded action");
      }
      validateBoundedMemoryPolicy(policy);
      if (!boundedMemoryAdmissionActive(agentId)) {
        requireBoundedMemoryAdmission(agentId);
      }
      await getMemoryIndexManagerRegistry().retireAllForAgent(agentId);
      assertCurrent();
      const owner = await openBoundedMemoryWorkerOwner(policy, allocation, assertCurrent);
      let control: ReturnType<typeof installBoundedMemoryAdmission> | undefined;
      let manager: MemoryIndexManager | null = null;
      return withBoundedOwnerCleanup(
        {
          release: async () => {
            await control?.release();
          },
          closeManager: async () => {
            await manager?.close();
          },
          closeOwner: () => owner.close(),
        },
        async () => {
          assertCurrent();
          control = installBoundedMemoryAdmission(policy, owner.escrow);
          const admittedControl = control;
          const revoke = () => {
            void admittedControl.stop().catch(() => undefined);
          };
          signal?.addEventListener("abort", revoke, { once: true });
          try {
            if (signal?.aborted) {
              throw new Error("Bounded operation cancelled");
            }
            await admittedControl.run("forward", async () => {
              assertCurrent();
              const memoryFiles = getAgentWorkspaceAccess(
                resolveAgentWorkspaceDir(cfg, agentId),
                "memoryFiles",
              )?.memoryFiles;
              if (!memoryFiles) {
                throw new WorkspaceAccessUnavailableError(
                  "Native workspace memory files unavailable",
                );
              }
              memoryFiles.assertCurrent();
              manager = await MemoryIndexManager.get({ cfg, agentId, purpose: "cli", memoryFiles });
              if (!manager) {
                throw new Error("Native memory manager unavailable");
              }
              assertCurrent();
              memoryFiles.assertCurrent();
              await manager.bootstrapBoundedProvider();
              assertCurrent();
              memoryFiles.assertCurrent();
              await manager.sync({ reason: "bounded-owner" });
            });
            return jsonResult({
              operation: policy.operation,
              policySha256: pin,
              receipt: admittedControl.receipt(),
              requiredAfterCompletion: true,
              ordinaryResumed: false,
            });
          } finally {
            signal?.removeEventListener("abort", revoke);
          }
        },
      );
    },
  };
}
