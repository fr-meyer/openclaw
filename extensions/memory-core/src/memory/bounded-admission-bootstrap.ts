import type { DatabaseSync } from "node:sqlite";
import type { ResolvedMemorySearchConfig } from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import { readBoundedMemoryRequirement } from "./bounded-admission-required.js";
import {
  assertBoundedMemoryOperation,
  boundedMemoryAdmissionActive,
  requireBoundedMemoryAdmission,
  MemoryAdmissionRefused,
} from "./bounded-admission.js";

export function assertBoundedMemoryBootstrap(
  db: DatabaseSync,
  agentId: string,
  settings: ResolvedMemorySearchConfig,
): void {
  if (readBoundedMemoryRequirement(db, agentId) && !boundedMemoryAdmissionActive(agentId)) {
    requireBoundedMemoryAdmission(agentId);
  }
  assertBoundedMemoryOperation(agentId);
  if (
    boundedMemoryAdmissionActive(agentId) &&
    (settings.remote?.batch?.enabled ||
      settings.fallback !== "none" ||
      settings.provider === "auto" ||
      settings.provider === "none")
  ) {
    throw new MemoryAdmissionRefused();
  }
}
