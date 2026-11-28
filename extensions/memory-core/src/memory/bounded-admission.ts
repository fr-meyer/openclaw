import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomUUID } from "node:crypto";
import { readFile, lstat, realpath } from "node:fs/promises";
import { resolve } from "node:path";
type Phase = "forward" | "recovery";
type Allowance = { calls: number; mass: number; money: number };
export type BoundedMemoryPolicy = {
  agent: string;
  operation: string;
  expiresAt: number;
  moneyPerUnit: number;
  provider: { id: string; model: string; key: string };
  cohort: Record<Phase, Record<string, string>>;
};
export type BoundedMemoryEscrow = {
  assertActive(operation: string, phase: Phase, now: number): void;
  debit(
    operation: string,
    phase: Phase,
    root: string,
    need: Allowance,
    now: number,
  ): void | Promise<void>;
  stop(operation: string): void | Promise<void>;
  recovery(): void | Promise<void>;
  resumeOrdinary(operation: string): void | Promise<void>;
  receipt(operation: string): unknown;
};
export class MemoryAdmissionRefused extends Error {
  readonly code = "MEMORY_ADMISSION_REFUSED";
  constructor() {
    super("MEMORY_ADMISSION_REFUSED");
  }
}
export function isMemoryAdmissionRefused(error: unknown): boolean {
  const seen = new Set<unknown>();
  let current = error;
  while (current && typeof current === "object" && !seen.has(current)) {
    seen.add(current);
    if (Reflect.get(current, "code") === "MEMORY_ADMISSION_REFUSED") {
      return true;
    }
    current = Reflect.get(current, "cause");
  }
  return false;
}
type Lease = { live: boolean; syncClaimed: boolean; children: Set<Promise<unknown>> };
type Admission = {
  policy: BoundedMemoryPolicy;
  escrow: BoundedMemoryEscrow;
  active: Promise<unknown> | null;
  lease: Lease | null;
  closing: boolean;
};
const owners = new Map<string, Admission | null>();
const scope = new AsyncLocalStorage<{ admission: Admission; phase: Phase; lease: Lease }>();
const digest = (text: string) => createHash("sha256").update(text).digest("hex");
// Bootstrap must register required agents before any manager import/open. A missing
// policy remains a tombstone, never an implicit return to ordinary traffic.
export function requireBoundedMemoryAdmission(agent: string) {
  if (!agent || owners.has(agent)) {
    throw new MemoryAdmissionRefused();
  }
  owners.set(agent, null);
}
export function validateBoundedMemoryPolicy(policy: BoundedMemoryPolicy) {
  if (
    !policy.agent ||
    !policy.operation ||
    !Number.isSafeInteger(policy.expiresAt) ||
    policy.expiresAt <= Date.now() ||
    !Number.isSafeInteger(policy.moneyPerUnit) ||
    policy.moneyPerUnit <= 0 ||
    !policy.provider.id ||
    !policy.provider.model ||
    !policy.provider.key
  ) {
    throw new MemoryAdmissionRefused();
  }
  for (const part of [policy.cohort.forward, policy.cohort.recovery]) {
    if (
      !Object.keys(part).length ||
      Object.entries(part).some(
        ([path, pin]) => !path.startsWith("/") || !/^[a-f0-9]{64}$/.test(pin),
      )
    ) {
      throw new MemoryAdmissionRefused();
    }
  }
}
export function installBoundedMemoryAdmission(
  sourcePolicy: BoundedMemoryPolicy,
  escrow: BoundedMemoryEscrow,
  initialPhase: Phase = "forward",
) {
  validateBoundedMemoryPolicy(sourcePolicy);
  if (owners.get(sourcePolicy.agent)) {
    throw new MemoryAdmissionRefused();
  }
  const admission: Admission = {
    policy: structuredClone(sourcePolicy),
    escrow,
    active: null,
    lease: null,
    closing: false,
  };
  const policy = admission.policy;
  escrow.assertActive(policy.operation, initialPhase, Date.now());
  owners.set(policy.agent, admission);
  async function drain() {
    if (owners.get(policy.agent) !== admission) {
      throw new MemoryAdmissionRefused();
    }
    admission.closing = true;
    if (admission.lease) {
      admission.lease.live = false;
    }
    if (scope.getStore()?.admission === admission) {
      throw new MemoryAdmissionRefused();
    }
    if (admission.active) {
      await admission.active.catch(() => undefined);
    }
  }
  return {
    async run<T>(phase: Phase, run: () => Promise<T>): Promise<T> {
      if (
        owners.get(policy.agent) !== admission ||
        scope.getStore() ||
        admission.active ||
        admission.closing ||
        !["forward", "recovery"].includes(phase)
      ) {
        throw new MemoryAdmissionRefused();
      }
      const lease: Lease = { live: true, syncClaimed: false, children: new Set() };
      admission.lease = lease;
      // Defer callback until active is published, including synchronous callbacks.
      const pending = Promise.resolve().then(() =>
        scope.run({ admission, phase, lease }, async () => {
          try {
            assertBoundedMemoryOperation(policy.agent);
            return await run();
          } catch (error) {
            try {
              await escrow.stop(policy.operation);
            } catch (stopError) {
              if (error instanceof Error && Object.isExtensible(error)) {
                Object.defineProperty(error, "boundedStopFailure", {
                  value: stopError,
                  enumerable: true,
                });
              }
            }
            throw error;
          } finally {
            lease.live = false;
            while (lease.children.size) {
              await Promise.allSettled(lease.children);
            }
          }
        }),
      );
      admission.active = pending;
      try {
        return await pending;
      } finally {
        admission.active = null;
        admission.lease = null;
      }
    },
    async stop() {
      await drain();
      await escrow.stop(policy.operation);
    },
    async recovery() {
      await drain();
      await escrow.recovery();
      admission.closing = false;
    },
    receipt() {
      return escrow.receipt(policy.operation);
    },
    async release() {
      await drain();
      await escrow.stop(policy.operation);
      owners.set(policy.agent, null);
    },
    // Ordinary operation resumes only after explicit owner acceptance, not failure.
    async resumeOrdinary() {
      await drain();
      await escrow.resumeOrdinary(policy.operation);
      owners.delete(policy.agent);
    },
  };
}
export function boundedMemoryAdmissionActive(agent: string) {
  return owners.has(agent);
}
export function assertBoundedMemoryOperation(agent: string, deny = false) {
  const inherited = scope.getStore();
  if (inherited?.admission.policy.agent === agent && !inherited.lease.live) {
    throw new MemoryAdmissionRefused();
  }
  if (!owners.has(agent)) {
    return;
  }
  const admission = owners.get(agent),
    current = inherited;
  if (
    !admission ||
    deny ||
    current?.admission !== admission ||
    !current.lease.live ||
    admission.closing ||
    Date.now() >= admission.policy.expiresAt
  ) {
    throw new MemoryAdmissionRefused();
  }
  try {
    admission.escrow.assertActive(admission.policy.operation, current.phase, Date.now());
  } catch {
    throw new MemoryAdmissionRefused();
  }
}
// Dispatch/join leases prevent stop/release from returning while already-admitted
// native work remains. Revocation blocks subsequent dispatch and publication.
export async function withBoundedMemoryWork<T>(agent: string, run: () => Promise<T>): Promise<T> {
  assertBoundedMemoryOperation(agent);
  if (!owners.has(agent)) {
    return await run();
  }
  const lease = scope.getStore()!.lease;
  const pending = Promise.resolve().then(() => {
    assertBoundedMemoryOperation(agent);
    return run();
  });
  void pending.catch(() => undefined);
  lease.children.add(pending);
  try {
    return await pending;
  } finally {
    lease.children.delete(pending);
  }
}
export function selectBoundedMemoryPaths(agent: string): string[] | undefined {
  assertBoundedMemoryOperation(agent);
  const current = scope.getStore();
  return owners.has(agent) && current
    ? Object.keys(current.admission.policy.cohort[current.phase])
    : undefined;
}
export function assertBoundedMemorySnapshot(
  agent: string,
  path: string,
  content: string,
  entryHash: string,
) {
  assertBoundedMemoryOperation(agent);
  if (!owners.has(agent)) {
    return;
  }
  const current = scope.getStore()!,
    expected = current.admission.policy.cohort[current.phase][path];
  if (!expected || digest(content) !== expected || entryHash !== expected) {
    throw new MemoryAdmissionRefused();
  }
}
export function assertBoundedMemoryIdentity(
  agent: string,
  provider: { id: string; model: string },
  key: string | null,
) {
  assertBoundedMemoryOperation(agent);
  if (!owners.has(agent)) {
    return;
  }
  const expected = scope.getStore()!.admission.policy.provider;
  if (provider.id !== expected.id || provider.model !== expected.model || key !== expected.key) {
    throw new MemoryAdmissionRefused();
  }
}
export async function reserveBoundedMemoryRoot(
  agent: string,
  root: string,
  texts: string[],
  provider: { id: string; model: string },
  key: string | null,
) {
  assertBoundedMemoryIdentity(agent, provider, key);
  if (!owners.has(agent)) {
    return;
  }
  const { admission, phase } = scope.getStore()!;
  const mass = texts.reduce((sum, text) => sum + Buffer.byteLength(text) + 64, 0);
  const money = mass * 36 * admission.policy.moneyPerUnit;
  if (!texts.length || !Number.isSafeInteger(mass) || !Number.isSafeInteger(money)) {
    throw new MemoryAdmissionRefused();
  }
  try {
    await admission.escrow.debit(
      admission.policy.operation,
      phase,
      root,
      { calls: 1, mass, money },
      Date.now(),
    );
  } catch {
    const refusal = new MemoryAdmissionRefused();
    try {
      await admission.escrow.stop(admission.policy.operation);
    } catch (stopError) {
      Object.defineProperty(refusal, "boundedStopFailure", { value: stopError, enumerable: true });
    }
    throw refusal;
  }
}
export function reserveBoundedMemoryProbe(
  agent: string,
  provider: { id: string; model: string },
  key: string | null,
) {
  return reserveBoundedMemoryRoot(agent, randomUUID(), ["ping"], provider, key);
}

export function claimBoundedMemorySync(agent: string) {
  assertBoundedMemoryOperation(agent);
  if (!owners.has(agent)) {
    return;
  }
  const lease = scope.getStore()!.lease;
  if (lease.syncClaimed) {
    throw new MemoryAdmissionRefused();
  }
  lease.syncClaimed = true;
}

// Runtime adapter must route each constructor probe through dispatch. No ambient
// provider factory is invoked here; constructor provenance is an artifact gate.
export async function bootstrapBoundedMemoryProvider<T>(
  agent: string,
  factory: (dispatch: <R>(texts: string[], run: () => Promise<R>) => Promise<R>) => Promise<T>,
): Promise<T> {
  assertBoundedMemoryOperation(agent);
  if (!owners.has(agent)) {
    throw new MemoryAdmissionRefused();
  }
  const provider = scope.getStore()!.admission.policy.provider;
  return await withBoundedMemoryWork(agent, () =>
    factory(async (texts, run) => {
      if (texts.length !== 1 || texts[0] !== "ping") {
        throw new MemoryAdmissionRefused();
      }
      await reserveBoundedMemoryRoot(agent, randomUUID(), texts, provider, provider.key);
      return await withBoundedMemoryWork(agent, run);
    }),
  );
}

export async function preflightBoundedMemorySources(agent: string) {
  const paths = selectBoundedMemoryPaths(agent);
  if (!paths) {
    return;
  }
  for (const path of paths) {
    assertBoundedMemoryOperation(agent);
    if (
      !path.endsWith(".md") ||
      (await lstat(path)).isSymbolicLink() ||
      (await realpath(path)) !== resolve(path)
    ) {
      throw new MemoryAdmissionRefused();
    }
    const content = await readFile(path, "utf8");
    assertBoundedMemorySnapshot(agent, path, content, digest(content));
  }
}

export function boundedMemoryProviderIdentity(agent: string) {
  assertBoundedMemoryOperation(agent);
  return owners.has(agent) ? { ...scope.getStore()!.admission.policy.provider } : undefined;
}
