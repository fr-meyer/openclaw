import { createHash } from "node:crypto";
import type {
  EmbeddingCandidateAdmission,
  EmbeddingCandidateControllerIdentity,
  EmbeddingProviderBatchRuntime,
} from "openclaw/plugin-sdk/embedding-provider-runtime-contract";
// Memory Core plugin module owns manager cache and close serialization.
import { toErrorObject } from "openclaw/plugin-sdk/error-runtime";
import { enqueueKeyedTask } from "openclaw/plugin-sdk/keyed-async-queue";
import type {
  MemoryEmbeddingProvider,
  MemoryEmbeddingProviderAdapter,
  MemoryEmbeddingProviderCreateResult,
} from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import {
  createSubsystemLogger,
  type ResolvedMemorySearchConfig,
} from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import type { MemoryEmbeddingProbeResult } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import { racePromiseWithAbortSignal } from "openclaw/plugin-sdk/time-runtime";
import {
  resolveMemoryCoreLocalServiceHostIdentity,
  type MemoryCoreAcquireLocalService,
} from "./embedding-local-service.js";
import {
  MemoryManagerReloadError,
  type MemoryManagerLifecycle,
  type MemoryReloadState,
} from "./lifecycle.js";
import { memoryRejectionError } from "./manager-rejection.js";

const log = createSubsystemLogger("memory");

export type MemoryIndexManagerPurpose = "default" | "status" | "cli" | "maintenance";

export function normalizeMemoryIndexManagerPurpose(
  purpose: MemoryIndexManagerPurpose | undefined,
): MemoryIndexManagerPurpose {
  return purpose === "status" || purpose === "cli" || purpose === "maintenance"
    ? purpose
    : "default";
}

export type ClosableMemoryManager = {
  close(): Promise<void>;
};

type PreparedMemoryManager<T extends ClosableMemoryManager> = {
  key: string;
  create: () => Promise<T> | T;
  reuse: (manager: T) => boolean;
};

type MemoryManagerRegistryCallbacks<T extends ClosableMemoryManager> = {
  prepare: () => Promise<PreparedMemoryManager<T> | null> | PreparedMemoryManager<T> | null;
};

export type MemoryManagerAdmission = { signal?: AbortSignal; waitMs?: number; deadlineMs?: number };

class MemoryManagerAdmissionUnavailableError extends Error {
  constructor() {
    super("Memory manager admission timed out");
    this.name = "MemoryManagerAdmissionUnavailableError";
  }
}

export function resolveMemoryIndexManagerCacheKey(params: {
  agentId: string;
  workspaceDir: string;
  settings: ResolvedMemorySearchConfig;
  providerRequirement: unknown;
  purpose: MemoryIndexManagerPurpose;
  acquireLocalService?: MemoryCoreAcquireLocalService;
}): string {
  return [
    params.agentId,
    params.workspaceDir,
    JSON.stringify(params.settings),
    JSON.stringify(params.providerRequirement),
    resolveMemoryCoreLocalServiceHostIdentity(params.acquireLocalService),
    params.purpose,
  ].join(":");
}

export type MemoryEmbeddingProbeCacheEntry = {
  result: MemoryEmbeddingProbeResult;
  adapters: readonly MemoryEmbeddingProviderAdapter[];
  checkedAtMs: number;
  expireAtMs: number;
};

type ProviderFactory = () => Promise<MemoryEmbeddingProviderCreateResult>;
export type MemoryManagerProviderFactory = (
  adapter: MemoryEmbeddingProviderAdapter,
  create: ProviderFactory,
) => Promise<MemoryEmbeddingProviderCreateResult>;

type ManagerOwnership = {
  key: string;
  pending: Map<object, MemoryEmbeddingProviderAdapter>;
  providers: Map<MemoryEmbeddingProvider, MemoryEmbeddingProviderAdapter>;
  failedAdapters: Set<MemoryEmbeddingProviderAdapter>;
  retiring: boolean;
};

export class MemoryManagerRegistry<T extends ClosableMemoryManager> {
  readonly embeddingProbeCache = new Map<string, MemoryEmbeddingProbeCacheEntry>();
  private readonly cache = new Map<string, T>();
  private readonly scopeOperations = new Map<string, Promise<void>>();
  private closePromise: Promise<void> | null = null;
  private readonly managers = new Map<T, ManagerOwnership>();
  private readonly candidateOwners = new WeakMap<
    MemoryEmbeddingProvider,
    {
      runtime: NonNullable<MemoryEmbeddingProviderCreateResult["runtime"]>;
      bind: EmbeddingProviderBatchRuntime["withCandidateBatch"];
    }
  >();
  constructor(private readonly lifecycle: MemoryManagerLifecycle = {}) {
    lifecycle.prepare = (reload) => this.prepareManagersForReload(reload);
  }

  private get reload() {
    return this.lifecycle.reload;
  }

  track(manager: T, key: string): ManagerOwnership {
    let owner = this.managers.get(manager);
    if (!owner) {
      owner = {
        key,
        pending: new Map(),
        providers: new Map(),
        failedAdapters: new Set(),
        retiring: false,
      };
      this.managers.set(manager, owner);
    }
    return owner;
  }

  async createProvider(
    manager: T,
    adapter: MemoryEmbeddingProviderAdapter,
    create: ProviderFactory,
  ) {
    const owner = this.managers.get(manager);
    if (!owner) {
      throw new Error("Memory manager has no lifecycle owner");
    }
    if (owner.retiring || this.reload?.retireRuntime || this.reload?.adapters.has(adapter)) {
      throw new MemoryManagerReloadError();
    }
    const acquisition = {};
    // Record the exact adapter before creation can yield; late results belong to
    // this manager's close, including when replacement began during creation.
    owner.pending.set(acquisition, adapter);
    try {
      const result = await create();
      if (result.provider) {
        owner.providers.set(result.provider, adapter);
        if (result.runtime) {
          this.candidateOwners.set(result.provider, {
            runtime: result.runtime,
            bind: result.runtime.withCandidateBatch,
          });
        }
        owner.failedAdapters.delete(adapter);
      } else {
        owner.failedAdapters.add(adapter);
      }
      return result;
    } catch (error) {
      owner.failedAdapters.add(adapter);
      throw error;
    } finally {
      owner.pending.delete(acquisition);
    }
  }

  withCandidateBatch<R>(
    manager: T,
    provider: MemoryEmbeddingProvider,
    runtime: NonNullable<MemoryEmbeddingProviderCreateResult["runtime"]>,
    admission: EmbeddingCandidateAdmission,
    run: (
      batch: EmbeddingProviderBatchRuntime["batchEmbed"],
      identity: EmbeddingCandidateControllerIdentity,
    ) => Promise<R>,
  ): Promise<R> {
    const operation = (async () => {
      const baseline = Object.freeze({
        agentId: admission.agentId,
        journal: Object.freeze({
          path: admission.journal.path,
          migrationId: admission.journal.migrationId,
          sourceRevision: admission.journal.sourceRevision,
          accountId: admission.journal.accountId,
          route: admission.journal.route,
        }),
        expected: Object.freeze({
          model: admission.expected.model,
          dimensions: admission.expected.dimensions,
        }),
      });
      const adapterAdmission = Object.freeze({
        ...baseline,
        journal: Object.freeze({ ...baseline.journal }),
        expected: Object.freeze({ ...baseline.expected }),
      });
      const expectedIdentity = createHash("sha256")
        .update(
          JSON.stringify({
            migrationId: baseline.journal.migrationId,
            sourceRevision: baseline.journal.sourceRevision,
            accountId: baseline.journal.accountId,
            route: baseline.journal.route,
            agentId: baseline.agentId,
            model: baseline.expected.model,
            dimensions: baseline.expected.dimensions,
          }),
        )
        .digest("hex");
      const owner = this.managers.get(manager);
      const adapter = owner?.providers.get(provider);
      const owned = this.candidateOwners.get(provider);
      const assertCurrent = () => {
        if (
          !owner ||
          owner.retiring ||
          this.reload?.retireRuntime ||
          !adapter ||
          this.reload?.adapters.has(adapter) ||
          owner.providers.get(provider) !== adapter ||
          !owned ||
          owned.runtime !== runtime ||
          !owned.bind ||
          runtime.withCandidateBatch !== owned.bind
        ) {
          throw new Error(
            "Candidate Batch capability is not owned by the current registered provider",
          );
        }
      };
      assertCurrent();
      const bind = owned!.bind!;
      return await bind(adapterAdmission, async (batch, identity) => {
        assertCurrent();
        if (
          identity.agentId !== baseline.agentId ||
          identity.identity !== expectedIdentity ||
          JSON.stringify(identity.journal) !== JSON.stringify(baseline.journal) ||
          JSON.stringify(identity.expected) !== JSON.stringify(baseline.expected)
        ) {
          throw new Error("Registered candidate controller changed its admitted identity");
        }
        const retainedIdentity = Object.freeze({ ...baseline, identity: expectedIdentity });
        let active = true;
        const pending = new Set<Promise<number[][] | null>>();
        const failures: unknown[] = [];
        const track = (work: Promise<number[][] | null>) => {
          pending.add(work);
          void work.then(
            () => {
              pending.delete(work);
            },
            (error: unknown) => {
              pending.delete(work);
              if (!failures.includes(error)) {
                failures.push(error);
              }
            },
          );
          return work;
        };
        let result: R | undefined;
        try {
          result = await run((options) => {
            try {
              assertCurrent();
              if (!active) {
                throw new Error("Candidate registry Batch custody retired");
              }
              const snapshot = {
                agentId: options.agentId,
                chunks: structuredClone(options.chunks),
                wait: options.wait,
                concurrency: options.concurrency,
                pollIntervalMs: options.pollIntervalMs,
                timeoutMs: options.timeoutMs,
                debug: options.debug,
              };
              return track(batch(snapshot));
            } catch (error) {
              return track(Promise.reject(memoryRejectionError(error)));
            }
          }, retainedIdentity);
        } catch (error) {
          const index = failures.indexOf(error);
          if (index >= 0) {
            failures.splice(index, 1);
          }
          failures.unshift(error);
        } finally {
          active = false;
          while (pending.size) {
            await Promise.allSettled(pending);
          }
        }
        try {
          assertCurrent();
        } catch (error) {
          failures.push(error);
        }
        if (failures.length === 1) {
          throw failures[0];
        }
        if (failures.length > 1) {
          throw new AggregateError(failures, "Candidate registry callback/drain/owner failed", {
            cause: failures[0],
          });
        }
        return result as R;
      });
    })();
    void operation.catch(() => {});
    return operation;
  }

  canPublishProbe(manager: T): boolean {
    const owner = this.managers.get(manager);
    return owner !== undefined && !owner.retiring;
  }

  getProbeOwners(manager: T): readonly MemoryEmbeddingProviderAdapter[] {
    const owner = this.managers.get(manager);
    return owner
      ? [
          ...new Set([
            ...owner.pending.values(),
            ...owner.providers.values(),
            ...owner.failedAdapters,
          ]),
        ]
      : [];
  }

  releaseProvider(manager: T, provider: MemoryEmbeddingProvider): void {
    this.managers.get(manager)?.providers.delete(provider);
  }

  private prepareManagersForReload(reload: MemoryReloadState) {
    // A probe can outlive its transient manager, but never the adapter that produced it.
    for (const [key, entry] of this.embeddingProbeCache) {
      if (reload.retireRuntime || entry.adapters.some((adapter) => reload.adapters.has(adapter))) {
        this.embeddingProbeCache.delete(key);
      }
    }
    return async () => {
      // Overlapping reloads join the manager's existing close; retirement alone
      // does not mean its cleanup has completed.
      const selected = [...this.managers].filter(
        ([manager, owner]) =>
          owner.retiring ||
          reload.retireRuntime ||
          this.getProbeOwners(manager).some((adapter) => reload.adapters.has(adapter)),
      );
      for (const [manager, owner] of selected) {
        owner.retiring = true;
        // Release reuse before cleanup can yield. Keep the retiring owner so
        // late provider/probe work cannot publish into its replacement's cache.
        if (this.cache.get(owner.key) === manager) {
          this.cache.delete(owner.key);
        }
        this.embeddingProbeCache.delete(owner.key);
      }
      // Capture construction tails with this retirement; a timeout followed by
      // resume must not make this old drain select newly acquired managers.
      const results = await Promise.allSettled([
        ...(reload.retireRuntime ? this.scopeOperations.values() : []),
        ...selected.map(([manager, owner]) => this.closeEntry(owner.key, manager)),
      ]);
      return {
        errors: results.flatMap((result) => (result.status === "rejected" ? [result.reason] : [])),
      };
    };
  }

  async acquire(
    params: {
      agentId: string;
      purpose: MemoryIndexManagerPurpose;
      admission?: MemoryManagerAdmission;
    },
    callbacks: MemoryManagerRegistryCallbacks<T>,
  ): Promise<T | null> {
    // A detached search handoff may race global teardown. Decline late
    // maintenance acquisition so closing the default manager cannot wait on itself.
    if (params.purpose === "maintenance" && (this.reload?.retireRuntime || this.closePromise)) {
      return null;
    }
    if (this.reload?.retireRuntime) {
      throw new MemoryManagerReloadError();
    }
    return await this.runScopeOperation(params, async () => {
      if (this.reload?.retireRuntime) {
        throw new MemoryManagerReloadError();
      }
      const prepared = await callbacks.prepare();
      if (!prepared) {
        return null;
      }
      if (this.reload?.retireRuntime) {
        throw new MemoryManagerReloadError();
      }
      const create = async () => {
        if (this.reload?.retireRuntime) {
          throw new MemoryManagerReloadError();
        }
        const manager = await prepared.create();
        const owner = this.track(manager, prepared.key);
        if (this.reload?.retireRuntime) {
          owner.retiring = true;
          await this.closeEntries([[prepared.key, manager]]);
          throw new MemoryManagerReloadError();
        }
        return manager;
      };
      if (params.purpose !== "default") {
        return await create();
      }
      const cachedManager = this.cache.get(prepared.key);
      await this.closeScopeUnlocked({
        agentId: params.agentId,
        purpose: params.purpose,
        ...(cachedManager && prepared.reuse(cachedManager) ? { exceptKey: prepared.key } : {}),
      });
      // The scope queue already serializes creation and replacement for this agent.
      const existing = this.cache.get(prepared.key);
      if (existing) {
        // Other sidecars may drain between preparation and memory cleanup.
        // Recheck after the scope await without discarding the manager needed for rollback.
        const reload = this.reload;
        if (
          reload &&
          (reload.retireRuntime ||
            this.getProbeOwners(existing).some((adapter) => reload.adapters.has(adapter)))
        ) {
          throw new MemoryManagerReloadError();
        }
        return existing;
      }
      const manager = await create();
      this.cache.set(prepared.key, manager);
      return manager;
    });
  }

  async closeAll(): Promise<void> {
    const previous = this.closePromise ?? Promise.resolve();
    const operation = () => this.closeAllUnlocked();
    const closePromise = previous.then(operation, operation);
    this.closePromise = closePromise;
    await closePromise;
    if (this.closePromise === closePromise) {
      this.closePromise = null;
    }
  }

  async retireAllForAgent(agentId: string): Promise<void> {
    const agent = normalizeAgentId(agentId);
    // Admission must already be required, blocking queued/new acquisitions.
    const pending = [...this.scopeOperations.entries()]
      .filter(([key]) => {
        try {
          return JSON.parse(key)[0] === agent;
        } catch {
          return false;
        }
      })
      .map(([, task]) => task);
    await Promise.allSettled(pending);
    await this.closeEntries(
      [...this.managers]
        .filter(([, owner]) => owner.key.startsWith(agent + ":"))
        .map(([manager, owner]) => [owner.key, manager]),
      agent,
    );
  }

  async closeForAgent(params: {
    agentId: string;
    purpose: MemoryIndexManagerPurpose;
  }): Promise<void> {
    const scope = { agentId: normalizeAgentId(params.agentId), purpose: params.purpose };
    await this.runScopeOperation(scope, () => this.closeScopeUnlocked(scope));
  }

  deleteIfCurrent(key: string, manager: T): void {
    this.managers.delete(manager);
    if (this.cache.get(key) === manager) {
      this.cache.delete(key);
    }
  }

  private async runScopeOperation<R>(
    params: {
      agentId: string;
      purpose: MemoryIndexManagerPurpose;
      admission?: MemoryManagerAdmission;
    },
    operation: () => Promise<R>,
  ): Promise<R> {
    const admission = new AbortController();
    const callerSignal = params.admission?.signal;
    const onCallerAbort = () => admission.abort(callerSignal?.reason);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onQueuedAbort: (() => void) | undefined;
    const disarm = () => {
      clearTimeout(timer);
      timer = undefined;
      callerSignal?.removeEventListener("abort", onCallerAbort);
      if (onQueuedAbort) {
        admission.signal.removeEventListener("abort", onQueuedAbort);
      }
    };
    callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
    if (callerSignal?.aborted) {
      onCallerAbort();
    }
    const deadlineMs = params.admission?.deadlineMs;
    const waitMs =
      deadlineMs !== undefined ? Math.max(0, deadlineMs - Date.now()) : params.admission?.waitMs;
    if (waitMs === 0) {
      admission.abort(new MemoryManagerAdmissionUnavailableError());
    } else if (waitMs !== undefined && Number.isFinite(waitMs) && waitMs > 0) {
      timer = setTimeout(
        () => admission.abort(new MemoryManagerAdmissionUnavailableError()),
        waitMs,
      );
      timer.unref?.();
    }
    try {
      // One budget covers both admission barriers. Never cancel either shared owner.
      while (this.closePromise) {
        const globalClose = this.closePromise;
        try {
          await racePromiseWithAbortSignal(
            globalClose,
            admission.signal,
            (signal) => signal.reason,
          );
        } catch (error) {
          if (admission.signal.aborted) {
            throw error;
          }
          if (this.closePromise === globalClose) {
            await racePromiseWithAbortSignal(
              () => this.closeAll(),
              admission.signal,
              (signal) => signal.reason,
            );
          }
        }
      }
      admission.signal.throwIfAborted();
      let started = false;
      let abandoned = false;
      const queued = enqueueKeyedTask({
        tails: this.scopeOperations,
        key: JSON.stringify([params.agentId, params.purpose]),
        task: async () => {
          if (abandoned) {
            throw admission.signal.reason;
          }
          callerSignal?.throwIfAborted();
          admission.signal.throwIfAborted();
          if (deadlineMs !== undefined && Date.now() >= deadlineMs) {
            throw new MemoryManagerAdmissionUnavailableError();
          }
          started = true;
          // The bound ends before prepare, replacement close, or factory work starts.
          disarm();
          return await operation();
        },
      });
      return await new Promise<R>((resolve, reject) => {
        onQueuedAbort = () => {
          if (started) {
            return;
          }
          abandoned = true;
          reject(memoryRejectionError(admission.signal.reason));
        };
        admission.signal.addEventListener("abort", onQueuedAbort, { once: true });
        if (admission.signal.aborted) {
          onQueuedAbort();
        }
        // Keep observing a rejected abandoned queue callback after our caller exits.
        queued.then(resolve, reject);
      });
    } finally {
      disarm();
    }
  }

  private async closeAllUnlocked(): Promise<void> {
    const scopedOperations = Array.from(this.scopeOperations.values());
    if (scopedOperations.length > 0) {
      await Promise.allSettled(scopedOperations);
    }
    // Withdrawn retirement owners still need explicit retry; live transient managers remain caller-owned.
    await this.closeEntries(
      [...this.managers]
        .filter(([manager, owner]) => owner.retiring || this.cache.get(owner.key) === manager)
        .map(([manager, owner]) => [owner.key, manager]),
    );
  }

  private async closeScopeUnlocked(params: {
    agentId: string;
    purpose: MemoryIndexManagerPurpose;
    exceptKey?: string;
  }): Promise<void> {
    const isScopedKey = (key: string) =>
      key !== params.exceptKey &&
      key.startsWith(`${params.agentId}:`) &&
      key.endsWith(`:${params.purpose}`);
    await this.closeEntries(
      Array.from(this.cache.entries()).filter(([key]) => isScopedKey(key)),
      params.agentId,
    );
  }

  private async closeEntry(key: string, manager: T): Promise<void> {
    await manager.close();
    this.deleteIfCurrent(key, manager);
  }

  private async closeEntries(entries: Array<[string, T]>, agentId?: string): Promise<void> {
    let firstError: unknown;
    for (const [key, manager] of entries) {
      try {
        await this.closeEntry(key, manager);
      } catch (err) {
        firstError ??= err;
        const scope = agentId ? ` for agent ${agentId}` : "";
        log.warn(`failed to close memory index manager${scope}: ${String(err)}`);
      }
    }
    if (firstError !== undefined) {
      throw toErrorObject(firstError, "Failed to close memory index manager");
    }
  }
}

/** Provider ownership only; ancestor state must not depend on the concrete cached manager. */
export type MemoryManagerProviderOwnerRegistry = Pick<
  MemoryManagerRegistry<ClosableMemoryManager>,
  | "createProvider"
  | "releaseProvider"
  | "canPublishProbe"
  | "getProbeOwners"
  | "embeddingProbeCache"
  | "withCandidateBatch"
>;
