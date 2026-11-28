import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { resolveUserPath } from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import { assertBoundedMemoryBootstrap } from "./bounded-admission-bootstrap.js";
import {
  parseCandidateMetadata,
  snapshotCandidateReloadRequest,
} from "./manager-candidate-schema.js";
import {
  MemoryCandidateBuildError,
  type MemoryCandidateManifest,
  type MemoryCandidateRequest,
} from "./manager-candidate.js";
import { MemoryIndexDatabase } from "./manager-database-context.js";
import { readMemoryDatabaseRevision } from "./manager-db-kernel.js";
import { MemoryManagerState } from "./manager-owner-state.js";
import { waitForMemoryReindexLock } from "./manager-reindex-lock.js";
import { readMemoryIndexMetadata } from "./manager-retrieval-read.js";
import { readMemoryShadowIdentity } from "./manager-shadow-task.js";
import { observeNativeSources, type SourceObservation } from "./manager-source-observation.js";
import type { MemoryIndexManager } from "./manager.js";
export abstract class MemoryCandidateOrchestration extends MemoryManagerState {
  /** Internal build-only boundary on a dedicated, isolated CLI manager.
   * The serving manager is observed for identity, never reconfigured.
   * No activation, resubmission or retained-artifact cleanup is exposed here.
   */
  async buildCandidate(
    serving: MemoryIndexManager,
    request: MemoryCandidateRequest,
  ): Promise<MemoryCandidateManifest> {
    if (
      this === serving ||
      this.purpose !== "cli" ||
      this.closed ||
      this.closing ||
      serving.closed ||
      serving.closing ||
      this.syncing ||
      this.candidateBuildClaimed ||
      this.candidateOperationId !== request.operationId ||
      this.agentId !== serving.agentId ||
      this.workspaceDir !== serving.workspaceDir ||
      this.settings.fallback !== "none"
    ) {
      throw new Error("Memory candidate requires an idle isolated CLI manager with no fallback");
    }
    if (
      !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(request.operationId) ||
      !request.expected.provider ||
      !request.expected.model ||
      !Number.isSafeInteger(request.expected.dimensions) ||
      request.expected.dimensions <= 0
    ) {
      throw new Error("Invalid memory candidate operation or provider identity");
    }
    // Claim before any await. Ordinary sync can never auto-publish this manager.
    this.candidateBuildClaimed = true;
    const expected = { ...request.expected };
    const operationId = request.operationId;
    const signal = request.signal;
    const controllerRequest = request.controller
      ? {
          accountId: request.controller.accountId,
          route: request.controller.route,
          sourceRevision: request.controller.sourceRevision,
        }
      : undefined;
    const run = this.withManagerOperation(async () => {
      signal?.throwIfAborted();
      const ownPath = await fs.realpath(resolveUserPath(this.settings.store.databasePath));
      const servingPath = await fs.realpath(resolveUserPath(serving.settings.store.databasePath));
      const ownIdentity = readMemoryShadowIdentity(ownPath);
      const servingIdentity = readMemoryShadowIdentity(servingPath);
      if (
        ownPath === servingPath ||
        (ownIdentity.device === servingIdentity.device &&
          ownIdentity.inode === servingIdentity.inode)
      ) {
        throw new Error("Memory candidate store aliases the serving database");
      }
      if (this.closed || this.closing || serving.closed || serving.closing) {
        throw new Error("Memory candidate owner retired during admission");
      }
      const sourceFence = serving.candidateSourceFence();
      const assertSourceCurrent = () => {
        if (serving.candidateSourceFence() !== sourceFence) {
          throw new Error("Candidate serving source index changed during build");
        }
      };
      const directory = ownPath + ".memory-candidate-" + operationId;
      const databasePath = path.join(directory, "index.sqlite");
      // Exclusive deterministic export custody. Existing work after restart
      // must be reconciled, never silently replaced or purchased again.
      await fs.mkdir(directory, { mode: 0o700 });
      let sourceWorkStarted = false;
      let complete = false;
      let retainedManifest: MemoryCandidateManifest | undefined;
      try {
        signal?.throwIfAborted();
        await this.publishedDatabase.withPublicationGeneration(async () => {
          const lock = await waitForMemoryReindexLock(ownPath, { waitForActive: true });
          const admissionFailures: unknown[] = [];
          try {
            await this.ensureProviderInitialized();
            signal?.throwIfAborted();
            if (this.provider?.id !== expected.provider || this.provider.model !== expected.model) {
              throw new Error(
                "Memory candidate configured provider differs from approved identity",
              );
            }
            const provider = this.provider;
            const runtime = this.providerRuntime;
            const build = async (
              controller?: import("openclaw/plugin-sdk/embedding-provider-runtime-contract").EmbeddingCandidateControllerIdentity,
            ) => {
              assertSourceCurrent();
              if (this.settings.outputDimensionality !== expected.dimensions) {
                throw new Error(
                  "Memory candidate configured dimensions differ from approved identity",
                );
              }
              await this.ensureVectorReady();
              signal?.throwIfAborted();
              await this.publishedDatabase.closePublicationWorker();
              this.beginSyncProviderGeneration();
              const buildFailures: unknown[] = [];
              try {
                const manifest = await this.runInPlaceReindex(undefined, {
                  databasePath,
                  stamp: {
                    version: 1,
                    sourceFence,
                    controller,
                    cacheFileIdentity: readMemoryShadowIdentity(ownPath),
                    operationId,
                    phase: "building",
                    servingDatabasePath: servingPath,
                    servingFileIdentity: servingIdentity,
                    cacheDatabasePath: ownPath,
                  },
                  expected,
                  signal,
                  onSourceWork: () => {
                    sourceWorkStarted = true;
                  },
                });
                if (!manifest) {
                  throw new Error("Memory candidate build returned no retained artifact");
                }
                assertSourceCurrent();
                retainedManifest = manifest;
                complete = true;
                signal?.throwIfAborted();
              } catch (error) {
                buildFailures.push(error);
              } finally {
                try {
                  this.endSyncProviderGeneration();
                } catch (error) {
                  buildFailures.push(error);
                }
                try {
                  await this.publishedDatabase.closePublicationWorker();
                } catch (error) {
                  buildFailures.push(error);
                }
              }
              if (buildFailures.length === 1) {
                throw buildFailures[0];
              }
              if (buildFailures.length > 1) {
                throw new AggregateError(buildFailures, "Candidate source/worker cleanup failed", {
                  cause: buildFailures[0],
                });
              }
            };
            if (provider.id === "openai") {
              if (
                !controllerRequest ||
                controllerRequest.sourceRevision !== sourceFence ||
                !runtime ||
                !this.settings.remote?.batch?.enabled
              ) {
                throw new Error(
                  "Persistent OpenAI candidate requires explicit durable Batch journal binding",
                );
              }
              await this.managerRegistry.withCandidateBatch(
                this.managerOwner,
                provider,
                runtime,
                {
                  agentId: this.agentId,
                  journal: {
                    path: path.join(path.dirname(ownPath), "batch.sqlite"),
                    migrationId: operationId,
                    accountId: controllerRequest.accountId,
                    route: controllerRequest.route,
                    sourceRevision: controllerRequest.sourceRevision,
                  },
                  expected: { model: expected.model, dimensions: expected.dimensions },
                },
                async (batchEmbed, identity) => {
                  // Only the current registered owner can install this runtime.
                  // Direct document/query embedding is forbidden, not a fallback.
                  const refuse = async () => {
                    throw new Error("Candidate direct embedding fallback forbidden");
                  };
                  this.provider = { ...provider, embed: refuse, embedBatch: refuse };
                  this.providerRuntime = {
                    ...runtime,
                    batchEmbed,
                    batchEmbedPartial: undefined,
                    batchFailureMode: "fail-closed",
                    sourceWideBatchEmbed: true,
                  };
                  this.batch = this.resolveBatchConfig();
                  try {
                    await build(structuredClone(identity));
                  } finally {
                    this.provider = provider;
                    this.providerRuntime = runtime;
                    this.batch = this.resolveBatchConfig();
                  }
                },
              );
            } else {
              if (controllerRequest) {
                throw new Error("Candidate controller requires the registered OpenAI provider");
              }
              await build();
            }
          } catch (error) {
            admissionFailures.push(error);
          } finally {
            try {
              await lock.release();
            } catch (error) {
              admissionFailures.push(error);
            }
          }
          if (admissionFailures.length === 1) {
            throw admissionFailures[0];
          }
          if (admissionFailures.length > 1) {
            throw new AggregateError(
              admissionFailures,
              "Candidate source/admission cleanup failed",
              { cause: admissionFailures[0] },
            );
          }
        });
        // withPublicationGeneration deliberately returns void. Return the
        // retained result only after its cleanup and native admission release.
        if (!retainedManifest) {
          throw new Error("Memory candidate publication generation returned no retained manifest");
        }
        return retainedManifest;
      } catch (error) {
        if (sourceWorkStarted) {
          throw new MemoryCandidateBuildError(
            databasePath,
            complete ? "retained-complete" : "retained-unreconciled",
            error,
          );
        }
        // Only pre-source failures are disposable. Do not recursively delete a
        // directory if SQLite cleanup failed and its owned artifact remains.
        try {
          await fs.rmdir(directory);
        } catch {
          /* Preserve cleanup uncertainty. */
        }
        throw error;
      }
    });
    this.syncing = run.then(
      () => undefined,
      () => undefined,
    );
    try {
      return await run;
    } finally {
      this.syncing = null;
    }
  }

  /** Index-generation fence, not proof that an external corpus is authorized. */
  candidateSourceFence(): string {
    this.assertOrdinaryMemoryAdmission();
    if (this.closed || this.closing || this.syncing || this.dirty || this.sessionsDirty) {
      throw new Error("Serving index must be settled before candidate source admission");
    }
    return createHash("sha256")
      .update(
        JSON.stringify({
          path: resolveUserPath(this.settings.store.databasePath),
          file: readMemoryShadowIdentity(resolveUserPath(this.settings.store.databasePath)),
          revision: readMemoryDatabaseRevision(this.db),
        }),
      )
      .digest("hex");
  }

  /** Native observation only. Never a promotion fence or persisted candidate authority. */
  async observeCandidateSources(): Promise<SourceObservation> {
    this.assertOrdinaryMemoryAdmission();
    const snapshot = {
      workspaceDir: this.workspaceDir,
      sources: [...this.sources],
      settings: structuredClone({
        extraPaths: this.settings.extraPaths,
        multimodal: this.settings.multimodal,
      }),
      files: this.memoryFiles,
      indexFence: this.candidateSourceFence(),
    };
    return await this.withManagerOperation(async () => {
      const result = await observeNativeSources({
        ...snapshot,
        sessions: () => this.listSessionCorpusEntries(true),
      });
      if (
        this.candidateSourceFence() !== snapshot.indexFence ||
        JSON.stringify([...this.sources]) !== JSON.stringify(snapshot.sources) ||
        JSON.stringify({
          extraPaths: this.settings.extraPaths,
          multimodal: this.settings.multimodal,
        }) !== JSON.stringify(snapshot.settings)
      ) {
        return {
          ...result,
          status: "unverified",
          digest: null,
          issues: [...result.issues, "index-fence-changed"],
        };
      }
      return result;
    });
  }

  /** Read only; reload never resumes work, submits a provider job or activates. */
  async loadCandidateManifest(request: MemoryCandidateRequest): Promise<MemoryCandidateManifest> {
    this.assertOrdinaryMemoryAdmission();
    const snapshot = snapshotCandidateReloadRequest(request);
    return await this.withManagerOperation(async () => {
      const sourceFence = this.candidateSourceFence();
      const servingPath = await fs.realpath(resolveUserPath(this.settings.store.databasePath));
      const outer = servingPath + ".memory-candidate-" + snapshot.operationId;
      const cachePath = path.join(outer, "store.sqlite");
      const databasePath = path.join(
        cachePath + ".memory-candidate-" + snapshot.operationId,
        "index.sqlite",
      );
      for (const directory of [outer, path.dirname(databasePath)]) {
        const info = await fs.lstat(directory);
        if (
          !info.isDirectory() ||
          info.isSymbolicLink() ||
          (info.mode & 0o077) !== 0 ||
          (typeof process.getuid === "function" && info.uid !== process.getuid()) ||
          (await fs.realpath(directory)) !== directory
        ) {
          throw new Error("Invalid private candidate reload custody");
        }
      }
      const inspectLeaf = async (filename: string) => {
        const leaf = await fs.lstat(filename, { bigint: true });
        if (
          !leaf.isFile() ||
          leaf.isSymbolicLink() ||
          (leaf.mode & 0o077n) !== 0n ||
          (typeof process.getuid === "function" && leaf.uid !== BigInt(process.getuid())) ||
          (await fs.realpath(filename)) !== filename
        ) {
          throw new Error("Candidate/cache leaf custody is unsafe");
        }
        return { device: String(leaf.dev), inode: String(leaf.ino) };
      };
      const fileIdentity = await inspectLeaf(databasePath);
      const cacheIdentity = await inspectLeaf(cachePath);
      const database = await MemoryIndexDatabase.openPublished({
        agentId: this.agentId,
        writeOptions: MemoryIndexDatabase.captureWriteOptions(this.agentId, databasePath),
        readOnly: true,
        allowExtension: false,
        beforeSchema: (db) => {
          this.assertOrdinaryMemoryAdmission();
          assertBoundedMemoryBootstrap(db, this.agentId, this.settings);
        },
        schema: {
          cacheEnabled: true,
          ftsEnabled: false,
          ftsTokenizer: this.settings.store.fts.tokenizer,
        },
      });
      try {
        const meta = parseCandidateMetadata(readMemoryIndexMetadata(database.db).serialized);
        const stamp = meta?.candidate;
        if (
          !meta ||
          stamp?.version !== 1 ||
          stamp.phase !== "complete" ||
          stamp.operationId !== snapshot.operationId ||
          stamp.sourceFence !== sourceFence ||
          stamp.servingDatabasePath !== servingPath ||
          stamp.cacheDatabasePath !== cachePath ||
          JSON.stringify(stamp.candidateFileIdentity) !== JSON.stringify(fileIdentity) ||
          JSON.stringify(stamp.cacheFileIdentity) !== JSON.stringify(cacheIdentity) ||
          meta.provider !== snapshot.expected.provider ||
          meta.model !== snapshot.expected.model ||
          meta.vectorDims !== snapshot.expected.dimensions ||
          !meta.providerKey ||
          !meta.scopeHash
        ) {
          throw new Error("Candidate persistent manifest identity/source fence mismatch");
        }
        if (snapshot.expected.provider === "openai") {
          const controller = stamp.controller;
          if (
            !snapshot.controller ||
            !controller ||
            controller.agentId !== this.agentId ||
            controller.journal.path !== path.join(outer, "batch.sqlite") ||
            controller.journal.migrationId !== snapshot.operationId ||
            controller.journal.sourceRevision !== sourceFence ||
            controller.journal.accountId !== snapshot.controller.accountId ||
            controller.journal.route !== snapshot.controller.route ||
            snapshot.controller.sourceRevision !== sourceFence ||
            controller.expected.model !== meta.model ||
            controller.expected.dimensions !== meta.vectorDims ||
            controller.identity !==
              createHash("sha256")
                .update(
                  JSON.stringify({
                    migrationId: controller.journal.migrationId,
                    sourceRevision: controller.journal.sourceRevision,
                    accountId: controller.journal.accountId,
                    route: controller.journal.route,
                    agentId: controller.agentId,
                    model: controller.expected.model,
                    dimensions: controller.expected.dimensions,
                  }),
                )
                .digest("hex")
          ) {
            throw new Error("Candidate controller reload linkage mismatch");
          }
        } else if (stamp.controller || snapshot.controller) {
          throw new Error("Unexpected candidate controller linkage");
        }
        if (sourceFence !== this.candidateSourceFence()) {
          throw new Error("Candidate source changed during reload");
        }
        if (
          JSON.stringify(await inspectLeaf(databasePath)) !== JSON.stringify(fileIdentity) ||
          JSON.stringify(await inspectLeaf(cachePath)) !== JSON.stringify(cacheIdentity)
        ) {
          throw new Error("Candidate/cache leaf changed during inspection");
        }
        // Exact native readonly owner returns db/path/close, NOT handle inode.
        // No pathname check can invent proof of the opened SQLite file descriptor.
        return {
          databasePath,
          fileIdentity,
          meta,
          activation: "manual-only",
          inspection: {
            status: "unverified-inspection-only",
            openedIdentity: "unavailable",
            cacheIdentity,
            cacheStatus: "path-identity-only",
          },
        };
      } finally {
        database.release();
      }
    });
  }
}
