// Source-only release proof: real transport, plugin, SQLite and execution owner.
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { WorkboardCard } from "@openclaw/workboard-contract";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDeferred } from "../../test/helpers/promise.js";
import { createTempDirTracker } from "../../test/helpers/temp-dir.js";
import { captureEnv } from "../test-utils/env.js";
import { acquireTestPortBlock } from "../test-utils/port-claims.js";
import {
  assertNativeSandboxMountsSettled,
  createNativeSandboxFixture,
} from "./native-sandbox.test-support.js";
import {
  installChannelBindingRuntimeLoader,
  installInstanceBindingConfigIo,
} from "./server-plugins.lifecycle.test-support.js";
import {
  agentCommandMock,
  connectWebchatClient,
  installGatewayTestHooks,
  rpcReq,
  startTestGatewayServer,
} from "./test-helpers.js";

vi.doUnmock("../plugins/loader.js");
installGatewayTestHooks({ scope: "suite" });
installInstanceBindingConfigIo();
const tempDirs = createTempDirTracker();
let sandboxReleased = true;
afterEach(() => {
  if (!sandboxReleased) {
    throw new Error("Native sandbox retirement unconfirmed; temporary state retained");
  }
  tempDirs.cleanup();
});

describe("native Workboard Gateway release contract", () => {
  it(
    "binds one wire target and intent to the real producer without touching sibling cards",
    {
      timeout: 300_000,
    },
    async () => {
      const env = captureEnv([
        "OPENCLAW_TEST_MINIMAL_GATEWAY",
        "OPENCLAW_DISABLE_BUNDLED_PLUGINS",
        "OPENCLAW_BUNDLED_PLUGINS_DIR",
        "OPENCLAW_TEST_TRUST_BUNDLED_PLUGINS_DIR",
      ]);
      const finishInference = createDeferred();
      const inferenceStarted = createDeferred();
      const restoreRuntime = await installChannelBindingRuntimeLoader({ observations: [] });
      const clients: Array<Awaited<ReturnType<typeof connectWebchatClient>>> = [];
      let sandbox: ReturnType<typeof createNativeSandboxFixture> | undefined;
      let restoreEngine: (() => void) | undefined;
      let server: Awaited<ReturnType<typeof startTestGatewayServer>> | undefined;
      let closure: Promise<void> | undefined;
      let cancelled = false;
      const closeFixture = () =>
        (closure ??= (async () => {
          finishInference.resolve();
          for (const client of clients) {
            client.close();
          }
          if (sandbox) {
            await sandbox.retire();
            sandboxReleased = true;
          }
          if (server) {
            await server.close({ reason: "native Workboard fixture cleanup" });
          }
        })());
      const cancelFixture = () => {
        cancelled = true;
        // The same fixture owner settles cancellation and ordinary teardown.
        // Its held record prevents state/cache disposal if closure fails.
        void closeFixture().catch(() => {});
      };
      agentCommandMock.mockImplementation(async () => {
        inferenceStarted.resolve();
        await finishInference.promise;
        return { payloads: [], meta: { durationMs: 0 } };
      });
      try {
        const uid = process.getuid?.();
        const gid = process.getgid?.();
        if (uid === undefined || gid === undefined) {
          throw new Error("Native sandbox fixture requires an admitted POSIX runner");
        }
        const workspace = tempDirs.make("openclaw-native-workboard-");
        const recordPath = process.env.OPENCLAW_NATIVE_SANDBOX_RECORD;
        const admissionPath = process.env.OPENCLAW_NATIVE_SANDBOX_ADMISSION;
        const endMs = Number(process.env.OPENCLAW_NATIVE_SANDBOX_END_MS);
        if (
          !recordPath ||
          !admissionPath ||
          !Number.isSafeInteger(endMs) ||
          endMs <= Date.now() + 120_000
        ) {
          throw new Error("Native sandbox fixture has no bounded runner admission");
        }
        const admission: unknown = JSON.parse(await fs.readFile(admissionPath, "utf8"));
        if (
          !admission ||
          typeof admission !== "object" ||
          !("format" in admission) ||
          admission.format !== 1 ||
          !("host" in admission) ||
          admission.host !== "unix:///var/run/docker.sock" ||
          !("engineId" in admission) ||
          typeof admission.engineId !== "string" ||
          !("image" in admission) ||
          admission.image !==
            "docker.io/library/python@sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a" ||
          !("socket" in admission) ||
          !admission.socket ||
          typeof admission.socket !== "object" ||
          !("path" in admission.socket) ||
          typeof admission.socket.path !== "string" ||
          !("device" in admission.socket) ||
          typeof admission.socket.device !== "number" ||
          !("inode" in admission.socket) ||
          typeof admission.socket.inode !== "number" ||
          !Number.isSafeInteger(admission.socket.device) ||
          !Number.isSafeInteger(admission.socket.inode)
        ) {
          throw new Error("Native sandbox engine admission differs");
        }
        const engineId = admission.engineId;
        const image = admission.image;
        const socket = {
          path: admission.socket.path,
          device: admission.socket.device,
          inode: admission.socket.inode,
        };
        const assertSocket = async () => {
          const value = await fs.stat(socket.path);
          if (
            (await fs.realpath("/var/run/docker.sock")) !== socket.path ||
            !value.isSocket() ||
            value.dev !== socket.device ||
            value.ino !== socket.inode
          ) {
            throw new Error("Native sandbox engine socket changed; custody retained");
          }
        };
        const engine = await import("../agents/sandbox/container-engine.js");
        const registry = await import("../agents/sandbox/registry.js");
        const manager = await import("../agents/sandbox/manage.js");
        const execute = engine.execContainer;
        let cgroup: string | undefined;
        const prefix = `openclaw-native-${createHash("sha256").update(workspace).digest("hex").slice(0, 12)}-`;
        sandbox = createNativeSandboxFixture({
          workspace,
          prefix,
          image,
          workEnd: Math.min(Date.now() + 120_000, endMs - 120_000),
          closureEnd: endMs,
          dependencies: {
            engine: engine.DOCKER_SANDBOX_ENGINE,
            now: Date.now,
            deadline: AbortSignal.timeout,
            async assertEngine() {
              await assertSocket();
              const result = await execute(
                engine.DOCKER_SANDBOX_ENGINE,
                ["info", "--format", "{{.ID}}"],
                { signal: AbortSignal.timeout(5_000) },
              );
              if (result.stdout.trim() !== engineId) {
                throw new Error("Native sandbox engine changed; custody retained");
              }
            },
            async execute(selected, args, options) {
              await assertSocket();
              const result = await execute(selected, args, options);
              await assertSocket();
              if (args[0] === "start" && result.code === 0) {
                const state = await execute(
                  selected,
                  ["inspect", "-f", "{{.State.Pid}}", args[1]],
                  { signal: options?.signal },
                );
                const pid = Number(state.stdout.trim());
                if (!Number.isSafeInteger(pid) || pid <= 0) {
                  throw new Error("Native sandbox process accounting unavailable");
                }
                const text = await fs.readFile(`/proc/${pid}/cgroup`, "utf8");
                const match = /^0::(\/[^\n]*)\n$/u.exec(text);
                if (!match || match[1].includes("..")) {
                  throw new Error("Native sandbox requires unified cgroup accounting");
                }
                cgroup = path.join("/sys/fs/cgroup", match[1]);
              }
              return result;
            },
            readEntry: registry.readRegistryEntry,
            assertEntry: registry.assertSandboxRegistryEntryCurrent,
            remove: (entry, id, assertCurrent) =>
              manager.removeSandboxRuntimeGeneration({
                runtime: { kind: "container", entry },
                engine: engine.DOCKER_SANDBOX_ENGINE,
                id,
                bridges: [],
                assertCurrent,
              }),
            async persist(record) {
              const text = JSON.stringify({
                format: 1,
                engineId,
                workspace,
                cgroup,
                ...record,
              });
              if (text.length > 65_536) {
                throw new Error("Native sandbox recovery record exceeds private bound");
              }
              if (record.phase === "armed") {
                await fs.writeFile(recordPath, text, { mode: 0o600, flag: "wx" });
                return;
              }
              const temporary = `${recordPath}.next`;
              await fs.writeFile(temporary, text, { mode: 0o600, flag: "wx" });
              await fs.rename(temporary, recordPath);
            },
            async assertSettled(id, mountPaths) {
              if (cgroup) {
                try {
                  const events = await fs.readFile(path.join(cgroup, "cgroup.events"), "utf8");
                  if (!/^populated 0$/mu.test(events)) {
                    throw new Error("Native sandbox cgroup still populated; custody retained");
                  }
                } catch (error) {
                  if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
                    throw error;
                  }
                }
              }
              if (id) {
                await assertSocket();
                await assertNativeSandboxMountsSettled({
                  id,
                  mountPaths,
                  owners: "owners" in admission ? admission.owners : undefined,
                  end: endMs,
                  now: Date.now,
                  deadline: AbortSignal.timeout,
                  readDirectory: () => fs.readdir("/proc"),
                  readFile: (file, signal) => fs.readFile(file, { encoding: "utf8", signal }),
                });
                await assertSocket();
              }
            },
          },
        });
        // Observe and bound real owner calls. No sandbox result is mocked.
        const spy = vi.spyOn(engine, "execContainer").mockImplementation(sandbox.execute);
        restoreEngine = () => spy.mockRestore();
        sandboxReleased = false;
        await sandbox.arm();
        process.once("SIGTERM", cancelFixture);
        process.once("SIGINT", cancelFixture);
        const configPath = process.env.OPENCLAW_CONFIG_PATH;
        if (!configPath) {
          throw new Error("Gateway hooks did not provide an isolated config path");
        }
        process.env.OPENCLAW_TEST_MINIMAL_GATEWAY = "0";
        delete process.env.OPENCLAW_DISABLE_BUNDLED_PLUGINS;
        process.env.OPENCLAW_BUNDLED_PLUGINS_DIR = path.resolve("extensions");
        process.env.OPENCLAW_TEST_TRUST_BUNDLED_PLUGINS_DIR = "1";
        await fs.writeFile(
          configPath,
          JSON.stringify({
            gateway: {
              mode: "local",
              auth: { mode: "token", token: "test-gateway-token-1234567890" },
            },
            agents: {
              defaults: {
                workspace: workspace,
                sandbox: {
                  mode: "all",
                  backend: "docker",
                  scope: "session",
                  workspaceAccess: "rw",
                  workspaceRoot: path.join(path.dirname(workspace), "sandbox-workspaces"),
                  docker: {
                    image:
                      "docker.io/library/python@sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a",
                    containerPrefix: prefix,
                    workdir: "/workspace",
                    user: `${uid}:${gid}`,
                    readOnlyRoot: true,
                    tmpfs: [
                      "/tmp:rw,nosuid,nodev,noexec,size=16m",
                      "/var/tmp:rw,nosuid,nodev,noexec,size=16m",
                      "/run:rw,nosuid,nodev,noexec,size=16m",
                    ],
                    network: "none",
                    capDrop: ["ALL"],
                    binds: [],
                    memory: "256m",
                    memorySwap: "256m",
                    cpus: 0.5,
                    pidsLimit: 64,
                    setupCommand: "python3 -I -S -c 'pass'",
                    env: {
                      PYTHONDONTWRITEBYTECODE: "1",
                    },
                  },
                  browser: {
                    enabled: false,
                    allowHostControl: false,
                  },
                  prune: {
                    idleHours: 0,
                    maxAgeDays: 0,
                  },
                },
              },
            },
            tools: {
              exec: {
                host: "sandbox",
              },
              elevated: {
                enabled: false,
              },
              sessions: {
                visibility: "self",
              },
              sandbox: {
                tools: {
                  allow: [
                    "exec",
                    "process",
                    "read",
                    "write",
                    "edit",
                    "apply_patch",
                    "workboard_heartbeat",
                    "workboard_complete",
                    "workboard_block",
                  ],
                },
              },
            },
            plugins: {
              enabled: true,
              allow: ["workboard"],
              entries: { workboard: { enabled: true } },
            },
            cron: { enabled: false },
          }),
        );
        const claim = await acquireTestPortBlock({ offsets: [0, 1, 2, 3, 4] });
        server = await startTestGatewayServer(claim, {
          auth: { mode: "token", token: "test-gateway-token-1234567890" },
          controlUiEnabled: false,
          sidecarStartup: "start",
        });
        await server.startupSettled;
        if (cancelled) {
          await server.close({ reason: "native fixture cancelled during startup" });
          throw new Error("Native fixture cancelled during startup");
        }
        const writer = await connectWebchatClient({
          port: claim.port,
          scopes: ["operator.read", "operator.write"],
        });
        clients.push(writer);
        const reader = await connectWebchatClient({ port: claim.port, scopes: ["operator.read"] });
        clients.push(reader);
        const namespace = await rpcReq<{ bootId: string; namespace: string }>(
          reader,
          "gateway.workerNamespace.get",
          {},
        );
        expect(namespace.ok, namespace.error?.message).toBe(true);
        expect(namespace.payload?.bootId).toEqual(expect.any(String));
        expect(namespace.payload?.namespace).toMatch(/^gateway-[0-9a-f]{32}$/);
        const create = async (title: string, agentId: string, priority: string) => {
          const result = await rpcReq<{ card: WorkboardCard }>(writer, "workboard.cards.create", {
            title,
            boardId: "native-proof",
            status: "ready",
            agentId,
            priority,
            workspace: { kind: "dir", path: workspace },
          });
          expect(result.ok, result.error?.message).toBe(true);
          if (!result.payload?.card) {
            throw new Error("Workboard did not return its persisted card");
          }
          return result.payload.card;
        };
        const stale = await create("Unrelated expired claim", "stale-owner", "urgent");
        const staleClaim = await rpcReq(writer, "workboard.cards.claim", {
          id: stale.id,
          ownerId: "stale-owner",
          token: "synthetic-native-claim",
          ttlSeconds: 1,
        });
        expect(staleClaim.ok, staleClaim.error?.message).toBe(true);
        await create("Unrelated ready card", "main", "urgent");
        const target = await create("Exact wire target", "main", "low");
        await delay(1_100);
        const cards = async () => {
          const result = await rpcReq<{ cards: WorkboardCard[] }>(reader, "workboard.cards.list", {
            boardId: "native-proof",
          });
          expect(result.ok, result.error?.message).toBe(true);
          if (!result.payload?.cards) {
            throw new Error("Workboard list did not return persisted rows");
          }
          return result.payload.cards;
        };
        const before = await cards();
        expect(
          before.find((card) => card.id === stale.id)?.metadata?.claim?.expiresAt,
        ).toBeLessThan(Date.now());
        const intentRunId = `wb-${"a".repeat(40)}`;
        const params = { boardId: "native-proof", cardId: target.id, intentRunId, maxStarts: 1 };
        const denied = await rpcReq(reader, "workboard.cards.dispatchWithTarget", params);
        expect(denied.ok).toBe(false);
        expect(denied.error?.message).toMatch(/scope|write/i);
        expect(await cards()).toEqual(before);
        expect(agentCommandMock).not.toHaveBeenCalled();
        const accepted = await rpcReq<{
          started: Array<{ cardId: string; runId: string }>;
          startFailures: Array<{ cardId: string; title: string; error: string }>;
        }>(writer, "workboard.cards.dispatchWithTarget", params);
        expect(accepted.ok, accepted.error?.message).toBe(true);
        expect(accepted.payload?.started, JSON.stringify(accepted.payload)).toHaveLength(1);
        const runId = accepted.payload?.started[0]?.runId;
        const expectedRunId = `workboard:intent:${createHash("sha256").update(target.id).update("\0").update(intentRunId).digest("hex")}`;
        expect(accepted.payload?.started[0]).toMatchObject({
          cardId: target.id,
          runId: expectedRunId,
        });
        await inferenceStarted.promise;
        expect(agentCommandMock).toHaveBeenCalledOnce();
        const after = await cards();
        expect(after.filter((card) => card.id !== target.id)).toEqual(
          before.filter((card) => card.id !== target.id),
        );
        const launched = after.find((card) => card.id === target.id);
        expect(launched).toMatchObject({
          status: "running",
          runId,
          metadata: {
            automation: {
              launch: { phase: "accepted", provisionalRunId: expectedRunId, acceptedRunId: runId },
            },
          },
        });
        const observe = () =>
          rpcReq(reader, "workboard.cards.executionSettlement", { id: target.id });
        const pending = await observe();
        expect(pending.ok, pending.error?.message).toBe(true);
        expect(pending.payload).toMatchObject({
          cardId: target.id,
          runId,
          producerState: "pending",
          resourceFencing: "unknown",
          releaseAuthorized: false,
        });
        finishInference.resolve();
        await expect
          .poll(async () => (await observe()).payload?.producerState, { timeout: 30_000 })
          .toBe("settled");
        expect((await cards()).find((card) => card.id === target.id)).toEqual(launched);
      } finally {
        finishInference.resolve();
        try {
          await closeFixture();
        } finally {
          for (const client of clients) {
            client.close();
          }
          process.removeListener("SIGTERM", cancelFixture);
          process.removeListener("SIGINT", cancelFixture);
          if (sandboxReleased) {
            restoreEngine?.();
          }
          restoreRuntime();
          agentCommandMock.mockReset().mockResolvedValue(undefined);
          env.restore();
        }
        if (server) {
          expect(clients.every((client) => client.readyState === client.CLOSED)).toBe(true);
        }
      }
    },
  );
});
