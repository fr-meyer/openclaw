// Source-only release proof: real transport, plugin, SQLite and execution owner.
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { WorkboardCard } from "@openclaw/workboard-contract";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDeferred } from "../../test/helpers/promise.js";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import { captureEnv } from "../test-utils/env.js";
import { acquireTestPortBlock } from "../test-utils/port-claims.js";
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
const tempDirs = useAutoCleanupTempDirTracker(afterEach);

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
      let server: Awaited<ReturnType<typeof startTestGatewayServer>> | undefined;
      agentCommandMock.mockImplementation(async () => {
        inferenceStarted.resolve();
        await finishInference.promise;
        return { payloads: [], meta: { durationMs: 0 } };
      });
      try {
        const workspace = await tempDirs.make("openclaw-native-workboard-");
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
            agents: { defaults: { workspace } },
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
        const accepted = await rpcReq<{ started: Array<{ cardId: string; runId: string }> }>(
          writer,
          "workboard.cards.dispatchWithTarget",
          params,
        );
        expect(accepted.ok, accepted.error?.message).toBe(true);
        expect(accepted.payload?.started).toHaveLength(1);
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
          for (const client of clients) {
            client.close();
          }
          if (server) {
            await server.close({ reason: "native Workboard fixture cleanup" });
          }
        } finally {
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
