import fs from "node:fs";
import { afterEach, expect, it, vi } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../../test/helpers/temp-dir.js";
import * as nodeSqlite from "../../infra/node-sqlite.js";
import { createCurrentOpenClawAgentDatabaseFixtures } from "../../state/openclaw-agent-db.test-support.js";
import * as transcriptIndex from "./session-transcript-index.js";
import type { SessionTranscriptWorkerInput } from "./session-transcript-worker.types.js";

const worker = vi.hoisted(() => ({
  read: vi.fn<(input: SessionTranscriptWorkerInput) => Promise<unknown>>(),
  close: vi.fn<(key?: string) => void>(),
}));
vi.mock("../../infra/worker-task-server.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../infra/worker-task-server.js")>()),
  serveOwnedWorkerTasks(
    handler: (input: unknown) => Promise<unknown>,
    options: { closeResource: (key?: string) => void },
  ) {
    worker.read.mockImplementation(handler);
    worker.close.mockImplementation(options.closeResource);
  },
}));
import "./session-transcript.worker.js";

const tempDirs = useAutoCleanupTempDirTracker(afterEach);
afterEach(() => vi.restoreAllMocks());

function request(
  path: string,
  sessionId?: string,
): Extract<SessionTranscriptWorkerInput, { kind: "transcript-reconcile-pending" }> {
  return {
    kind: "transcript-reconcile-pending",
    database: { agentId: "main", path },
    env: { OPENCLAW_STATE_DIR: path },
    sessionId,
  };
}

it("reads missing stores without creating a database", async () => {
  const root = tempDirs.make("openclaw-reconcile-reader-missing-");
  const path = `${root}/missing.sqlite`;
  await expect(worker.read(request(path))).resolves.toMatchObject({
    ok: true,
    value: { kind: "transcript-reconcile-pending", result: { found: false, pending: false } },
  });
  expect(fs.existsSync(path)).toBe(false);
});

it("uses a fresh snapshot for each retained global and selected-session probe", async () => {
  const root = tempDirs.make("openclaw-reconcile-reader-fresh-");
  const path = `${root}/agent.sqlite`;
  createCurrentOpenClawAgentDatabaseFixtures(`${root}/template.sqlite`, [
    { agentId: "main", path },
  ]);
  const peer = new (nodeSqlite.requireNodeSqlite().DatabaseSync)(path);
  // Foreign constraints are disabled only on this synthetic fixture peer so orphan
  // projection rows reproduce the reconciler's existing independent cleanup contract.
  peer.exec("PRAGMA foreign_keys = OFF");
  const opens = vi.spyOn(nodeSqlite, "openNodeSqliteDatabase");
  const expected = (pending: boolean) => ({
    ok: true,
    value: { kind: "transcript-reconcile-pending", result: { found: true, pending } },
  });
  try {
    await expect(worker.read(request(path))).resolves.toMatchObject(expected(false));
    // A native peer is a foreign committing owner; no local publication refreshes the reader.
    peer.exec(`
      INSERT INTO session_windows (session_id, session_key, created_at, updated_at)
        VALUES ('selected', 'agent:main:selected', 1, 1);
      INSERT INTO transcript_events (session_id, seq, event_json, created_at)
        VALUES ('selected', 1, '{"type":"message"}', 1);
    `);
    await expect(worker.read(request(path))).resolves.toMatchObject(expected(true));
    await expect(worker.read(request(path, "selected"))).resolves.toMatchObject(expected(true));
    await expect(worker.read(request(path, "unrelated"))).resolves.toMatchObject(expected(false));
    peer.exec("DELETE FROM transcript_events; DELETE FROM session_windows;");
    await expect(worker.read(request(path))).resolves.toMatchObject(expected(false));
    // Orphan-only state must still schedule cleanup without a live pending session.
    peer.exec(`INSERT INTO session_transcript_index_state
      (session_id, indexed_seq, updated_at) VALUES ('orphan', 1, 1)`);
    await expect(worker.read(request(path))).resolves.toMatchObject(expected(true));
    expect(opens.mock.calls.filter(([filename]) => filename === path)).toHaveLength(1);
  } finally {
    peer.close();
    worker.close(JSON.stringify([{ path }]));
  }
});

it("returns only settled data errors as uncertain results and rejects changed physical owners", async () => {
  const root = tempDirs.make("openclaw-reconcile-reader-error-");
  const path = `${root}/agent.sqlite`;
  createCurrentOpenClawAgentDatabaseFixtures(`${root}/template.sqlite`, [
    { agentId: "main", path },
  ]);
  vi.spyOn(transcriptIndex, "sessionTranscriptIndexNeedsReconcile").mockImplementationOnce(() => {
    throw new Error("query refused");
  });
  try {
    await expect(worker.read(request(path, "selected"))).resolves.toMatchObject({
      ok: true,
      value: {
        kind: "transcript-reconcile-pending",
        readError: { kind: "read-error", message: "query refused" },
      },
    });
    await expect(
      worker.read({ ...request(path), fileIdentity: { key: "file:incorrect" } }),
    ).resolves.toMatchObject({
      ok: false,
      error: { kind: "read-error", message: expect.stringMatching(/identity changed/) },
    });
  } finally {
    worker.close(JSON.stringify([{ path }]));
  }
});

it("rejects a data read whose native rollback did not settle", async () => {
  const root = tempDirs.make("openclaw-reconcile-reader-rollback-");
  const path = `${root}/agent.sqlite`;
  createCurrentOpenClawAgentDatabaseFixtures(`${root}/template.sqlite`, [
    { agentId: "main", path },
  ]);
  vi.spyOn(transcriptIndex, "sessionTranscriptIndexNeedsReconcile").mockImplementationOnce(() => {
    throw new Error("query refused before rollback");
  });
  const open = nodeSqlite.openNodeSqliteDatabase;
  vi.spyOn(nodeSqlite, "openNodeSqliteDatabase").mockImplementation((filename, options) => {
    const database = open(filename, options);
    if (filename === path) {
      const exec = database.exec.bind(database);
      vi.spyOn(database, "exec").mockImplementation((sql) => {
        if (sql === "ROLLBACK") {
          throw new Error("native rollback refused");
        }
        return exec(sql);
      });
    }
    return database;
  });
  try {
    await expect(worker.read(request(path, "selected"))).resolves.toMatchObject({
      ok: false,
      error: { kind: "read-error" },
    });
  } finally {
    worker.close(JSON.stringify([{ path }]));
  }
});
