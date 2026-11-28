import fs from "node:fs/promises";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { resolveSessionTranscriptsDirForAgent } from "openclaw/plugin-sdk/memory-core-host-runtime-core";
import { upsertSessionEntry } from "openclaw/plugin-sdk/session-store-runtime";
import { appendSessionTranscriptMessageByIdentity } from "openclaw/plugin-sdk/session-transcript-runtime";
import type { ManagerIndexFixture } from "./manager-index.test-support.js";

export const seedMemoryIndexSessionTranscript: ManagerIndexFixture["seedSessionTranscript"] =
  async (params) => {
    const sessionsDir = resolveSessionTranscriptsDirForAgent("main");
    const storePath = path.join(sessionsDir, "sessions.json");
    const sessionKey = params.sessionKey ?? `agent:main:memory:${params.sessionId}`;
    const updatedAt = Date.now();
    await fs.mkdir(sessionsDir, { recursive: true });
    await upsertSessionEntry({
      agentId: "main",
      sessionKey,
      storePath,
      entry: { sessionId: params.sessionId, updatedAt },
    });
    for (const message of params.messages) {
      await appendSessionTranscriptMessageByIdentity({
        agentId: "main",
        sessionId: params.sessionId,
        sessionKey,
        storePath,
        message: {
          role: message.role,
          timestamp: message.timestamp,
          content: [{ type: "text", text: message.content }],
          ...(message.senderIsOwner ? { __openclaw: { senderIsOwner: true } } : {}),
        },
      });
    }
  };

export function readPublishedSessionIndex(
  database: DatabaseSync,
  sessionPath: string,
  query: string,
) {
  return {
    source: database
      .prepare(
        "SELECT path, hash, mtime, size FROM memory_index_sources WHERE path = ? AND source = 'sessions'",
      )
      .get(sessionPath),
    chunks: database
      .prepare(
        "SELECT id, hash, text, embedding, updated_at FROM memory_index_chunks WHERE path = ? AND source = 'sessions' ORDER BY id",
      )
      .all(sessionPath),
    search: database
      .prepare(
        "SELECT text, id, path, model, start_line, end_line FROM memory_index_chunks_fts WHERE memory_index_chunks_fts MATCH ? AND path = ? ORDER BY id",
      )
      .all(query, sessionPath),
  };
}
