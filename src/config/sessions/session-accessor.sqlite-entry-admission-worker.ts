import type { OpenClawAgentDatabaseOptions } from "../../state/openclaw-agent-db.js";
import { withSessionHistoryWorkerDatabase } from "./session-transcript-worker-runtime.js";
import type { SessionExactEntriesWorkerResult } from "./session-transcript-worker.types.js";

/** Execute the lazy authorization read; the caller validates its retained claim after settlement. */
export function readSessionEntryForAdmissionInWorker(params: {
  options: OpenClawAgentDatabaseOptions;
  sessionKey: string;
  assertCurrent: () => void;
  signal?: AbortSignal;
}): Promise<SessionExactEntriesWorkerResult> {
  const { options, sessionKey, assertCurrent, signal } = params;
  assertCurrent();
  return withSessionHistoryWorkerDatabase(options, (owner) => {
    assertCurrent();
    return owner.readExactEntries(
      { sessionKeys: [sessionKey], env: options.env!, includeAuthorization: true },
      signal,
    );
  });
}
