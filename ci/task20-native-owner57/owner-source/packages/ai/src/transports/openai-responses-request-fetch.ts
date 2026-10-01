import type { Model } from "@openclaw/llm-core";
import { buildGuardedModelFetch } from "./host-policy.js";
import { createBoundedOpenAIResponsesCompactionFetch } from "./openai-responses-compaction-window.js";
import type { ResponsesRequestLifecycle } from "./openai-responses-request-lifecycle.js";

function withDefaultResponsesStreamEncoding(
  fetch: typeof globalThis.fetch,
): typeof globalThis.fetch {
  return (input, init) => {
    // Apply the SSE default after the SDK merges environment and caller headers.
    const headers = new Headers(
      init?.headers ?? (input instanceof Request ? input.headers : undefined),
    );
    if (headers.has("accept-encoding")) {
      return fetch(input, init);
    }
    // Some compatible endpoints truncate compressed streams before the terminal event.
    headers.set("accept-encoding", "identity");
    return fetch(input, { ...init, headers });
  };
}

/** Preserve the existing fetch policy while binding explicit continuation dispatch to its signal. */
export function createResponsesRequestFetch(
  model: Model,
  options: { compact: boolean; stream?: boolean; lifecycle?: ResponsesRequestLifecycle; timeoutMs?: number },
): typeof globalThis.fetch | undefined {
  const lifecycle = options.lifecycle;
  if (options.timeoutMs !== undefined && (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0)) {
    throw new Error("Responses request timeout invalid");
  }
  if (lifecycle && options.compact) {
    throw new Error(
      "Provider review continuation cannot replace its reviewed input with compaction",
    );
  }
  const guardedFetch = () => buildGuardedModelFetch(model, options.timeoutMs);
  let fetchOverride = options.compact
    ? createBoundedOpenAIResponsesCompactionFetch(guardedFetch())
    : options.stream
      ? withDefaultResponsesStreamEncoding(guardedFetch())
      : undefined;
  if (lifecycle) {
    const dispatchFetch = fetchOverride ?? guardedFetch();
    fetchOverride = async (input, init) => {
      const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
      await lifecycle.beforeDispatch(signal ?? undefined);
      signal?.throwIfAborted();
      lifecycle.assertCurrent();
      return dispatchFetch(input, init);
    };
  }
  return fetchOverride;
}
