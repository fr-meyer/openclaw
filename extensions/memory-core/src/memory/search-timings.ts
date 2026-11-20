import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

type Phase =
  | "query"
  | "index"
  | "keyword-full"
  | "keyword-fallback"
  | "keyword-metadata"
  | "provider-ready"
  | "embedding"
  | "vector"
  | "rank";
type Event = {
  id: string;
  phase: Phase;
  name: "start" | "done" | "abort" | "final";
  durationMs: number;
  count?: number;
};
type Scope = {
  emit: (event: Event) => void;
  id: string;
  remaining: number;
  closed: boolean;
  started: number;
};
const scopes = new AsyncLocalStorage<Scope>();

function emit(scope: Scope, phase: Phase, name: Event["name"], started: number, count?: number) {
  if (scope.closed || (scope.remaining <= 1 && name !== "abort" && name !== "final")) {
    return;
  }
  if (scope.remaining <= 0) {
    return;
  }
  scope.remaining--;
  try {
    scope.emit({
      id: scope.id,
      phase,
      name,
      durationMs: Math.max(0, performance.now() - started),
      ...(count === undefined ? {} : { count }),
    });
  } catch {
    // Diagnostics must never change search results or cancellation behavior.
  }
}

export function withSearchTimings<T>(
  enabled: boolean,
  sink: Scope["emit"],
  signal: AbortSignal | undefined,
  run: () => Promise<T>,
): Promise<T> {
  if (!enabled) {
    return run();
  }
  const scope: Scope = {
    emit: sink,
    id: randomUUID(),
    remaining: 32,
    closed: false,
    started: performance.now(),
  };
  return scopes.run(scope, async () => {
    const abort = () => {
      emit(scope, "query", "abort", scope.started);
      scope.closed = true;
    };
    emit(scope, "query", "start", scope.started);
    signal?.addEventListener("abort", abort, { once: true });
    try {
      if (signal?.aborted) {
        abort();
      }
      return await run();
    } finally {
      signal?.removeEventListener("abort", abort);
      emit(scope, "query", "final", scope.started);
      scope.closed = true;
    }
  });
}

export async function timeSearchPhase<T>(
  phase: Phase,
  run: () => Promise<T>,
  count?: number,
): Promise<T> {
  const scope = scopes.getStore();
  if (!scope || scope.closed) {
    return run();
  }
  const started = performance.now();
  emit(scope, phase, "start", started, count);
  try {
    return await run();
  } finally {
    emit(scope, phase, "done", started, count);
  }
}

export function startSearchPhase(phase: Phase): () => void {
  const scope = scopes.getStore();
  if (!scope || scope.closed) {
    return () => {};
  }
  const started = performance.now();
  emit(scope, phase, "start", started);
  return () => emit(scope, phase, "done", started);
}
