import path from "node:path";
import { normalizeAgentId } from "@openclaw/normalization-core/agent-id";
import { toErrorObject } from "@openclaw/normalization-core/error-coercion";
import { isPathInside } from "../infra/path-guards.js";
import { createDeferredCore } from "../shared/deferred.js";
import { resolveGlobalSingleton } from "../shared/global-singleton.js";
import { getOpenClawDatabaseMaintenanceScope } from "./openclaw-state-db-async-lifecycle.js";

export type OpenClawAgentDatabaseAsyncResource = {
  agentId: string;
  path: string;
  revoke: () => void;
  close: () => Promise<void>;
};
export type OpenClawAgentDatabaseReadCandidateResource = Omit<
  OpenClawAgentDatabaseAsyncResource,
  "agentId"
> & { scope?: "sibling-family" };
type AgentDatabaseResource =
  | (OpenClawAgentDatabaseAsyncResource & { ownership: "known"; closeSync?: () => void })
  | (OpenClawAgentDatabaseReadCandidateResource & {
      ownership: "unresolved";
      agentId?: never;
    });
export type AgentDatabaseCloseSelection = {
  path?: string;
  rootPath?: string;
  agentId?: string;
};

const resources = resolveGlobalSingleton(
  Symbol.for("openclaw.agentDatabaseAsyncResources"),
  () => ({
    active: new Set<AgentDatabaseResource>(),
    closing: new Map<AgentDatabaseResource, Promise<void> | undefined>(),
    selections: new Map<AgentDatabaseCloseSelection, Promise<void>>(),
  }),
);

/** CLI cleanup can skip loading native database owners when no Worker was admitted. */
export function hasOpenClawAgentDatabaseAsyncResources(): boolean {
  return resources.active.size > 0 || resources.closing.size > 0;
}

/** Match captured read custody without inspecting files or inferring their owners. */
export function matchesAgentDatabaseReadCandidatePath(
  candidate: Pick<OpenClawAgentDatabaseReadCandidateResource, "path" | "scope">,
  pathname: string,
): boolean {
  const capturedPath = path.resolve(candidate.path);
  const resolvedPath = path.resolve(pathname);
  if (capturedPath === resolvedPath) {
    return true;
  }
  if (candidate.scope !== "sibling-family") {
    return false;
  }
  const captured = path.parse(capturedPath);
  const selected = path.parse(resolvedPath);
  return (
    selected.dir === captured.dir &&
    selected.base.startsWith(`${captured.name}.`) &&
    selected.base.endsWith(captured.ext)
  );
}

export function matchesAgentDatabaseClose(
  selection: AgentDatabaseCloseSelection,
  resource:
    | { agentId: string; path: string; ownership?: "known" }
    | (Pick<OpenClawAgentDatabaseReadCandidateResource, "path" | "scope"> & {
        agentId?: never;
        ownership: "unresolved";
      }),
): boolean {
  return (
    (selection.path === undefined ||
      selection.path === resource.path ||
      (resource.ownership === "unresolved" &&
        matchesAgentDatabaseReadCandidatePath(resource, selection.path))) &&
    (selection.rootPath === undefined ||
      isPathInside(selection.rootPath, resource.path) ||
      (resource.ownership === "unresolved" &&
        matchesAgentDatabaseReadCandidatePath(resource, selection.rootPath))) &&
    (selection.agentId === undefined ||
      resource.ownership === "unresolved" ||
      selection.agentId === resource.agentId)
  );
}

/** Register before admitting a Worker; revocation is synchronous, native drainage is joined. */
export function registerOpenClawAgentDatabaseAsyncResource(
  resource: OpenClawAgentDatabaseAsyncResource,
): () => void {
  return registerAgentDatabaseResource({
    ...resource,
    ownership: "known",
    agentId: normalizeAgentId(resource.agentId),
  });
}

/** Native readers close synchronously, so successful retirement leaves no asynchronous barrier. */
export function registerOpenClawAgentDatabaseSyncResource(
  resource: Omit<OpenClawAgentDatabaseAsyncResource, "close"> & { close: () => void },
): () => void {
  return registerAgentDatabaseResource({
    ...resource,
    ownership: "known",
    agentId: normalizeAgentId(resource.agentId),
    close: async () => resource.close(),
    closeSync: resource.close,
  });
}

/** Retain discovery until the known owner is registered, then release this candidate. */
export function registerOpenClawAgentDatabaseReadCandidateResource(
  resource: OpenClawAgentDatabaseReadCandidateResource,
): () => void {
  return registerAgentDatabaseResource({ ...resource, ownership: "unresolved" });
}

function registerAgentDatabaseResource(resource: AgentDatabaseResource): () => void {
  const owned = {
    ...resource,
    path: path.resolve(resource.path),
  };
  if (
    [...resources.selections.keys()].some((selection) =>
      matchesAgentDatabaseClose(selection, owned),
    ) ||
    [...resources.closing.keys()].some(
      (closing) =>
        (closing.path === owned.path ||
          (closing.ownership === "unresolved" &&
            matchesAgentDatabaseReadCandidatePath(closing, owned.path)) ||
          (owned.ownership === "unresolved" &&
            matchesAgentDatabaseReadCandidatePath(owned, closing.path))) &&
        (closing.ownership === "unresolved" ||
          owned.ownership === "unresolved" ||
          closing.agentId === owned.agentId),
    )
  ) {
    throw new Error(`Agent database resources are closing: ${owned.path}`);
  }
  const unregister = () => resources.active.delete(owned);
  getOpenClawDatabaseMaintenanceScope()?.own(unregister, "agent-resources", () =>
    closeAgentDatabaseResource(owned),
  );
  resources.active.add(owned);
  return unregister;
}

function closeAgentDatabaseResource(
  resource: AgentDatabaseResource,
  onCloseError?: (pathname: string, error: unknown) => void,
): Promise<void> {
  if (resource.ownership === "known" && resource.closeSync) {
    resources.closing.set(resource, undefined);
    try {
      resource.revoke();
      resource.closeSync();
      resources.active.delete(resource);
      resources.closing.delete(resource);
      return Promise.resolve();
    } catch (error) {
      if (onCloseError) {
        onCloseError(resource.path, error);
      }
      const failed = Promise.reject<void>(toErrorObject(error, "Agent database cleanup failed"));
      void failed.catch(() => {});
      return failed;
    }
  }
  let operation = resources.closing.get(resource);
  if (!operation) {
    operation = Promise.resolve().then(() => resource.close());
    resources.closing.set(resource, operation);
    void operation
      .then(
        () => {
          resources.active.delete(resource);
          resources.closing.delete(resource);
        },
        () => {
          // Keep exact custody even if the actor unregisters while its close fails.
          resources.closing.set(resource, undefined);
        },
      )
      .catch(() => {});
  }
  if (onCloseError) {
    void operation.catch((error: unknown) => onCloseError(resource.path, error)).catch(() => {});
  }
  // Retain closing custody before revocation can synchronously attempt admission.
  resource.revoke();
  return operation;
}

export function revokeAgentDatabaseResources(
  selection: AgentDatabaseCloseSelection,
  onCloseError?: (pathname: string, error: unknown) => void,
): Promise<void>[] {
  const closing = new Set([...resources.active, ...resources.closing.keys()]);
  const pending: Promise<void>[] = [];
  for (const resource of closing) {
    if (!matchesAgentDatabaseClose(selection, resource)) {
      continue;
    }
    pending.push(closeAgentDatabaseResource(resource, onCloseError));
  }
  return pending;
}

/** Join existing retirement fences without revoking resources or retrying failed cleanup. */
export async function waitForAgentDatabaseResourceClose(target: {
  agentId: string;
  path: string;
}): Promise<void> {
  const captured = { agentId: normalizeAgentId(target.agentId), path: path.resolve(target.path) };
  while (true) {
    const pending = new Set<Promise<void>>();
    for (const [selection, closed] of resources.selections) {
      if (matchesAgentDatabaseClose(selection, captured)) {
        pending.add(closed);
      }
    }
    let incomplete = false;
    for (const [resource, closed] of resources.closing) {
      if (matchesAgentDatabaseClose(captured, resource)) {
        if (closed) {
          pending.add(closed);
        } else {
          incomplete = true;
        }
      }
    }
    if (pending.size === 0 && !incomplete) {
      return;
    }
    const settled = await Promise.allSettled(pending);
    const errors = settled.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (incomplete) {
      errors.push(new Error("Agent database resource cleanup remains incomplete"));
    }
    if (errors.length > 0) {
      throw new AggregateError(errors, "Agent database close fence failed");
    }
    // A matching close may start while the preceding snapshot drains. Recheck
    // the authoritative owner before admitting the caller's successor resource.
  }
}

export async function drainAgentDatabaseResources<T>(
  selection: AgentDatabaseCloseSelection,
  closeNative: () => Promise<T>,
): Promise<T> {
  // Each invocation owns its fence, including overlapping drains passed the
  // same caller selection object. Capture it before any revocation or yield.
  const retainedSelection = Object.freeze({ ...selection });
  const closed = createDeferredCore();
  void closed.promise.catch(() => {});
  resources.selections.set(retainedSelection, closed.promise);
  try {
    const results = await Promise.allSettled(revokeAgentDatabaseResources(retainedSelection));
    const errors = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (errors.length > 0) {
      throw new AggregateError(errors, "Agent database resource drainage failed");
    }
    return await closeNative();
  } catch (error) {
    resources.selections.delete(retainedSelection);
    closed.reject(error);
    throw error;
  } finally {
    resources.selections.delete(retainedSelection);
    closed.resolve();
  }
}
