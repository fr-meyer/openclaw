import { formatErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import { ErrorCodes, errorShape } from "openclaw/plugin-sdk/gateway-runtime";
import { parseStrictPositiveInteger } from "openclaw/plugin-sdk/number-runtime";
import {
  asRecord,
  isRecord,
  normalizeOptionalString,
} from "openclaw/plugin-sdk/string-coerce-runtime";
import type { OpenClawPluginApi } from "../api.js";
import { redactClaimToken, redactDispatchResult } from "./card-redaction.js";
import { dispatchAndStartWorkboardCards } from "./dispatcher.js";
import { WorkboardCardConflictError, type WorkboardStore } from "./store.js";
import {
  assertWorkboardWorkspaceMutationAccess,
  canonicalizeWorkboardWorkspaceAccess,
  resolveAgentWorkboardWorkspaceRuntime,
  resolveConfiguredWorkboardWorkspaceAccess,
  resolveWorkboardAgentWorkspace,
  type WorkboardWorkspaceAccess,
} from "./workspace-access.js";

export type GatewayMethodContext = Parameters<
  Parameters<OpenClawPluginApi["registerGatewayMethod"]>[1]
>[0];
type GatewayRespond = GatewayMethodContext["respond"];

export class WorkboardUploadsDisabledError extends Error {
  constructor() {
    super("File and image uploads are disabled by gateway.uploads.enabled");
    this.name = "WorkboardUploadsDisabledError";
  }
}

export function respondError(respond: GatewayRespond, error: unknown) {
  if (error instanceof WorkboardUploadsDisabledError) {
    respond(
      false,
      undefined,
      errorShape(ErrorCodes.FORBIDDEN, error.message, { details: { code: "UPLOADS_DISABLED" } }),
    );
    return;
  }
  if (error instanceof WorkboardCardConflictError) {
    respond(false, undefined, {
      code: "workboard_conflict",
      message: error.message,
      details: {
        type: "workboard_card_conflict",
        card: redactClaimToken(error.current),
      },
    });
    return;
  }
  respond(false, undefined, {
    code: "workboard_error",
    message: formatErrorMessage(error),
  });
}

export function readExpectedUpdatedAt(params: Record<string, unknown>): number | undefined {
  const value = params.expectedUpdatedAt;
  if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value))) {
    throw new Error("expectedUpdatedAt must be a finite number.");
  }
  return value;
}

export function readId(params: Record<string, unknown>): string {
  const value = params.id;
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  throw new Error("id is required.");
}

function readOptionalPositiveInteger(value: unknown, fieldName: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const parsed = parseStrictPositiveInteger(value);
  if (typeof value !== "number" || parsed === undefined) {
    throw new Error(`${fieldName} must be a positive integer.`);
  }
  return parsed;
}

export function readPatch(params: Record<string, unknown>): Record<string, unknown> {
  return isRecord(params.patch) ? params.patch : params;
}

export function assertNoCursorAdvance(params: Record<string, unknown>) {
  if (params.advance === true) {
    throw new Error("notification cursor advancement requires workboard.notifications.advance.");
  }
}

function resolveGatewayWorkboardWorkspaceAccess(params: {
  context: GatewayMethodContext["context"];
  client: GatewayMethodContext["client"];
}): WorkboardWorkspaceAccess {
  // In-process plugin dispatch has no remote client and already runs with host
  // authority. Connected write-scope clients stay within configured workspaces.
  if (!params.client) {
    return { unrestricted: true };
  }
  const scopes = Array.isArray(params.client?.connect?.scopes) ? params.client.connect.scopes : [];
  if (scopes.includes("operator.admin")) {
    return { unrestricted: true };
  }
  return resolveConfiguredWorkboardWorkspaceAccess({
    config: params.context.getRuntimeConfig(),
    unrestricted: false,
  });
}

export async function resolveGatewayWorkspaceMutationAccess(
  request: GatewayMethodContext,
  value: unknown,
): Promise<WorkboardWorkspaceAccess> {
  const access = await canonicalizeWorkboardWorkspaceAccess(
    resolveGatewayWorkboardWorkspaceAccess(request),
  );
  await assertWorkboardWorkspaceMutationAccess(value, access);
  return access;
}

export function createWorkboardDispatchHandler(params: {
  api: OpenClawPluginApi;
  store: WorkboardStore;
}) {
  return async (
    { params: requestParams, client, context }: GatewayMethodContext,
    options: { supportsMaxStarts: boolean; supportsCardId?: boolean; directCard?: boolean },
  ) => {
    const {
      boardId,
      cardId: rawCardId,
      intentRunId: rawIntentRunId,
      maxStarts: rawMaxStarts,
    } = asRecord(requestParams);
    if (!options.directCard && !options.supportsCardId && rawCardId !== undefined) {
      throw new Error("cardId requires workboard.cards.dispatchWithOptions.");
    }
    let cardId = options.directCard ? readId(requestParams) : undefined;
    if (!options.directCard && rawCardId !== undefined) {
      if (typeof rawCardId !== "string" || !rawCardId.trim()) {
        throw new Error("cardId must be a non-empty string.");
      }
      cardId = rawCardId.trim();
    }
    if (!options.supportsMaxStarts && rawMaxStarts !== undefined) {
      throw new Error("maxStarts requires workboard.cards.dispatchWithOptions.");
    }
    const maxStarts = options.supportsMaxStarts
      ? readOptionalPositiveInteger(rawMaxStarts, "maxStarts")
      : undefined;
    if (cardId && maxStarts !== undefined && maxStarts !== 1) {
      throw new Error("maxStarts must be 1 when cardId is provided.");
    }
    if (rawIntentRunId !== undefined && (!options.supportsCardId || !cardId)) {
      throw new Error("intentRunId requires one exact card through dispatchWithOptions.");
    }
    if (
      rawIntentRunId !== undefined &&
      (typeof rawIntentRunId !== "string" ||
        rawIntentRunId.length !== 43 ||
        !/^wb-[0-9a-f]{40}$/.test(rawIntentRunId))
    ) {
      throw new Error("intentRunId must be a wb-<40 lowercase hex> dispatch intent id.");
    }
    const provider = options.directCard
      ? normalizeOptionalString(requestParams.provider)
      : undefined;
    const model = options.directCard ? normalizeOptionalString(requestParams.model) : undefined;
    const result = await dispatchAndStartWorkboardCards({
      store: params.store,
      subagent: params.api.runtime.subagent,
      worktrees: params.api.runtime.worktrees,
      options: {
        ...(cardId ? { cardId, maxStarts: 1 } : {}),
        boardId: typeof boardId === "string" ? boardId : undefined,
        ...(maxStarts !== undefined ? { maxStarts } : {}),
        ...(cardId && !options.directCard ? { targetMode: "dispatch" } : {}),
        ...(typeof rawIntentRunId === "string" ? { intentRunId: rawIntentRunId } : {}),
        ...(provider ? { provider } : {}),
        ...(model ? { model } : {}),
        materializeWorktree: true,
        resolveAgentWorkspace: (agentId) =>
          resolveWorkboardAgentWorkspace(context.getRuntimeConfig(), agentId),
        resolveAgentWorkspaceRuntime: (
          agentId,
          sessionKey,
          workspaceDir,
          modelProvider,
          modelId,
        ) => {
          const config = context.getRuntimeConfig();
          return resolveAgentWorkboardWorkspaceRuntime({
            config,
            agentId,
            sessionKey,
            workspaceDir,
            modelProvider,
            modelId,
            prepareSandboxWorkspaceAuthority: params.api.runtime.sandbox.prepareWorkspaceAuthority,
          });
        },
        workspaceAccess: resolveGatewayWorkboardWorkspaceAccess({ context, client }),
      },
    });
    if (options.directCard) {
      const started = result.started[0];
      if (!started?.card) {
        throw new Error(result.startFailures[0]?.error ?? "Workboard card did not start.");
      }
      return { ...started, card: redactClaimToken(started.card) };
    }
    return {
      ...redactDispatchResult(result),
      started: result.started.map((started) =>
        started.card ? { ...started, card: redactClaimToken(started.card) } : started,
      ),
    };
  };
}
