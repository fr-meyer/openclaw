import { WORKBOARD_STATUSES, type WorkboardCard } from "@openclaw/workboard-contract";
// Workboard plugin module implements shared gateway request helpers.
import { formatErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import { parseStrictPositiveInteger } from "openclaw/plugin-sdk/number-runtime";
import type { OpenClawPluginApi } from "../api.js";
import { redactClaimToken } from "./card-redaction.js";
import {
  dispatchAndStartWorkboardCards,
  type WorkboardDispatchStartOptions,
} from "./dispatcher.js";
import { WorkboardCardConflictError, type WorkboardStore } from "./store.js";
import {
  resolveAgentWorkboardWorkspaceRuntime,
  resolveConfiguredWorkboardWorkspaceAccess,
  resolveWorkboardAgentWorkspace,
  type WorkboardWorkspaceAccess,
} from "./workspace-access.js";

export type GatewayMethodContext = Parameters<
  Parameters<OpenClawPluginApi["registerGatewayMethod"]>[1]
>[0];
type GatewayRespond = GatewayMethodContext["respond"];
type WorkboardGatewayResultHandler = (context: GatewayMethodContext) => unknown;
type WorkboardGatewayScope = NonNullable<
  NonNullable<Parameters<OpenClawPluginApi["registerGatewayMethod"]>[2]>["scope"]
>;

export function respondError(respond: GatewayRespond, error: unknown) {
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

export function registerWorkboardResultMethods(
  api: OpenClawPluginApi,
  methods: ReadonlyArray<
    readonly [method: string, scope: WorkboardGatewayScope, handler: WorkboardGatewayResultHandler]
  >,
): void {
  for (const [method, scope, handler] of methods) {
    api.registerGatewayMethod(
      method,
      async (context) => {
        try {
          context.respond(true, await handler(context));
        } catch (error) {
          respondError(context.respond, error);
        }
      },
      { scope },
    );
  }
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
  const patch = params.patch;
  if (patch && typeof patch === "object" && !Array.isArray(patch)) {
    return patch as Record<string, unknown>;
  }
  return params;
}

export function assertNoCursorAdvance(params: Record<string, unknown>) {
  if (params.advance === true) {
    throw new Error("notification cursor advancement requires workboard.notifications.advance.");
  }
}

export async function listWorkboardCards(
  store: WorkboardStore,
  boardId: unknown,
  redactCard: (card: WorkboardCard) => WorkboardCard,
) {
  const [cards, { boards }] = await Promise.all([store.list({ boardId }), store.listBoards()]);
  return { cards: cards.map(redactCard), boards, statuses: WORKBOARD_STATUSES };
}

export function resolveGatewayWorkboardWorkspaceAccess(params: {
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

function gatewayDispatchOptions(params: {
  api: OpenClawPluginApi;
  request: Pick<GatewayMethodContext, "client" | "context">;
  input: Pick<
    WorkboardDispatchStartOptions,
    "boardId" | "cardId" | "maxStarts" | "provider" | "model" | "intentRunId"
  >;
}): WorkboardDispatchStartOptions {
  const { context, client } = params.request;
  return {
    ...params.input,
    materializeWorktree: true,
    resolveAgentWorkspace: (agentId) =>
      resolveWorkboardAgentWorkspace(context.getRuntimeConfig(), agentId),
    resolveAgentWorkspaceRuntime: (agentId, sessionKey, workspaceDir, modelProvider, modelId) => {
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
  };
}

export function createWorkboardDispatchHandler(params: {
  api: OpenClawPluginApi;
  store: WorkboardStore;
  redactCard: (card: WorkboardCard) => WorkboardCard;
}) {
  return async (
    { params: requestParams, respond, client, context }: GatewayMethodContext,
    options: { supportsMaxStarts: boolean; supportsCardId?: boolean; directCard?: boolean },
  ) => {
    try {
      const rawCardId = options.directCard
        ? requestParams.id
        : requestParams && typeof requestParams === "object" && "cardId" in requestParams
          ? requestParams.cardId
          : undefined;
      if (!options.directCard && !options.supportsCardId && rawCardId !== undefined) {
        throw new Error("cardId requires workboard.cards.dispatchWithOptions.");
      }
      let cardId: string | undefined;
      if (options.directCard) {
        cardId = readId({ id: rawCardId });
      } else if (rawCardId !== undefined) {
        if (typeof rawCardId !== "string" || !rawCardId.trim()) {
          throw new Error("cardId must be a non-empty string.");
        }
        cardId = rawCardId.trim();
      }
      const rawBoardId =
        requestParams && typeof requestParams === "object" && "boardId" in requestParams
          ? requestParams.boardId
          : undefined;
      let boardId: string | undefined;
      if (rawBoardId !== undefined) {
        if (typeof rawBoardId !== "string" || !rawBoardId.trim()) {
          throw new Error("boardId must be a non-empty string.");
        }
        boardId = rawBoardId.trim();
      }
      const rawMaxStarts =
        requestParams && typeof requestParams === "object" && "maxStarts" in requestParams
          ? requestParams.maxStarts
          : undefined;
      if (!options.supportsMaxStarts && rawMaxStarts !== undefined) {
        throw new Error("maxStarts requires workboard.cards.dispatchWithOptions.");
      }
      const maxStarts = options.supportsMaxStarts
        ? readOptionalPositiveInteger(rawMaxStarts, "maxStarts")
        : undefined;
      if (cardId && maxStarts !== undefined && maxStarts !== 1) {
        throw new Error("maxStarts must be 1 when cardId is provided.");
      }
      const rawIntentRunId =
        requestParams && typeof requestParams === "object" && "intentRunId" in requestParams
          ? requestParams.intentRunId
          : undefined;
      if (rawIntentRunId !== undefined && (!options.supportsCardId || !cardId)) {
        throw new Error("intentRunId requires one exact card through dispatchWithOptions.");
      }
      if (
        rawIntentRunId !== undefined &&
        (typeof rawIntentRunId !== "string" || !/^wb-[0-9a-f]{40}$/.test(rawIntentRunId))
      ) {
        throw new Error("intentRunId must be a wb-<40 lowercase hex> dispatch intent id.");
      }
      const intentRunId = typeof rawIntentRunId === "string" ? rawIntentRunId : undefined;
      const provider =
        options.directCard &&
        typeof requestParams.provider === "string" &&
        requestParams.provider.trim()
          ? requestParams.provider.trim()
          : undefined;
      const model =
        options.directCard && typeof requestParams.model === "string" && requestParams.model.trim()
          ? requestParams.model.trim()
          : undefined;
      const result = await dispatchAndStartWorkboardCards({
        store: params.store,
        subagent: params.api.runtime.subagent,
        worktrees: params.api.runtime.worktrees,
        options: {
          ...gatewayDispatchOptions({
            api: params.api,
            request: { context, client },
            input: {
              ...(cardId ? { cardId, maxStarts: 1 } : {}),
              boardId,
              ...(maxStarts !== undefined ? { maxStarts } : {}),
              ...(provider ? { provider } : {}),
              ...(model ? { model } : {}),
              ...(intentRunId ? { intentRunId } : {}),
            },
          }),
          ...(cardId ? { targetMode: options.directCard ? "start" : "dispatch" } : {}),
        },
      });
      if (options.directCard) {
        const started = result.started[0];
        if (!started?.card) {
          throw new Error(result.startFailures[0]?.error ?? "Workboard card did not start.");
        }
        respond(true, { ...started, card: params.redactCard(started.card) });
        return;
      }
      respond(true, {
        ...result,
        promoted: result.promoted.map(params.redactCard),
        reclaimed: result.reclaimed.map(params.redactCard),
        blocked: result.blocked.map(params.redactCard),
        orchestrated: result.orchestrated.map(params.redactCard),
      });
    } catch (error) {
      respondError(respond, error);
    }
  };
}
