/** Content-free MCP ownership facts; never accept aliases, commands, URLs, or errors. */
export type DiagnosticMcpRetirementIntent = "none" | "deferred" | "required";

export type DiagnosticMcpLifecycleFields = {
  generationId: string;
  /** Prepared transport class; vendor attribution requires a separate PID census. */
  providerClass: "stdio" | "sse" | "streamable-http";
  /** PID in the emitting process's namespace, retained after transport closure. */
  childPid?: number;
  /** Server-runtime leases, shared across that runtime's transport generations. */
  serverRuntimeActiveLeases: number;
  retirementIntent: DiagnosticMcpRetirementIntent;
  retiring: boolean;
  connected: boolean;
  closeOutcome: "not-requested" | "pending" | "closed" | "uncertain";
};

export type DiagnosticMcpLifecyclePhase =
  | "created"
  | "connected"
  | "lease"
  | "retirement"
  | "transport-closed"
  | "cleanup";

export type DiagnosticMcpLifecycleEventFields = {
  type: "mcp.lifecycle";
  phase: DiagnosticMcpLifecyclePhase;
  mcp: DiagnosticMcpLifecycleFields;
};

const GENERATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_COUNT = 2_147_483_647;

export function sanitizeMcpLifecyclePhase(value: unknown): DiagnosticMcpLifecyclePhase | undefined {
  return value === "created" ||
    value === "connected" ||
    value === "lease" ||
    value === "retirement" ||
    value === "transport-closed" ||
    value === "cleanup"
    ? value
    : undefined;
}

export function sanitizeMcpLifecycleFields(
  value: unknown,
): DiagnosticMcpLifecycleFields | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const read = (key: string): unknown => {
    const descriptor = descriptors[key];
    return descriptor && "value" in descriptor ? descriptor.value : undefined;
  };
  const generationId = read("generationId");
  const providerClass = read("providerClass");
  const childPid = read("childPid");
  const serverRuntimeActiveLeases = read("serverRuntimeActiveLeases");
  const retirementIntent = read("retirementIntent");
  const retiring = read("retiring");
  const connected = read("connected");
  const closeOutcome = read("closeOutcome");
  if (
    typeof generationId !== "string" ||
    !GENERATION_ID.test(generationId) ||
    (providerClass !== "stdio" && providerClass !== "sse" && providerClass !== "streamable-http") ||
    (childPid !== undefined &&
      (typeof childPid !== "number" ||
        !Number.isSafeInteger(childPid) ||
        childPid < 1 ||
        childPid > MAX_COUNT)) ||
    typeof serverRuntimeActiveLeases !== "number" ||
    !Number.isSafeInteger(serverRuntimeActiveLeases) ||
    serverRuntimeActiveLeases < 0 ||
    serverRuntimeActiveLeases > MAX_COUNT ||
    (retirementIntent !== "none" &&
      retirementIntent !== "deferred" &&
      retirementIntent !== "required") ||
    typeof retiring !== "boolean" ||
    typeof connected !== "boolean" ||
    (closeOutcome !== "not-requested" &&
      closeOutcome !== "pending" &&
      closeOutcome !== "closed" &&
      closeOutcome !== "uncertain")
  ) {
    return undefined;
  }
  return {
    generationId,
    providerClass,
    ...(childPid !== undefined ? { childPid } : {}),
    serverRuntimeActiveLeases,
    retirementIntent,
    retiring,
    connected,
    closeOutcome,
  };
}
