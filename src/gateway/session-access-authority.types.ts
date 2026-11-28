/** Leaf session-authority shapes; no imports, registration or writable capability source. */
export type RetainedGatewaySessionAccess = {
  readonly signal: AbortSignal;
  assertCurrent: () => void;
  release: () => void;
};

export type GatewaySessionAccessAuthority = {
  readonly target: Readonly<{
    agentId: string;
    sessionKey: string;
    sessionId: string;
    lifecycleRevision?: string;
  }>;
  readonly sandboxRequired: boolean;
  /** Invocation guard, including the admitted model turn when applicable. */
  assertCurrent: () => void;
  /** Retain original actor, grant, sharing and tool policy for a viewer or accepted operation. */
  retain: () => RetainedGatewaySessionAccess;
  /** Session resource lifetime only. Revoking one collaborator must not destroy shared state. */
  retainSession: () => RetainedGatewaySessionAccess;
  /** Router-owned preparation hold; each service borrow has its own release. */
  release: () => void;
};
