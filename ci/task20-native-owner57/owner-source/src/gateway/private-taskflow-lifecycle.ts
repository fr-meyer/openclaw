import {SubagentRegistryWriteError} from "../agents/subagents/registry/subagent-registry-persistence.js";
/** Private host attachment. The native Gateway remains the only execution owner. */
import type { SubagentRunRecord } from "../agents/subagents/registry/subagent-registry.types.js";
import { AsyncLocalStorage } from "node:async_hooks";
import { responsesRequestLifecycle } from "@openclaw/ai/internal/openai";
import type { AuditRunTerminalGuard } from "../audit/audit-event-writer.js";

type Binding = Readonly<{
  runId: string; childSessionKey: string; requesterSessionKey: string;
  lifecycleGeneration: string; pluginId: string; provider: string; model: string;
}>;
type AuditOwner = {
  protectRunTerminal(input: {runId: string; lifecycleGeneration: string}): AuditRunTerminalGuard;
  flushRun(input: { runId: string; lifecycleGeneration: string }): {
    contract: "native-terminal-projection/v1"; runId: string; lifecycleGeneration: string; settled: boolean;
  };
  writerInstanceId: string;
  flushWriter(): Promise<{ contract: "audit-writer-flush/v1"; writerInstanceId: string;
    acceptedSequence: number; committedSequence: number; integrity: boolean }>;
};
export type PrivateTaskFlowHost = {
  /** Resolves only a captured opaque lease capability, never a public request or DTO. */
  binding(capability: object): Binding;
  assertCurrent(capability: object): void;
  gatewayContext: { chatAbortControllers: object };
  registerCanonicalAtomically(capability: object, identity: Binding, entry: SubagentRunRecord, assertCurrent: () => void): Promise<{
    bound: boolean; entryGeneration: number;
  }>;
  /** Pins only an exact live authority created by the actual native admitted context. */
  attachNativeExecution(capability: object, instance: object, authority: Frame["authority"]): void;
  /** Must reread the committed native terminal row and enforce the private lease CAS in its actor. */
  releaseNativeTerminal(capability: object, identity: Binding & {
    expectedEntryGeneration: number; operationalRunInstance: object; claimId: string;
  }, assertCurrent: () => void, settlementTicket: object): Promise<{ released: boolean }>;
};
type ProviderRequest = { dispatched: boolean; responseId?: string; terminal: boolean; localSettled: boolean };
type Frame = {
  host: PrivateTaskFlowHost; capability: object; binding: Binding;
  phase: "admitting" | "bound" | "executing" | "held" | "released";
  entryGeneration?: number; instance?: object; authority?: {
    operationalRunInstance: object; lifecycleGeneration: string; claimId: string;
  };
  executionGuard?: () => void; authorityGuard?: () => void;
  canonicalPublished: boolean; providers: ProviderRequest[]; settlementStarted: boolean;
  audit?: AuditOwner; auditTerminal?: AuditRunTerminalGuard;
};
const current = new AsyncLocalStorage<Frame>();
const settlementTickets = new WeakMap<object, {frame: Frame; guard: () => void}>();
const auditOwners = new WeakMap<object, AuditOwner>();
const attempts = new WeakMap<PrivateTaskFlowHost, Map<string, Frame>>();
const activeRuns = new Map<string, Frame>();
const MAX_PRIVATE_RUNS = 1024;
const MAX_PROVIDER_REQUESTS = 32;

function sourceCurrent(frame: Frame): void {
  frame.host.assertCurrent(frame.capability);
  if (frame.phase === "held" || frame.phase === "released" || activeRuns.get(frame.binding.runId) !== frame) {
    throw new Error("PRIVATE_TASKFLOW_OWNER_CLOSED");
  }
  if (frame.audit) {
    if (auditOwners.get(frame.host.gatewayContext.chatAbortControllers) !== frame.audit) throw new Error("PRIVATE_AUDIT_OWNER_REPLACED");
    frame.auditTerminal!.assertCurrent();
  }
}
export function assertPrivateTaskFlowSourceCurrent(): void {
  const frame = current.getStore(); if (frame) sourceCurrent(frame);
}
function executionCurrent(frame: Frame): void {
  sourceCurrent(frame);
  if (!frame.executionGuard || !frame.instance || !frame.authority) throw new Error("PRIVATE_NATIVE_AUTHORITY_MISSING");
  frame.executionGuard();
}
function providerCurrent(frame: Frame): void {
  executionCurrent(frame);
  if (!frame.authorityGuard) throw new Error("PRIVATE_PROVIDER_AUTHORITY_MISSING");
  frame.authorityGuard();
}
/** Settlement seals admissions while allowing already admitted transport receipts to drain. */
function providerAdmissionCurrent(frame: Frame): void {
  providerCurrent(frame);
  if (frame.settlementStarted) throw new Error("PRIVATE_PROVIDER_ADMISSION_SEALED");
  if (frame.providers.some(request => request.dispatched && (!request.terminal || !request.localSettled))) {
    throw new Error("PRIVATE_PROVIDER_PREVIOUS_DISPATCH_UNSETTLED");
  }
}
/** Called by the private TaskFlow controller with its captured lease port. No new dispatcher. */
export function createPrivateTaskFlowGatewayAttachment(host: PrivateTaskFlowHost) {
  if (attempts.has(host)) throw new Error("PRIVATE_ATTACHMENT_ALREADY_OWNED");
  const owned = new Map<string, Frame>(); attempts.set(host, owned);
  host = Object.freeze({ ...host });
  return Object.freeze({
    async run<T>(capability: object, invokeNativePluginRun: () => Promise<T>): Promise<T> {
      host.assertCurrent(capability);
      const binding = Object.freeze({ ...host.binding(capability) });
      if (!binding.runId.startsWith("taskflow:") || !binding.childSessionKey || !binding.requesterSessionKey ||
          !binding.lifecycleGeneration || !binding.pluginId || !binding.provider || !binding.model) {
        throw new Error("PRIVATE_LEASE_IDENTITY_INVALID");
      }
      if (owned.has(binding.runId) || activeRuns.has(binding.runId)) throw new Error("PRIVATE_LAUNCH_REPLAY_REFUSED");
      if (owned.size >= MAX_PRIVATE_RUNS || activeRuns.size >= MAX_PRIVATE_RUNS) throw new Error("PRIVATE_LAUNCH_CAPACITY_REFUSED");
      const frame: Frame = {host, capability, binding, phase: "admitting", canonicalPublished: false,
        providers: [], settlementStarted: false};
      owned.set(binding.runId, frame); activeRuns.set(binding.runId, frame);
      try { return await current.run(frame, invokeNativePluginRun); }
      catch (error) { frame.phase = "held"; throw error; }
    },
    inspect(runId: string) { const frame = owned.get(runId); return frame && Object.freeze({
      runId, phase: frame.phase, canonicalPublished: frame.canonicalPublished,
      providerRequests: frame.providers.length, settlementStarted: frame.settlementStarted }); },
  });
}
export function validatePrivateTaskFlowPluginRun(request: {
  sessionKey: string; idempotencyKey?: string; provider?: string; model?: string;
}, pluginId: string | undefined, gatewayContext: unknown): string | undefined {
  const frame = current.getStore(); if (!frame) return undefined;
  sourceCurrent(frame);
  if (gatewayContext !== frame.host.gatewayContext || pluginId !== frame.binding.pluginId ||
      request.sessionKey !== frame.binding.childSessionKey || request.provider !== frame.binding.provider ||
      request.model !== frame.binding.model || (request.idempotencyKey && request.idempotencyKey !== frame.binding.runId)) {
    throw new Error("PRIVATE_PLUGIN_RUN_IDENTITY_REFUSED");
  }
  return frame.binding.runId;
}
export async function bindPrivateTaskFlowCanonical(identity: {
  runId: string; childSessionKey: string; requesterSessionKey: string; pluginId?: string;
}, nativeAssertCurrent: () => void): Promise<void> {
  const frame = current.getStore(); if (!frame) return;
  const guard = () => { sourceCurrent(frame); nativeAssertCurrent(); };
  guard();
  if (identity.runId !== frame.binding.runId || identity.childSessionKey !== frame.binding.childSessionKey ||
      identity.requesterSessionKey !== frame.binding.requesterSessionKey || identity.pluginId !== frame.binding.pluginId ||
      frame.phase !== "bound") throw new Error("PRIVATE_CANONICAL_IDENTITY_REFUSED");
  if (frame.phase !== "bound" || !frame.entryGeneration) throw new Error("PRIVATE_ATOMIC_REGISTRATION_NOT_ACKNOWLEDGED");
  guard();

}
/** Presence only; never creates source or execution authority. */
export function hasPrivateTaskFlowRegistrationFrame(): boolean { return current.getStore() !== undefined; }
/** Called by the native launch manager after its original row factory, before lifecycle activation. */
export function persistPrivateTaskFlowCanonicalRegistration(entry: SubagentRunRecord,
 nativeAssertCurrent: () => void): Promise<void> | undefined {
 const frame=current.getStore(); if(!frame)return undefined;
 const guard=()=>{sourceCurrent(frame);nativeAssertCurrent();};
 return (async()=>{
  try{
   guard();
   if(frame.phase!=="admitting"||entry.runId!==frame.binding.runId||entry.taskRunId!==frame.binding.runId||
    entry.childSessionKey!==frame.binding.childSessionKey||entry.requesterSessionKey!==frame.binding.requesterSessionKey||
    entry.execution.lifecycleGeneration!==frame.binding.lifecycleGeneration||!Number.isSafeInteger(entry.generation)||entry.generation!<1)
    throw new Error("PRIVATE_ATOMIC_REGISTRATION_IDENTITY_REFUSED");
  }catch(error){throw new SubagentRegistryWriteError("not-committed",error);}
  const result=await frame.host.registerCanonicalAtomically(frame.capability,frame.binding,entry,guard);
  try{
   guard();if(!result.bound||result.entryGeneration!==entry.generation)throw new Error("PRIVATE_ATOMIC_REGISTRATION_ACK_REFUSED");
   frame.entryGeneration=result.entryGeneration;frame.phase="bound";
  }catch(error){throw new SubagentRegistryWriteError("committed",error,"superseded");}
 })();
}
/** Capture before handing work to trackExecution; never depend on the queue retaining ALS. */
export function retainPrivateTaskFlowExecution<T>(runId: string, lifecycleGeneration: string,
  instance: object, operation: () => Promise<T>): () => Promise<T> {
  const frame = current.getStore(); if (!frame) return operation;
  // Never reject prepared ownership before entering startAgentRunExecution's cleanup boundary.
  // Its first guarded step validates this captured transfer inside the native undispatched finally.
  let entered = false;
  return () => current.run(frame, async () => {
    if (entered) throw new Error("PRIVATE_EXECUTION_REPLAY_REFUSED"); entered = true;
    if (frame.binding.runId !== runId || frame.binding.lifecycleGeneration !== lifecycleGeneration || frame.phase !== "bound") {
      frame.phase = "held";
    } else { frame.instance = instance; frame.phase = "executing"; }
    try { return await operation(); }
    finally { if (frame.phase !== "released") frame.phase = "held"; }
  });
}
export function bindPrivateTaskFlowExecutionGuard(runId: string, instance: object,
  lifecycleGeneration: string, guard: () => void): void {
  const frame = current.getStore(); if (!frame) return;
  sourceCurrent(frame);
  if (frame.binding.runId !== runId || frame.instance !== instance || frame.binding.lifecycleGeneration !== lifecycleGeneration ||
      frame.executionGuard) throw new Error("PRIVATE_EXECUTION_OWNER_REFUSED");
  guard(); frame.executionGuard = guard;
}
export function bindPrivateTaskFlowNativeAuthority(authority: {
  operationalRunInstance: object; lifecycleGeneration: string; claimId: string;
}, guard: () => void): void {
  const frame = current.getStore(); if (!frame) return;
  sourceCurrent(frame); guard();
  if (authority.operationalRunInstance !== frame.instance || authority.lifecycleGeneration !== frame.binding.lifecycleGeneration ||
      (frame.authority && frame.authority !== authority)) throw new Error("PRIVATE_NATIVE_CLAIM_REPLACED");
  frame.host.attachNativeExecution(frame.capability, frame.instance!, authority);
  frame.authority = authority; frame.authorityGuard = guard;
  const audit = auditOwners.get(frame.host.gatewayContext.chatAbortControllers);
  if (!audit || frame.audit) throw new Error("PRIVATE_AUDIT_ADMISSION_REFUSED");
  const auditTerminal = audit.protectRunTerminal({runId: frame.binding.runId, lifecycleGeneration: frame.binding.lifecycleGeneration});
  auditTerminal.assertCurrent(); frame.audit = audit; frame.auditTerminal = auditTerminal;
}
export function notePrivateTaskFlowCanonicalPublication(entry: {
  runId: string; childSessionKey: string; requesterSessionKey: string; generation: number;
  execution: { lifecycleGeneration?: string; status: string; endedAt?: number };
}): void {
  const frame = activeRuns.get(entry.runId); if (!frame) return;
  try {
    sourceCurrent(frame);
    if (entry.childSessionKey !== frame.binding.childSessionKey || entry.requesterSessionKey !== frame.binding.requesterSessionKey ||
        entry.generation !== frame.entryGeneration || entry.execution.lifecycleGeneration !== frame.binding.lifecycleGeneration ||
        entry.execution.status !== "terminal" || !Number.isFinite(entry.execution.endedAt)) return;
    frame.canonicalPublished = true;
  } catch { /* Late/stale publication cannot reopen a held lease. */ }
}
export function publishPrivateTaskFlowAuditOwner(registrations: object, owner: AuditOwner): () => void {
  if (auditOwners.has(registrations)) throw new Error("PRIVATE_AUDIT_OWNER_ALREADY_BOUND");
  auditOwners.set(registrations, owner);
  return () => { if (auditOwners.get(registrations) === owner) auditOwners.delete(registrations); };
}
/** The private port can add assertions but cannot replace this trusted lifecycle barrier. */
export function assertPrivateTaskFlowSettlementTicket(ticket: object, capability: object,
 instance: object, authority: object): void {
 const captured=settlementTickets.get(ticket);
 if(!captured||captured.frame.capability!==capability||captured.frame.instance!==instance||
  captured.frame.authority!==authority||!captured.frame.settlementStarted||!captured.frame.canonicalPublished)
  throw new Error("PRIVATE_SETTLEMENT_TICKET_REFUSED");
 captured.guard();
}
/** Native command finish drains terminal writes while its exact delegated claim remains owned. */
export async function settlePrivateTaskFlowFromAdmittedCommand(runId: string, instance: object,
  authority: object | undefined): Promise<{ held: boolean; released?: boolean }> {
  const frame = current.getStore(); if (!frame) return {held: false};
  return settlePrivateTaskFlowBeforeCleanup(runId, () => {
    if (frame.instance !== instance || frame.authority !== authority || !authority) {
      throw new Error("PRIVATE_COMMAND_TERMINAL_OWNER_CHANGED");
    }
  }, () => frame.instance === instance && frame.authority === authority);
}
/** Only exact raw Responses receipts can prove provider termination; EOF is local drain only. */
export function wrapPrivateTaskFlowProviderStream<T extends (...args: any[]) => any>(streamFn: T, selectedTransport: string): T {
  const frame = current.getStore(); if (!frame) return streamFn;
  if (selectedTransport !== "sse") throw new Error("PRIVATE_PROVIDER_TRANSPORT_UNSUPPORTED");
  return ((model: { provider: string; id: string; api: string }, context: unknown, options?: Record<string, any>) => {
    providerAdmissionCurrent(frame);
    if (model.provider !== frame.binding.provider || model.id !== frame.binding.model || model.api !== "openai-responses" ||
        (options?.transport !== undefined && options.transport !== "sse")) throw new Error("PRIVATE_PROVIDER_TRANSPORT_UNSUPPORTED");
    if (frame.providers.length >= MAX_PROVIDER_REQUESTS) throw new Error("PRIVATE_PROVIDER_REQUEST_CAPACITY_REFUSED");
    const inherited = responsesRequestLifecycle.get(options);
    const request: ProviderRequest = { dispatched: false, terminal: false, localSettled: false };
    frame.providers.push(request);
    const nextOptions = { ...options, transport: "sse" };
    responsesRequestLifecycle.set(nextOptions, {
      async beforeDispatch(signal) { providerAdmissionCurrent(frame); signal?.throwIfAborted();
        if (request.dispatched || request.localSettled) throw new Error("PRIVATE_PROVIDER_DISPATCH_REPLAY_REFUSED");
        await inherited?.beforeDispatch(signal); providerAdmissionCurrent(frame); signal?.throwIfAborted();
        if (request.dispatched || request.localSettled) throw new Error("PRIVATE_PROVIDER_DISPATCH_REPLAY_REFUSED");
        request.dispatched = true; },
      assertCurrent() { providerCurrent(frame); inherited?.assertCurrent(); },
      async accepted(responseId, signal) { providerCurrent(frame);
        if (!request.dispatched || !responseId || (request.responseId && request.responseId !== responseId)) throw new Error("PRIVATE_PROVIDER_RESPONSE_ID_CHANGED");
        await inherited?.accepted(responseId, signal); providerCurrent(frame); request.responseId = responseId; },
      observed(event: unknown) {
        providerCurrent(frame); inherited?.observed?.(event);
        if (!event || typeof event !== "object") return;
        const value = event as {type?: string; response?: {id?: string; status?: string}};
        if (["response.completed", "response.done", "response.failed", "response.incomplete"].includes(value.type ?? "")) {
          const status = value.response?.status;
          const expectedStatus = value.type === "response.failed" ? "failed" : value.type === "response.incomplete" ? "incomplete" : "completed";
          if (!request.responseId || value.response?.id !== request.responseId || status !== expectedStatus) {
            throw new Error("PRIVATE_PROVIDER_TERMINAL_IDENTITY_REFUSED");
          }
          request.terminal = true;
        }
      },
      async settle() { await inherited?.settle(); sourceCurrent(frame); request.localSettled = true; },
    });
    return streamFn(model, context, nextOptions);
  }) as T;
}
/** Called by the real native dispatch owner before clearing its abort-map registration. */
export async function settlePrivateTaskFlowBeforeCleanup(runId: string, nativeSettlementGuard: () => void,
  ownsNativeRegistration: () => boolean): Promise<{ held: boolean; released?: boolean }> {
  const frame = current.getStore(); if (!frame) return { held: false };
  if (frame.settlementStarted) return { held: frame.phase !== "released", released: frame.phase === "released" };
  frame.settlementStarted = true;
  // Preserve request identity and an independent drained postimage across audit/actor awaits.
  const drainedProviders = frame.providers.map(request => ({request, expected: Object.freeze({...request})}));
  const assertCertifiedDrain = () => {
    if (!frame.canonicalPublished || !drainedProviders.length || frame.providers.length !== drainedProviders.length ||
        drainedProviders.some(({request, expected}, index) => frame.providers[index] !== request ||
          !expected.dispatched || !expected.terminal || !expected.localSettled || !expected.responseId ||
          request.dispatched !== expected.dispatched || request.terminal !== expected.terminal ||
          request.localSettled !== expected.localSettled || request.responseId !== expected.responseId)) {
      throw new Error("PRIVATE_CANONICAL_OR_PROVIDER_DRAIN_UNKNOWN");
    }
  };
    const guard = () => { providerCurrent(frame); nativeSettlementGuard(); assertCertifiedDrain();
      if (!ownsNativeRegistration() || frame.binding.runId !== runId) throw new Error("PRIVATE_NATIVE_SETTLEMENT_OWNER_LOST"); };
  try {
    guard();
    const audit = frame.audit;
    if (!audit || !frame.auditTerminal) throw new Error("PRIVATE_AUDIT_OWNER_MISSING");
    const terminal = audit.flushRun({runId, lifecycleGeneration: frame.binding.lifecycleGeneration}); guard();
    if (terminal.contract !== "native-terminal-projection/v1" || terminal.runId !== runId ||
        terminal.lifecycleGeneration !== frame.binding.lifecycleGeneration || !terminal.settled) throw new Error("PRIVATE_AUDIT_TERMINAL_UNSETTLED");
    let timer: ReturnType<typeof setTimeout> | undefined;
    const flushed = await Promise.race([audit.flushWriter(), new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("PRIVATE_AUDIT_FLUSH_TIMEOUT")), 2500);
    })]).finally(() => { if (timer) clearTimeout(timer); }); guard();
    if (flushed.contract !== "audit-writer-flush/v1" || flushed.writerInstanceId !== audit.writerInstanceId || !flushed.integrity ||
        !Number.isSafeInteger(flushed.acceptedSequence) || flushed.acceptedSequence < 0 ||
        !Number.isSafeInteger(flushed.committedSequence) || flushed.committedSequence < flushed.acceptedSequence) {
      throw new Error("PRIVATE_AUDIT_DURABILITY_REFUSED");
    }
    frame.auditTerminal.assertCommitted();
    const settlementTicket=Object.freeze(Object.create(null));
    const committedGuard = () => { guard(); frame.auditTerminal!.assertCommitted(); };
    settlementTickets.set(settlementTicket,{frame,guard: committedGuard});
    const result = await frame.host.releaseNativeTerminal(frame.capability, {
      ...frame.binding, expectedEntryGeneration: frame.entryGeneration!,
      operationalRunInstance: frame.instance!, claimId: frame.authority!.claimId,
    }, committedGuard, settlementTicket); committedGuard();
    if (!result.released) throw new Error("PRIVATE_LEASE_TERMINAL_CAS_REFUSED");
    frame.phase = "released"; activeRuns.delete(runId); return {held: false, released: true};
  } catch { frame.phase = "held"; return {held: true}; }
}
