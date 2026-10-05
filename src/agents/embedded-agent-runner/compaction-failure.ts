/** Closed compaction-failure construction and policy helpers. */
import type {
  CompactionFailure,
  FallbackCompactionFailureReason,
  RetryableCompactionFailureReason,
  TerminalCompactionFailureReason,
} from "../../context-engine/types.js";
import type { FailoverReason } from "../failover/signal.js";
import type { ModelFallbackResultClassification } from "../model-fallback-attempt.js";
import type { EmbeddedAgentCompactResult } from "./types.js";

const RETRYABLE_REASONS = [
  "empty_response",
  "overloaded",
  "rate_limit",
  "server_error",
  "timeout",
] as const satisfies readonly RetryableCompactionFailureReason[];

const FALLBACK_REASONS = [
  "missing_thread_binding",
  "stale_thread_binding",
] as const satisfies readonly FallbackCompactionFailureReason[];

const TERMINAL_FAILOVER_REASONS = [
  "auth",
  "auth_permanent",
  "billing",
  "context_overflow",
  "format",
  "model_not_found",
  "no_error_details",
  "session_expired",
  "tls_certificate",
  "unclassified",
  "unknown",
] as const satisfies readonly TerminalCompactionFailureReason[];

const TERMINAL_COMPACTION_REASONS = [
  ...TERMINAL_FAILOVER_REASONS,
  "aborted",
  "active_run",
  "auth_profile_mismatch",
  "background_compaction_pending",
  "deferred_compaction_not_scheduled",
  "invalid_request",
  "model_selection_locked",
  "runtime_unavailable",
  "summary_rejected",
  "transcript_persistence_failed",
  "unsupported_harness_compaction",
] as const satisfies readonly TerminalCompactionFailureReason[];

function includesReason<const T extends readonly string[]>(
  reasons: T,
  value: unknown,
): value is T[number] {
  return typeof value === "string" && reasons.some((reason) => reason === value);
}

const COMPACTION_FAILURE_KEYS = new Set(["disposition", "reason", "status"]);

/** Returns whether a value claims the typed compaction-failure contract. */
export function hasCompactionFailureDisposition(value: unknown): boolean {
  if (!value || (typeof value !== "object" && typeof value !== "function")) {
    return false;
  }
  try {
    return "disposition" in value;
  } catch {
    // An uninspectable value must fail closed instead of entering legacy parsing.
    return true;
  }
}

function normalizeStatus(status: unknown): number | undefined {
  return typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599
    ? status
    : undefined;
}

export function isStructuredCompactionFailure(value: unknown): value is CompactionFailure {
  if (!value || typeof value !== "object") {
    return false;
  }
  let ownKeys: (string | symbol)[];
  let descriptors: PropertyDescriptorMap;
  try {
    ownKeys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return false;
  }
  if (
    ownKeys.some(
      (key) =>
        typeof key !== "string" ||
        !COMPACTION_FAILURE_KEYS.has(key) ||
        descriptors[key]?.enumerable !== true ||
        !("value" in descriptors[key]),
    )
  ) {
    return false;
  }
  const disposition = descriptors.disposition?.value;
  const reason = descriptors.reason?.value;
  const status = descriptors.status?.value;
  if (!descriptors.disposition || !descriptors.reason) {
    return false;
  }
  if (descriptors.status && normalizeStatus(status) === undefined) {
    return false;
  }
  if (disposition === "retryable") {
    return includesReason(RETRYABLE_REASONS, reason);
  }
  if (disposition === "fallback") {
    return includesReason(FALLBACK_REASONS, reason);
  }
  return disposition === "terminal" && includesReason(TERMINAL_COMPACTION_REASONS, reason);
}

function retryableCompactionFailure(
  reason: RetryableCompactionFailureReason,
  status?: unknown,
): CompactionFailure {
  const normalizedStatus = normalizeStatus(status);
  return {
    disposition: "retryable",
    reason,
    ...(normalizedStatus === undefined ? {} : { status: normalizedStatus }),
  };
}

export function terminalCompactionFailure(
  reason: TerminalCompactionFailureReason,
  status?: unknown,
): CompactionFailure {
  const normalizedStatus = normalizeStatus(status);
  return {
    disposition: "terminal",
    reason,
    ...(normalizedStatus === undefined ? {} : { status: normalizedStatus }),
  };
}

export function compactionFailureFromFailoverReason(
  reason: FailoverReason | undefined,
  status?: unknown,
): CompactionFailure {
  if (includesReason(RETRYABLE_REASONS, reason)) {
    return retryableCompactionFailure(reason, status);
  }
  if (includesReason(TERMINAL_FAILOVER_REASONS, reason)) {
    return terminalCompactionFailure(reason, status);
  }
  return terminalCompactionFailure("unknown", status);
}

function failoverReasonFromCompactionFailure(failure: CompactionFailure): FailoverReason {
  return includesReason(RETRYABLE_REASONS, failure.reason) ||
    includesReason(TERMINAL_FAILOVER_REASONS, failure.reason)
    ? failure.reason
    : "unknown";
}

/** Classifies one compaction result for the generic model-fallback loop. */
export function classifyCompactionResultForModelFallback(
  result: EmbeddedAgentCompactResult,
): ModelFallbackResultClassification {
  if (result.ok) {
    return null;
  }
  const failure = isStructuredCompactionFailure(result.failure)
    ? result.failure
    : terminalCompactionFailure("unknown");
  if (failure.disposition === "fallback") {
    // A binding fallback selects the synchronous context-engine owner. Returning
    // null preserves the original failed result without trying another model.
    return null;
  }
  if (
    failure.disposition === "terminal" &&
    !includesReason(TERMINAL_FAILOVER_REASONS, failure.reason)
  ) {
    return null;
  }
  return {
    message: `Compaction failed (${failure.reason})`,
    reason: failoverReasonFromCompactionFailure(failure),
    status: failure.status,
    preserveResultOnExhaustion: true,
    // Terminal identities win over a later transient model failure if all
    // configured compaction candidates are exhausted.
    preserveResultPriority: failure.disposition === "retryable" ? 0 : 1,
  };
}
