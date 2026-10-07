/** Closed diagnostic code and level projection for the stability recorder. */
import type { DiagnosticEventPayload } from "../infra/diagnostic-events.js";

const LIVENESS_EVENT_LOOP_DELAY_WARN_MS = 1_000;
const SAFE_REASON_CODE = /^[A-Za-z0-9_.:-]{1,120}$/u;
const SAFE_EXPORTER_CODE = /^[A-Za-z0-9_-]{1,120}$/u;

export function copyReasonCode(reason: unknown): string | undefined {
  if (typeof reason !== "string" || !SAFE_REASON_CODE.test(reason)) {
    return undefined;
  }
  return reason;
}

export function copyExporterCode(value: unknown): string | undefined {
  return typeof value === "string" && SAFE_EXPORTER_CODE.test(value) ? value : undefined;
}

export function assignReasonCode(record: { reason?: string }, reason: string | undefined): void {
  const reasonCode = copyReasonCode(reason);
  if (reasonCode) {
    record.reason = reasonCode;
  }
}

export function resolveDiagnosticLivenessRecordLevel(
  event: Extract<DiagnosticEventPayload, { type: "diagnostic.liveness.warning" }>,
): "warning" | "info" {
  const hasBlockingWork = event.waiting > 0 || event.queued > 0;
  const hasSustainedEventLoopDelay =
    (event.eventLoopDelayP99Ms ?? 0) >= LIVENESS_EVENT_LOOP_DELAY_WARN_MS;
  return event.degradedSinceMs !== undefined ||
    hasBlockingWork ||
    (event.active > 0 && hasSustainedEventLoopDelay)
    ? "warning"
    : "info";
}
