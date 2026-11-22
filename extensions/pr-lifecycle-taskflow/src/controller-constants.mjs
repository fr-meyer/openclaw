export const CONTROLLER_ID = "pr-lifecycle-taskflow/v1";
export const STATE_SCHEMA_VERSION = 1;
export const REMEDIATOR_PROFILE_SCHEMA_VERSION = 1;
export const MERGE_AUTHORIZATION_SCHEMA_VERSION = 1;
export const TERMINAL_ENVELOPE_SCHEMA_VERSION = 1;

export const PHASE = Object.freeze({
  REVIEW_QUEUED: "review_queued",
  REVIEW_RUNNING: "review_running",
  REVIEW_WAITING: "review_waiting",
  REMEDIATION_QUEUED: "remediation_queued",
  REMEDIATION_RUNNING: "remediation_running",
  WAITING_HEAD_EVENT: "waiting_head_event",
  MERGE_QUEUED: "merge_queued",
  MERGE_READY: "merge_ready",
  MERGED: "merged",
  BLOCKED: "blocked",
  FAILED: "failed",
  CANCELLED: "cancelled",
});

export const INFRASTRUCTURE_BACKOFF_BASE_MS = 5 * 60_000;
export const INFRASTRUCTURE_BACKOFF_MAX_MS = 2 * 60 * 60_000;
export const MAX_INFRASTRUCTURE_RETRIES = 8;
export const MAX_PROTOCOL_RETRIES = 1;
export const PRIMARY_FIXER_MODEL = "primary-fixer";
export const FALLBACK_FIXER_MODEL = "fallback-fixer";
export const FIXER_FALLBACK_INFRASTRUCTURE_REASONS = new Set([
  "primary_model_backend_unavailable",
  "primary_model_rate_limited",
  "primary_model_timeout",
  "primary_model_transport_unavailable",
]);
export const INFRASTRUCTURE_FAILURE_PATTERNS = [
  /^worker_session_missing(?:$|:)/,
  /^worker_session_liveness_unknown(?:$|:)/,
  /^worker_session_identity_mismatch(?:$|:)/,
  /^worker_lost_after_process_restart(?:$|:)/,
  /^worker_not_active(?:$|:)/,
  /^worker_start_failed(?:$|:)/,
  /^worker_execution_failed:.*(?:worker_session_(?:missing|liveness_unknown)|gateway[ _-]restart|process[ _-]restart|task[_ ]link|task backing ownership|exec[_ ]approval)/,
  /^task_link_failed(?:$|:)/,
  /^task_link_missing(?:$|:)/,
  /^worker_handshake_timeout(?:$|:)/,
  /^exec_approval_(?:cancelled|denied|expired)(?:$|:)/,
  /^worker_completed_without_structured_report(?:$|:)/,
];

export const TERMINAL_PHASES = new Set([PHASE.MERGED, PHASE.FAILED, PHASE.CANCELLED]);
export const SHA_PATTERN = /^[0-9a-f]{40}$/;
export const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
export const SAFE_TEXT_PATTERN = /^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]*$/;
export const MAX_SEEN_EVENTS = 64;
export const MAX_FINDINGS = 20;
export const MAX_TERMINAL_ENVELOPES = 8;
