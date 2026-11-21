import { createHmac, timingSafeEqual } from "node:crypto";
import {
  normalizeCheckSuiteEvent,
  normalizePullRequestEvent,
  normalizeReviewResult,
} from "./controller.mjs";

export const MAX_BODY_BYTES = 256 * 1024;
export const BODY_TIMEOUT_MS = 15_000;

function headerValue(req, name) {
  const value = req.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

export function verifySha256Signature(body, secret, signature) {
  if (
    !Buffer.isBuffer(body) ||
    typeof secret !== "string" ||
    !secret ||
    typeof signature !== "string"
  ) {
    return false;
  }
  if (!/^sha256=[0-9a-f]{64}$/i.test(signature)) {
    return false;
  }
  const expected = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
  const left = Buffer.from(expected, "ascii");
  const right = Buffer.from(signature.toLowerCase(), "ascii");
  return left.length === right.length && timingSafeEqual(left, right);
}

export async function readJsonBody(req, options = {}) {
  const maxBytes = options.maxBytes ?? MAX_BODY_BYTES;
  const timeoutMs = options.timeoutMs ?? BODY_TIMEOUT_MS;
  const chunks = [];
  let size = 0;
  let timer;
  let settled = false;
  let onData;
  let onEnd;
  let onError;
  let onAborted;
  const detach = ({ keepError = false } = {}) => {
    if (typeof req.off === "function") {
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("aborted", onAborted);
      if (!keepError) {
        req.off("error", onError);
      }
    } else {
      req.removeListener("data", onData);
      req.removeListener("end", onEnd);
      req.removeListener("aborted", onAborted);
      if (!keepError) {
        req.removeListener("error", onError);
      }
    }
  };
  const drainAfterRejection = () => {
    if (typeof req.resume !== "function") {
      return;
    }
    // Keep request errors handled while the remaining body is discarded.  A
    // rejected webhook must still be able to receive its HTTP error response;
    // destroying IncomingMessage here can destroy the response socket too.
    const cleanupDrain = () => {
      if (typeof req.off === "function") {
        req.off("error", onError);
        req.off("end", cleanupDrain);
        req.off("close", cleanupDrain);
      } else {
        req.removeListener("error", onError);
        req.removeListener("end", cleanupDrain);
        req.removeListener("close", cleanupDrain);
      }
    };
    if (typeof req.once === "function") {
      req.once("end", cleanupDrain);
      req.once("close", cleanupDrain);
    }
    req.resume();
  };
  const settle = (callback, value) => {
    if (settled) {
      return;
    }
    settled = true;
    if (value instanceof Error) {
      chunks.length = 0;
      detach({ keepError: true });
      drainAfterRejection();
    } else {
      detach();
    }
    callback(value);
  };
  try {
    const body = await new Promise((resolve, reject) => {
      timer = setTimeout(() => settle(reject, new Error("request_body_timeout")), timeoutMs);
      onData = (chunk) => {
        if (settled) {
          return;
        }
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > maxBytes) {
          settle(reject, new Error("request_body_too_large"));
          return;
        }
        chunks.push(buffer);
      };
      onEnd = () => settle(resolve, Buffer.concat(chunks));
      onError = (error) => settle(reject, error);
      onAborted = () => settle(reject, new Error("request_aborted"));
      req.on("data", onData);
      req.on("end", onEnd);
      req.on("error", onError);
      req.on("aborted", onAborted);
    });
    let json;
    try {
      json = JSON.parse(body.toString("utf8"));
    } catch {
      throw new Error("invalid_json");
    }
    return { body, json };
  } finally {
    clearTimeout(timer);
  }
}

export function parseGitHubEvent(req, payload) {
  const githubEvent = headerValue(req, "x-github-event");
  const deliveryId = headerValue(req, "x-github-delivery");
  if (typeof deliveryId !== "string") {
    throw new Error("unsupported_github_event");
  }
  if (githubEvent === "check_suite") {
    const suite = payload?.check_suite;
    const pullRequests = Array.isArray(suite?.pull_requests) ? suite.pull_requests : [];
    if (pullRequests.length < 1 || pullRequests.length > 20) {
      throw new Error("unsupported_github_event");
    }
    const prNumbers = [...new Set(pullRequests.map((pullRequest) => pullRequest?.number))];
    if (prNumbers.length < 1 || prNumbers.some((prNumber) => !Number.isInteger(prNumber))) {
      throw new Error("unsupported_github_event");
    }
    const events = prNumbers.map((prNumber) =>
      normalizeCheckSuiteEvent({
        eventId:
          prNumbers.length === 1 ? `github:${deliveryId}` : `github:${deliveryId}:pr:${prNumber}`,
        action: payload?.action,
        repo: payload?.repository?.full_name,
        prNumber,
        headSha: suite?.head_sha,
        suiteId: suite?.id,
        updatedAt: suite?.updated_at,
        url: suite?.url,
      }),
    );
    return events.length === 1 ? events[0] : events;
  }
  if (githubEvent !== "pull_request") {
    throw new Error("unsupported_github_event");
  }
  const repository = payload?.repository?.full_name;
  const pullRequest = payload?.pull_request;
  return normalizePullRequestEvent({
    eventId: `github:${deliveryId}`,
    action: payload?.action,
    repo: repository,
    prNumber: pullRequest?.number,
    headSha: pullRequest?.head?.sha,
    baseSha: pullRequest?.base?.sha,
    baseRef: pullRequest?.base?.ref,
    headRepo: pullRequest?.head?.repo?.full_name,
    headRef: pullRequest?.head?.ref,
    updatedAt: pullRequest?.updated_at,
  });
}

export const parseGitHubPullRequest = parseGitHubEvent;

export function parseBrokerReviewEvent(req, payload) {
  const eventName = headerValue(req, "x-broker-event");
  const deliveryId = headerValue(req, "x-broker-delivery");
  if (eventName !== "review.completed" || typeof deliveryId !== "string") {
    throw new Error("unsupported_broker_event");
  }
  if (typeof payload?.claimRef !== "string" || !payload.claimRef.trim()) {
    throw new Error("review completion claimRef is required");
  }
  return normalizeReviewResult({
    eventId: `broker:${deliveryId}`,
    repo: payload?.repository,
    prNumber: payload?.pullRequest,
    headSha: payload?.headSha,
    outcome: payload?.outcome,
    reviewId: payload?.reviewId,
    coverageComplete: payload?.coverageComplete,
    retryAllowed: payload?.retryAllowed,
    findings: payload?.findings ?? [],
    summary: payload?.summary,
    claimRef: payload?.claimRef,
  });
}

export function createFixedWindowLimiter(options = {}) {
  const windowMs = options.windowMs ?? 60_000;
  const maxRequests = options.maxRequests ?? 120;
  const maxKeys = options.maxKeys ?? 4096;
  const entries = new Map();
  return {
    allow(key, now = Date.now()) {
      const normalized = String(key || "unknown");
      let entry = entries.get(normalized);
      if (!entry || now - entry.startedAt >= windowMs) {
        entry = { startedAt: now, count: 0 };
      }
      entry.count += 1;
      entries.delete(normalized);
      entries.set(normalized, entry);
      while (entries.size > maxKeys) {
        entries.delete(entries.keys().next().value);
      }
      return entry.count <= maxRequests;
    },
    size() {
      return entries.size;
    },
  };
}

export function createInFlightLimiter(options = {}) {
  const maxPerKey = options.maxPerKey ?? 8;
  const maxKeys = options.maxKeys ?? 4096;
  const counts = new Map();
  return {
    acquire(key) {
      const normalized = String(key || "unknown");
      const current = counts.get(normalized) ?? 0;
      if (current >= maxPerKey || (!counts.has(normalized) && counts.size >= maxKeys)) {
        return null;
      }
      counts.set(normalized, current + 1);
      let released = false;
      return () => {
        if (released) {
          return;
        }
        released = true;
        const next = (counts.get(normalized) ?? 1) - 1;
        if (next <= 0) {
          counts.delete(normalized);
        } else {
          counts.set(normalized, next);
        }
      };
    },
  };
}

export function requestKey(req, routeId) {
  return `${routeId}:${req.socket?.remoteAddress ?? "unknown"}`;
}

export function requireJsonPost(req) {
  if (req.method !== "POST") {
    throw new Error("method_not_allowed");
  }
  const contentType = headerValue(req, "content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new Error("unsupported_media_type");
  }
}

export function writeJson(res, statusCode, body) {
  if (res.headersSent) {
    return;
  }
  const encoded = Buffer.from(JSON.stringify(body));
  res.statusCode = statusCode;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("content-length", String(encoded.length));
  res.setHeader("cache-control", "no-store");
  res.end(encoded);
}

export function mapHttpError(error) {
  const code = error instanceof Error ? error.message : "request_rejected";
  if (code === "method_not_allowed") return { status: 405, code };
  if (code === "unsupported_media_type") return { status: 415, code };
  if (code === "request_body_too_large") return { status: 413, code };
  if (code === "request_body_timeout") return { status: 408, code };
  if (code === "invalid_signature") return { status: 401, code };
  if (code === "rate_limited" || code === "too_many_in_flight") return { status: 429, code };
  if (code === "unsupported_github_event" || code === "unsupported_broker_event") {
    return { status: 202, code };
  }
  return { status: 400, code: "request_rejected" };
}
