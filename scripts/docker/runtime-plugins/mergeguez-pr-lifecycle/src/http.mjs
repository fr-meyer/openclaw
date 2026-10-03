import { createHmac, timingSafeEqual } from "node:crypto";
import { normalizePullRequestEvent, normalizeReviewResult } from "./controller.mjs";

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
  try {
    const body = await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error("request_body_timeout")), timeoutMs);
      req.on("data", (chunk) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > maxBytes) {
          reject(new Error("request_body_too_large"));
          return;
        }
        chunks.push(buffer);
      });
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("error", reject);
      req.on("aborted", () => reject(new Error("request_aborted")));
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

export function parseGitHubPullRequest(req, payload) {
  const githubEvent = headerValue(req, "x-github-event");
  const deliveryId = headerValue(req, "x-github-delivery");
  if (githubEvent !== "pull_request" || typeof deliveryId !== "string") {
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
  });
}

export function parseMergeguezReviewEvent(req, payload) {
  const eventName = headerValue(req, "x-mergeguez-event");
  const deliveryId = headerValue(req, "x-mergeguez-delivery");
  if (eventName !== "review.completed" || typeof deliveryId !== "string") {
    throw new Error("unsupported_mergeguez_event");
  }
  return normalizeReviewResult({
    eventId: `mergeguez:${deliveryId}`,
    repo: payload?.repository,
    prNumber: payload?.pullRequest,
    headSha: payload?.headSha,
    outcome: payload?.outcome,
    reviewId: payload?.reviewId,
    coverageComplete: payload?.coverageComplete,
    retryAllowed: payload?.retryAllowed,
    findings: payload?.findings ?? [],
    summary: payload?.summary,
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
  if (code === "method_not_allowed") {
    return { status: 405, code };
  }
  if (code === "unsupported_media_type") {
    return { status: 415, code };
  }
  if (code === "request_body_too_large") {
    return { status: 413, code };
  }
  if (code === "request_body_timeout") {
    return { status: 408, code };
  }
  if (code === "invalid_signature") {
    return { status: 401, code };
  }
  if (code === "rate_limited" || code === "too_many_in_flight") {
    return { status: 429, code };
  }
  if (code === "unsupported_github_event" || code === "unsupported_mergeguez_event") {
    return { status: 202, code };
  }
  return { status: 400, code: "request_rejected" };
}
