import { randomUUID } from "node:crypto";
import { resolveEmbeddingEndpointUrl } from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import type { GeminiBatchOperation } from "./embedding-batch-observability.js";

export function getGeminiBatchFileUrl(
  baseUrl: string,
  route: "upload" | "download",
  fileId: string,
): string {
  const base = new URL(baseUrl);
  const pathname = base.pathname.replace(/\/+$/, "");
  // Google file routes precede the API version; custom download gateways own their prefix.
  if (route === "upload" || base.origin === "https://generativelanguage.googleapis.com") {
    const version = pathname.match(/^(.*)\/(v\d+(?:alpha|beta)?)$/);
    base.pathname = version
      ? `${version[1]}/${route}/${version[2]}`
      : route === "upload"
        ? `${pathname}/upload`
        : pathname;
  }
  const endpoint =
    route === "upload"
      ? fileId
      : `${fileId.startsWith("files/") ? fileId : `files/${fileId}`}:download`;
  const url = new URL(resolveEmbeddingEndpointUrl(base.href, endpoint));
  url.searchParams.set(
    route === "upload" ? "uploadType" : "alt",
    route === "upload" ? "multipart" : "media",
  );
  return url.href;
}

export function getGeminiBatchOutputFileId(operation: GeminiBatchOperation): string | undefined {
  // Prefer the canonical top-level Batch output. Legacy Operation aliases can
  // lag behind the terminal Batch fields, so they are fallback-only.
  const outputFile = operation.output?.responsesFile;
  const responseFile = operation.response?.responsesFile;
  const metadataFile = operation.metadata?.output?.responsesFile;
  if (!outputFile && responseFile && metadataFile && responseFile !== metadataFile) {
    throw new Error("gemini batch operation returned conflicting output files");
  }
  return outputFile ?? responseFile ?? metadataFile;
}

export function buildGeminiUploadBody(params: { jsonl: string; displayName: string }): {
  body: Blob;
  contentType: string;
} {
  const boundary = `openclaw-${randomUUID()}`;
  const jsonPart = JSON.stringify({
    file: {
      displayName: params.displayName,
      mimeType: "application/jsonl",
    },
  });
  const delimiter = `--${boundary}\r\n`;
  const closeDelimiter = `--${boundary}--\r\n`;
  const parts = [
    `${delimiter}Content-Type: application/json; charset=UTF-8\r\n\r\n${jsonPart}\r\n`,
    `${delimiter}Content-Type: application/jsonl; charset=UTF-8\r\n\r\n${params.jsonl}\r\n`,
    closeDelimiter,
  ];
  const body = new Blob([parts.join("")], { type: "multipart/related" });
  return {
    body,
    contentType: `multipart/related; boundary=${boundary}`,
  };
}
