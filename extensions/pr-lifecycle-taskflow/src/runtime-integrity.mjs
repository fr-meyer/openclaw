import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { HTTP_SOURCE_PATH, INDEX_SOURCE_PATH, RUNTIME_SOURCE_PATH } from "./runtime-foundation.mjs";

export function isDisposableRuntimePath(value) {
  const normalizedPath = typeof value === "string" ? value.replaceAll("\\", "/") : "";
  return (
    normalizedPath.includes("/.openclaw/tmp/") ||
    normalizedPath.includes("/.openclaw/worktrees/") ||
    normalizedPath.startsWith("/tmp/")
  );
}

export function hashSourceFile(path, reader) {
  return createHash("sha256").update(reader(path)).digest("hex");
}

export function executableSourceSet(options = {}) {
  const reader = options.readFileSync ?? readFileSync;
  const modules = {
    index: hashSourceFile(INDEX_SOURCE_PATH, reader),
    runtime: createHash("sha256")
      .update(
        [
          fileURLToPath(new URL("./runtime.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-foundation.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-remediation.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-remediation-primitives.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-integrity.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-merge-gates.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-merge.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-config.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-state-effects.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-state-primitives.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-contention.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-workspace.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-workspace-primitives.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-dispatch.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-worker-orchestration.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-ingest.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-status.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-status-primitives.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-tools.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-registration.mjs", import.meta.url)),
          fileURLToPath(new URL("./runtime-testing.mjs", import.meta.url)),
        ]
          .map(
            (path) =>
              path.slice(path.lastIndexOf("/") + 1) + ":" + hashSourceFile(path, reader) + "\n",
          )
          .join(""),
      )
      .digest("hex"),
    controller: createHash("sha256")
      .update(
        [
          fileURLToPath(new URL("./controller.mjs", import.meta.url)),
          fileURLToPath(new URL("./controller-constants.mjs", import.meta.url)),
          fileURLToPath(new URL("./controller-policy.mjs", import.meta.url)),
          fileURLToPath(new URL("./controller-validation.mjs", import.meta.url)),
          fileURLToPath(new URL("./controller-events.mjs", import.meta.url)),
          fileURLToPath(new URL("./controller-state.mjs", import.meta.url)),
          fileURLToPath(new URL("./controller-workers.mjs", import.meta.url)),
          fileURLToPath(new URL("./controller-recovery.mjs", import.meta.url)),
        ]
          .map(
            (path) =>
              path.slice(path.lastIndexOf("/") + 1) + ":" + hashSourceFile(path, reader) + "\n",
          )
          .join(""),
      )
      .digest("hex"),
    http: hashSourceFile(HTTP_SOURCE_PATH, reader),
  };
  return {
    path: RUNTIME_SOURCE_PATH,
    modules,
    sha256: createHash("sha256")
      .update(
        `index:${modules.index}\nruntime:${modules.runtime}\n` +
          `controller:${modules.controller}\nhttp:${modules.http}\n`,
      )
      .digest("hex"),
    durable: !isDisposableRuntimePath(RUNTIME_SOURCE_PATH),
  };
}

export function runtimeSourceIntegrity(expectedPath, expectedSha256, options = {}) {
  const source = executableSourceSet(options);
  return {
    path: source.path,
    sha256: source.sha256,
    modules: source.modules,
    durable: source.durable,
    verified:
      typeof expectedPath === "string" &&
      expectedPath === source.path &&
      typeof expectedSha256 === "string" &&
      expectedSha256 === source.sha256 &&
      (source.durable || options.allowDisposable === true),
  };
}
