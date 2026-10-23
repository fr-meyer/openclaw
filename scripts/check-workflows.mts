#!/usr/bin/env node
// Runs local workflow sanity checks.
// Uses qualified installed tools, otherwise falls back to pinned hooks where
// possible, then runs repo-specific workflow guards.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

const ACTIONLINT_REVISION = "011a6d15e749bb3f2d771eed9c7aa0e7e3e10ee7";
const ACTIONLINT_PATCH = fileURLToPath(new URL("actionlint-cache-mode.patch", import.meta.url));
const ACTIONLINT_PATCH_BYTES = readFileSync(ACTIONLINT_PATCH);
const ACTIONLINT_PATCH_SHA = createHash("sha256").update(ACTIONLINT_PATCH_BYTES).digest("hex");
const ACTIONLINT_VERSION = `v1.7.13-0.20260419144658-${ACTIONLINT_REVISION.slice(0, 12)}+openclaw-cache-mode.${ACTIONLINT_PATCH_SHA.slice(0, 12)}`;
const PRE_COMMIT_VERSION = "4.6.2";
// pre-commit 4.6.2 declares requires-python >=3.10, so an older interpreter only
// fails after a venv build and a network pip install.
const PRE_COMMIT_PYTHON_FLOOR = "3.10";
const WORKFLOW_DIR = ".github/workflows";

function commandExists(command: string, args: readonly string[] = ["--version"]): boolean {
  const result = spawnSync(command, args, { stdio: "ignore" });
  return !result.error && result.status === 0;
}

function hasPinnedActionlint(): boolean {
  const result = spawnSync("actionlint", ["--version"], { encoding: "utf8" });
  if (result.error || result.status !== 0) {
    return false;
  }
  // Reuse only the exact upstream pin plus this transparent parser patch.
  // Bare upstream builds cannot validate GitHub's token-enforced cache-mode.
  const version = result.stdout.split(/\r?\n/u, 1)[0]?.trim() ?? "";
  if (version === ACTIONLINT_VERSION) {
    return true;
  }
  console.warn(
    `[check-workflows] installed actionlint does not match ${ACTIONLINT_VERSION}; using pinned fallback.`,
  );
  return false;
}

function probePythonVersion(
  command: string,
): { runnable: false } | { runnable: true; version?: string } {
  const result = spawnSync(command, ["--version"], { encoding: "utf8" });
  if (result.error || result.status !== 0) {
    return { runnable: false };
  }
  const match = /Python (\d+\.\d+(?:\.\d+)?)/u.exec(`${result.stdout ?? ""}${result.stderr ?? ""}`);
  const version = match?.[1];
  return version ? { runnable: true, version } : { runnable: true };
}

function isBelowPythonFloor(version: string, floor: string): boolean {
  const [major = 0, minor = 0] = version.split(".").map((part) => Number(part));
  const [floorMajor = 0, floorMinor = 0] = floor.split(".").map((part) => Number(part));
  return major < floorMajor || (major === floorMajor && minor < floorMinor);
}

function run(command: string, args: readonly string[]): void {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.error) {
    console.error(`[check-workflows] failed to run ${command}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function runChecked(command: string, args: readonly string[]) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.error) {
    return {
      message: `[check-workflows] failed to run ${command}: ${result.error.message}`,
      status: 1,
    };
  }
  if (result.status !== 0) {
    return {
      message: null,
      status: result.status ?? 1,
    };
  }
  return null;
}

function exitWithFailure(failure: NonNullable<ReturnType<typeof runChecked>>): never {
  if (failure.message) {
    console.error(failure.message);
  }
  process.exit(failure.status);
}

function verifyActionlintParser(binary: string): boolean {
  const fixtureDir = mkdtempSync(join(tmpdir(), "openclaw-actionlint-parser-"));
  try {
    const fixtures: { name: string; root?: string; job?: string; diagnostic?: string }[] = [];
    for (const value of ["read", "write", "write-only", "none"]) {
      fixtures.push({
        name: `valid-${value}`,
        root: `cache-mode: ${value}\n`,
        job: `    cache-mode: ${value}\n`,
      });
    }
    for (const [index, value] of [
      "bogus",
      "'${{ github.ref }}'",
      "true",
      "42",
      "[none]",
      "null",
    ].entries()) {
      const diagnostic = index < 2 ? "invalid cache-mode" : "cache-mode must be a string";
      fixtures.push({ name: `invalid-root-${index}`, root: `cache-mode: ${value}\n`, diagnostic });
      fixtures.push({
        name: `invalid-job-${index}`,
        job: `    cache-mode: ${value}\n`,
        diagnostic,
      });
    }
    fixtures.push({
      name: "unknown-root",
      root: "unexpected-cache-key: none\n",
      diagnostic: 'unexpected key "unexpected-cache-key"',
    });
    fixtures.push({
      name: "unknown-job",
      job: "    unexpected-cache-key: none\n",
      diagnostic: 'unexpected key "unexpected-cache-key"',
    });
    for (const fixture of fixtures) {
      const path = join(fixtureDir, `${fixture.name}.yml`);
      writeFileSync(
        path,
        `name: Parser fixture\non: push\n${fixture.root ?? ""}jobs:\n  fixture:\n    runs-on: ubuntu-latest\n${fixture.job ?? ""}    steps:\n      - run: 'true'\n`,
      );
      // These fixtures exercise parsing only; the real workflow audit retains all tools.
      const result = spawnSync(binary, ["-shellcheck=", "-pyflakes=", path], {
        cwd: fixtureDir,
        encoding: "utf8",
        timeout: 30_000,
      });
      const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
      if (
        result.error ||
        result.status !== (fixture.diagnostic ? 1 : 0) ||
        (fixture.diagnostic && !output.includes(fixture.diagnostic))
      ) {
        console.error(`[check-workflows] parser fixture ${fixture.name} failed: ${output}`);
        return false;
      }
    }
    console.log(`[check-workflows] ${fixtures.length} actual actionlint parser fixtures passed.`);
    return true;
  } finally {
    rmSync(fixtureDir, { force: true, recursive: true });
  }
}

function installActionlint(binDir: string): boolean {
  if (!commandExists("go", ["version"]) || !commandExists("git", ["--version"])) {
    return false;
  }
  const sourceDir = mkdtempSync(join(tmpdir(), "openclaw-actionlint-source-"));
  const binary = join(binDir, process.platform === "win32" ? "actionlint.exe" : "actionlint");
  try {
    mkdirSync(binDir, { recursive: true });
    const commands: [string, string[]][] = [
      ["git", ["init", "--quiet"]],
      [
        "git",
        [
          "fetch",
          "--quiet",
          "--depth=1",
          "https://github.com/rhysd/actionlint.git",
          ACTIONLINT_REVISION,
        ],
      ],
      ["git", ["checkout", "--quiet", "--detach", "FETCH_HEAD"]],
    ];
    for (const [command, args] of commands) {
      const result = spawnSync(command, args, {
        cwd: sourceDir,
        stdio: "inherit",
        timeout: 120_000,
      });
      if (result.error || result.status !== 0) {
        return false;
      }
    }
    const identity = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: sourceDir,
      encoding: "utf8",
      timeout: 10_000,
    });
    if (identity.error || identity.status !== 0 || identity.stdout.trim() !== ACTIONLINT_REVISION) {
      console.error(
        "[check-workflows] fetched actionlint source identity differs from the exact pin.",
      );
      return false;
    }
    for (const args of [
      ["apply", "--check", "--unidiff-zero", "--whitespace=error-all", "-"],
      ["apply", "--unidiff-zero", "--whitespace=error-all", "-"],
    ]) {
      const result = spawnSync("git", args, {
        cwd: sourceDir,
        input: ACTIONLINT_PATCH_BYTES,
        stdio: ["pipe", "inherit", "inherit"],
        timeout: 10_000,
      });
      if (result.error || result.status !== 0) {
        return false;
      }
    }
    const formatting = spawnSync("gofmt", ["-l", "ast.go", "parse.go"], {
      cwd: sourceDir,
      encoding: "utf8",
      timeout: 10_000,
    });
    if (formatting.error || formatting.status !== 0 || formatting.stdout.trim()) {
      return false;
    }
    console.log(
      `[check-workflows] building ${ACTIONLINT_REVISION} with parser patch sha256:${ACTIONLINT_PATCH_SHA}`,
    );
    const built = spawnSync(
      "go",
      [
        "build",
        "-trimpath",
        "-ldflags",
        `-X github.com/rhysd/actionlint.version=${ACTIONLINT_VERSION}`,
        "-o",
        binary,
        "./cmd/actionlint",
      ],
      { cwd: sourceDir, stdio: "inherit", timeout: 600_000 },
    );
    if (built.error || built.status !== 0) {
      return false;
    }
    const version = spawnSync(binary, ["--version"], { encoding: "utf8", timeout: 10_000 });
    if (
      version.error ||
      version.status !== 0 ||
      version.stdout.split(/\r?\n/u, 1)[0]?.trim() !== ACTIONLINT_VERSION
    ) {
      return false;
    }
    return verifyActionlintParser(binary);
  } finally {
    rmSync(sourceDir, { force: true, recursive: true });
  }
}

function runGoActionlint(files: string[]): boolean {
  const binDir = mkdtempSync(join(tmpdir(), "openclaw-check-workflows-actionlint-"));
  let lintFailure: ReturnType<typeof runChecked> = null;
  try {
    if (!installActionlint(binDir)) {
      return false;
    }
    lintFailure = runChecked(
      join(binDir, process.platform === "win32" ? "actionlint.exe" : "actionlint"),
      files,
    );
  } finally {
    rmSync(binDir, { force: true, recursive: true });
  }
  if (lintFailure) {
    exitWithFailure(lintFailure);
  }
  return true;
}

function runPreCommitFromTempVenv(hookArgs: string[]): boolean {
  const pythonProbe = probePythonVersion("python3");
  if (!pythonProbe.runnable) {
    return false;
  }
  if (pythonProbe.version && isBelowPythonFloor(pythonProbe.version, PRE_COMMIT_PYTHON_FLOOR)) {
    console.error(
      `[check-workflows] python3 is ${pythonProbe.version}, but pre-commit ${PRE_COMMIT_VERSION} requires Python >=${PRE_COMMIT_PYTHON_FLOOR}. Install a newer python3 or a pre-commit runtime.`,
    );
    process.exit(1);
  }
  const venvDir = mkdtempSync(join(tmpdir(), "openclaw-check-workflows-pre-commit-"));
  const python = join(venvDir, process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
  let postVenvFailure: ReturnType<typeof runChecked> = null;
  try {
    const venvFailure = runChecked("python3", ["-m", "venv", venvDir]);
    if (venvFailure) {
      return false;
    }
    postVenvFailure = runChecked(python, [
      "-m",
      "pip",
      "install",
      "--disable-pip-version-check",
      `pre-commit==${PRE_COMMIT_VERSION}`,
    ]);
    if (postVenvFailure) {
      return false;
    }
    postVenvFailure = runChecked(python, ["-m", "pre_commit", ...hookArgs]);
    if (postVenvFailure) {
      return false;
    }
    return true;
  } finally {
    rmSync(venvDir, { force: true, recursive: true });
    if (postVenvFailure) {
      exitWithFailure(postVenvFailure);
    }
  }
}

function workflowFiles(): string[] {
  return readdirSync(WORKFLOW_DIR)
    .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
    .toSorted()
    .map((file) => join(WORKFLOW_DIR, file));
}

function runPreCommitHook(hook: string, files: string[]): void {
  const hookArgs = ["run", "--config", ".pre-commit-config.yaml", hook, "--files", ...files];
  if (commandExists("pre-commit")) {
    run("pre-commit", hookArgs);
    return;
  }
  if (commandExists("python3", ["-m", "pre_commit", "--version"])) {
    run("python3", ["-m", "pre_commit", ...hookArgs]);
    return;
  }
  if (runPreCommitFromTempVenv(hookArgs)) {
    return;
  }

  console.error(
    `[check-workflows] missing pre-commit runtime for ${hook}: install pre-commit or Python venv support for pre-commit ${PRE_COMMIT_VERSION}.`,
  );
  process.exit(1);
}

if (process.argv[2] === "--install-actionlint") {
  const binDir = process.argv[3];
  if (process.argv.length !== 4 || !binDir || !isAbsolute(binDir)) {
    console.error("Usage: check-workflows.mts --install-actionlint <absolute-bin-directory>");
    process.exit(1);
  }
  if (!installActionlint(binDir)) {
    console.error(
      "[check-workflows] failed to build and qualify pinned actionlint with its parser patch.",
    );
    process.exit(1);
  }
  process.exit(0);
}

// The pre-commit caller uses the same qualified linter without recursing into
// pre-commit's independent zizmor hook or repeating other repository guards.
const actionlintOnly = process.argv[2] === "--actionlint-only";
const workflows =
  actionlintOnly && process.argv.length > 3 ? process.argv.slice(3) : workflowFiles();
if (hasPinnedActionlint()) {
  run("actionlint", workflows);
} else if (!runGoActionlint(workflows)) {
  console.error(
    `[check-workflows] missing workflow linter: install actionlint built from ${ACTIONLINT_REVISION} with parser patch ${ACTIONLINT_PATCH_SHA}, or provide Go and Git to acquire that exact build.`,
  );
  process.exit(1);
}

if (actionlintOnly) {
  process.exit(0);
}

runPreCommitHook("zizmor", workflows);

run("node", ["scripts/generate-ci-git-owner.mts", "--check"]);
run("python3", ["scripts/check-composite-action-input-interpolation.py"]);
run("node", ["scripts/check-no-conflict-markers.mjs"]);
