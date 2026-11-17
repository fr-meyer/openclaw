#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { run, fileDigest, sourcePlan } from "./no-copy-layout.mjs";
const SELF = fileURLToPath(import.meta.url),
  TOOLS = path.dirname(SELF);
const fail = (m) => {
    throw Error(m);
  },
  same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sha = (b) => createHash("sha256").update(b).digest("hex");
export function binding(config) {
  const f = config.sourceBindingFile;
  if (!f || fs.realpathSync(f) !== path.resolve(f) || fileDigest(f) !== config.sourceBindingSha256)
    fail("exact approved source binding required");
  const b = JSON.parse(fs.readFileSync(f));
  const selectors = JSON.parse(fs.readFileSync(path.join(TOOLS, "sources.json")));
  if (
    !["bfl", "embeddings"].includes(b.project) ||
    b.repo !== "fr-meyer/openclaw" ||
    b.expectedCandidateTree !== config.expectedTree ||
    !/^[a-f0-9]{40}$/.test(b.carrierSha ?? "") ||
    !/^[a-f0-9]{40}$/.test(b.base ?? "") ||
    !/^[a-f0-9]{64}$/.test(b.patchSha256 ?? "") ||
    !b.files ||
    !same(b.tests, selectors[b.project].tests) ||
    b.tests.length !== (b.project === "bfl" ? 27 : 7)
  )
    fail("complete project/source/selector binding mismatch");
  if (b.project === "bfl" && b.expectedCandidateTree !== "bbb498d0086e48faf499ea5f7a230ee892a04ecf")
    fail("accepted BFL73 tree required; no old69 fallback");
  const plan = sourcePlan(config),
    entries = new Map(plan.entries.map((e) => [e.path, e.sha256]));
  for (const [name, digest] of Object.entries(b.files))
    if (!/^[a-f0-9]{64}$/.test(digest) || entries.get(name) !== digest)
      fail("approved changed-file pin mismatch");
  for (const name of b.tests)
    if (!entries.has(name)) fail("test selector absent from complete source");
  return b;
}
const formatter = [
  "/usr/local/bin/node",
  "--input-type=module",
  "-e",
  'import fs from "node:fs";import path from "node:path";import {spawnSync} from "node:child_process";const root=fs.realpathSync("node_modules/oxfmt");const p=JSON.parse(fs.readFileSync(path.join(root,"package.json")));const bin=typeof p.bin==="string"?p.bin:p.bin.oxfmt;const r=spawnSync(path.join(root,bin),["--check",...process.argv.slice(1)],{stdio:"inherit"});if(r.error)throw r.error;process.exit(r.status??1);',
];
export function matrix(b) {
  const rows = [
    [
      "native-dependency-probes",
      60,
      [
        "/usr/local/bin/node",
        "--input-type=module",
        "-e",
        'import {createRequire} from "node:module";const r=createRequire(process.cwd()+"/package.json");r("node:sqlite");r("esbuild").transformSync("const a=1");await import(r.resolve("rastermill"));await import(r.resolve("@openclaw/fs-safe"));console.log("NATIVE_DEPENDENCIES_READY");',
      ],
    ],
    [
      "new-regressions",
      300,
      [
        "/usr/local/bin/node",
        "scripts/run-vitest.mjs",
        "run",
        b.tests[0],
        "--maxWorkers=1",
        "--pool=forks",
        "--passWithNoTests=false",
      ],
    ],
    [
      "companion-regressions",
      600,
      [
        "/usr/local/bin/node",
        "scripts/run-vitest.mjs",
        "run",
        ...b.tests.slice(1),
        "--maxWorkers=1",
        "--pool=forks",
        "--passWithNoTests=false",
      ],
    ],
    ...[
      ["types-core", "tsconfig.core.json"],
      ["types-extensions", "tsconfig.extensions.json"],
      ["types-extension-tests", "test/tsconfig/tsconfig.extensions.test.json"],
    ].map(([n, p]) => [
      n,
      240,
      [
        "/usr/local/bin/node",
        "scripts/run-tsgo.mjs",
        "-p",
        p,
        "--noEmit",
        "--incremental",
        "false",
      ],
    ]),
    ["lint", 240, ["/usr/local/bin/node", "--import", "./scripts/tsx.mjs", "scripts/run-lint.mts"]],
    [
      "format-changed",
      90,
      [
        ...formatter,
        ...Object.keys(b.files).filter((p) =>
          /\.(?:[cm]?[jt]sx?|jsonc?|md|ya?ml|html|css|scss)$/.test(p),
        ),
      ],
    ],
    ["format-full", 90, formatter],
    [
      "frozen-lock",
      90,
      [
        "/usr/local/bin/node",
        "-e",
        'console.log("FROZEN_COMPLETE=1: mandatory trusted offline stage already succeeded")',
      ],
    ],
  ];
  return rows.map(([label, seconds, command]) => ({
    label,
    seconds,
    command: [
      "/bin/bash",
      "-c",
      'set -Eeuo pipefail; /usr/local/bin/node --import ./scripts/tsx.mjs scripts/generate-kysely-types.mts; "$@"; git diff --exit-code; test -z "$(git ls-files --others --exclude-standard)"',
      "isolated-check",
      ...command,
    ],
  }));
}
function requireOffline(config, receiptFile) {
  const raw = fs.readFileSync(receiptFile);
  if (sha(raw) !== config.receiptSha256) fail("sealed receipt mismatch");
  const r = JSON.parse(raw);
  if (
    config.fullValidation !== true ||
    !r.offlineQualification ||
    r.toolingPins?.["offline_lock.py"] !==
      "31d877c7123b1bf2e6b829eb8621cbe25425d58dc70ed4c87f66d3f041fb1426"
  )
    fail("full validation requires genuine pinned offline R2 stage");
  return r;
}
export function check(config, receiptFile, workspace, image, seconds, label, command) {
  if (fs.realpathSync(workspace) !== config.sourceRoot || image !== config.finalImageId)
    fail("exact helper workspace/image mismatch");
  if (label) {
    requireOffline(config, receiptFile);
    const row = matrix(binding(config)).find((r) => r.label === label);
    if (!row || row.seconds !== Number(seconds) || !same(row.command, command))
      fail("full validation command vector differs from exact matrix");
  } else if (
    config.fullValidation === true ||
    !same(config.command, command) ||
    config.timeoutSeconds !== Number(seconds)
  )
    fail("generic command vector mismatch");
  return run({ ...config, command, timeoutSeconds: Number(seconds) }, receiptFile, image);
}
export function full(configFile, receiptFile) {
  const config = JSON.parse(fs.readFileSync(configFile));
  requireOffline(config, receiptFile);
  const b = binding(config);
  let exit = 0;
  const checks = [];
  for (const row of matrix(b)) {
    const argv = [
      "bash",
      path.join(TOOLS, "openclaw-worktree-test-isolated"),
      "--workspace",
      config.sourceRoot,
      "--image",
      config.finalImageId,
      "--timeout",
      String(row.seconds),
      "--label",
      row.label,
      "--command",
      "--",
      ...row.command,
    ];
    console.log("CHECK_BEGIN=" + row.label);
    const r = spawnSync(argv[0], argv.slice(1), {
      stdio: "inherit",
      env: {
        ...process.env,
        OPENCLAW_NO_COPY_CONFIG: configFile,
        OPENCLAW_NO_COPY_RECEIPT: receiptFile,
      },
    });
    const rc = r.status ?? 1;
    checks.push({ label: row.label, exit: rc });
    console.log("CHECK_END=" + row.label + " EXIT=" + rc);
    if (rc) exit = 1;
  }
  return { exit, project: b.project, checks, actualProductQualified: false };
}
if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  try {
    const [mode, configFile, receiptFile, ...args] = process.argv.slice(2);
    let result;
    if (mode === "full") result = full(configFile, receiptFile);
    else if (mode === "matrix") result = matrix(JSON.parse(fs.readFileSync(configFile)));
    else if (mode === "check") {
      const [workspace, image, seconds, label, separator, ...command] = args;
      if (separator !== "--") fail("command vector separator required");
      result = check(
        JSON.parse(fs.readFileSync(configFile)),
        receiptFile,
        workspace,
        image,
        seconds,
        label,
        command,
      );
      process.stdout.write(result.stdout);
      process.stderr.write(result.stderr);
      delete result.stdout;
      delete result.stderr;
      result.exit = result.status ?? 1;
    } else fail("mode full|check|matrix required");
    console.log(JSON.stringify(result));
    process.exitCode = result.exit ?? 0;
  } catch (e) {
    console.error(JSON.stringify({ status: "FULL_VALIDATION_FAILED_CLOSED", error: e.message }));
    process.exitCode = 1;
  }
}
