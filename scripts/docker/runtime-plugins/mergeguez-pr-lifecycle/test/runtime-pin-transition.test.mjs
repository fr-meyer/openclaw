import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { inflateRawSync } from "node:zlib";
import {
  createInstalledPublisherPinTransition,
  INSTALLED_PUBLISHER_PIN_PAIR,
  readPublisherArtifactBytes,
} from "../src/runtime-pin-transition.mjs";

const ID = "mergeguez-pr-lifecycle";
const P = "/synthetic/plugin/src/runtime.mjs";
const C = "/synthetic/openclaw.json";
const H0 = INSTALLED_PUBLISHER_PIN_PAIR.predecessor.files["src/runtime.mjs"];
const H1 = INSTALLED_PUBLISHER_PIN_PAIR.candidate.files["src/runtime.mjs"];
const sha = (value) => createHash("sha256").update(value).digest("hex");
const packageRoot = path.resolve(import.meta.dirname, "..");
const candidateBytes = new Map(
  Object.keys(INSTALLED_PUBLISHER_PIN_PAIR.candidate.files).map((p) => [
    p,
    fs.readFileSync(path.join(packageRoot, p)),
  ]),
);
const predecessorFixture = JSON.parse(
  fs.readFileSync(new URL("./fixtures/predecessor-pin-package.json", import.meta.url), "utf8"),
);
const predecessorBytes = new Map(candidateBytes);
for (const [name, compressed] of Object.entries(predecessorFixture.deflatedFiles)) {
  predecessorBytes.set(name, inflateRawSync(Buffer.from(compressed, "base64")));
}

const mutationSource = stripTypeScriptTypes(
  fs.readFileSync(new URL("../../../../../src/config/mutate.ts", import.meta.url), "utf8"),
  { mode: "strip" },
);
const mutationFunction = (name) => {
  const start = mutationSource.search(new RegExp(`(?:export )?(?:async )?function ${name}\\s*\\(`));
  assert.ok(start >= 0, name);
  const tail = mutationSource.slice(start);
  const end = tail.search(/^}\n/m);
  assert.ok(end >= 0);
  return tail.slice(0, end + 2).replace(/^export /, "");
};

// Actual public entry, transform and canonical revision CAS body. Snapshot IO,
// lock acquisition and commit effects stay inert; no native publisher or fsync.
function useCanonicalMutationBody(f) {
  const names = [
    "assertBaseHashMatches",
    "assertExpectedConfigPathMatches",
    "mergeConfigMutationWriteOptions",
    "configMutationTransform",
    "transformConfigFileAttempt",
    "mutateConfigFile",
  ];
  class Conflict extends Error {}
  const make = vm.compileFunction(
    names.map(mutationFunction).join("\n") +
      "\nreturn {mutateConfigFile,transformConfigFileAttempt};",
    [
      "ConfigMutationConflictError",
      "resolveConfigSnapshotHash",
      "copyRuntimeConfigWriteApplication",
      "assertConfigWriteAllowedInCurrentMode",
      "markActiveConfigMutationPath",
      "resolveConfigWriteAfterWrite",
      "resolveConfigWriteFollowUp",
      "transformConfigFile",
      "commitPreparedConfigMutation",
    ],
  );
  const actual = make(
    Conflict,
    (snapshot) => snapshot.hash,
    (_base, options) => options,
    () => {},
    () => {},
    (value) => value,
    (value) => value,
    async (params) =>
      actual.transformConfigFileAttempt(params, 0, undefined, {
        snapshot: f.snapshot(),
        writeOptions: {},
      }),
    async ({ nextConfig, writeOptions, snapshot }) => {
      assert.equal(writeOptions.requireBackup, true);
      await writeOptions.beforeCommit();
      writeOptions.assertCurrent();
      const result = await f.sdk.mutateConfigFile({
        base: "source",
        baseHash: snapshot.hash,
        afterWrite: { mode: "none" },
        writeOptions,
        mutate: (draft) => {
          Object.assign(draft, nextConfig);
        },
      });
      return {
        config: nextConfig,
        persistedHash: result.persistedHash,
        afterWrite: { mode: "none" },
      };
    },
  );
  return actual.mutateConfigFile;
}

test("actual canonical mutation body joins component source/CAS/backup intent", async () => {
  const f = fixture();
  const run = createInstalledPublisherPinTransition({
    authority: f.authority,
    readArtifact: f.readArtifact,
    loadConfigMutation: async () => ({ ...f.sdk, mutateConfigFile: useCanonicalMutationBody(f) }),
  });
  assert.equal((await run(f.request())).status, "applied");
  assert.equal(f.calls.writes, 1);
  assert.equal(f.get().plugins.entries[ID].config.expectedRuntimeSha256, H1);
});

test("actual canonical CAS rejects drift before plugin mutation or commit", async () => {
  const f = fixture();
  const actual = useCanonicalMutationBody(f);
  const run = createInstalledPublisherPinTransition({
    authority: f.authority,
    readArtifact: f.readArtifact,
    loadConfigMutation: async () => ({
      ...f.sdk,
      mutateConfigFile: (params) => {
        f.edit();
        return actual(params);
      },
    }),
  });
  await assert.rejects(run(f.request()), (error) => error.receipt.status === "unknown");
  assert.equal(f.calls.writes, 0);
  assert.equal(f.calls.backups, 0);
  assert.equal(f.get().plugins.entries[ID].config.expectedRuntimeSha256, H0);
});

function fixture() {
  let current = {
    unrelated: { keep: "synthetic-private-marker" },
    plugins: {
      entries: {
        [ID]: {
          enabled: true,
          config: {
            expectedRuntimePath: P,
            expectedRuntimeSha256: H0,
            enabled: true,
            extra: "preserved",
          },
        },
      },
    },
  };
  let revision = sha(JSON.stringify(current));
  let live = true;
  let rollbackSafe = true;
  let snapshotHashOverride;
  const calls = { writes: 0, reads: 0, backups: 0, artifactReads: 0, rollbackAdmissions: 0 };
  const hooks = {};
  const snapshot = () => ({
    path: C,
    exists: true,
    valid: true,
    hash: snapshotHashOverride ?? revision,
    sourceConfig: structuredClone(current),
    raw: JSON.stringify(current),
  });
  const authority = {
    assertCurrent() {
      if (!live) {
        throw new Error("synthetic_owner_retired");
      }
    },
    assertRollbackSafe() {
      calls.rollbackAdmissions++;
      if (!rollbackSafe) {
        throw new Error("synthetic_effects_unresolved");
      }
    },
  };
  const sdk = {
    CONFIG_MUTATION_CAPABILITIES: Object.freeze({ requireDurableBackup: 1 }),
    async readConfigFileSnapshotForWrite() {
      calls.reads++;
      return { snapshot: snapshot() };
    },
    async mutateConfigFile(options) {
      assert.equal(options.base, "source");
      assert.equal(options.baseHash, revision);
      assert.equal(options.writeOptions.expectedConfigPath, C);
      assert.equal(options.writeOptions.requireBackup, true);
      assert.equal(options.writeOptions.skipOutputLogs, true);
      assert.equal(options.afterWrite.mode, "none");
      if (hooks.beforeMutate) {
        hooks.beforeMutate();
      }
      const before = snapshot();
      if (options.baseHash !== revision) {
        throw new Error("synthetic_cas_conflict");
      }
      const draft = structuredClone(current);
      await options.mutate(draft, { snapshot: before, previousHash: revision });
      if (hooks.backupFailure) {
        throw new Error("synthetic_required_backup_failed");
      }
      calls.backups++;
      if (hooks.beforeCommit) {
        hooks.beforeCommit();
      }
      await options.writeOptions.beforeCommit();
      options.writeOptions.assertCurrent();
      current = draft;
      revision = sha(JSON.stringify(current));
      calls.writes++;
      if (hooks.afterCommit) {
        hooks.afterCommit();
      }
      if (hooks.postCommitFailure) {
        throw Object.assign(new Error("synthetic-private SDK message"), hooks.postCommitFailure);
      }
      return { persistedHash: hooks.missingCommitHash ? null : revision };
    },
  };
  const readArtifact = async (absolute) => {
    calls.artifactReads++;
    if (hooks.artifactRead) {
      return hooks.artifactRead(absolute);
    }
    const relative = path.relative("/synthetic/plugin", absolute);
    const bytes = candidateBytes.get(relative);
    if (!bytes) {
      throw new Error("unexpected_synthetic_artifact_path");
    }
    return bytes;
  };
  const run = createInstalledPublisherPinTransition({
    authority,
    loadConfigMutation: async () => sdk,
    readArtifact,
  });
  const request = (change = {}) => ({
    direction: "forward",
    expectedConfigPath: C,
    expectedConfigHash: revision,
    expectedRuntimePath: P,
    ...change,
  });
  return {
    run,
    request,
    calls,
    hooks,
    snapshot,
    sdk,
    authority,
    readArtifact,
    get: () => structuredClone(current),
    setHash: (h) => {
      current.plugins.entries[ID].config.expectedRuntimeSha256 = h;
      revision = sha(JSON.stringify(current));
    },
    edit: () => {
      current.unrelated.newer = true;
      revision = sha(JSON.stringify(current));
    },
    retire: () => {
      live = false;
    },
    unsafeRollback: () => {
      rollbackSafe = false;
    },
    include: () => {
      snapshotHashOverride = undefined;
      const original = sdk.readConfigFileSnapshotForWrite;
      sdk.readConfigFileSnapshotForWrite = async () => {
        const result = await original();
        result.snapshot.includeProvenance = [{}];
        return result;
      };
    },
  };
}

test("release entrypoint applies only the exact pin via canonical source mutation with required backup", async () => {
  const f = fixture();
  const before = f.get();
  const receipt = await f.run(f.request());
  assert.equal(receipt.status, "applied");
  assert.equal(receipt.configHash, f.snapshot().hash);
  assert.equal(f.calls.writes, 1);
  assert.equal(f.calls.backups, 1);
  before.plugins.entries[ID].config.expectedRuntimeSha256 = H1;
  assert.deepEqual(f.get(), before);
  assert.equal(JSON.stringify(receipt).includes("synthetic-private-marker"), false);
  assert.equal(JSON.stringify(receipt).includes(P), false);
  assert.equal(receipt.runtimeActivation, false);
  assert.equal(receipt.databaseRollback, false);
});

test("idempotent current-revision rerun performs no write or backup", async () => {
  const f = fixture();
  const oldRequest = f.request();
  await f.run(oldRequest);
  const receipt = await f.run(f.request());
  assert.equal(receipt.status, "already-target");
  assert.equal(f.calls.writes, 1);
  assert.equal(f.calls.backups, 1);
  await assert.rejects(f.run(oldRequest), (error) => error.code === "PIN_STALE_CONFIG");
});

for (const field of ["direction", "expectedConfigHash"]) {
  test(`malformed ${field} never leaks payload into refusal receipt`, async () => {
    const f = fixture();
    await assert.rejects(
      f.run(f.request({ [field]: { privatePayload: "x".repeat(2048) } })),
      (error) => {
        assert.equal(error.receipt[field === "direction" ? "direction" : "configHash"], null);
        assert.equal(JSON.stringify(error.receipt).includes("privatePayload"), false);
        assert.equal(error.receipt.status, "refused");
        return true;
      },
    );
    assert.equal(f.calls.artifactReads, 0);
    assert.equal(f.calls.writes, 0);
  });
}

for (const [label, setup, expected] of [
  ["stale full config", (f) => f.edit(), "PIN_STALE_CONFIG"],
  ["unrelated pin", (f) => f.setHash("f".repeat(64)), "PIN_HASH_PREIMAGE_MISMATCH"],
  ["included config", (f) => f.include(), "PIN_INCLUDED_CONFIG_UNSUPPORTED"],
  [
    "corrupt package",
    (f) => {
      f.hooks.artifactRead = () => Buffer.from("corrupt");
    },
    "PIN_TARGET_PACKAGE_MISMATCH",
  ],
  ["retired owner", (f) => f.retire(), "PIN_PREFLIGHT_FAILED"],
]) {
  test(`${label} refuses without config write`, async () => {
    const f = fixture();
    const originalRequest = f.request();
    setup(f);
    const request = label === "stale full config" ? originalRequest : f.request();
    await assert.rejects(
      f.run(request),
      (error) => error.code === expected && error.receipt.status === "refused",
    );
    assert.equal(f.calls.writes, 0);
  });
}

for (const [label, setup] of [
  [
    "config changes during lock acquisition",
    (f) => {
      f.hooks.beforeMutate = () => f.edit();
    },
  ],
  [
    "required backup failure",
    (f) => {
      f.hooks.backupFailure = true;
    },
  ],
  [
    "package replacement before commit",
    (f) => {
      f.hooks.beforeCommit = () => {
        f.hooks.artifactRead = () => Buffer.from("changed");
      };
    },
  ],
  [
    "owner retirement before commit",
    (f) => {
      f.hooks.beforeCommit = () => f.retire();
    },
  ],
]) {
  test(`${label} never silently retries or publishes`, async () => {
    const f = fixture();
    setup(f);
    await assert.rejects(f.run(f.request()), (error) => error.receipt.status === "unknown");
    assert.equal(f.calls.writes, 0);
    assert.equal(f.get().plugins.entries[ID].config.expectedRuntimeSha256, H0);
  });
}

for (const status of ["restored", "not-restored", "unknown"]) {
  test(`post-commit ${status} receipt stays unknown and retains owner outcome`, async () => {
    const f = fixture();
    f.hooks.postCommitFailure = { rollbackStatus: status, publication: "complete" };
    await assert.rejects(f.run(f.request()), (error) => {
      assert.equal(error.code, "PIN_TRANSITION_UNKNOWN");
      assert.equal(error.receipt.status, "unknown");
      assert.equal(error.receipt.ownerRollbackStatus, status);
      assert.equal(error.receipt.ownerPublication, "complete");
      assert.equal(JSON.stringify(error.receipt).includes("private SDK"), false);
      return true;
    });
    assert.equal(f.calls.writes, 1);
  });
}

test("missing committed hash fails closed after one write", async () => {
  const f = fixture();
  f.hooks.missingCommitHash = true;
  await assert.rejects(f.run(f.request()), (error) => error.receipt.status === "unknown");
  assert.equal(f.calls.writes, 1);
});

test("reverse needs original live rollback admission before target/config access", async () => {
  const f = fixture();
  f.unsafeRollback();
  await assert.rejects(
    f.run(f.request({ direction: "reverse" })),
    (error) => error.receipt.status === "refused",
  );
  assert.equal(f.calls.artifactReads, 0);
  assert.equal(f.calls.reads, 0);
});

test("reverse verifies predecessor package and changes only the pin", async () => {
  const f = fixture();
  f.setHash(H1);
  f.edit();
  f.hooks.artifactRead = (absolute) =>
    predecessorBytes.get(path.relative("/synthetic/plugin", absolute));
  const before = f.get();
  const receipt = await f.run(f.request({ direction: "reverse" }));
  assert.equal(receipt.status, "applied");
  before.plugins.entries[ID].config.expectedRuntimeSha256 = H0;
  assert.deepEqual(f.get(), before);
  assert.ok(f.calls.rollbackAdmissions > 1);
  assert.equal(f.calls.backups, 1);
  assert.equal((await f.run(f.request({ direction: "reverse" }))).status, "already-target");
  assert.equal(f.calls.writes, 1);
});

test("replacing rollback callback across await cannot replace original live guard", async () => {
  const f = fixture();
  f.setHash(H1);
  let first = true;
  f.hooks.artifactRead = (absolute) => {
    if (first) {
      first = false;
      f.unsafeRollback();
      f.authority.assertRollbackSafe = () => {};
    }
    return predecessorBytes.get(path.relative("/synthetic/plugin", absolute));
  };
  await assert.rejects(
    f.run(f.request({ direction: "reverse" })),
    (error) => error.receipt.status === "refused",
  );
  assert.equal(f.calls.writes, 0);
  assert.equal(f.calls.reads, 0);
});

for (const field of ["assertCurrent", "assertRollbackSafe"]) {
  test(`async ${field} refuses before artifact/config access`, async () => {
    const f = fixture();
    f.authority[field] = async () => {};
    const run = createInstalledPublisherPinTransition({
      authority: f.authority,
      loadConfigMutation: async () => f.sdk,
      readArtifact: f.readArtifact,
    });
    await assert.rejects(
      run(f.request({ direction: field === "assertRollbackSafe" ? "reverse" : "forward" })),
      (error) => error.receipt.status === "refused",
    );
    assert.equal(f.calls.artifactReads, 0);
    assert.equal(f.calls.reads, 0);
  });
}

for (const change of ["target", "owner"]) {
  test(`post-commit ${change} loss retains unknown outcome without reverse write`, async () => {
    const f = fixture();
    const request = f.request();
    f.hooks.afterCommit = () => {
      if (change === "target") {
        f.hooks.artifactRead = () => Buffer.from("changed");
      } else {
        f.retire();
      }
    };
    await assert.rejects(f.run(request), (error) => {
      assert.equal(error.receipt.status, "unknown");
      assert.equal(error.receipt.inputConfigHash, request.expectedConfigHash);
      assert.equal(error.receipt.committedConfigHash, f.snapshot().hash);
      assert.equal(error.receipt.configHash, f.snapshot().hash);
      assert.equal(error.receipt.mutationAttempted, true);
      return true;
    });
    assert.equal(f.calls.writes, 1);
    assert.equal(f.get().plugins.entries[ID].config.expectedRuntimeSha256, H1);
  });
}

test("read-only default artifact reader binds the actual candidate runtime bytes", async () => {
  const runtime = path.join(packageRoot, "src/runtime.mjs");
  assert.equal(sha(await readPublisherArtifactBytes(runtime)), H1);
});

const backupSource = fs.readFileSync(
  new URL("../../../../../src/config/backup-rotation.ts", import.meta.url),
  "utf8",
);
const stripped = stripTypeScriptTypes(backupSource, { mode: "strip" })
  .replace(/^import[\s\S]*?from\s+["'][^"']+["'];\n/gm, "")
  .replace(/^export (?=(?:async )?(?:const|function))/gm, "");

function backupFixture(fail = {}) {
  const files = new Map();
  const fds = new Map();
  const events = [];
  let next = 10;
  const makeFile = (name, bytes = "original") =>
    files.set(name, { ino: BigInt(next++), bytes, mode: 0o600 });
  const stat = (entry) => ({ dev: 1n, ino: entry.ino, nlink: 1n, isFile: () => true });
  const opened = (name) => {
    if (!files.has(name)) {
      return { ok: false, code: "ENOENT" };
    }
    const fd = next++;
    fds.set(fd, files.get(name));
    return { ok: true, fd, path: name };
  };
  const io = {
    promises: {
      open: async (name) => {
        if (fail.prepare) {
          throw fail.prepare;
        }
        makeFile(name);
        return {
          async writeFile(bytes) {
            files.get(name).bytes = bytes;
          },
          async sync() {
            events.push("file-sync");
            if (fail.fileSync) {
              throw fail.fileSync;
            }
          },
          async [Symbol.asyncDispose]() {},
        };
      },
    },
    fstatSync: (fd) => stat(fds.get(fd)),
    lstatSync: (name) => (files.has(name) ? stat(files.get(name)) : undefined),
    closeSync: (fd) => {
      const kind = fds.get(fd)?.kind;
      fds.delete(fd);
      if (kind === "directory" && fail.close) {
        throw fail.close;
      }
    },
    fchmodSync: (fd, mode) => {
      fds.get(fd).mode = mode;
    },
    renameSync: (from, to) => {
      events.push("rename:" + to);
      if (fail.rename) {
        throw fail.rename;
      }
      files.set(to, files.get(from));
      files.delete(from);
    },
    unlinkSync: (name) => {
      files.delete(name);
    },
    openSync: () => {
      const fd = next++;
      fds.set(fd, { kind: "directory" });
      return fd;
    },
    fsyncSync: () => {
      events.push("directory-sync");
      if (fail.directorySync) {
        throw fail.directorySync;
      }
    },
  };
  class Conflict extends Error {}
  const prepare = vm.compileFunction(stripped + "\nreturn prepareConfigFileWrite;", [
    "path",
    "tempFile",
    "replaceFileAtomicSync",
    "openRootFileSync",
    "isRootFileMissingFailure",
    "createConfigWriteAuthorityGuard",
    "ConfigMutationConflictError",
  ])(
    path,
    async () => ({
      path: "/synthetic/prepared",
      async [Symbol.asyncDispose]() {
        if (fail.cleanup) {
          throw fail.cleanup;
        }
        files.delete("/synthetic/prepared");
      },
    }),
    (options) => {
      options.assertBeforeMutation?.();
      options.beforeRename();
      events.push("config-published");
      return { method: "rename" };
    },
    ({ absolutePath }) =>
      fail.open && absolutePath.endsWith(".bak")
        ? { ok: false, code: "EACCES" }
        : opened(absolutePath),
    (entry) => entry.code === "ENOENT",
    (callback) => () => callback?.(),
    Conflict,
  );
  return { files, fds, events, prepare, io };
}

test("required canonical backup is retained and directory-synced before publication", async () => {
  const f = backupFixture();
  const prepared = await f.prepare({
    configPath: C,
    content: "new",
    previousRaw: "original",
    fsModule: f.io,
    requireBackup: true,
    durable: true,
  });
  prepared.publish();
  await prepared[Symbol.asyncDispose]();
  assert.equal(f.files.get(C + ".bak").bytes, "original");
  assert.equal(f.files.get(C + ".bak").mode, 0o600);
  assert.ok(f.events.indexOf("file-sync") < f.events.indexOf("directory-sync"));
  assert.ok(f.events.indexOf("directory-sync") < f.events.indexOf("config-published"));
  assert.equal(f.fds.size, 0);
});

for (const step of ["prepare", "fileSync", "open", "rename", "directorySync", "close"]) {
  test(`required backup ${step} failure prevents publication`, async () => {
    const f = backupFixture({ [step]: new Error("synthetic_" + step) });
    let prepared;
    try {
      await assert.rejects(async () => {
        prepared = await f.prepare({
          configPath: C,
          content: "new",
          previousRaw: "old",
          fsModule: f.io,
          requireBackup: true,
          durable: true,
        });
        prepared.publish();
      });
      assert.equal(f.events.includes("config-published"), false);
    } finally {
      await prepared?.[Symbol.asyncDispose]();
    }
    assert.equal(f.fds.size, 0);
  });
}

test("required missing config refuses before backup IO", async () => {
  const f = backupFixture();
  await assert.rejects(
    f.prepare({
      configPath: C,
      content: "new",
      previousRaw: null,
      fsModule: f.io,
      requireBackup: true,
    }),
    /no existing source/,
  );
  assert.equal(f.files.size, 0);
});

test("default best-effort preparation behavior is preserved", async () => {
  const f = backupFixture({ prepare: new Error("synthetic_failure") });
  const prepared = await f.prepare({
    configPath: C,
    content: "new",
    previousRaw: "old",
    fsModule: f.io,
  });
  prepared.publish();
  await prepared[Symbol.asyncDispose]();
  assert.ok(f.events.includes("config-published"));
});

for (const [step, cleanup] of [
  ["directorySync", "close"],
  ["prepare", "cleanup"],
]) {
  test(`combined ${step}/${cleanup} retains primary and secondary errors`, async () => {
    const primary = new Error("synthetic_primary");
    const secondary = new Error("synthetic_secondary");
    const f = backupFixture({ [step]: primary, [cleanup]: secondary });
    let prepared;
    try {
      await assert.rejects(
        async () => {
          prepared = await f.prepare({
            configPath: C,
            content: "new",
            previousRaw: "old",
            fsModule: f.io,
            requireBackup: true,
            durable: true,
          });
          prepared.publish();
        },
        (error) =>
          error instanceof AggregateError &&
          error.cause === primary &&
          error.errors[0] === primary &&
          error.errors[1] === secondary,
      );
    } finally {
      await prepared?.[Symbol.asyncDispose]();
    }
    assert.equal(f.events.includes("config-published"), false);
    assert.equal(f.fds.size, 0);
  });
}

for (const capability of [
  undefined,
  {},
  { requireDurableBackup: 0 },
  { requireDurableBackup: true },
]) {
  test(`legacy/unsupported SDK backup capability refuses before config IO (${JSON.stringify(capability)})`, async () => {
    const f = fixture();
    f.sdk.CONFIG_MUTATION_CAPABILITIES = capability;
    await assert.rejects(
      f.run(f.request()),
      (error) =>
        error.code === "PIN_REQUIRED_BACKUP_SDK_UNSUPPORTED" && error.receipt.status === "refused",
    );
    assert.equal(f.calls.reads, 0);
    assert.equal(f.calls.writes, 0);
    assert.equal(f.calls.backups, 0);
  });
}

test("public SDK advertises the exact required-backup contract", () => {
  const source = stripTypeScriptTypes(
    fs.readFileSync(
      new URL("../../../../../src/plugin-sdk/config-mutation.ts", import.meta.url),
      "utf8",
    ),
    { mode: "strip" },
  );
  const definition = source.match(/export const CONFIG_MUTATION_CAPABILITIES = ([\s\S]*?);/);
  assert.ok(definition);
  const capability = vm.runInNewContext(definition[1]);
  assert.equal(capability.requireDurableBackup, 1);
  assert.equal(Object.isFrozen(capability), true);
});
