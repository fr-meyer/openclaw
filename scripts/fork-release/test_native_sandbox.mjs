import assert from "node:assert/strict";
import test from "node:test";
import {
  assertNativeSandboxMountsSettled,
  createNativeSandboxFixture,
} from "../../src/gateway/native-sandbox.test-support.ts";

const ID = "a".repeat(64);
const FOREIGN = "b".repeat(64);
const image = "sha256:" + "c".repeat(64);
function fixture() {
  const entry = {
    containerName: "native-one",
    backendId: "docker",
    sessionKey: "one",
    createdAtMs: 1,
    lastUsedAtMs: 1,
    workspaceDir: "/owned/work",
    image,
    configHash: "hash",
    runtimeState: "pending",
  };
  const calls = [],
    records = [],
    containers = new Map([[FOREIGN, { Id: FOREIGN }]]);
  const state = {
    entry,
    now: 0,
    createFailure: false,
    removeFailure: false,
    settled: true,
    removals: 0,
    timeout: false,
    signals: [],
  };
  const engine = { id: "docker", command: "docker", displayName: "Docker" };
  const args = [
    "create",
    "--name",
    entry.containerName,
    "--label",
    "openclaw.sessionKey=one",
    "--label",
    "openclaw.configHash=hash",
    "-v",
    "/owned/work:/workspace:rw",
    image,
  ];
  const owner = createNativeSandboxFixture({
    prefix: "native-",
    workspace: "/owned/work",
    image,
    workEnd: 120_000,
    closureEnd: 240_000,
    dependencies: {
      engine,
      now: () => state.now,
      deadline: (ms) => {
        assert(ms > 0 && ms <= 5_000);
        return new AbortController().signal;
      },
      assertEngine: async () => {},
      readEntry: async () => state.entry,
      assertEntry: (captured) => {
        if (state.entry?.createdAtMs !== captured.createdAtMs) {
          throw new Error("generation changed");
        }
      },
      persist: async (record) => {
        records.push(structuredClone(record));
      },
      execute: async (_engine, command, options) => {
        calls.push(command);
        state.signals.push(options.signal);
        if (options.signal.aborted) {
          throw new Error("cancelled");
        }
        if (command[0] === "create") {
          containers.set(ID, {
            Id: ID,
            Image: image,
            Name: "/native-one",
            Config: {
              Image: image,
              Labels: { "openclaw.sessionKey": "one", "openclaw.configHash": "hash" },
            },
            GraphDriver: {
              Name: "overlay2",
              Data: {
                MergedDir: "/engine/selected-layer/merged",
                UpperDir: "/engine/selected-layer/diff",
                WorkDir: "/engine/selected-layer/work",
                LowerDir: "/engine/shared-image/diff",
              },
            },
            Mounts: [{ Type: "bind", Source: "/owned/work", Destination: "/workspace", RW: true }],
          });
          if (state.createFailure) {
            throw new Error("create response lost");
          }
          if (state.timeout) {
            state.now = 120_001;
          }
          return { code: 0, stdout: ID, stderr: "" };
        }
        if (command[0] === "inspect") {
          const found = [...containers.values()].find(
            (c) => c.Id === command.at(-1) || c.Name === "/" + command.at(-1),
          );
          return found
            ? { code: 0, stdout: JSON.stringify([found]), stderr: "" }
            : { code: 1, stdout: "", stderr: "No such container" };
        }
        return { code: 0, stdout: "", stderr: "" };
      },
      remove: async (captured, id, guard) => {
        guard();
        if (state.removeFailure) {
          throw new Error("removal denied");
        }
        assert.equal(captured.containerName, "native-one");
        const { lastUsedAtMs: _capturedUse, ...expected } = captured;
        const { lastUsedAtMs: _currentUse, ...current } = state.entry;
        // Match exact registry.ts generation equality, including runtimeState.
        assert.deepEqual(expected, current);
        if (id !== null) {
          assert.equal(id, ID);
        }
        ++state.removals;
        containers.delete(id);
        state.entry = null;
      },
      assertSettled: async () => {
        if (!state.settled) {
          throw new Error("writers still present");
        }
      },
    },
  });
  return { owner, state, engine, args, records, calls, containers };
}

test("real owner response is forwarded; retirement is exact, once, and preserves foreign resources", async () => {
  const f = fixture();
  await f.owner.arm();
  assert.equal((await f.owner.execute(f.engine, f.args)).stdout, ID);
  assert.equal(f.records[1].phase, "creating");
  assert.equal(f.records[2].id, ID);
  await f.owner.retire();
  await f.owner.retire();
  assert.equal(f.state.removals, 1);
  assert.deepEqual([...f.containers.keys()], [FOREIGN]);
  assert.equal(f.records.at(-1).phase, "retired");
  assert(f.state.signals.every((signal) => signal instanceof AbortSignal));
});

test("lost create response is reconciled from the captured intent before exact retirement", async () => {
  const f = fixture();
  await f.owner.arm();
  f.state.createFailure = true;
  await assert.rejects(f.owner.execute(f.engine, f.args), /response lost/);
  assert.equal(f.records.at(-1).phase, "creating");
  assert.equal(f.records.at(-1).id, undefined);
  await f.owner.retire();
  assert.equal(f.state.removals, 1);
  assert.equal(f.records.at(-1).id, ID);
  assert(f.containers.has(FOREIGN));
});

test("pending publication advances to ready without losing exact retirement custody", async () => {
  const f = fixture();
  await f.owner.arm();
  await f.owner.execute(f.engine, f.args);
  f.state.entry = { ...f.state.entry, runtimeState: "ready", lastUsedAtMs: 2 };
  await f.owner.retire();
  assert.equal(f.state.removals, 1);
  assert.equal(f.records.at(-1).entry.runtimeState, "ready");
  assert.equal(f.state.entry, null);
  assert.equal(f.records.at(-1).phase, "retired");
});

test("refresh refuses changed creation facts and removal intent before physical deletion", async () => {
  for (const changed of [{ configHash: "replacement" }, { runtimeState: "removing" }]) {
    const f = fixture();
    await f.owner.arm();
    await f.owner.execute(f.engine, f.args);
    f.state.entry = { ...f.state.entry, ...changed };
    await assert.rejects(f.owner.retire(), /generation changed/);
    assert.equal(f.state.removals, 0);
    assert(f.containers.has(ID));
    assert.equal(f.records.at(-1).phase, "held");
  }
});

test("physical mount capture refuses unknown graphs and unrelated sources before removal", async () => {
  for (const kind of ["graph", "foreign"]) {
    const f = fixture();
    await f.owner.arm();
    await f.owner.execute(f.engine, f.args);
    if (kind === "graph") {
      delete f.containers.get(ID).GraphDriver;
    } else {
      f.containers.get(ID).Mounts.push({ Type: "bind", Source: "/foreign/work" });
    }
    await assert.rejects(f.owner.retire(), /mount metadata unavailable|unrelated realized mount/);
    assert.equal(f.state.removals, 0);
    assert(f.containers.has(ID));
    assert.equal(f.records.at(-1).phase, "held");
  }
  const f = fixture();
  await f.owner.arm();
  await f.owner.execute(f.engine, f.args);
  await f.owner.retire();
  assert(f.records.at(-1).mountPaths.includes("/engine/selected-layer/merged"));
  assert(!f.records.at(-1).mountPaths.includes("/engine/shared-image/diff"));
});

test("captured protected readonly inputs are admitted and shared sources are preserved", async () => {
  const f = fixture();
  f.args.splice(-1, 0, "-v", "/protected/skills:/workspace/skills:ro");
  await f.owner.arm();
  await f.owner.execute(f.engine, f.args);
  f.containers.get(ID).Mounts.push({
    Type: "bind",
    Source: "/protected/skills",
    Destination: "/workspace/skills",
    RW: false,
  });
  await f.owner.retire();
  assert.equal(f.records.at(-1).phase, "retired");
  assert(f.records.at(-1).binds.some((bind) => bind.source === "/protected/skills"));
  assert(!f.records.at(-1).mountPaths.includes("/protected/skills"));
  assert(f.containers.has(FOREIGN));
  for (const kind of ["source", "mode", "missing"]) {
    const changed = fixture();
    changed.args.splice(-1, 0, "-v", "/protected/skills:/workspace/skills:ro");
    await changed.owner.arm();
    await changed.owner.execute(changed.engine, changed.args);
    if (kind !== "missing") {
      changed.containers.get(ID).Mounts.push({
        Type: "bind",
        Source: kind === "source" ? "/foreign/skills" : "/protected/skills",
        Destination: "/workspace/skills",
        RW: kind === "mode",
      });
    }
    await assert.rejects(changed.owner.retire(), /unrelated realized mount|mount paths ambiguous/);
    assert.equal(changed.state.removals, 0);
    assert.equal(changed.records.at(-1).phase, "held");
  }
});

test("owner-selected comma options and default writable mode are consumed without changing create", async () => {
  for (const primary of ["/owned/work:/workspace:z", "/owned/work:/workspace"]) {
    const f = fixture();
    f.args[f.args.indexOf("-v") + 1] = primary;
    f.args.splice(-1, 0, "-v", "/protected/skills:/workspace/skills:ro,z");
    const intended = [...f.args];
    await f.owner.arm();
    await f.owner.execute(f.engine, f.args);
    f.containers.get(ID).Mounts.push({
      Type: "bind",
      Source: "/protected/skills",
      Destination: "/workspace/skills",
      RW: false,
    });
    await f.owner.retire();
    assert.deepEqual(
      f.calls.find((args) => args[0] === "create"),
      intended,
    );
    assert.equal(f.records.at(-1).phase, "retired");
    assert.equal(f.records.at(-1).binds.find((bind) => bind.readOnly).options, "ro,z");
  }
});

test("cancelled start retains allocated custody and can retire the exact generation", async () => {
  const f = fixture();
  await f.owner.arm();
  await f.owner.execute(f.engine, f.args);
  const cancel = new AbortController();
  cancel.abort();
  await assert.rejects(
    f.owner.execute(f.engine, ["start", ID], { signal: cancel.signal }),
    /cancelled/,
  );
  assert.equal(f.records.at(-1).phase, "allocated");
  await f.owner.retire();
  assert.equal(f.state.removals, 1);
});

test("an uncertain create with current absence keeps its registry intent and never retries", async () => {
  const f = fixture();
  await f.owner.arm();
  f.state.createFailure = true;
  await assert.rejects(f.owner.execute(f.engine, f.args), /response lost/);
  f.containers.delete(ID);
  await assert.rejects(f.owner.retire(), /no settled physical ID/);
  assert.equal(f.state.removals, 0);
  assert(f.state.entry);
  assert.equal(f.records.at(-1).phase, "held");
  assert(f.containers.has(FOREIGN));
});

test("work timeout leaves a reconciliable partial generation; closure has a separate bound", async () => {
  const f = fixture();
  await f.owner.arm();
  f.state.timeout = true;
  await assert.rejects(f.owner.execute(f.engine, f.args), /deadline/);
  await f.owner.retire();
  assert.equal(f.records.at(-1).phase, "retired");
  const late = fixture();
  await late.owner.arm();
  late.state.now = 240_001;
  await assert.rejects(late.owner.retire(), /deadline/);
  assert.equal(late.records.at(-1).phase, "held");
});

test("changed registry/physical/image generations are retained without removing replacements", async () => {
  for (const kind of ["registry", "physical", "image"]) {
    const f = fixture();
    await f.owner.arm();
    await f.owner.execute(f.engine, f.args);
    if (kind === "registry") {
      f.state.entry = { ...f.state.entry, createdAtMs: 2 };
    } else if (kind === "physical") {
      f.containers.set(ID, { ...f.containers.get(ID), Id: FOREIGN });
    } else {
      f.containers.get(ID).Image = "sha256:" + "d".repeat(64);
    }
    await assert.rejects(f.owner.retire(), /generation changed/);
    assert.equal(f.state.removals, 0);
    assert.equal(f.records.at(-1).phase, "held");
    assert(f.containers.has(FOREIGN));
  }
});

test("failed removal and unsettled writers never publish retired or retry the mutation", async () => {
  for (const kind of ["remove", "settlement"]) {
    const f = fixture();
    await f.owner.arm();
    await f.owner.execute(f.engine, f.args);
    if (kind === "remove") {
      f.state.removeFailure = true;
    } else {
      f.state.settled = false;
    }
    await assert.rejects(f.owner.retire(), /removal denied|writers still present/);
    const before = f.state.removals;
    await assert.rejects(f.owner.retire());
    assert.equal(f.state.removals, before);
    assert.equal(f.records.at(-1).phase, "held");
    assert(f.containers.has(FOREIGN));
    if (kind === "remove") {
      assert(f.containers.has(ID));
    }
  }
});

test("pre-existing names, second allocation, and post-retirement work are refused", async () => {
  const f = fixture();
  await f.owner.arm();
  f.containers.set(ID, { Id: ID, Name: "/native-one" });
  await assert.rejects(f.owner.execute(f.engine, f.args), /already exists/);
  assert.equal(f.calls.filter((command) => command[0] === "create").length, 0);
  const fresh = fixture();
  await fresh.owner.arm();
  await fresh.owner.execute(fresh.engine, fresh.args);
  await assert.rejects(fresh.owner.execute(fresh.engine, fresh.args), /one physical/);
  await fresh.owner.retire();
  await assert.rejects(fresh.owner.execute(fresh.engine, ["start", ID]), /new work refused/);
});

function mounts() {
  const owners = [
    { pid: 1, kind: "dockerd", start: "10" },
    { pid: 2, kind: "containerd", start: "20" },
  ];
  const state = { mounted: false, graphMounted: false, changed: false, unread: false, now: 0 };
  return {
    state,
    params: {
      id: ID,
      mountPaths: ["/engine/selected-layer/merged", "/engine/selected-layer/diff", "/owned/work"],
      owners,
      end: 100,
      now: () => state.now,
      deadline: () => new AbortController().signal,
      readDirectory: async () => ["self", "1", "2"],
      readFile: async (file) => {
        const [, , pid, kind] = file.split("/");
        const owner = owners.find((owner) => String(owner.pid) === pid);
        if (kind === "cmdline") {
          return `/usr/bin/${owner.kind}\0`;
        }
        if (kind === "stat") {
          return `${pid} (${owner.kind}) ${Array(19).fill("0").join(" ")} ${state.changed ? "99" : owner.start}`;
        }
        if (state.unread) {
          throw new Error("mountinfo unreadable");
        }
        if (state.mounted) {
          return `/engine/runtime/${ID}/mounts`;
        }
        return state.graphMounted
          ? "/engine/selected-layer/merged active"
          : "/engine/shared-image/diff unrelated retained mount";
      },
    },
  };
}

test("workspace mount proof requires admitted daemons and settled engine mounts", async () => {
  const f = mounts();
  await assertNativeSandboxMountsSettled(f.params);
  f.state.mounted = true;
  await assert.rejects(assertNativeSandboxMountsSettled(f.params), /mounts still present/);
  f.state.mounted = false;
  f.state.graphMounted = true;
  await assert.rejects(assertNativeSandboxMountsSettled(f.params), /mounts still present/);
});

test("unknown mount settlement and replaced daemons keep workspace custody", async () => {
  for (const kind of ["unread", "changed"]) {
    const f = mounts();
    f.state[kind] = true;
    await assert.rejects(assertNativeSandboxMountsSettled(f.params), /unreadable|owner changed/);
  }
});

test("mount proof refuses missing admission and exhausted closure before reading", async () => {
  const f = mounts();
  await assert.rejects(
    assertNativeSandboxMountsSettled({ ...f.params, owners: undefined }),
    /admission unavailable/,
  );
  f.state.now = 100;
  await assert.rejects(assertNativeSandboxMountsSettled(f.params), /deadline exhausted/);
});
