// Release fixture adapter. SQLite and the existing sandbox manager remain owners.
import type {
  ExecContainerRawOptions,
  SandboxContainerEngine,
} from "../agents/sandbox/container-engine.js";
import type { SandboxRegistryEntry } from "../agents/sandbox/registry.types.js";

type Result = { code: number; stdout: string; stderr: string };
type BindIntent = { source: string; destination: string; readOnly: boolean; options: string };
type FixtureRecord = {
  phase: "armed" | "creating" | "allocated" | "retiring" | "retired" | "held";
  entry?: SandboxRegistryEntry;
  id?: string;
  mountPaths?: string[];
  binds?: BindIntent[];
};
type Dependencies = {
  engine: SandboxContainerEngine;
  execute: (
    engine: SandboxContainerEngine,
    args: string[],
    options?: ExecContainerRawOptions,
  ) => Promise<Result>;
  readEntry: (name: string) => Promise<SandboxRegistryEntry | null | undefined>;
  assertEntry: (entry: SandboxRegistryEntry) => void;
  remove: (
    entry: SandboxRegistryEntry,
    id: string | null,
    assertCurrent: () => void,
  ) => Promise<void>;
  persist: (record: FixtureRecord) => Promise<void>;
  assertEngine: () => Promise<void>;
  assertSettled: (id: string | undefined, mountPaths: string[] | undefined) => Promise<void>;
  now: () => number;
  deadline: (milliseconds: number) => AbortSignal;
};

// Read-only proof before the fixture releases any workspace. Unknown process
// identity, unreadable mountinfo, or a changing engine census retains custody.
export async function assertNativeSandboxMountsSettled(params: {
  id: string;
  mountPaths: string[] | undefined;
  owners: unknown;
  end: number;
  now: () => number;
  deadline: (milliseconds: number) => AbortSignal;
  readDirectory: () => Promise<string[]>;
  readFile: (file: string, signal: AbortSignal) => Promise<string>;
}) {
  const object = (value: unknown): value is { [key: string]: unknown } =>
    value !== null && typeof value === "object" && !Array.isArray(value);
  const owners = params.owners;
  if (
    !/^[a-f0-9]{64}$/u.test(params.id) ||
    !params.mountPaths ||
    params.mountPaths.length < 3 ||
    params.mountPaths.length > 128 ||
    params.mountPaths.some(
      (file) => !file.startsWith("/") || file === "/" || /[\r\n\0]/u.test(file),
    ) ||
    !Array.isArray(owners) ||
    owners.length < 2 ||
    owners.length > 128 ||
    !owners.every(
      (owner: unknown) =>
        object(owner) &&
        typeof owner.pid === "number" &&
        Number.isSafeInteger(owner.pid) &&
        owner.pid > 0 &&
        typeof owner.start === "string" &&
        /^[0-9]+$/u.test(owner.start) &&
        ["dockerd", "containerd"].includes(String(owner.kind)),
    ) ||
    !owners.some((owner) => owner.kind === "dockerd") ||
    !owners.some((owner) => owner.kind === "containerd") ||
    new Set(owners.map((owner) => owner.pid)).size !== owners.length
  ) {
    throw new Error("Native sandbox engine owner admission unavailable; custody retained");
  }
  const mountPaths = params.mountPaths;
  const guard = () => {
    if (params.now() >= params.end) {
      throw new Error("Native sandbox mount settlement deadline exhausted; custody retained");
    }
  };
  const read = async (file: string) => {
    guard();
    const text = await params.readFile(
      file,
      params.deadline(Math.max(1, Math.min(5_000, params.end - params.now()))),
    );
    guard();
    if (text.length > 1_048_576) {
      throw new Error("Native sandbox engine observation exceeds bound; custody retained");
    }
    return text;
  };
  const census = async (mounts: boolean) => {
    guard();
    const directories = await params.readDirectory();
    guard();
    if (directories.length > 16_384) {
      throw new Error("Native sandbox process census exceeds bound; custody retained");
    }
    const found = new Map<number, string>();
    for (const name of directories.filter((name) => /^[0-9]+$/u.test(name))) {
      const pid = Number(name);
      try {
        const argv = await read(`/proc/${pid}/cmdline`);
        const kind = argv.split("\0", 1)[0]?.split("/").at(-1);
        if (!["dockerd", "containerd", "containerd-shim-runc-v2"].includes(kind ?? "")) {
          continue;
        }
        if (argv.length > 8192 || found.size >= 128) {
          throw new Error("Native sandbox engine census exceeds bound; custody retained");
        }
        const identity = async () => {
          const stat = await read(`/proc/${pid}/stat`);
          const start = stat
            .slice(stat.lastIndexOf(") ") + 2)
            .trim()
            .split(/\s+/u)[19];
          if (!start || !/^[0-9]+$/u.test(start)) {
            throw new Error("Native sandbox engine birth identity unavailable; custody retained");
          }
          return `${kind}:${start}`;
        };
        const before = await identity();
        if (mounts) {
          const text = await read(`/proc/${pid}/mountinfo`);
          const escape = (file: string) =>
            file.replace(/\\/gu, "\\134").replace(/ /gu, "\\040").replace(/\t/gu, "\\011");
          if ([params.id, ...mountPaths].some((file) => text.includes(escape(file)))) {
            throw new Error("Native sandbox runtime mounts still present; custody retained");
          }
        }
        if ((await identity()) !== before) {
          throw new Error("Native sandbox engine process changed; custody retained");
        }
        found.set(pid, before);
      } catch (error) {
        if (
          error instanceof Error &&
          "code" in error &&
          error.code === "ENOENT" &&
          !owners.some((owner) => owner.pid === pid)
        ) {
          continue;
        }
        throw error;
      }
    }
    if (owners.some((owner) => found.get(owner.pid) !== `${owner.kind}:${owner.start}`)) {
      throw new Error("Native sandbox engine owner changed; custody retained");
    }
    return found;
  };
  const inspected = await census(true);
  const current = await census(false);
  if (
    inspected.size !== current.size ||
    [...inspected].some(([pid, identity]) => current.get(pid) !== identity)
  ) {
    throw new Error("Native sandbox engine census changed; custody retained");
  }
  guard();
}

export function createNativeSandboxFixture(params: {
  prefix: string;
  workspace: string;
  image: string;
  workEnd: number;
  closureEnd: number;
  dependencies: Dependencies;
}) {
  const d = params.dependencies;
  let record: FixtureRecord = { phase: "armed" };
  let end = params.workEnd;
  let closing = false;
  let created = false;
  let labels: Map<string, string> | undefined;
  let binds: Map<string, BindIntent> | undefined;
  let reconciliationReads = 0;
  let retirement: Promise<void> | undefined;
  let registryRetired = false;
  const guard = () => {
    if (d.now() >= end) {
      throw new Error("Native sandbox owner deadline exhausted; custody retained");
    }
    if (record.entry && !registryRetired) {
      d.assertEntry(record.entry);
    }
  };
  const bounded = async (
    engine: SandboxContainerEngine,
    args: string[],
    options?: ExecContainerRawOptions,
  ) => {
    if (engine.id !== "docker" || engine.command !== "docker" || engine.globalArgs?.length) {
      throw new Error("Native fixture engine differs from admitted local Docker");
    }
    guard();
    const timeout = d.deadline(Math.max(1, Math.min(5_000, end - d.now())));
    const result = await d.execute(engine, args, {
      ...options,
      signal: options?.signal ? AbortSignal.any([options.signal, timeout]) : timeout,
    });
    guard();
    return result;
  };
  const missing = (result: Result) =>
    result.code !== 0 && /no such (?:container|object)|does not exist/iu.test(result.stderr);
  const reconcile = async () => {
    if (!record.entry || ++reconciliationReads > 2) {
      throw new Error("Native sandbox reconciliation allowance exhausted");
    }
    const result = await bounded(d.engine, ["inspect", record.entry.containerName], {
      allowFailure: true,
    });
    if (missing(result)) {
      return null;
    }
    if (result.code !== 0 || result.stdout.length > 65_536) {
      throw new Error("Native sandbox allocation is unconfirmed; custody retained");
    }
    const values: unknown = JSON.parse(result.stdout);
    if (!Array.isArray(values) || values.length !== 1) {
      throw new Error("Native sandbox inspect is ambiguous");
    }
    const value: unknown = values[0];
    const object = (input: unknown): input is { [key: string]: unknown } =>
      input !== null && typeof input === "object" && !Array.isArray(input);
    if (!object(value) || !object(value.Config) || !object(value.Config.Labels)) {
      throw new Error("Native sandbox inspect configuration is missing");
    }
    const configuration = value.Config;
    const capturedLabels = value.Config.Labels;
    if (
      !value ||
      typeof value.Id !== "string" ||
      !/^[a-f0-9]{64}$/u.test(value.Id) ||
      value.Name !== `/${record.entry.containerName}` ||
      configuration.Image !== params.image ||
      !labels ||
      [...labels].some(([key, text]) => capturedLabels[key] !== text) ||
      (record.id && record.id !== value.Id)
    ) {
      throw new Error("Native sandbox physical generation changed; custody retained");
    }
    const graph = value.GraphDriver;
    const data = object(graph) ? graph.Data : undefined;
    const mounts = value.Mounts;
    if (
      !object(graph) ||
      !["overlay2", "overlayfs"].includes(String(graph.Name)) ||
      !object(data) ||
      !["MergedDir", "UpperDir", "WorkDir"].every(
        (key) => typeof data[key] === "string" && data[key].startsWith("/"),
      ) ||
      !Array.isArray(mounts)
    ) {
      throw new Error("Native sandbox physical mount metadata unavailable; custody retained");
    }
    // LowerDir is shared immutable image content. Its presence in another
    // container grants no custody and cannot block this workspace's release.
    const paths = ["MergedDir", "UpperDir", "WorkDir"].map((key) => String(data[key]));
    let workspaceMounts = 0;
    const realized = new Set<string>();
    for (const mount of mounts) {
      if (!object(mount)) {
        throw new Error("Native sandbox realized mount unavailable; custody retained");
      }
      if (mount.Type === "bind" && typeof mount.Destination === "string") {
        const declared = binds?.get(mount.Destination);
        if (
          !declared ||
          realized.has(mount.Destination) ||
          mount.Source !== declared.source ||
          mount.RW !== !declared.readOnly
        ) {
          throw new Error("Native sandbox unrelated realized mount refused; custody retained");
        }
        realized.add(mount.Destination);
        if (!declared.readOnly) {
          ++workspaceMounts;
          paths.push(declared.source);
        }
        // Additional readonly inputs came from this exact owner create plan.
        // Shared input sources grant no deletion or disappearance authority.
      } else if (
        mount.Type !== "tmpfs" ||
        (mount.Source !== undefined && mount.Source !== "") ||
        !["/tmp", "/var/tmp", "/run"].includes(String(mount.Destination))
      ) {
        throw new Error("Native sandbox unrelated realized mount refused; custody retained");
      }
    }
    if (
      workspaceMounts !== 1 ||
      realized.size !== binds?.size ||
      new Set(paths.slice(0, 3)).size !== 3 ||
      paths.length > 128 ||
      paths.some(
        (file) =>
          file.length > 4096 ||
          !file.startsWith("/") ||
          file === "/" ||
          file.split("/").some((part) => part === ".." || part === ".") ||
          /[\r\n\0]/u.test(file),
      )
    ) {
      throw new Error("Native sandbox physical mount paths ambiguous; custody retained");
    }
    record = { ...record, mountPaths: [...new Set(paths)] };
    return value.Id;
  };
  return {
    async arm() {
      await d.assertEngine();
      guard();
      await d.persist(record);
    },
    async execute(
      engine: SandboxContainerEngine,
      args: string[],
      options?: ExecContainerRawOptions,
    ): Promise<Result> {
      if (args[0] === "create") {
        if (closing || created) {
          throw new Error("Native fixture permits one physical allocation only");
        }
        const name = args[args.indexOf("--name") + 1];
        if (
          !args.includes("--name") ||
          typeof name !== "string" ||
          !name.startsWith(params.prefix)
        ) {
          throw new Error("Native fixture allocation name differs");
        }
        const entry = await d.readEntry(name);
        if (
          !entry ||
          entry.runtimeState !== "pending" ||
          entry.backendId !== "docker" ||
          entry.backendTarget ||
          entry.workspaceDir !== params.workspace ||
          entry.image !== params.image ||
          !entry.configHash
        ) {
          throw new Error("Native fixture requires its exact pending registry generation");
        }
        record = { phase: "creating", entry: { ...entry } };
        labels = new Map();
        for (const [index, arg] of args.entries()) {
          if (arg !== "--label") {
            continue;
          }
          const label = args[index + 1];
          if (!label || label.indexOf("=") <= 0) {
            throw new Error("Native fixture allocation label is malformed");
          }
          const equal = label.indexOf("=");
          labels.set(label.slice(0, equal), label.slice(equal + 1));
        }
        if (
          labels.get("openclaw.sessionKey") !== entry.sessionKey ||
          labels.get("openclaw.configHash") !== entry.configHash ||
          !args.includes(params.image)
        ) {
          throw new Error("Native fixture allocation does not match its generation");
        }
        // Consume the existing mount owner plan as emitted by exact docker.ts
        // appendCustomBinds. Never guess its protected skills/resource paths.
        binds = new Map();
        for (const [index, arg] of args.entries()) {
          if (arg !== "-v") {
            continue;
          }
          const [source, destination, mode, extra] = args[index + 1]?.split(":") ?? [];
          const options = mode?.split(",") ?? [];
          const readOnly = options.includes("ro");
          if (
            !source ||
            !destination ||
            extra !== undefined ||
            options.some((option) => !/^[A-Za-z0-9_-]+$/u.test(option)) ||
            (readOnly && options.includes("rw")) ||
            [source, destination].some(
              (file) =>
                !file.startsWith("/") ||
                file === "/" ||
                file.length > 4096 ||
                file.split("/").some((part) => part === ".." || part === ".") ||
                /[\r\n\0]/u.test(file),
            ) ||
            binds.has(destination) ||
            binds.size >= 128 ||
            (!readOnly && (source !== params.workspace || destination !== "/workspace"))
          ) {
            throw new Error("Native fixture owner bind intent differs; allocation refused");
          }
          binds.set(destination, { source, destination, readOnly, options: mode ?? "" });
        }
        const writable = binds.get("/workspace");
        if (!writable || writable.source !== params.workspace || writable.readOnly) {
          throw new Error("Native fixture owner workspace bind missing; allocation refused");
        }
        record = { ...record, binds: [...binds.values()] };
        await d.assertEngine();
        guard();
        // Fresh absence plus the captured create intent permits reconciliation if
        // the CLI loses its response after the engine accepted this one request.
        const absent = await bounded(engine, ["inspect", "-f", "{{.Id}}", name], {
          allowFailure: true,
        });
        if (!missing(absent)) {
          throw new Error("Native fixture name already exists; allocation refused");
        }
        created = true;
        await d.persist(record);
        const result = await bounded(engine, args, options);
        const id = result.stdout.trim();
        if (result.code !== 0 || !/^[a-f0-9]{64}$/u.test(id)) {
          throw new Error("Native fixture allocation ID unconfirmed; custody retained");
        }
        record = { ...record, phase: "allocated", id };
        await d.persist(record);
        return result;
      }
      if (closing && ["start", "exec", "create"].some((command) => command === args[0])) {
        throw new Error("Native fixture is retiring; new work refused");
      }
      // Other sandbox owners still execute their real reads/operations. This
      // adapter never selects them for retirement or grants name-based custody.
      return await bounded(engine, args, options);
    },
    retire(): Promise<void> {
      return (retirement ??= (async () => {
        closing = true;
        end = Math.min(params.closureEnd, d.now() + 120_000);
        try {
          await d.assertEngine();
          if (record.entry && created) {
            const captured = record.entry;
            guard();
            // The real owner publishes pending -> ready. Re-admit that same
            // creation identity before passing its current row to retirement.
            const entry = await d.readEntry(captured.containerName);
            if (!entry) {
              throw new Error("Native sandbox registry generation missing; custody retained");
            }
            const identity = (row: SandboxRegistryEntry) => {
              const { lastUsedAtMs: _lastUsed, runtimeState: _state, ...fields } = row;
              return JSON.stringify(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b)));
            };
            if (
              identity(entry) !== identity(captured) ||
              ![undefined, "pending", "ready"].includes(entry.runtimeState)
            ) {
              throw new Error("Native sandbox registry generation changed; custody retained");
            }
            d.assertEntry(entry);
            record = { ...record, entry: { ...entry } };
            guard();
            record = { ...record, phase: "retiring" };
            await d.persist(record);
            const id = await reconcile();
            if (!id && !record.id) {
              throw new Error("Unconfirmed create has no settled physical ID; custody retained");
            }
            if (id) {
              record = { ...record, id };
              await d.persist(record);
            }
            if (!record.mountPaths?.length) {
              throw new Error("Native sandbox mount custody unknown; registry retained");
            }
            await d.remove(entry, id ?? record.id ?? null, guard);
            registryRetired = true;
            // The manager checks name absence and removes only this generation.
            // Independently check the physical ID and registry after it returns.
            if (record.id) {
              const absent = await bounded(d.engine, ["inspect", "-f", "{{.Id}}", record.id], {
                allowFailure: true,
              });
              if (!missing(absent)) {
                throw new Error("Native sandbox physical retirement unconfirmed");
              }
            }
            if (await d.readEntry(entry.containerName)) {
              throw new Error("Native sandbox registry retirement unconfirmed");
            }
            await d.assertSettled(record.id, record.mountPaths);
          } else if (record.entry) {
            throw new Error("Native allocation admission failed; registry custody retained");
          }
          record = { ...record, phase: "retired" };
          if (d.now() >= end) {
            throw new Error("Native sandbox retirement exceeded its deadline");
          }
          await d.persist(record);
        } catch (error) {
          record = { ...record, phase: "held" };
          await d.persist(record);
          throw error;
        }
      })());
    },
  };
}
