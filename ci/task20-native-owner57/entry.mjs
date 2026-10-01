import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createInterface } from "node:readline";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const input = createInterface({ input: process.stdin });
const queued = [];
let pending;
let closed = false;
let received = 0;
input.on("line", (value) => {
  if (++received > 3 || !["TASK20_GO", "TASK20_ACTOR_GO", "TASK20_CLOSE"].includes(value)) {
    throw new Error("fixture control protocol mismatch");
  }
  if (pending) pending(value);
  else queued.push(value);
});
input.on("close", () => {
  closed = true;
  if (pending) pending(undefined);
});
async function receive(expected) {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("fixture admission/close timeout")), 10_000);
    function finish(error) {
      clearTimeout(timer);
      pending = undefined;
      error ? reject(error) : resolve();
    }
    const accept = (value) => finish(value === expected ? undefined : new Error("fixture admission/close mismatch or EOF"));
    if (queued.length) accept(queued.shift());
    else if (closed) accept(undefined);
    else pending = accept;
  });
}

// Observed diagnostics confer no admission; all identity and confinement assertions still follow.
console.log("TASK20_RUNTIME_OBSERVED " + JSON.stringify({ version: process.version, versions: process.versions,
  platform: process.platform, architecture: process.arch, uid: process.getuid(), gid: process.getgid(),
  nodeOptionsPresent: process.env.NODE_OPTIONS !== undefined }));
assert.equal(process.version, "v24.19.0");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.versions.modules, "137");
assert.equal(process.versions.napi, "10");
assert.equal(process.versions.v8, "13.6.233.17-node.51");
assert.equal(process.versions.sqlite, "3.53.3");
const libc = process.report.getReport().header.glibcVersionRuntime;
assert.equal(libc, "2.36");
assert.equal(process.getuid(), 1000);
assert.equal(process.getgid(), 1000);
assert.equal(process.env.NODE_OPTIONS, undefined);
const status = Object.fromEntries(fs.readFileSync("/proc/self/status", "utf8").trim().split("\n").map((line) => {
  const index = line.indexOf(":");
  return [line.slice(0, index), line.slice(index + 1).trim()];
}));
assert.equal(status.NoNewPrivs, "1");
assert.equal(BigInt("0x" + status.CapEff), 0n);
assert.equal(BigInt("0x" + status.CapBnd), 0n);
const mounts = fs.readFileSync("/proc/self/mountinfo", "utf8").trim().split("\n").map((line) => {
  const fields = line.split(" ");
  return { target: fields[4], options: fields[5].split(","), filesystem: fields[fields.indexOf("-") + 1] };
});
for (const target of ["/", "/work", "/entry.mjs", "/watchdog.mjs", "/dev/shm", "/dev/mqueue"]) {
  assert.ok(mounts.some((mount) => mount.target === target && mount.options.includes("ro")), target);
}
assert.ok(mounts.some((mount) => mount.target === "/fixture" && mount.filesystem === "tmpfs" &&
  ["rw", "nosuid", "nodev", "noexec"].every((option) => mount.options.includes(option))));
assert.throws(() => fs.accessSync("/dev", fs.constants.W_OK));
const capacity = fs.statfsSync("/fixture", { bigint: true });
assert.equal(capacity.bsize * capacity.blocks, 16n * 1024n * 1024n);
assert.equal(fs.statSync("/fixture").uid, 1000);
assert.equal(fs.statSync("/fixture").gid, 1000);
console.log("TASK20_CONFINEMENT " + JSON.stringify({ noNewPrivileges: true, effectiveCapabilities: "0",
  boundingCapabilities: "0", fixtureCapacityBytes: Number(capacity.bsize * capacity.blocks), mounts }));
const fd = fs.openSync(process.execPath, "r");
const hash = crypto.createHash("sha256");
const buffer = Buffer.alloc(1024 * 1024);
let bytes = 0;
try {
  for (;;) {
    const count = fs.readSync(fd, buffer);
    if (!count) break;
    bytes += count;
    hash.update(buffer.subarray(0, count));
  }
} finally {
  fs.closeSync(fd);
}
console.log("TASK20_RUNTIME " + JSON.stringify({ version: process.version, versions: process.versions,
  architecture: process.arch, glibcVersionRuntime: libc, nodeBytes: bytes, nodeSha256: hash.digest("hex"),
  uid: process.getuid(), gid: process.getgid(), nodeOptions: null }));
// Original native owner imports remain behind external resource/confinement admission.
const admitted = receive("TASK20_GO");
console.log("TASK20_READY " + JSON.stringify({ phase: "ADMISSION_WAIT_NATIVE_OWNER_NOT_IMPORTED" }));
await admitted;
const manifest = JSON.parse(fs.readFileSync("/work/control/actor-manifest.json", "utf8"));
const sha = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const within = (root, file) => { const rel=path.relative(root,file); return rel==="" || !rel.startsWith("..") && !path.isAbsolute(rel); };
const stateRoot=fs.realpathSync("/fixture"), sourceRoot=fs.realpathSync("/work/source");
const allowedEnv=new Set(["PATH","HOSTNAME","NODE_VERSION","YARN_VERSION","HOME","TMPDIR","LANG",
  "TSX_TSCONFIG_PATH","TSX_DISABLE_CACHE","OPENCLAW_STATE_DIR","OPENCLAW_CONFIG_PATH"]);
for(const key of Object.keys(process.env))assert(allowedEnv.has(key),"Unexpected fixture environment key: "+key);
for(const [key,value] of Object.entries(manifest.runtimeEnvironment))assert.equal(process.env[key],value,key);
assert.equal(process.env.HOME,stateRoot);assert.equal(process.env.TMPDIR,stateRoot);
assert.equal(process.env.TSX_TSCONFIG_PATH,"/work/source/tsconfig.json");
const sourceMap={};
for(const row of manifest.sourceOverlays) {
  const file=fs.realpathSync(path.join(sourceRoot,row.path));assert(within(sourceRoot,file));
  assert.equal(fs.statSync(file).size,row.bytes);assert.equal(sha(file),row.sha256,row.path);
  sourceMap[row.path]=row.sha256;
}
assert.equal(Object.keys(sourceMap).length,57);
// Python default json.dumps spaces are part of the original owner map recipe.
const pythonJson="{"+Object.keys(sourceMap).sort().map(key=>JSON.stringify(key)+": "+JSON.stringify(sourceMap[key])).join(", ")+"}";
assert.equal(crypto.createHash("sha256").update(pythonJson).digest("hex"),manifest.sourceMapRevision);
for(const [relative,row] of Object.entries(manifest.sourceGraphFiles)) {
  const file=fs.realpathSync(path.join(sourceRoot,relative));assert(within(sourceRoot,file));
  assert.equal(fs.statSync(file).size,row.bytes);assert.equal(sha(file),row.sha256,relative);
}
// Resolver-only probes sit beside the original importer and use the actual stock
// tsx chain. They do not import their resolved application or package targets.
const probes=new Map();
async function originalResolve(row) {
  const directory=path.posix.dirname(row.parent);
  const file=fs.realpathSync(path.join(sourceRoot,directory,manifest.resolverProbe.filename));
  assert(within(sourceRoot,file));assert.equal(sha(file),manifest.resolverProbe.sha256);
  let probe=probes.get(directory);
  if(!probe){probe=await import(pathToFileURL(file).href);assert.equal(typeof probe.resolveOriginalContext,"function");probes.set(directory,probe);}
  const url=probe.resolveOriginalContext(row.specifier);assert.equal(new URL(url).protocol,"file:");
  return fs.realpathSync(fileURLToPath(url));
}
const exportBindings=[];
for(const row of manifest.sourceBareBindings) {
  const expected=row.expected, physical=await originalResolve(row);
  assert.equal(physical,fs.realpathSync(path.join("/work",expected.target)),row.specifier+" exact export target");
  assert.equal(sha(physical),expected.sha256);
  const packageFile=path.join("/work",expected.root,"package.json");
  assert.equal(sha(packageFile),expected.packageJsonSha256);
  const pkg=JSON.parse(fs.readFileSync(packageFile,"utf8"));assert.equal(pkg.name,expected.name);assert.equal(pkg.version,expected.version);
  const root=manifest.roots.find(r=>r.path===expected.root);
  assert(root);assert.equal(root.snapshot,expected.snapshot);assert.equal(root.integrity,expected.integrity);
  for(const peer of expected.peerLinks)assert.equal(fs.realpathSync(path.join("/work",peer.path)),fs.realpathSync(path.join("/work",peer.target)));
  exportBindings.push({specifier:row.specifier,parent:row.parent,target:expected.target,sha256:sha(physical),
    snapshot:expected.snapshot,integrity:expected.integrity,packageJsonSha256:expected.packageJsonSha256,peerLinksVerified:expected.peerLinks.length});
}
const aliasBindings=[];
for(const row of manifest.sourceAliases) {
  const physical=await originalResolve(row);
  assert.equal(physical,fs.realpathSync(path.join(sourceRoot,row.target)),row.specifier+" actual stock tsx alias");
  assert.equal(sha(physical),manifest.sourceGraphFiles[row.target].sha256);
  aliasBindings.push({parent:row.parent,specifier:row.specifier,target:row.target,sha256:sha(physical)});
}
for(const relative of [...manifest.requiredOperationClosure.computedWorkerEntries,
  manifest.requiredOperationClosure.lazySharedStore,manifest.requiredOperationClosure.backendRuntime]) {
  assert(manifest.sourceGraphFiles[relative],"required native worker/source owner is not bound");
}
assert.deepEqual(manifest.requiredOperationClosure.loaderExports,["tsx","tsx/esm","tsx/esm/api"]);
for(const specifier of manifest.requiredOperationClosure.loaderExports)assert(exportBindings.some(r=>r.specifier===specifier));
const moduleBindings={};
const nativeExports={writer:"createAuditEventWriter",writerKernel:"executeAuditWriterCommand",scheduler:"GatewayScheduler",
  context:"captureOpenClawStateWorkerContext",database:"openOpenClawStateDatabase",cache:"closeOpenClawStateDatabaseByPathAsync",
  owner:"getOpenClawStateWorkerOwner",store:"getSqliteWorkerActorIdentity",paths:"resolveOpenClawStateSqlitePath",readKernel:"listAuditEventsInDatabase"};
for(const [name,row] of Object.entries(manifest.modules)) {
  const physicalPath=fs.realpathSync(path.join(sourceRoot,row.relativePath));assert(within(sourceRoot,physicalPath));
  assert.equal(sha(physicalPath),row.loadedSha256,name);
  moduleBindings[name]=Object.freeze({nativeCommit:manifest.nativeCommit,physicalPath,loadedSha256:row.loadedSha256});
}
// Stock tsx and its pinned paths perform source alias resolution. No custom hook,
// substitute compiler, Worker or transformed application fixture is introduced.
for(const [name,expected] of Object.entries(nativeExports)) {
  const native=await import(pathToFileURL(moduleBindings[name].physicalPath).href);
  assert.equal(typeof native[expected],"function",name+" original native export");
}
console.log("TASK20_SOURCE_BINDINGS "+JSON.stringify({sourceMapRevision:manifest.sourceMapRevision,
  ownerPostimages:57,eagerSourceFiles:Object.keys(manifest.sourceGraphFiles).length,
  packageExportBindings:exportBindings,sourceAliasBindings:aliasBindings,originalEntryExports:10,
  requiredOperationClosure:manifest.requiredOperationClosure,operationClosureBound:true,
  resolverProbeDirectoriesVerified:probes.size,
  publishedOrCompiledGraphQualified:false,privateIssuerQualified:false}));
const fixture="/work/fixture-source/native-owned-receipt-fixture.mjs";
assert.equal(sha(fixture),manifest.fixtureFiles[0].sha256);
const {runOriginalNativeAuditReceiptFixture}=await import(pathToFileURL(fixture).href);
// The same 120s/30CPU budget continues across warm imports. An independent
// host observer must freshly admit the actor immediately before the DB fixture.
const actorAdmitted=receive("TASK20_ACTOR_GO");
console.log("TASK20_BINDINGS_READY "+JSON.stringify({sourceMapRevision:manifest.sourceMapRevision,
  phase:"OPERATION_BINDINGS_VERIFIED_DATABASE_FIXTURE_NOT_INVOKED"}));
await actorAdmitted;
const eligibility=Object.freeze({status:"SOURCE_FIXTURE_EXECUTION_ADMITTED",nativeCommit:manifest.nativeCommit,
 runtimeRoot:sourceRoot,fixtureRoot:stateRoot,modules:Object.freeze(moduleBindings),fixtureEnvironment:Object.freeze({...process.env}),
 completeRuntimeClosureVerified:true,moduleSourceArtifactJoinVerified:true,allPackageExportBindingsVerified:true,
 sameRuntimeManifestVerified:true,isolatedEnvironmentAndWritesVerified:true,resourceAdmissionFresh:true,
 fixtureEnvironmentHasNoCredentials:true,requiredCandidateManifestVerified:true,
 dispatchAllowed:false,providerCallsAllowed:false,workerFaultsAllowed:false});
const result=await runOriginalNativeAuditReceiptFixture(eligibility);
assert.deepEqual(result.checks,manifest.expectedScope.orderedCheckNames);

console.log("TASK20_COMPONENT " + JSON.stringify(result));
const cpu = Object.fromEntries(fs.readFileSync("/sys/fs/cgroup/cpu.stat", "utf8").trim().split("\n").map((line) => line.split(/\s+/u)));
const events = Object.fromEntries(fs.readFileSync("/sys/fs/cgroup/memory.events", "utf8").trim().split("\n").map((line) => line.split(/\s+/u)));
console.log("TASK20_FINAL_COUNTERS " + JSON.stringify({ cpuSeconds: Number(cpu.usage_usec) / 1e6,
  peakMemoryBytes: Number(fs.readFileSync("/sys/fs/cgroup/memory.peak", "utf8")),
  oom: Number(events.oom), oomKill: Number(events.oom_kill),
  fixtureUsedBytes: Number(fs.statfsSync("/fixture", { bigint: true }).bsize *
    (fs.statfsSync("/fixture", { bigint: true }).blocks - fs.statfsSync("/fixture", { bigint: true }).bfree)) }));
await receive("TASK20_CLOSE");
input.close();
