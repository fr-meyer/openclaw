// Small task-owned filesystem fixtures only. No native owner, package manager, tar parser, build or network execution.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { validateTarEntries, inventory, mergeDependencies, validateBuildReceipt, completeRunnablePackageLifecycle } from './materialize.mjs';
const contract = JSON.parse(fs.readFileSync(new URL('./contract.json', import.meta.url)));
let checks = 0;
function check(fn) { fn(); checks++; }
const file = (name, bytes = 1) => ({ path: name, type: 'File', size: bytes });
const dir = name => ({ path: name, type: 'Directory', size: 0 });
const link = (name, target) => ({ path: name, type: 'SymbolicLink', linkpath: target, size: 0 });
check(() => assert.deepEqual(validateTarEntries([dir('package'), file('package/a'), link('package/b', 'a')], 5), { total: 1, files: 1 }));
for (const entries of [[file('/package/a')], [file('package/../a')], [file('package/a\\b')], [file('package//a')], [file('package/a'), file('package/a')], [{ ...file('package/a'), type: 'Link' }], [{ ...file('package/a'), size: -1 }], [{ ...file('package/a'), size: NaN }], [{ ...file('package/a'), path: null }], [link('package/a', '/tmp/a')], [link('package/a', '../../a')], [link('package/a', 'missing')], [link('package/a', 'b'), link('package/b', 'a')], [link('package/a', 'b'), file('package/a/sub'), file('package/b')]]) check(() => assert.throws(() => validateTarEntries(entries, 8)));
check(() => assert.throws(() => validateTarEntries([file('package/a', 9)], 8), /cap/));
const build = { complete: true, source_commit: contract.source_commit, source_tree: contract.source_tree, targeted_test_argv: contract.targeted_test_argv, compile_argv: contract.compile_argv, environment: contract.compile_environment, job: '1-1', commands: [['corepack', contract.packageManager, ...contract.install_argv], ...contract.targeted_test_argv, ...contract.compile_argv].map(argv => ({argv, code:0, signal:null})) };
check(() => validateBuildReceipt(build, contract, '1-1'));
for (const broken of [{ complete: false }, { source_commit: 'f'.repeat(40) }, { source_tree: 'f'.repeat(40) }, { targeted_test_argv: undefined }, { targeted_test_argv: [] }, { compile_argv: [['pnpm', 'build']] }, { environment: {} }, { job: '' }, { job: '2-1' }, { commands: [] }]) check(() => assert.throws(() => validateBuildReceipt({ ...build, ...broken }, contract, '1-1'), /build|job/));
check(() => assert.throws(() => validateBuildReceipt({ ...build, commands: build.commands.filter(command => command.argv[0] !== 'node') }, contract, '1-1'), /command receipts/));
check(() => assert.throws(() => validateBuildReceipt({ ...build, commands: build.commands.map(command => command.argv[0] === 'node' ? {...command, code:1} : command) }, contract, '1-1'), /command receipts/));
// Evaluate the actual package-entry admission prefix before any extraction or
// lifecycle operation. Both parser and filesystem ports are inert fixtures.
const materializerSource = fs.readFileSync(new URL('./materialize.mjs', import.meta.url), 'utf8');
const materializeStart = materializerSource.indexOf('export async function materialize(');
const materializeGuardEnd = materializerSource.indexOf('  fs.mkdirSync(runnable, { mode: 0o700 });', materializeStart);
assert(materializeStart >= 0 && materializeGuardEnd > materializeStart);
const admissionPrefix = materializerSource.slice(materializeStart, materializeGuardEnd) + '\n  return { proofEntries };\n}';
const profileEntries = {
  legacy: ['dist/proofs/native-ipc-gateway-driver.js', 'dist/proofs/native-ipc-gateway-api.js', 'dist/proofs/native-ipc-gateway-fixture.js'],
  workboard: ['dist/proofs/workboard-private-recovery-controller.js', 'dist/proofs/workboard-private-recovery-api.js', 'dist/extensions/workboard/src/sqlite-store.worker.js'],
};
async function profileFixture(profile, omitted) {
  const profileContract = {...contract, qualification_scope: profile === 'workboard' ? 'workboard-native-worker-logical-recovery.synthetic.v1' : 'legacy-native-ipc-gateway-source-fixture'};
  const entries = ['openclaw.mjs', 'dist/build-info.json', 'dist/plugin-sdk/sqlite-runtime.js', ...profileEntries[profile]]
    .filter(relative => relative !== omitted).map(relative => file('package/' + relative));
  const calls = [];
  const context = vm.createContext({
    fs: {readFileSync(name) { if (name === '/fixture/contract.json') return JSON.stringify(profileContract); if (name === '/fixture/build.json') return JSON.stringify(build); throw Error('unexpected fixture read'); }, existsSync() { return false; }},
    path, process: {env: {QUALIFICATION_JOB: '1-1'}}, validateBuildReceipt,
    need(value, reason) { assert(value, reason); }, hash() {return 'a'.repeat(64);}, validateTarEntries, Date,
    createRequire(name) { assert.equal(name, '/fixture/source/package.json'); return dependency => {assert.equal(dependency, 'tar'); return {
      async t(options) { calls.push('tar-list-double'); for (const entry of entries) options.onReadEntry(entry); },
      async x() { throw Error('extraction must not execute in source fixtures'); },
    }; }; },
  });
  const module = new vm.SourceTextModule(admissionPrefix, {context}); await module.link(() => {throw Error('unexpected materializer import');}); await module.evaluate();
  let result, error;
  try {result = await module.namespace.materialize('/fixture/source','/fixture/package.tgz','/fixture/deployed','/fixture/runnable','/fixture/build.json','/fixture/contract.json');} catch (caught) {error = caught;}
  return {result, error, calls};
}
for (const profile of ['legacy', 'workboard']) {
  const admitted = await profileFixture(profile);
  assert.equal(admitted.error, undefined); assert.deepEqual(Array.from(admitted.result.proofEntries), profileEntries[profile]); assert.deepEqual(admitted.calls, ['tar-list-double']); checks++;
  for (const omitted of profileEntries[profile]) {
    const refused = await profileFixture(profile, omitted);
    assert.equal(refused.result, undefined); assert.match(refused.error.message, /actual checked package lacks required driver\/runtime entry/); assert(refused.error.message.endsWith(omitted)); assert.deepEqual(refused.calls, ['tar-list-double']); checks++;
  }
}
const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'mergeguez-materialize-')));
try {
  const deployed = path.join(root, 'deployed'), runnable = path.join(root, 'runnable');
  function put(base, name, bytes) { const file = path.join(base, name); fs.mkdirSync(path.dirname(file), {recursive:true}); fs.writeFileSync(file, bytes); }
  put(runnable, 'package.json', '{"name":"openclaw"}');
  put(runnable, 'node_modules/@openclaw/ai/package.json', '{"name":"@openclaw/ai","version":"packed"}');
  put(runnable, 'node_modules/@openclaw/ai/original.mjs', 'original checked bundled AI');
  put(deployed, 'node_modules/.pnpm/dependency/package.json', '{"name":"dependency","version":"1.0.0"}');
  put(deployed, 'node_modules/.pnpm/ai/package.json', '{"name":"@openclaw/ai","version":"deployed"}');
  fs.mkdirSync(path.join(deployed, 'node_modules/@openclaw'), {recursive:true});
  fs.symlinkSync('../.pnpm/ai', path.join(deployed, 'node_modules/@openclaw/ai'));
  fs.symlinkSync('.pnpm/dependency', path.join(deployed, 'node_modules/dependency'));
  const before = inventory(runnable, 4096);
  check(() => { const result = mergeDependencies(deployed, runnable, 8192); assert.ok(result.preservedPackedPackages.includes('node_modules/@openclaw/ai')); assert.equal(fs.readFileSync(path.join(runnable, 'node_modules/@openclaw/ai/original.mjs'), 'utf8'), 'original checked bundled AI'); assert.equal(fs.lstatSync(path.join(runnable, 'node_modules/@openclaw/ai')).isSymbolicLink(), false); for (const old of before.entries) assert.deepEqual(result.merged.entries.find(x => x.path === old.path), old); });
  check(() => assert.throws(() => inventory(runnable, 1), /cap/));
  put(deployed, 'node_modules/collision', 'deployed'); put(runnable, 'node_modules/collision', 'packed');
  check(() => assert.throws(() => mergeDependencies(deployed, runnable, 8192), /collision/));
  fs.unlinkSync(path.join(deployed, 'node_modules/collision')); fs.unlinkSync(path.join(runnable, 'node_modules/collision'));
  for (const target of ['/tmp', '../../escape', 'absent']) { const bad = path.join(runnable, 'bad'); fs.symlinkSync(target, bad); check(() => assert.throws(() => inventory(runnable, 8192))); fs.unlinkSync(bad); }
  const hard = path.join(runnable, 'hard'); fs.linkSync(path.join(runnable, 'package.json'), hard); check(() => assert.throws(() => inventory(runnable, 8192), /hard/)); fs.unlinkSync(hard);
  const alias = path.join(root, 'alias'); fs.symlinkSync(runnable, alias); check(() => assert.throws(() => inventory(alias, 8192), /aliased/));
  check(() => assert.throws(() => inventory(runnable, 8192, 0), /deadline/));
} finally { fs.rmSync(root, {recursive:true, force:true}); }
// Lifecycle cases use deliberately synthetic module/filesystem owners; no shipped native owner runs.
const lifecycleRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'mergeguez-lifecycle-fixtures-')));
let lifecycleCase = 0;
async function lifecycleCheck(fn) { await fn(); checks++; }
function fixture(body, markers = ['.openclaw-lifecycle-pending', 'dist/openclaw-install-guard']) {
  const base = path.join(lifecycleRoot, String(++lifecycleCase));
  fs.mkdirSync(path.join(base, 'dist/infra'), {recursive:true});
  fs.writeFileSync(path.join(base, 'package.json'), '{"type":"module"}');
  fs.writeFileSync(path.join(base, 'checked.dat'), 'checked package bytes');
  for (const name of markers) fs.writeFileSync(path.join(base, name), 'pending');
  fs.writeFileSync(path.join(base, 'dist/infra/package-lifecycle.js'),
    "import fs from 'node:fs'; import path from 'node:path'; export async function completePendingPackageLifecycle({packageRoot,timeoutMs}) { " + body + " }");
  return base;
}
const retireMarkers = "for (const name of ['.openclaw-lifecycle-pending','dist/openclaw-install-guard']) fs.rmSync(path.join(packageRoot,name),{force:true});";
const complete = "if (!(timeoutMs>0 && timeoutMs<=60000)) throw new Error('invalid owner script budget'); " + retireMarkers + " return true;";
const invoke = (base, deadline = Date.now() + 5000) => completeRunnablePackageLifecycle(base, 1024*1024, deadline);
try {
  await lifecycleCheck(async () => {
    const base = fixture(complete); const receipt = await invoke(base);
    assert.equal(receipt.completed,true); assert.equal(receipt.writerLockAbsent,true);
    assert.equal(receipt.unchangedCheckedFileBytesAndLinks,true); assert.equal(receipt.admissionOrReleaseAcceptance,false);
    assert.deepEqual(receipt.removedMarkers,['.openclaw-lifecycle-pending','dist/openclaw-install-guard']);
    assert.equal(fs.readFileSync(path.join(base,'checked.dat'),'utf8'),'checked package bytes');
  });
  await lifecycleCheck(async () => { const base=fixture('return false;',[]);assert.equal((await invoke(base)).completed,false); });
  await lifecycleCheck(async () => { const base=fixture('return true;');await assert.rejects(invoke(base),/marker remains/);assert.ok(fs.existsSync(path.join(base,'.openclaw-lifecycle-pending'))); });
  await lifecycleCheck(async () => { const base=fixture(retireMarkers+'return false;');await assert.rejects(invoke(base),/did not attest/); });
  await lifecycleCheck(async () => { const base=fixture(retireMarkers+"return 'true';");await assert.rejects(invoke(base),/did not attest/); });
  await lifecycleCheck(async () => { const base=fixture("throw new Error('synthetic owner failed');");await assert.rejects(invoke(base),/synthetic owner failed/);assert.ok(fs.existsSync(path.join(base,'.openclaw-lifecycle-pending'))); });
  await lifecycleCheck(async () => { const base=fixture(complete);fs.writeFileSync(path.join(base,'.openclaw-lifecycle-lock'),'unresolved');await assert.rejects(invoke(base),/unresolved owner/);assert.ok(fs.existsSync(path.join(base,'.openclaw-lifecycle-pending'))); });
  await lifecycleCheck(async () => { const base=fixture(complete);fs.writeFileSync(path.join(base,'dist/infra/package-lifecycle.js'),'export const wrong=true;');await assert.rejects(invoke(base),/interface absent/); });
  await lifecycleCheck(async () => { const base=fixture(complete);fs.unlinkSync(path.join(base,'dist/infra/package-lifecycle.js'));await assert.rejects(invoke(base),/owner absent/); });
  await lifecycleCheck(async () => { const base=fixture(complete);fs.renameSync(path.join(base,'dist/infra/package-lifecycle.js'),path.join(base,'dist/infra/other.js'));fs.symlinkSync('other.js',path.join(base,'dist/infra/package-lifecycle.js'));await assert.rejects(invoke(base),/owner absent/); });
  await lifecycleCheck(async () => { const base=fixture(complete);fs.unlinkSync(path.join(base,'.openclaw-lifecycle-pending'));fs.symlinkSync('checked.dat',path.join(base,'.openclaw-lifecycle-pending'));await assert.rejects(invoke(base),/marker is not a regular/); });
  await lifecycleCheck(async () => { const base=fixture("fs.writeFileSync(path.join(packageRoot,'checked.dat'),'changed');"+complete);await assert.rejects(invoke(base),/changed checked runnable bytes/); });
  await lifecycleCheck(async () => { const base=fixture("fs.writeFileSync(path.join(packageRoot,'unchecked.dat'),'added');"+complete);await assert.rejects(invoke(base),/unchecked runnable content/); });
  await lifecycleCheck(async () => { const base=fixture("fs.writeFileSync(path.join(packageRoot,'.openclaw-lifecycle-lock'),'unresolved');"+complete);await assert.rejects(invoke(base),/ownership remains unresolved/); });
  await lifecycleCheck(async () => { const base=fixture("fs.renameSync(packageRoot,packageRoot+'.retired');fs.mkdirSync(packageRoot);return true;");await assert.rejects(invoke(base),/root generation changed/);assert.ok(fs.existsSync(path.join(base+'.retired','.openclaw-lifecycle-pending'))); });
  await lifecycleCheck(async () => { const base=fixture(complete);await assert.rejects(invoke(base,Date.now()-1),/deadline exhausted/);assert.ok(fs.existsSync(path.join(base,'.openclaw-lifecycle-pending'))); });
  await lifecycleCheck(async () => { const base=fixture("await new Promise(resolve=>setTimeout(resolve,50));"+complete);await assert.rejects(invoke(base,Date.now()+25),/deadline exhausted/); });
  await lifecycleCheck(async () => { const base=fixture(complete);const alias=base+'-alias';fs.symlinkSync(base,alias);await assert.rejects(invoke(alias),/aliased lifecycle package root/); });
  await lifecycleCheck(async () => { const base=fixture(complete);await assert.rejects(completeRunnablePackageLifecycle(base,1,Date.now()+5000),/artifact cap exceeded/); });
  for (const name of ['.openclaw-lifecycle-pending','dist/openclaw-install-guard']) {
    await lifecycleCheck(async () => {
      const base=fixture("fs.writeFileSync(path.join(packageRoot,'checked.dat'),'owner dispatched');"+complete);
      fs.unlinkSync(path.join(base,name));fs.mkdirSync(path.join(base,name));
      await assert.rejects(invoke(base),/marker is not a regular file/);
      assert.equal(fs.readFileSync(path.join(base,'checked.dat'),'utf8'),'checked package bytes');
    });
    await lifecycleCheck(async () => {
      const base=fixture("fs.mkdirSync(path.join(packageRoot,"+JSON.stringify(name)+"));return false;",[]);
      await assert.rejects(invoke(base),/marker remains pending/);
    });
    await lifecycleCheck(async () => {
      const base=fixture(retireMarkers+"fs.mkdirSync(path.join(packageRoot,"+JSON.stringify(name)+"));return true;");
      await assert.rejects(invoke(base),/marker remains pending/);
    });
  }

} finally { fs.rmSync(lifecycleRoot,{recursive:true,force:true}); }

console.log(JSON.stringify({ checks, passed: checks, scope: 'small adapter, two-profile actual entry-admission prefix with inert parser/filesystem ports, and synthetic lifecycle-owner fixtures; actual tar/parser/deploy/shipped native lifecycle behavior unexecuted', native_commands_or_network: 0 }));
