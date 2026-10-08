import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto, {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';

// Actual frozen public source selected from the sealed patch, evaluated only with
// explicit unit doubles. No Worker, helper, database, container or build executes.
const root = path.dirname(fileURLToPath(import.meta.url));
const contract = JSON.parse(fs.readFileSync(path.join(root, 'contract.json'), 'utf8'));
const patch = fs.readFileSync(path.join(root, 'workboard-source.patch'), 'utf8');
assert.equal(crypto.createHash('sha256').update(patch).digest('hex'), '0cce713b2f9651eae7df7e6f357d2c9bf99f7bb5552835aa218b4871c87d860b');
function patchSection(relative) {
  const marker = `diff --git a/${relative} b/${relative}\n`;
  const start = patch.indexOf(marker); assert(start >= 0, 'named source patch section absent');
  const end = patch.indexOf('\ndiff --git ', start + marker.length);
  return patch.slice(start, end < 0 ? undefined : end);
}
function selectedPostimageHunk(relative) {
  const section = patchSection(relative); let hunk = false; const result = [];
  for (const line of section.split('\n')) {
    if (line.startsWith('@@ ')) { hunk = true; continue; }
    if (!hunk || line.startsWith('\\ No newline')) continue;
    if (line.startsWith('+') || line.startsWith(' ')) result.push(line.slice(1));
  }
  return result.join('\n') + '\n';
}
function addedSource(relative) {
  assert(patchSection(relative).includes('new file mode 100644\n'), 'source must be an added complete file');
  const source = selectedPostimageHunk(relative);
  const pin = contract.source_inputs.find(input => input.path === relative); assert(pin);
  assert.equal(Buffer.byteLength(source), pin.bytes);
  assert.equal(crypto.createHash('sha256').update(source).digest('hex'), pin.sha256);
  return source;
}
const source = addedSource('scripts/proofs/workboard-private-recovery/controller.mjs');
const cases = [];
const ack = () => ({contract: 'workboard.native-runtime-logical-recovery.v1', kind: 'capture', synthetic: true, productionAcceptance: false, fullRecoveryReady: false, privateProofKept: true, rawProofPublished: false, runtimeStartAllowed: false, claimsRearmed: false, notificationsDelivered: false});
const error = code => Object.assign(new Error(code), {code});
async function fixture(options = {}) {
  const calls = [], directories = new Set();
  let current = true, revoked = false, captures = 0;
  const target = {}, authority = {};
  const stat = () => ({uid: options.wrongUid ? 0 : 1000, mode: 0o40700, dev: 1, isDirectory: () => true, isSymbolicLink: () => !!options.symlink});
  const fakeFs = {
    lstatSync: () => stat(), realpathSync: value => value,
    mkdirSync(value) { calls.push('mkdir'); if (options.preexisting || directories.has(value)) throw error('EEXIST'); directories.add(value); },
  };
  let retainedGuard;
  const store = {
    async ready() { calls.push('store-ready'); if (options.retireAt === 'ready') current = false; },
    async preparePrivateRecoveryTarget() { calls.push('target'); if (options.targetFailure) throw options.targetFailure; return target; },
    async create(input, scope, guard) { calls.push('create-card'); assert.equal(input.status, 'todo'); assert.equal(scope, undefined); guard(); return {id: 'unit-only-card'}; },
    async addAttachment(id, input, scope, guard) { calls.push('attachment'); assert.equal(id, 'unit-only-card'); assert.equal(input.contentBase64, Buffer.from('synthetic recovery bytes\n').toString('base64')); assert.equal(scope, undefined); guard(); if (options.attachmentFailure) throw options.attachmentFailure; },
    async capturePrivateRecovery(value) {
      calls.push('capture'); assert.equal(value, authority);
      if (revoked) { if (options.brokenRevocation) return ack(); throw error('closed'); }
      captures++; retainedGuard();
      if (options.captureThrowsUndefined) throw undefined;
      if (options.captureFailure) throw options.captureFailure;
      return options.invalidAck ? {...ack(), claimsRearmed: true} : ack();
    },
    async close() { calls.push('store-close'); if (options.storeCloseFailure) throw error('store-close-failed'); },
  };
  const custodian = {
    async ready(guard) { calls.push('custody-ready'); guard(); if (options.custodyFailure) throw options.custodyFailure; if (options.retireAt === 'custody-ready') current = false; },
    async persist() { throw error('UNIT_MUST_NOT_PERSIST_DATABASE_BYTES'); },
    async close() { calls.push('custodian-close'); if (options.custodyCloseFailure) throw error('custody-close-failed'); },
  };
  const api = {
    async openWorkboardRecoveryQualificationStore(input, guard) {
      calls.push('original-factory'); guard();
      assert.equal(input.dbPath, '/qualification/native-state/workboard-proof/store.sqlite');
      assert.equal(input.workerModuleUrl.href, 'file:///artifact/dist/extensions/workboard/src/sqlite-store.worker.js');
      if (options.retireAt === 'factory') current = false;
      return store;
    },
    issueSqliteWorkerPrivateRecoveryAuthority(value, owner) {
      calls.push('issuer'); assert.equal(value, target); assert.equal(owner.custodian, custodian); owner.assertCurrent(); retainedGuard = owner.assertCurrent;
      return {authority, revoke() { calls.push('revoke'); revoked = true; }};
    },
    async drainGlobalSingletonLifecycleState() { calls.push('broker-drain'); if (options.drainFailure) throw error('broker-drain-failed'); },
  };
  const bridge = {createWorkerCustodian(input) { calls.push('custodian-factory'); assert.equal(input.python, '/usr/bin/python3'); assert.equal(input.custodyRoot, '/qualification/native-output/workboard-proof-custody'); assert.equal(input.sizeLimit, 4 * 1024 * 1024); assert.equal(input.sourceBinding.profileSha256, 'a'.repeat(64)); return custodian; }};
  const context = vm.createContext({Buffer, process: {geteuid: () => 1000}, URL});
  const moduleOf = values => new vm.SyntheticModule(Object.keys(values), function () { for (const [key, value] of Object.entries(values)) this.setExport(key, value); }, {context});
  const ports = {'node:fs': moduleOf({default: fakeFs}), 'node:path': moduleOf({default: path}), 'node:crypto': moduleOf({default: {randomUUID}}), 'node:url': moduleOf({pathToFileURL: value => new URL('file://' + value)}), './native-api.js': moduleOf(api)};
  const companion = moduleOf(bridge);
  const module = new vm.SourceTextModule(source, {context, importModuleDynamically: async specifier => {
    assert.equal(specifier, 'file:///proof/workboard-custody/worker-custody-bridge.mjs'); calls.push('companion-import');
    if (options.retireAt === 'import') current = false;
    if (companion.status === 'unlinked') await companion.link(() => {throw Error('unexpected import');});
    if (companion.status === 'linked') await companion.evaluate();
    return companion;
  }});
  await module.link(specifier => {assert(specifier in ports); return ports[specifier];}); await module.evaluate();
  const run = override => module.namespace.runWorkboardPrivateRecoveryQualification(override ?? {assertCurrent() {calls.push('current'); if (!current) throw error('OWNER_RETIRED');}, profileSha256: 'a'.repeat(64), python: '/usr/bin/python3'});
  return {run, calls, get captures() {return captures;}, get guard() {return retainedGuard;}};
}
async function test(name, fn) {await fn(); cases.push(name);}
await test('source joins original factory,target,issuer,custodian and drains owners', async () => {
  const f = await fixture(); const result = await f.run();
  assert.equal(result.completed, true); assert.equal(result.storeAndCustodianJoined, true); assert.equal(result.postAcknowledgementRestoreQualified, false); assert.equal(f.captures, 1);
  const ordered = f.calls.filter(c => c !== 'current' && c !== 'mkdir');
  assert.deepEqual(ordered, ['companion-import','original-factory','store-ready','target','custodian-factory','issuer','custody-ready','create-card','attachment','capture','revoke','capture','revoke','store-close','custodian-close','broker-drain']);
  assert.throws(f.guard, /SYNTHETIC_NATIVE_OWNER_RETIRED/);
});
await test('missing live callback rejected before any factory', async () => {const f = await fixture(); await assert.rejects(f.run({profileSha256: 'a'.repeat(64), python: '/usr/bin/python3'}), /SYNTHETIC_NATIVE_CONTEXT_INVALID/); assert.equal(f.calls.length, 0);});
await test('no caller-selected path or production flag accepted', async () => {const f = await fixture(); await assert.rejects(f.run({assertCurrent() {}, profileSha256: 'a'.repeat(64), python: '/usr/bin/python3', dbPath: '/private/live.sqlite'}), /SYNTHETIC_NATIVE_CONTEXT_INVALID/); assert.equal(f.calls.length, 0);});
for (const stage of ['import','factory','ready','custody-ready']) await test('retirement across awaited '+stage+' prevents capture and joins acquired owners', async () => {const f = await fixture({retireAt: stage}); await assert.rejects(f.run(), e => e.code === 'OWNER_RETIRED'); assert.equal(f.captures, 0); assert(f.calls.includes('broker-drain')); if (stage !== 'import') assert(f.calls.includes('store-close')); if (stage === 'custody-ready') assert(f.calls.includes('custodian-close'));});
await test('target failure closes actual acquired store', async () => {const primary = error('TARGET_FAILED'), f = await fixture({targetFailure: primary}); await assert.rejects(f.run(), e => e.cause === primary); assert(f.calls.includes('store-close')); assert(!f.calls.includes('issuer'));});
await test('custodian readiness failure retains primary and joins both owners', async () => {const primary = error('CUSTODY_FAILED'), f = await fixture({custodyFailure: primary}); await assert.rejects(f.run(), e => e.cause === primary); assert.deepEqual(f.calls.slice(-3), ['store-close','custodian-close','broker-drain']);});
await test('attachment failure never admits capture', async () => {const f = await fixture({attachmentFailure: error('ATTACHMENT_FAILED')}); await assert.rejects(f.run(), e => e.code === 'ATTACHMENT_FAILED'); assert.equal(f.captures, 0);});
await test('unsafe acknowledgement cannot report complete', async () => {const f = await fixture({invalidAck: true}); await assert.rejects(f.run(), e => e.code === 'SYNTHETIC_CUSTODY_ACK_INVALID'); assert(f.calls.includes('custodian-close'));});
await test('lost acknowledgement remains unknown with no retry', async () => {const primary = error('outcome-unknown'), f = await fixture({captureFailure: primary}); await assert.rejects(f.run(), e => e.cause === primary); assert.equal(f.captures, 1);});
await test('revoked call success refuses qualification', async () => {const f = await fixture({brokenRevocation: true}); await assert.rejects(f.run(), e => e.code === 'REVOKED_PRIVATE_CAPTURE_ADMITTED');});
await test('all cleanup owners attempted and primary retained as cause', async () => {const primary = error('outcome-unknown'), f = await fixture({captureFailure: primary, storeCloseFailure: true, custodyCloseFailure: true, drainFailure: true}); await assert.rejects(f.run(), e => {assert.equal(e.cause, primary); assert.equal(e.code, 'outcome-unknown'); assert.deepEqual(Array.from(e.cleanupCodes), ['WORKBOARD_STORE_CLOSE_FAILED','CUSTODIAN_CLOSE_FAILED','SQLITE_BROKER_DRAIN_FAILED']); return true;}); assert.deepEqual(f.calls.slice(-3), ['store-close','custodian-close','broker-drain']);});
await test('throw undefined remains rejection rather than completed result', async () => {const f = await fixture({captureThrowsUndefined: true}); let rejected = false; try {await f.run();} catch (e) {rejected = true; assert.equal(e.cause, undefined); assert.equal(e.code, 'SYNTHETIC_NATIVE_OPERATION_FAILED'); assert.equal(e.qualificationContext.captureInvoked, true);} assert(rejected);});
for (const [name, options] of [['preexisting',{preexisting: true}],['symlink',{symlink: true}],['foreign UID',{wrongUid: true}]]) await test(name+' parent/state cannot open any store', async () => {const f = await fixture(options); await assert.rejects(f.run()); assert(!f.calls.includes('original-factory'));});
console.log(JSON.stringify({schema: 'workboard.source-composition-controller-units.v1', passed: cases.length, cases, actualFactoryWorkerCustodianPorts: false, ports: 'explicit source-unit doubles; never runtime admission evidence', nativeWorkerStarted: false, helperStarted: false, databaseOpened: false, productionAcceptance: false}));
