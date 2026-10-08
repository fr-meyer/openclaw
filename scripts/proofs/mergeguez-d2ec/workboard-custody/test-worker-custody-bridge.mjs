import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import vm from 'node:vm';
import {DatabaseSync} from 'node:sqlite';
import {captureOwnedDatabase, snapshotBytes, verifySnapshotBytes, canonical, sha} from './vendor/adapter/native-memory-codec.mjs';
import {LOGICAL_ASSURANCE, LOGICAL_ASSURANCE_SHA256} from './vendor/adapter/logical-assurance.mjs';
import {WorkerError} from './vendor/adapter/sealed-python-client.mjs';
import {createWorkerCustodian, validateWorkerCapturePayload, WORKER_CAPTURE_BYTE_LIMIT} from './worker-custody-bridge.mjs';

const sourceBinding = Object.freeze({sourceBootId: crypto.randomUUID(), sourceOwnerId: 'synthetic-native-actor:7:lease:1', sourceGenerationId: crypto.randomUUID(), profileSha256: 'a'.repeat(64)});
const options = () => ({sourceBinding, python: '/opt/homebrew/bin/python3.13', custodyRoot: '/tmp/unused-synthetic-worker-custody', executionBootId: crypto.randomUUID(), sizeLimit: 4 * 1024 * 1024});
function fixture() {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(fs.readFileSync(new URL('./vendor/adapter/schema.sql', import.meta.url), 'utf8'));
    db.exec("INSERT INTO workboard_schema_migrations VALUES ('schema-3',1)");
    db.prepare('INSERT INTO workboard_cards(id,board_id,title,notes,status,priority,position,created_at,updated_at,claim_json) VALUES (?,?,?,?,?,?,?,?,?,?)').run('synthetic-card', 'synthetic-board', 'synthetic-title', 'private-synthetic-body-é\0🦞', 'running', 'high', 0, 1n, 9223372036854775806n, '{"owner":"fixture","token":"private-synthetic-token"}');
    const {exported} = captureOwnedDatabase(db);
    return {exported, snapshotBase64: snapshotBytes(exported).toString('base64'), captureInterval: {startedAtMs: 1, completedAtMs: 2, elapsedMs: 1, cutoff: LOGICAL_ASSURANCE.source.readCutoff, exactCommitTimestampProven: false}};
  } finally { db.close(); }
}
const value = fixture();
const payloadOf = data => Buffer.from(JSON.stringify(data));
const payload = payloadOf(value);
const packaging = () => validateWorkerCapturePayload(payload, crypto.randomUUID(), sourceBinding);

test('all17 exact schema and raw int64/claim/text bindings package without a grant', () => {
  const p = packaging();
  assert.equal(Object.keys(value.exported.tables).length, 17);
  const m = JSON.parse(p.files['manifest.json']);
  assert.equal(m.assuranceSha256, LOGICAL_ASSURANCE_SHA256);
  assert.equal(m.logicalSha256, sha(p.files['raw-export.json']));
  assert.equal(p.binding.manifestSha256, sha(p.files['manifest.json']));
  assert.equal(p.receipt.outputSha256, sha(p.files['snapshot.sqlite']));
  assert.equal(p.receipt.bindingSha256, sha(canonical(p.binding)));
  assert.equal(m.sourceGenerationId, sourceBinding.sourceGenerationId);
  assert.equal(m.productionAcceptance, false);
  assert.equal(m.fullRecoveryReady, false);
  assert.equal(m.assurance.source.kernelMainWalShmBackingRequired, false);
});
test('unrecognized payload and caller assurance fields are rejected', () => {
  assert.throws(() => validateWorkerCapturePayload(payloadOf({...value, assurance: LOGICAL_ASSURANCE}), crypto.randomUUID(), sourceBinding), /WORKER_CAPTURE_PAYLOAD_INVALID/);
  assert.throws(() => validateWorkerCapturePayload(payloadOf([value]), crypto.randomUUID(), sourceBinding), /WORKER_CAPTURE_PAYLOAD_INVALID/);
});
test('payload malformed UTF8 and JSON are rejected without replacement', () => {
  assert.throws(() => validateWorkerCapturePayload(Buffer.from([0xff]), crypto.randomUUID(), sourceBinding), /WORKER_CAPTURE_PAYLOAD_INVALID/);
  assert.throws(() => validateWorkerCapturePayload(Buffer.from('{'), crypto.randomUUID(), sourceBinding), /WORKER_CAPTURE_PAYLOAD_INVALID/);
});
test('noncanonical snapshot transport fails and snapshot semantics remain worker codec responsibility', () => {
  assert.throws(() => validateWorkerCapturePayload(payloadOf({...value, snapshotBase64: value.snapshotBase64 + '\n'}), crypto.randomUUID(), sourceBinding), /WORKER_SNAPSHOT_BASE64_INVALID/);
  const edited = structuredClone(value); edited.exported.userVersion++;
  // Host accepts structurally consistent transport; it cannot attest semantic
  // SQLite equality. The exact worker codec must reject this before transfer.
  assert.ok(validateWorkerCapturePayload(payloadOf(edited), crypto.randomUUID(), sourceBinding));
  assert.throws(() => verifySnapshotBytes(Buffer.from(edited.snapshotBase64, 'base64'), edited.exported), /SNAPSHOT_EXPORT_MISMATCH/);
});
test('table/hash, typed int64/blob and fixed logical export shape fail closed', () => {
  const rowHash = structuredClone(value); rowHash.exported.tables.workboard_cards.sha256 = '0'.repeat(64);
  assert.throws(() => validateWorkerCapturePayload(payloadOf(rowHash), crypto.randomUUID(), sourceBinding), /LOGICAL_EXPORT_TRANSPORT_INVALID/);
  const integer = structuredClone(value), table = integer.exported.tables.workboard_cards;
  table.rows[0][table.columns.indexOf('updated_at')] = {type: 'integer', decimal: '9223372036854775808'};
  table.sha256 = sha(canonical(table.rows));
  assert.throws(() => validateWorkerCapturePayload(payloadOf(integer), crypto.randomUUID(), sourceBinding), /LOGICAL_TYPED_TRANSPORT_INVALID/);
  const added = structuredClone(value); added.exported.authority = true;
  assert.throws(() => validateWorkerCapturePayload(payloadOf(added), crypto.randomUUID(), sourceBinding), /LOGICAL_EXPORT_TRANSPORT_INVALID/);
});
test('logical cutoff cannot claim an exact commit timestamp', () => {
  assert.throws(() => validateWorkerCapturePayload(payloadOf({...value, captureInterval: {...value.captureInterval, exactCommitTimestampProven: true}}), crypto.randomUUID(), sourceBinding), /CAPTURE_INTERVAL_INVALID/);
});
test('broker32MiB and aggregate descriptor quota both fail closed', () => {
  assert.throws(() => validateWorkerCapturePayload(new Uint8Array(WORKER_CAPTURE_BYTE_LIMIT + 1), crypto.randomUUID(), sourceBinding), /WORKER_CAPTURE_BYTE_LIMIT/);
  assert.throws(() => validateWorkerCapturePayload(payload, crypto.randomUUID(), sourceBinding, 1024), /CUSTODY_ARTIFACT_BYTE_LIMIT/);
});
test('source binding is fixed construction metadata and cannot accept added authority fields', () => {
  assert.throws(() => validateWorkerCapturePayload(payload, crypto.randomUUID(), {...sourceBinding, scope: 'capture'}), /SOURCE_BINDING_INVALID/);
  assert.throws(() => validateWorkerCapturePayload(payload, crypto.randomUUID(), {...sourceBinding, sourceOwnerId: undefined}), /SOURCE_BINDING_INVALID/);
  assert.throws(() => createWorkerCustodian({...options(), approvedModules: {}}), /CUSTODIAN_OPTIONS_INVALID/);
  assert.throws(() => createWorkerCustodian({...options(), assurance: {}}), /CUSTODIAN_OPTIONS_INVALID/);
});
test('real companion construction is dormant and absent admission prevents helper creation', async () => {
  const c = createWorkerCustodian(options());
  assert.equal(Object.isFrozen(c), true);
  await assert.rejects(c.persist(payload, crypto.randomUUID()), /LIVE_ADMISSION_CALLBACK_REQUIRED/);
  await c.close();
  await assert.rejects(c.persist(payload, crypto.randomUUID(), () => {}), /CUSTODIAN_CLOSED/);
});

// VM-link only the transport to inspect bridge control flow. This is explicitly
// an interface fixture: no Python process, custody tree or SQLite worker starts.
async function fixtureBridge(hooks = {}) {
  const calls = [], clients = [], imports = [];
  const pins = JSON.parse(fs.readFileSync(new URL('./dependency-pins.json', import.meta.url)));
  const moduleNames = ['family_publish_io', 'workboard_private_custody', 'workboard_acceptance_ledger', 'workboard_private_proof_keeper', 'recovery_worker'];
  const moduleDigests = Object.fromEntries(moduleNames.map((name, index) => [name, pins.pins[index + 4].sha256]));
  class Client {
    constructor(opts) { clients.push(this); this.options = opts; }
    async call(action, p = {}, beforeSend) {
      if (action === 'accept-and-keep') hooks.beforeAcceptSend?.();
      beforeSend?.(); calls.push({action, payload: p});
      if (action === 'hello') return {synthetic: true, productionAcceptance: false, descriptorByteIO: true, sqlitePathConsumer: false, rawProofWireAllowed: false, privateProofKeeper: true, assuranceContract: LOGICAL_ASSURANCE.contract, assuranceSha256: LOGICAL_ASSURANCE_SHA256, compiledModuleDigests: moduleDigests, ...hooks.hello};
      if (action === 'stage') { hooks.stage?.(p); return {revision: 1, role: 'capture', operationId: p.operationId, ...hooks.stageAck}; }
      if (action === 'reject-stage') return {state: 'failed', revision: 2};
      if (action === 'accept-and-keep') {
        hooks.accept?.(p);
        if (hooks.acceptError) throw hooks.acceptError;
        return {operationId: p.operationId, kind: p.kind, state: 'accepted', revision: 2, receipt: p.receipt, receiptSha256: sha(canonical(p.receipt)), proofSha256: 'b'.repeat(64), keeperReceiptSha256: 'c'.repeat(64), assuranceContract: LOGICAL_ASSURANCE.contract, assuranceSha256: LOGICAL_ASSURANCE_SHA256, privateProofKept: true, synthetic: true, productionAcceptance: false, ...hooks.acceptAck};
      }
      throw Error('UNEXPECTED_FIXTURE_ACTION');
    }
    async close() { calls.push({action: 'close'}); }
  }
  const url = new URL('./worker-custody-bridge.mjs', import.meta.url);
  const module = new vm.SourceTextModule(fs.readFileSync(url, 'utf8'), {identifier: url.href, initializeImportMeta(meta) { meta.url = url.href; }});
  await module.link(async specifier => {
    imports.push(specifier);
    const exports = specifier.endsWith('/sealed-python-client.mjs') ? {SealedPythonClient: Client, WorkerError} : await import(specifier.startsWith('.') ? new URL(specifier, url).href : specifier);
    const names = Object.keys(exports);
    return new vm.SyntheticModule(names, function() { for (const name of names) this.setExport(name, exports[name]); });
  });
  await module.evaluate();
  return {custodian: module.namespace.createWorkerCustodian(options()), calls, clients, imports};
}
test('host bridge dependency graph has no SQLite or memory codec import', async () => {
  const f = await fixtureBridge();
  assert.ok(!f.imports.some(specifier => specifier.includes('native-memory-codec') || specifier === 'node:sqlite'));
  const contract = fs.readFileSync(new URL('./logical-transport-contract.mjs', import.meta.url), 'utf8');
  assert.ok(!contract.includes('node:sqlite'));
  assert.ok(!contract.includes('native-memory-codec'));
  const sealed = fs.readFileSync(new URL('./vendor/adapter/sealed-python-client.mjs', import.meta.url), 'utf8');
  assert.ok(!sealed.includes('node:sqlite'));
  await f.custodian.close();
});
test('reentrant local closure during live check prevents helper construction', async () => {
  const f = await fixtureBridge();
  await assert.rejects(f.custodian.ready(() => { void f.custodian.close(); }), /CUSTODIAN_CLOSED/);
  assert.equal(f.clients.length, 0);
  assert.deepEqual(f.calls, []);
  await f.custodian.close();
});
test('stage and accept bind hashes through the sealed-client interface and return sanitized receipt', async () => {
  const f = await fixtureBridge(); let checks = 0;
  const r = await f.custodian.persist(payload, crypto.randomUUID(), () => { checks++; });
  assert.deepEqual(f.calls.map(x => x.action), ['hello', 'stage', 'accept-and-keep']);
  assert.ok(checks >= 9);
  assert.ok(!JSON.stringify(r).includes('private-synthetic-token'));
  assert.ok(!JSON.stringify(r).includes('private-synthetic-body'));
  assert.ok(!Object.hasOwn(r, 'snapshotBase64'));
  assert.equal(r.privateProofKept, true);
  assert.equal(r.productionAcceptance, false);
  assert.equal(r.runtimeStartAllowed, false);
  assert.equal(f.calls[2].payload.expiresAt > Date.now(), true);
  assert.equal(f.clients[0].options.approvedModules.family_publish_io, 'ef1f6341e8fbc29c13b3acb873fbc9181f0075f6869c37bc6fa87fba52d6b967');
  await f.custodian.close();
});
test('revocation after stage rejects bookkeeping and never accepts', async () => {
  let retired = false;
  const f = await fixtureBridge({stage() { retired = true; }});
  await assert.rejects(f.custodian.persist(payload, crypto.randomUUID(), () => { if (retired) throw new WorkerError('PRIVATE_CAPABILITY_REVOKED'); }), /PRIVATE_CAPABILITY_REVOKED/);
  assert.deepEqual(f.calls.map(x => x.action), ['hello', 'stage', 'reject-stage']);
  await f.custodian.close();
});
test('retirement after acceptance is explicitly an unknown acknowledgement outcome', async () => {
  let retired = false;
  const f = await fixtureBridge({accept() { retired = true; }});
  await assert.rejects(f.custodian.persist(payload, crypto.randomUUID(), () => { if (retired) throw new WorkerError('ORIGINAL_ACTOR_RETIRED'); }), /PRIVATE_ACKNOWLEDGEMENT_OUTCOME_UNKNOWN/);
  await f.custodian.close();
});
test('queued admission denial before acceptance send rejects its known stage', async () => {
  let retired = false;
  const f = await fixtureBridge({beforeAcceptSend() { retired = true; }});
  await assert.rejects(f.custodian.persist(payload, crypto.randomUUID(), () => { if (retired) throw new WorkerError('ORIGINAL_ACTOR_RETIRED'); }), /ORIGINAL_ACTOR_RETIRED/);
  assert.deepEqual(f.calls.map(x => x.action), ['hello', 'stage', 'reject-stage']);
  await f.custodian.close();
});
test('altered sealed helper hello cannot proceed to staging', async () => {
  const f = await fixtureBridge({hello: {sqlitePathConsumer: true}});
  await assert.rejects(f.custodian.persist(payload, crypto.randomUUID(), () => {}), /SEALED_CUSTODY_BINDING_INVALID/);
  assert.deepEqual(f.calls.map(x => x.action), ['hello']);
  await f.custodian.close();
});
test('sent acceptance transport failure is a machine-explicit unknown outcome with bounded diagnostics', async () => {
  const f = await fixtureBridge({acceptError: new WorkerError('WORKER_RESPONSE_INVALID', undefined, ['FILE_CLOSE_FAILED'])});
  await assert.rejects(f.custodian.persist(payload, crypto.randomUUID(), () => {}), error => {
    assert.equal(error.code, 'PRIVATE_ACKNOWLEDGEMENT_OUTCOME_UNKNOWN');
    assert.equal(error.originalCode, 'WORKER_RESPONSE_INVALID');
    assert.deepEqual(error.cleanupCodes, ['FILE_CLOSE_FAILED']);
    assert.equal(error.failureDisposition.recorded, false);
    assert.equal(error.failureDisposition.code, error.code);
    assert.equal(error.outcomeDisposition.acceptanceIssued, true);
    assert.equal(error.outcomeDisposition.acceptanceMayBeDurable, true);
    assert.equal(error.outcomeDisposition.reconciliationRequired, true);
    assert.equal(error.outcomeDisposition.retryAllowed, false);
    assert.ok(Object.isFrozen(error.outcomeDisposition));
    assert.ok(!JSON.stringify(error).includes('private-synthetic-body'));
    return true;
  });
  assert.deepEqual(f.calls.map(x => x.action), ['hello', 'stage', 'accept-and-keep']);
  await f.custodian.close();
});
test('malformed stage or acceptance acknowledgements cannot create a successful receipt', async () => {
  const stage = await fixtureBridge({stageAck: {revision: 2}});
  await assert.rejects(stage.custodian.persist(payload, crypto.randomUUID(), () => {}), /CUSTODY_STAGE_ACK_INVALID/);
  assert.deepEqual(stage.calls.map(x => x.action), ['hello', 'stage']);
  await stage.custodian.close();
  const accepted = await fixtureBridge({acceptAck: {rawProof: 'forbidden'}});
  await assert.rejects(accepted.custodian.persist(payload, crypto.randomUUID(), () => {}), error => {
    assert.equal(error.code, 'PRIVATE_ACKNOWLEDGEMENT_OUTCOME_UNKNOWN');
    assert.equal(error.originalCode, 'PRIVATE_ACKNOWLEDGEMENT_INVALID');
    assert.equal(error.outcomeDisposition.retryAllowed, false);
    return true;
  });
  await accepted.custodian.close();
});
