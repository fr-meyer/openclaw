// Host-only isolated companion. This module does not issue private authority.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {canonical, sha, schemaDdlSha256, LOGICAL_ASSURANCE, LOGICAL_ASSURANCE_SHA256, assertLogicalAssurance, assertCaptureInterval} from './logical-transport-contract.mjs';
import {SealedPythonClient, WorkerError} from './vendor/adapter/sealed-python-client.mjs';

const CONTRACT = 'workboard.native-runtime-logical-recovery.v1';
export const WORKER_CAPTURE_BYTE_LIMIT = 32 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX = /^[0-9a-f]{64}$/;
const OWNER = /^[A-Za-z0-9_.:-]{1,128}$/;
const TABLES = Object.freeze(['workboard_schema_migrations', 'workboard_boards', 'workboard_cards', 'workboard_card_labels', 'workboard_card_events', 'workboard_card_attempts', 'workboard_card_comments', 'workboard_card_links', 'workboard_card_proof', 'workboard_card_artifacts', 'workboard_card_diagnostics', 'workboard_card_notifications', 'workboard_worker_logs', 'workboard_worker_protocol', 'workboard_card_attachments', 'workboard_attachment_blobs', 'workboard_notification_subscriptions'].sort());
const here = path.dirname(fileURLToPath(import.meta.url));
const fail = code => { throw new WorkerError(code); };
function unknownAcknowledgement(primary) {
  const code = 'PRIVATE_ACKNOWLEDGEMENT_OUTCOME_UNKNOWN';
  const error = new WorkerError(code, {recorded: false, code, cleanupCodes: primary?.cleanupCodes}, primary?.cleanupCodes);
  const originalCode = typeof primary?.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(primary.code) ? primary.code : 'WORKER_OPERATION_FAILED';
  Object.defineProperty(error, 'originalCode', {value: originalCode, enumerable: true});
  Object.defineProperty(error, 'outcomeDisposition', {value: Object.freeze({acceptanceIssued: true, acceptanceMayBeDurable: true, reconciliationRequired: true, retryAllowed: false}), enumerable: true});
  return error;
}
const clone = value => JSON.parse(canonical(value));
const inert = Object.freeze({synthetic: true, productionAcceptance: false, runtimeStartAllowed: false, claimsRearmed: false, notificationsDelivered: false});
const modulePins = Object.freeze({
  family_publish_io: 'ef1f6341e8fbc29c13b3acb873fbc9181f0075f6869c37bc6fa87fba52d6b967',
  workboard_private_custody: 'c9b291c42e9179be0ea363f56694db3b0ae8c4957a7e968a9a6b56f8dc20a917',
  workboard_acceptance_ledger: '03cd5b84db0866813f3d9e2b7cd718302d7af0705f11edd8a931d79dc5938d9e',
  workboard_private_proof_keeper: '94b64e5d5167829aa47240ffd259f1132df60a12196d2afcf77820ea7e9cde4c',
  recovery_worker: 'd3a5748ce502327b96c759f7a6e378e7e93de088a97d83deed9a360199d8ef19',
});
const jsPins = Object.freeze({
  'native-memory-codec.mjs': 'b995bc4a98b2916b4285ef8974f28d2c1312628e0070dd713cfcf0d2cd993565',
  'logical-assurance.mjs': '1d3703c3dfa65553b3f89f9d0a373cd8b10e82a0d1f119d6ce2cf3765fc44814',
  'sealed-python-client.mjs': 'd86506c5ac8960b89e75a66ed641b5501e0fdf87dd211f6160210df062ba6e69',
  'schema.sql': schemaDdlSha256,
});

function exactFields(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function sourceBindingOf(value) {
  if (!exactFields(value, ['sourceBootId', 'sourceOwnerId', 'sourceGenerationId', 'profileSha256']) || Object.values(value).some(item => typeof item !== 'string') || !UUID.test(value.sourceBootId) || !UUID.test(value.sourceGenerationId) || !OWNER.test(value.sourceOwnerId) || !HEX.test(value.profileSha256)) fail('SOURCE_BINDING_INVALID');
  return Object.freeze(clone(value));
}
function assertVendorPins() {
  // These are source-custody checks, not an operational executed-image attestation.
  for (const [name, digest] of Object.entries(jsPins)) if (sha(fs.readFileSync(path.join(here, 'vendor/adapter', name))) !== digest) fail('COMPANION_SOURCE_PIN_CHANGED');
  assertLogicalAssurance(LOGICAL_ASSURANCE);
  if (sha(canonical(LOGICAL_ASSURANCE)) !== LOGICAL_ASSURANCE_SHA256) fail('LOGICAL_ASSURANCE_REQUIRED');
}

function checkedTypedTransport(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('LOGICAL_TYPED_TRANSPORT_INVALID');
  if (value.type === 'null' && exactFields(value, ['type'])) return;
  if (value.type === 'text' && exactFields(value, ['type', 'value']) && typeof value.value === 'string' && value.value.isWellFormed()) return;
  if (value.type === 'real' && exactFields(value, ['type', 'value']) && typeof value.value === 'number' && Number.isFinite(value.value)) return;
  if (value.type === 'integer' && exactFields(value, ['type', 'decimal']) && typeof value.decimal === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value.decimal) && value.decimal.length <= 20) {
    const number = BigInt(value.decimal); if (number >= -(1n << 63n) && number < (1n << 63n)) return;
  }
  if (value.type === 'blob' && exactFields(value, ['type', 'base64', 'bytes', 'sha256']) && typeof value.base64 === 'string' && Number.isSafeInteger(value.bytes) && value.bytes >= 0 && typeof value.sha256 === 'string' && HEX.test(value.sha256)) {
    const bytes = Buffer.from(value.base64, 'base64');
    if (bytes.length === value.bytes && bytes.toString('base64') === value.base64 && sha(bytes) === value.sha256) return;
  }
  fail('LOGICAL_TYPED_TRANSPORT_INVALID');
}
function checkedLogicalTransport(value) {
  if (!exactFields(value, ['contract', 'schemaVersion', 'schemaObjects', 'schemaSha256', 'applicationId', 'userVersion', 'tables']) || value.contract !== 'workboard.native-descriptor-recovery.v2' || value.schemaVersion !== 3 || !Array.isArray(value.schemaObjects) || value.schemaObjects.length > 128 || typeof value.schemaSha256 !== 'string' || !HEX.test(value.schemaSha256) || sha(canonical(value.schemaObjects)) !== value.schemaSha256 || !exactFields(value.tables, TABLES)) fail('LOGICAL_EXPORT_TRANSPORT_INVALID');
  for (const key of ['applicationId', 'userVersion']) if (!Number.isInteger(value[key]) || value[key] < -2147483648 || value[key] > 2147483647) fail('LOGICAL_EXPORT_TRANSPORT_INVALID');
  for (const object of value.schemaObjects) if (!Array.isArray(object) || object.length !== 4 || object.some(item => typeof item !== 'string' || !item.isWellFormed()) || !['table', 'index'].includes(object[0])) fail('LOGICAL_EXPORT_TRANSPORT_INVALID');
  if (canonical(value.schemaObjects.filter(object => object[0] === 'table').map(object => object[1]).sort()) !== canonical(TABLES)) fail('LOGICAL_EXPORT_TRANSPORT_INVALID');
  let rows = 0;
  for (const table of Object.values(value.tables)) {
    if (!exactFields(table, ['columns', 'rows', 'sha256']) || !Array.isArray(table.columns) || table.columns.length === 0 || table.columns.length > 155 || table.columns.some(column => typeof column !== 'string' || !/^[A-Za-z0-9_]+$/.test(column)) || new Set(table.columns).size !== table.columns.length || !Array.isArray(table.rows) || typeof table.sha256 !== 'string' || !HEX.test(table.sha256) || sha(canonical(table.rows)) !== table.sha256) fail('LOGICAL_EXPORT_TRANSPORT_INVALID');
    for (const row of table.rows) {
      if (++rows > 100000 || !Array.isArray(row) || row.length !== table.columns.length) fail('LOGICAL_EXPORT_TRANSPORT_INVALID');
      for (const value of row) checkedTypedTransport(value);
    }
  }
}

/** Pure validation and packaging. Success grants no authority or filesystem access. */
export function validateWorkerCapturePayload(payload, operationId, sourceBinding, sizeLimit = 4 * 1024 * 1024) {
  if (typeof operationId !== 'string' || !UUID.test(operationId)) fail('OPERATION_UUID_INVALID');
  const source = sourceBindingOf(sourceBinding);
  if (!Number.isSafeInteger(sizeLimit) || sizeLimit <= 0 || sizeLimit > WORKER_CAPTURE_BYTE_LIMIT) fail('CUSTODY_SIZE_LIMIT_INVALID');
  if (!(payload instanceof Uint8Array) || payload.byteLength === 0 || payload.byteLength > WORKER_CAPTURE_BYTE_LIMIT) fail('WORKER_CAPTURE_BYTE_LIMIT');
  // Own the bytes before any await. Malformed UTF-8 cannot become replacement text.
  const bytes = Buffer.from(payload);
  let decoded;
  try { decoded = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)); }
  catch { fail('WORKER_CAPTURE_PAYLOAD_INVALID'); }
  if (!exactFields(decoded, ['exported', 'snapshotBase64', 'captureInterval']) || typeof decoded.snapshotBase64 !== 'string') fail('WORKER_CAPTURE_PAYLOAD_INVALID');
  const interval = assertCaptureInterval(decoded.captureInterval);
  const snapshot = Buffer.from(decoded.snapshotBase64, 'base64');
  if (snapshot.toString('base64') !== decoded.snapshotBase64 || snapshot.length === 0) fail('WORKER_SNAPSHOT_BASE64_INVALID');
  if (snapshot.subarray(0, 16).toString('latin1') !== 'SQLite format 3\0') fail('WORKER_SNAPSHOT_TRANSPORT_INVALID');
  checkedLogicalTransport(decoded.exported);
  // Semantic snapshot/export equality is established inside the exact native
  // worker codec before transfer. Only the private-gated original broker result
  // may reach persist; no payload field or caller assertion establishes it here.
  const files = {
    'raw-export.json': Buffer.from(canonical(decoded.exported)),
    'snapshot.sqlite': snapshot,
    'inert.json': Buffer.from(canonical(inert)),
  };
  const manifest = {
    contract: CONTRACT, role: 'capture', operationId, ...source, captureInterval: interval,
    captureIntervalSha256: sha(canonical(interval)), nativeProfileSha256: source.profileSha256,
    assurance: LOGICAL_ASSURANCE, assuranceSha256: LOGICAL_ASSURANCE_SHA256,
    synthetic: true, productionAcceptance: false, fullRecoveryReady: false,
    logicalSha256: sha(files['raw-export.json']), schemaDdlSha256, schemaSha256: decoded.exported.schemaSha256,
    members: Object.fromEntries(Object.entries(files).map(([name, data]) => [name, {sha256: sha(data), bytes: data.length}])),
  };
  files['manifest.json'] = Buffer.from(canonical(manifest));
  // Apply the companion's tighter aggregate quota in addition to broker framing.
  if (Object.values(files).reduce((sum, data) => sum + data.length, 0) > sizeLimit) fail('CUSTODY_ARTIFACT_BYTE_LIMIT');
  const binding = Object.freeze({
    ...source, schemaSha256: manifest.schemaSha256, assuranceSha256: LOGICAL_ASSURANCE_SHA256,
    captureIntervalSha256: manifest.captureIntervalSha256,
    manifestSha256: sha(files['manifest.json']), inputSha256: manifest.logicalSha256,
  });
  const receipt = Object.freeze({
    artifactRole: 'capture', artifactId: operationId,
    assuranceContract: LOGICAL_ASSURANCE.contract, assuranceSha256: LOGICAL_ASSURANCE_SHA256,
    captureIntervalSha256: binding.captureIntervalSha256,
    manifestSha256: binding.manifestSha256, inputSha256: binding.inputSha256,
    bindingSha256: sha(canonical(binding)), outputSha256: sha(snapshot),
  });
  return {files, binding, receipt, interval};
}

/** Construction is host-only and dormant; the caller must retain opaque admission. */
export function createWorkerCustodian(options) {
  if (!exactFields(options, ['sourceBinding', 'python', 'custodyRoot', 'executionBootId', 'sizeLimit'])) fail('CUSTODIAN_OPTIONS_INVALID');
  const {python, custodyRoot, executionBootId, sizeLimit} = options;
  const source = sourceBindingOf(options.sourceBinding);
  if (typeof python !== 'string' || typeof custodyRoot !== 'string' || typeof executionBootId !== 'string' || !path.isAbsolute(python) || !path.isAbsolute(custodyRoot) || !UUID.test(executionBootId) || !Number.isSafeInteger(sizeLimit) || sizeLimit <= 0 || sizeLimit > WORKER_CAPTURE_BYTE_LIMIT) fail('CUSTODIAN_OPTIONS_INVALID');
  assertVendorPins();
  let client, helloPromise, closePromise, closed = false;
  function requireCurrent(assertCurrent) {
    if (typeof assertCurrent !== 'function') fail('LIVE_ADMISSION_CALLBACK_REQUIRED');
    if (closed) fail('CUSTODIAN_CLOSED');
    assertCurrent();
    // Owner callbacks may synchronously trigger shutdown. Never create or send
    // through a helper after that reentrant local retirement.
    if (closed) fail('CUSTODIAN_CLOSED');
  }
  async function ready(assertCurrent) {
    requireCurrent(assertCurrent);
    if (!client) {
      client = new SealedPythonClient({python, approvedModules: modulePins, policy: {synthetic: true, root: custodyRoot, uid: process.geteuid(), sizeLimit, executionBootId}});
      requireCurrent(assertCurrent);
    }
    // Each caller checks its own authority, including when a shared hello is queued.
    const result = await (helloPromise ??= client.call('hello', {}, () => requireCurrent(assertCurrent)));
    requireCurrent(assertCurrent);
    if (result?.synthetic !== true || result.productionAcceptance !== false || result.descriptorByteIO !== true || result.sqlitePathConsumer !== false || result.rawProofWireAllowed !== false || result.privateProofKeeper !== true || result.assuranceContract !== LOGICAL_ASSURANCE.contract || result.assuranceSha256 !== LOGICAL_ASSURANCE_SHA256 || canonical(result.compiledModuleDigests) !== canonical(modulePins)) fail('SEALED_CUSTODY_BINDING_INVALID');
    return Object.freeze({synthetic: true, productionAcceptance: false, descriptorByteIO: true, assuranceContract: LOGICAL_ASSURANCE.contract, assuranceSha256: LOGICAL_ASSURANCE_SHA256});
  }
  async function persist(payload, operationId, assertCurrent) {
    requireCurrent(assertCurrent);
    const artifact = validateWorkerCapturePayload(payload, operationId, source, sizeLimit);
    requireCurrent(assertCurrent);
    // A local acknowledgement deadline is NOT a private permission grant.
    const expiresAt = Date.now() + 60000;
    const check = () => { requireCurrent(assertCurrent); if (Date.now() >= expiresAt) fail('CUSTODY_ACK_DEADLINE_EXCEEDED'); };
    const {files, binding, receipt, interval} = artifact;
    const context = Object.freeze({contract: CONTRACT, kind: 'capture', operationId, assuranceSha256: LOGICAL_ASSURANCE_SHA256, binding});
    async function rejectStage(primary, revision) {
      // Reject-only bookkeeping remains allowed after capture authority retires.
      try { await client.call('reject-stage', {operationId, binding, revision, code: primary.code === 'CUSTODY_ACK_DEADLINE_EXCEEDED' ? 'PRIVATE_CAPABILITY_EXPIRED' : 'PRIVATE_CAPABILITY_REVOKED'}); } catch {}
    }
    try {
      await ready(check); check();
      const staged = await client.call('stage', {kind: 'capture', operationId, binding, files: Object.fromEntries(Object.entries(files).map(([name, bytes]) => [name, bytes.toString('base64')]))}, check);
      if (!exactFields(staged, ['revision', 'role', 'operationId']) || staged.revision !== 1 || staged.role !== 'capture' || staged.operationId !== operationId) fail('CUSTODY_STAGE_ACK_INVALID');
      try { check(); }
      catch (primary) {
        await rejectStage(primary, staged.revision);
        throw primary;
      }
      let acceptanceSent = false, ack;
      try {
        ack = await client.call('accept-and-keep', {kind: 'capture', operationId, binding, receipt, revision: staged.revision, expiresAt}, () => {check(); acceptanceSent = true;});
      } catch (primary) {
        // A denied queued send is known not to have issued acceptance. Once sent,
        // transport failure is potentially indeterminate and must not be retried.
        if (!acceptanceSent) { await rejectStage(primary, staged.revision); throw primary; }
        throw unknownAcknowledgement(primary);
      }
      try { check(); } catch (primary) { throw unknownAcknowledgement(primary); }
      try {
        if (!exactFields(ack, ['operationId', 'kind', 'state', 'revision', 'receipt', 'receiptSha256', 'proofSha256', 'keeperReceiptSha256', 'assuranceContract', 'assuranceSha256', 'privateProofKept', 'synthetic', 'productionAcceptance']) || ack.operationId !== operationId || ack.kind !== 'capture' || ack.state !== 'accepted' || ack.revision !== 2 || ack.assuranceContract !== LOGICAL_ASSURANCE.contract || ack.assuranceSha256 !== LOGICAL_ASSURANCE_SHA256 || ack.synthetic !== true || ack.productionAcceptance !== false || canonical(ack.receipt) !== canonical(receipt) || ack.receiptSha256 !== sha(canonical(receipt)) || !HEX.test(ack.proofSha256) || !HEX.test(ack.keeperReceiptSha256) || ack.privateProofKept !== true) fail('PRIVATE_ACKNOWLEDGEMENT_INVALID');
      } catch (primary) { throw unknownAcknowledgement(primary); }
      return Object.freeze({
        contract: CONTRACT, operationId, kind: 'capture', captureInterval: interval,
        captureIntervalSha256: binding.captureIntervalSha256, assurance: LOGICAL_ASSURANCE,
        assuranceSha256: LOGICAL_ASSURANCE_SHA256, binding, receipt,
        receiptSha256: ack.receiptSha256, proofSha256: ack.proofSha256, keeperReceiptSha256: ack.keeperReceiptSha256,
        sourceBootId: source.sourceBootId, executionBootId, privateProofKept: true, rawProofPublished: false,
        synthetic: true, productionAcceptance: false, fullRecoveryReady: false,
        runtimeStartAllowed: false, claimsRearmed: false, notificationsDelivered: false,
      });
    } catch (error) {
      if (error && typeof error === 'object' && !Object.hasOwn(error, 'recoveryContext')) Object.defineProperty(error, 'recoveryContext', {value: context, enumerable: true});
      throw error;
    }
  }
  function close() { closed = true; return closePromise ??= Promise.resolve().then(() => client?.close()); }
  return Object.freeze({persist, ready, close});
}
