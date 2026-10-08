"""Isolated synthetic metadata ledger and descriptor startup-role gate.

No SQLite, path reopening, host authorization mint, or production startup occurs
here. The sealed bootstrap must inject the reviewed workboard_private_custody module.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import re
import secrets
import uuid

from workboard_private_custody import CustodyError

CONTRACT = "workboard.private-acceptance-ledger.logical.v1"
LOGICAL_ASSURANCE = {'contract': 'workboard.logical-recovery-assurance.v1',
 'destination': {'descriptorCustodyRequired': True,
                 'overwriteExistingAllowed': False,
                 'sealedWorkerRequired': True},
 'preservation': {'attachmentReferencesAndBytesRequired': True,
                  'claimsAndLeasesRequired': True,
                  'exactSchemaRequired': True,
                  'lossyTextAllowed': False,
                  'rawValuesRequired': True,
                  'tableCount': 17,
                  'textEncoding': 'UTF-8'},
 'restore': {'acceptedOriginalCaptureRequired': True,
             'claimsRearmed': False,
             'inertQuarantineRequired': True,
             'notificationsDelivered': False,
             'overwriteLiveSourceAllowed': False,
             'runtimeStartAllowed': False,
             'sourceProfileBindingRequired': True},
 'source': {'captureRegistryEpochRequired': True,
            'coherentReadTransactionRequired': True,
            'deployedStoreSelectionProven': False,
            'deployedStoreSelectionRequiredBeforeProduction': True,
            'kernelMainWalShmBackingProven': False,
            'kernelMainWalShmBackingRequired': False,
            'opaqueOriginalOwnerRequired': True,
            'postCutoffCommitsIncluded': False,
            'readCutoff': 'first-read-in-source-transaction',
            'reopenByPathAllowed': False}}
LOGICAL_ASSURANCE_SHA256 = "536844e6da186aa8c6e5c23506ed1727f56c7f0f56e4d7149abc4f4d9c9d6387"
MAX_RECORD_BYTES = 65536
KINDS = {"capture": "capture", "restore-quarantine": "quarantine",
         "startup-policy": "operational-fixture"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
OWNER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
BINDING_FIELDS = {"sourceBootId", "sourceOwnerId", "profileSha256",
                  "schemaSha256", "manifestSha256", "inputSha256", "assuranceSha256", "captureIntervalSha256", "sourceGenerationId"}
RECEIPT_FIELDS = {"artifactRole", "artifactId", "manifestSha256",
                  "inputSha256", "bindingSha256", "outputSha256", "assuranceContract", "assuranceSha256", "captureIntervalSha256"}
RECORD_FIELDS = {"operationId", "kind", "binding", "state", "revision",
                 "executionBootId", "transitionBootId", "previousSha256",
                 "receipt", "receiptSha256", "proofSha256", "failureCode"}
PROOF_FIELDS = {"contract", "operationId", "kind", "bindingSha256",
                "receiptSha256", "revision", "nonce", "synthetic",
                "productionAcceptance"}


class LedgerError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def fail(code):
    raise LedgerError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def clone(value):
    return json.loads(canonical(value))


def operation_uuid(value):
    try:
        parsed = uuid.UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            fail("OPERATION_UUID_INVALID")
    except (ValueError, TypeError, AttributeError):
        fail("OPERATION_UUID_INVALID")
    return value


def hex_digest(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def checked_capture_interval(value):
    fields = {"startedAtMs", "completedAtMs", "elapsedMs", "cutoff", "exactCommitTimestampProven"}
    if not isinstance(value, dict) or set(value) != fields:
        fail("CAPTURE_INTERVAL_INVALID")
    if any(type(value[k]) is not int or not 0 <= value[k] <= 9007199254740991 for k in ("startedAtMs", "completedAtMs", "elapsedMs")) or value["completedAtMs"] < value["startedAtMs"] or value["cutoff"] != LOGICAL_ASSURANCE["source"]["readCutoff"] or value["exactCommitTimestampProven"] is not False:
        fail("CAPTURE_INTERVAL_INVALID")
    return clone(value)


def binding(value):
    if not isinstance(value, dict) or set(value) != BINDING_FIELDS:
        fail("BINDING_INVALID")
    operation_uuid(value["sourceBootId"])
    operation_uuid(value["sourceGenerationId"])
    if not isinstance(value["sourceOwnerId"], str) or not OWNER.fullmatch(value["sourceOwnerId"]):
        fail("BINDING_INVALID")
    if any(not hex_digest(value[k]) for k in BINDING_FIELDS - {"sourceBootId", "sourceOwnerId", "sourceGenerationId"}):
        fail("BINDING_INVALID")
    if value["assuranceSha256"] != LOGICAL_ASSURANCE_SHA256:
        fail("LOGICAL_ASSURANCE_REQUIRED")
    return clone(value)


def checked_receipt(value, kind, bound):
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
        fail("RECEIPT_INVALID")
    operation_uuid(value["artifactId"])
    if value["artifactRole"] != KINDS[kind] or any(not hex_digest(value[k]) for k in RECEIPT_FIELDS - {"artifactRole", "artifactId", "assuranceContract"}):
        fail("RECEIPT_INVALID")
    if value["captureIntervalSha256"] != bound["captureIntervalSha256"]:
        fail("CAPTURE_INTERVAL_INVALID")
    if value["assuranceContract"] != LOGICAL_ASSURANCE["contract"] or value["assuranceSha256"] != LOGICAL_ASSURANCE_SHA256 or value["assuranceSha256"] != bound["assuranceSha256"]:
        fail("LOGICAL_ASSURANCE_REQUIRED")
    if value["manifestSha256"] != bound["manifestSha256"] or value["inputSha256"] != bound["inputSha256"] or value["bindingSha256"] != digest(canonical(bound)):
        fail("RECEIPT_BINDING_CONFLICT")
    return clone(value)


def _record_valid(value):
    try:
        if not isinstance(value, dict) or set(value) != RECORD_FIELDS:
            fail("LEDGER_CORRUPT")
        operation_uuid(value["operationId"])
        operation_uuid(value["executionBootId"])
        operation_uuid(value["transitionBootId"])
        binding(value["binding"])
        if value["kind"] not in KINDS or type(value["revision"]) is not int:
            fail("LEDGER_CORRUPT")
        if value["state"] == "staged":
            if value["revision"] != 1 or value["executionBootId"] != value["transitionBootId"] or any(value[k] is not None for k in ["previousSha256", "receipt", "receiptSha256", "proofSha256", "failureCode"]):
                fail("LEDGER_CORRUPT")
        elif value["state"] in {"accepted", "failed", "indeterminate"}:
            if value["revision"] != 2 or not hex_digest(value["previousSha256"]):
                fail("LEDGER_CORRUPT")
            if value["state"] == "accepted":
                receipt = checked_receipt(value["receipt"], value["kind"], value["binding"])
                if receipt["artifactId"] != value["operationId"] or value["executionBootId"] != value["transitionBootId"] or value["receiptSha256"] != digest(canonical(receipt)) or not hex_digest(value["proofSha256"]) or value["failureCode"] is not None:
                    fail("LEDGER_CORRUPT")
            elif any(value[k] is not None for k in ["receipt", "receiptSha256", "proofSha256"]) or not isinstance(value["failureCode"], str) or not re.fullmatch(r"[A-Z0-9_]{1,64}", value["failureCode"]):
                fail("LEDGER_CORRUPT")
        else:
            fail("LEDGER_CORRUPT")
    except (LedgerError, KeyError, TypeError):
        fail("LEDGER_CORRUPT")
    return value


def _proof_valid(proof, record):
    if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS:
        fail("ACCEPTANCE_PROOF_REQUIRED")
    expected = {"contract": CONTRACT, "operationId": record["operationId"],
                "kind": record["kind"], "bindingSha256": digest(canonical(record["binding"])),
                "receiptSha256": record["receiptSha256"], "revision": record["revision"],
                "synthetic": True, "productionAcceptance": False}
    if not hex_digest(proof.get("nonce")) or any(proof.get(k) != v for k, v in expected.items()) or digest(canonical(proof)) != record["proofSha256"]:
        fail("ACCEPTANCE_PROOF_REQUIRED")


class DurableLedger:
    """One bounded record per stable operation UUID, under custody's stable lock.

    Only a proof returned after descriptor write/fsync/lock-exit can resolve an
    accepted record. Its fresh nonce is not persisted, so a visible record from
    an unacknowledged failed commit cannot reconstruct a proof from disk.
    """
    def __init__(self, custody, execution_boot_id):
        self.custody = custody
        self.execution_boot_id = operation_uuid(execution_boot_id)
        self.handle = custody.role("ledger", create=True)

    def close(self):
        self.handle.close()

    @contextmanager
    def _locked(self):
        try:
            with self.custody.owner_lock(timeout=5):
                self.handle.verify()
                yield
                self.handle.verify()
        except CustodyError as error:
            raise LedgerError("CUSTODY_" + error.code) from None

    def _read(self, operation_id):
        filename = operation_uuid(operation_id) + ".json"
        try:
            if self.handle.stat(filename)["bytes"] > MAX_RECORD_BYTES:
                fail("LEDGER_SIZE_LIMIT")
            with self.handle.open_reader(filename) as reader:
                if reader.metadata["bytes"] > MAX_RECORD_BYTES:
                    fail("LEDGER_SIZE_LIMIT")
                raw = reader.read_bytes()
        except CustodyError as error:
            if error.code == "NOT_FOUND":
                return None, None
            raise
        if len(raw) > MAX_RECORD_BYTES:
            fail("LEDGER_SIZE_LIMIT")
        try:
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or set(envelope) != {"contract", "record", "recordSha256"} or envelope["contract"] != CONTRACT or envelope["recordSha256"] != digest(canonical(envelope["record"])):
                fail("LEDGER_CORRUPT")
            record = _record_valid(envelope["record"])
            if record["operationId"] != operation_id or raw != canonical(envelope):
                fail("LEDGER_CORRUPT")
        except (ValueError, TypeError, KeyError, UnicodeError):
            fail("LEDGER_CORRUPT")
        return record, digest(raw)

    def _write(self, record, expected_sha):
        _record_valid(record)
        envelope = {"contract": CONTRACT, "record": record,
                    "recordSha256": digest(canonical(record))}
        raw = canonical(envelope)
        if len(raw) > MAX_RECORD_BYTES:
            fail("LEDGER_SIZE_LIMIT")
        self.handle.replace_bytes(record["operationId"] + ".json", raw,
                                  expected_sha256=expected_sha)

    @staticmethod
    def _match(record, kind, bound):
        if record["kind"] != kind or record["binding"] != bound:
            fail("OPERATION_BINDING_CONFLICT")

    @staticmethod
    def _summary(record):
        return {"operationId": record["operationId"], "kind": record["kind"],
                "state": "accepted-proof-required" if record["state"] == "accepted" else record["state"],
                "revision": record["revision"],
                "bindingSha256": digest(canonical(record["binding"])),
                "executionBootId": record["executionBootId"],
                "synthetic": True, "productionAcceptance": False}

    def prepare(self, operation_id, kind, bound):
        operation_uuid(operation_id)
        bound = binding(bound)
        if not isinstance(kind, str) or kind not in KINDS:
            fail("OPERATION_KIND_INVALID")
        with self._locked():
            record, current_sha = self._read(operation_id)
            if record:
                self._match(record, kind, bound)
                if record["state"] in {"failed", "indeterminate"}:
                    fail("OPERATION_TERMINAL")
                if record["state"] == "staged" and record["executionBootId"] != self.execution_boot_id:
                    fail("STALE_STAGE_BOOT")
            else:
                record = {"operationId": operation_id, "kind": kind, "binding": bound,
                          "state": "staged", "revision": 1,
                          "executionBootId": self.execution_boot_id,
                          "transitionBootId": self.execution_boot_id,
                          "previousSha256": None, "receipt": None,
                          "receiptSha256": None, "proofSha256": None, "failureCode": None}
                self._write(record, current_sha)
            result = self._summary(record)
        return result

    def accept(self, operation_id, expected_revision, bound, receipt, previous_proof=None):
        operation_uuid(operation_id)
        bound = binding(bound)
        if type(expected_revision) is not int or expected_revision < 1:
            fail("REVISION_INVALID")
        with self._locked():
            record, current_sha = self._read(operation_id)
            if record is None:
                fail("OPERATION_NOT_PREPARED")
            self._match(record, record["kind"], bound)
            receipt = checked_receipt(receipt, record["kind"], bound)
            if receipt["artifactId"] != operation_id:
                fail("RECEIPT_BINDING_CONFLICT")
            if record["state"] == "accepted":
                if receipt != record["receipt"] or expected_revision not in {1, 2}:
                    fail("OPERATION_RECEIPT_CONFLICT")
                _proof_valid(previous_proof, record)
                result = {"record": clone(record), "acceptance_proof": clone(previous_proof)}
            else:
                if record["state"] != "staged":
                    fail("OPERATION_TERMINAL")
                if record["revision"] != expected_revision:
                    fail("REVISION_CONFLICT")
                if record["executionBootId"] != self.execution_boot_id:
                    fail("STALE_STAGE_BOOT")
                proof = {"contract": CONTRACT, "operationId": operation_id,
                         "kind": record["kind"], "bindingSha256": digest(canonical(bound)),
                         "receiptSha256": digest(canonical(receipt)), "revision": 2,
                         "nonce": secrets.token_hex(32), "synthetic": True,
                         "productionAcceptance": False}
                record = {**record, "state": "accepted", "revision": 2,
                          "transitionBootId": self.execution_boot_id,
                          "previousSha256": current_sha, "receipt": receipt,
                          "receiptSha256": proof["receiptSha256"],
                          "proofSha256": digest(canonical(proof))}
                self._write(record, current_sha)
                result = {"record": clone(record), "acceptance_proof": proof}
        # The nonce is not returned if write, fsync, anchor check or lock exit fails.
        return result

    def resolve(self, operation_id, kind, bound, acceptance_proof):
        operation_uuid(operation_id)
        bound = binding(bound)
        with self._locked():
            record, _ = self._read(operation_id)
            if record is None:
                fail("OPERATION_NOT_FOUND")
            self._match(record, kind, bound)
            if record["state"] != "accepted":
                fail("OPERATION_NOT_ACCEPTED")
            _proof_valid(acceptance_proof, record)
            result = clone(record)
        return result

    def mark_failure(self, operation_id, expected_revision, bound, state, code):
        operation_uuid(operation_id)
        bound = binding(bound)
        if not isinstance(state, str) or state not in {"failed", "indeterminate"} or not isinstance(code, str) or not re.fullmatch(r"[A-Z0-9_]{1,64}", code):
            fail("FAILURE_TRANSITION_INVALID")
        if type(expected_revision) is not int or expected_revision < 1:
            fail("REVISION_INVALID")
        with self._locked():
            record, current_sha = self._read(operation_id)
            if record is None:
                fail("OPERATION_NOT_FOUND")
            self._match(record, record["kind"], bound)
            if record["state"] == state and record["failureCode"] == code:
                if expected_revision not in {1, 2}:
                    fail("REVISION_CONFLICT")
                result = self._summary(record)
            else:
                if record["state"] != "staged":
                    fail("OPERATION_TERMINAL")
                if type(expected_revision) is not int or expected_revision != record["revision"]:
                    fail("REVISION_CONFLICT")
                record = {**record, "state": state, "revision": 2,
                          "transitionBootId": self.execution_boot_id,
                          "previousSha256": current_sha, "failureCode": code}
                self._write(record, current_sha)
                result = self._summary(record)
        return result


@dataclass(frozen=True)
class StartupAdmission:
    fd: int
    identity: tuple
    sha256: str
    source_bytes: bytes
    assert_current: object = field(repr=False)
    role: str = "operational-fixture"
    synthetic: bool = True
    productionAcceptance: bool = False


class StartupGate:
    """Fixed synthetic host policy; never accepts a card/RPC source pathname.

    Production loader authority is not supplied by this constructor. Recovery
    roles are rejected even if their bytes/marker files are copied or removed.
    Consumers must use admitted bytes/fd, never reopen an observed pathname.
    """
    POLICY_FIELDS = {"contract", "synthetic", "productionAcceptance", "role",
                     "sourceIdentity", "sourceSha256", "custodyIdentity"}

    def __init__(self, ledger, custody, fixed_policy, policy_operation_id,
                 policy_binding, acceptance_proof):
        if not isinstance(fixed_policy, dict) or set(fixed_policy) != self.POLICY_FIELDS or fixed_policy["contract"] != CONTRACT or fixed_policy["synthetic"] is not True or fixed_policy["productionAcceptance"] is not False:
            fail("STARTUP_POLICY_INVALID")
        if fixed_policy["role"] != "operational-fixture":
            fail("RECOVERY_STARTUP_ROLE_FORBIDDEN")
        for field in ["sourceIdentity", "custodyIdentity"]:
            if not isinstance(fixed_policy[field], (tuple, list)) or len(fixed_policy[field]) != 2 or any(type(v) is not int or v < 0 for v in fixed_policy[field]):
                fail("STARTUP_POLICY_INVALID")
        if not hex_digest(fixed_policy["sourceSha256"]):
            fail("STARTUP_POLICY_INVALID")
        self.ledger, self.custody = ledger, custody
        self.policy = clone(fixed_policy)
        self.operation_id = operation_uuid(policy_operation_id)
        self.bound = binding(policy_binding)
        if self.bound["inputSha256"] != digest(canonical(self.policy)):
            fail("STARTUP_POLICY_BINDING_CONFLICT")
        self.proof = clone(acceptance_proof)

    @contextmanager
    def admit(self):
        # This entire check precedes any database opener, initializer or producer.
        self.ledger.resolve(self.operation_id, "startup-policy", self.bound, self.proof)
        with self.custody.role("operational-fixture") as handle:
            handle.verify()
            if tuple(handle.identity) != tuple(self.policy["custodyIdentity"]):
                fail("STARTUP_OWNER_IDENTITY_CONFLICT")
            with handle.open_reader("source.sqlite") as reader:
                def check_current():
                    self.ledger.resolve(self.operation_id, "startup-policy", self.bound, self.proof)
                    source = reader.read_bytes()
                    if tuple(reader.identity) != tuple(self.policy["sourceIdentity"]) or reader.sha256 != self.policy["sourceSha256"] or digest(source) != self.policy["sourceSha256"]:
                        fail("STARTUP_SOURCE_BINDING_CONFLICT")
                    return source
                source = check_current()
                yield StartupAdmission(reader.fd, tuple(reader.identity), reader.sha256,
                                       source, check_current)

    def run(self, opener, initializer=None, producers=()):
        with self.admit() as admission:
            opened = opener(admission)
            admission.assert_current()
            if initializer is not None:
                initializer(opened)
            for producer in producers:
                admission.assert_current()
                producer(opened)
            admission.assert_current()
            return opened
