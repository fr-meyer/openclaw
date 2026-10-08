"""Offline private retention of exact v2 acknowledgements; no nonce minting.

Raw values returned by load stay within the private host/worker seam. No file
pathname, SQLite handle, runtime permission or public/model response is created.
"""
from __future__ import annotations

from contextlib import contextmanager
import json

import family_publish_io as _vendor
import workboard_private_custody as _custody
import workboard_acceptance_ledger as _ledger

SOURCE_PINS = {
    "family_publish_io": "ef1f6341e8fbc29c13b3acb873fbc9181f0075f6869c37bc6fa87fba52d6b967",
    "workboard_private_custody": "c9b291c42e9179be0ea363f56694db3b0ae8c4957a7e968a9a6b56f8dc20a917",
    "workboard_acceptance_ledger": "03cd5b84db0866813f3d9e2b7cd718302d7af0705f11edd8a931d79dc5938d9e",
}
if any(getattr(module, "__source_sha256__", None) != SOURCE_PINS[name]
       for name, module in (("family_publish_io", _vendor),
                            ("workboard_private_custody", _custody),
                            ("workboard_acceptance_ledger", _ledger))):
    raise RuntimeError("PROOF_KEEPER_SOURCE_BINDING_REQUIRED")

CONTRACT = "workboard.private-proof-keeper.v1"
MAX_PROOF_BYTES = 16384
RECORD_FIELDS = {"operationId", "kind", "binding", "receipt", "proof",
                 "ledgerRecordSha256", "rootIdentity", "ledgerIdentity"}


class ProofKeeperError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise ProofKeeperError(code)


def _clone(value):
    try:
        return _ledger.clone(value)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _fail("PROOF_INPUT_INVALID")


class PrivateProofKeeper:
    """One fixed private ledger-role namespace; no artifact or nonce discovery.

Use the exact same admitted custody object as the existing DurableLedger.
Acknowledgements are saved once or matched idempotently, never overwritten.
"""
    def __init__(self, custody, ledger):
        if (not isinstance(custody, _custody.PrivateCustody) or
                not isinstance(ledger, _ledger.DurableLedger) or
                ledger.custody is not custody):
            _fail("PROOF_OWNER_MISMATCH")
        self.custody, self.ledger = custody, ledger
        self.handle = custody.role("ledger", create=False)
        self.root_identity = tuple(custody.identity)
        self.ledger_identity = tuple(self.handle.identity)
        if self.ledger_identity != tuple(ledger.handle.identity):
            self.handle.close()
            _fail("PROOF_OWNER_MISMATCH")

    def close(self):
        self.handle.close()

    @contextmanager
    def _locked(self):
        try:
            with self.custody.owner_lock(timeout=5):
                self.handle.verify()
                if (tuple(self.custody.identity) != self.root_identity or
                        tuple(self.handle.identity) != self.ledger_identity):
                    _fail("PROOF_OWNER_CHANGED")
                yield
                self.handle.verify()
        except _custody.CustodyError as error:
            raise ProofKeeperError("CUSTODY_" + error.code) from None
        except _ledger.LedgerError as error:
            raise ProofKeeperError("LEDGER_" + error.code) from None

    @staticmethod
    def _inputs(operation_id, kind, bound):
        _ledger.operation_uuid(operation_id)
        if not isinstance(kind, str) or kind not in _ledger.KINDS:
            _fail("PROOF_KIND_INVALID")
        return _ledger.binding(bound)

    @staticmethod
    def _filename(operation_id):
        return "proof-" + operation_id + ".json"

    def _prove(self, operation_id, kind, bound, proof):
        # resolve validates exact nonce, accepted operation, binding and receipt.
        return self.ledger.resolve(operation_id, kind, bound, proof)

    def _record(self, operation_id, kind, bound, proof, accepted):
        return {"operationId": operation_id, "kind": kind, "binding": bound,
                "receipt": _clone(accepted["receipt"]), "proof": _clone(proof),
                "ledgerRecordSha256": _ledger.digest(_ledger.canonical(accepted)),
                "rootIdentity": list(self.root_identity),
                "ledgerIdentity": list(self.ledger_identity)}

    def _read(self, operation_id):
        filename = self._filename(operation_id)
        try:
            if self.handle.stat(filename)["bytes"] > MAX_PROOF_BYTES:
                _fail("PROOF_SIZE_LIMIT")
            with self.handle.open_reader(filename) as reader:
                if reader.size > MAX_PROOF_BYTES:
                    _fail("PROOF_SIZE_LIMIT")
                raw = reader.read_bytes()
        except _custody.CustodyError as error:
            if error.code == "NOT_FOUND":
                return None
            raise
        if len(raw) > MAX_PROOF_BYTES:
            _fail("PROOF_SIZE_LIMIT")
        try:
            envelope = json.loads(raw)
            if (type(envelope) is not dict or
                    set(envelope) != {"contract", "record", "recordSha256"} or
                    envelope["contract"] != CONTRACT or
                    type(envelope["record"]) is not dict or
                    set(envelope["record"]) != RECORD_FIELDS or
                    envelope["recordSha256"] != _ledger.digest(_ledger.canonical(envelope["record"])) or
                    raw != _ledger.canonical(envelope)):
                _fail("PROOF_CORRUPT")
            record = envelope["record"]
            if (record["operationId"] != operation_id or
                    record["rootIdentity"] != list(self.root_identity) or
                    record["ledgerIdentity"] != list(self.ledger_identity)):
                _fail("PROOF_RECORD_CONFLICT")
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            _fail("PROOF_CORRUPT")
        return record

    def _exact(self, operation_id, kind, bound, record):
        if record["kind"] != kind or record["binding"] != bound:
            _fail("PROOF_RECORD_CONFLICT")
        accepted = self._prove(operation_id, kind, bound, record["proof"])
        expected = self._record(operation_id, kind, bound, record["proof"], accepted)
        if record != expected:
            _fail("PROOF_RECORD_CONFLICT")
        return accepted

    def save(self, operation_id, kind, bound, proof):
        """Privately retain an exact received acknowledgement; return metadata only."""
        with self._locked():
            bound = self._inputs(operation_id, kind, bound)
            # Validation precedes serialization or any proof-file write.
            accepted = self._prove(operation_id, kind, bound, proof)
            proof = _clone(proof)
            expected = self._record(operation_id, kind, bound, proof, accepted)
            existing = self._read(operation_id)
            if existing is not None:
                self._exact(operation_id, kind, bound, existing)
                if existing != expected:
                    _fail("PROOF_RECORD_CONFLICT")
            else:
                envelope = {"contract": CONTRACT, "record": expected,
                            "recordSha256": _ledger.digest(_ledger.canonical(expected))}
                raw = _ledger.canonical(envelope)
                if len(raw) > MAX_PROOF_BYTES:
                    _fail("PROOF_SIZE_LIMIT")
                # Exactly one absent-only atomic write; no overwrite/delete/retry.
                self.handle.replace_bytes(self._filename(operation_id), raw,
                                          expected_sha256=None)
                stored = self._read(operation_id)
                if stored != expected:
                    _fail("PROOF_RECORD_CONFLICT")
            self._exact(operation_id, kind, bound, expected)
            summary = {"operationId": operation_id, "kind": kind, "stored": True,
                       "proofSha256": accepted["proofSha256"],
                       "receiptSha256": accepted["receiptSha256"],
                       "synthetic": True, "productionAcceptance": False}
        # No successful save acknowledgement escapes a write/fsync/lock-exit failure.
        return summary

    def load(self, operation_id, kind, bound):
        """Return raw proof only to the private worker after exact ledger validation."""
        with self._locked():
            bound = self._inputs(operation_id, kind, bound)
            record = self._read(operation_id)
            if record is None:
                _fail("PROOF_MISSING")
            self._exact(operation_id, kind, bound, record)
            proof = _clone(record["proof"])
        # Reader close and owner-lock exit checks complete before nonce delivery.
        return proof
