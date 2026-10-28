"""Private Mac intent/custody journal for one guest generation.

The journal supplies durability, not VM or transport authority.  An existing
session directory is never reopened for sending.  Read-only audit can describe
an interrupted attempt, but it cannot issue or retry a guest operation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_REQUEST = 65536
MAX_RESPONSE = 3 * 1024 * 1024
MAX_EVIDENCE = 2 * 1024 * 1024
MAX_EVIDENCE_AGGREGATE = 3 * 1024 * 1024
MAX_UNCERTAIN_SAMPLE = 131072
MAX_AUDIT_ENTRIES = 160
MAX_CALLS = 32
METHODS = frozenset(('identity_once', 'preflight', 'prepare',
    'write_public_context_once', 'unmount_test_normally', 'test_is_unmounted',
    'start_worker_once', 'worker_observation', 'read_ready_once',
    'release_copied_inputs_then_gate', 'wait_worker_once',
    'read_exact_copied_report', 'stop_owned_unit_normally',
    'owned_cgroup_empty', 'collect_owned_evidence',
    'remove_only_copied_session_files_after_custody'))
OWNER_KEYS = frozenset(('vmId', 'bootId', 'sessionId', 'unitName',
                        'guestSourceSha256', 'providerStopAt',
                        'executionDeadlineUtc'))
VM_ID = '1'
DISK_IDS = ('11', '12')
OUTER_RESULT = {'vmState': 'TERMINATED', 'diskIds': ['11', '12'], 'retained': True, 'transportClosed': True}
EVIDENCE_ROLES = frozenset(('staging-manifest', 'host-snapshot', 'host-proof',
    'ready-frame', 'worker-stdout', 'worker-stderr', 'report', 'closeout'))
EVIDENCE_CAPS = {'staging-manifest': 131072, 'host-snapshot': 2097152, 'host-proof': 131072, 'ready-frame': 4096, 'worker-stdout': 131072, 'worker-stderr': 131072, 'report': 4315, 'closeout': 16384}
REQUIRED_CUSTODY = EVIDENCE_ROLES
_CUSTODY_KEY = object()


class Refusal(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _pairs(rows):
    value = {}
    for key, item in rows:
        need(key not in value, 'intent.duplicate_json_key')
        value[key] = item
    return value


def _json(raw, cap):
    need(type(raw) is bytes and len(raw) <= cap, 'intent.json_cap')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
            parse_constant=lambda _: need(False, 'intent.nonfinite'))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal('intent.json_invalid') from None
    need(canonical(value) == raw, 'intent.json_not_canonical')
    return value


def _outer_result(value):
    return (type(value) is dict and set(value) == set(OUTER_RESULT) and
            value['vmState'] == 'TERMINATED' and
            value['diskIds'] == list(DISK_IDS) and
            value['retained'] is True and value['transportClosed'] is True)


def _private_directory(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'intent.root_path')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o700, 'intent.root_identity')
    except BaseException as error:
        if 'fd' in locals():
            os.close(fd)
        if isinstance(error, OSError):
            raise Refusal('intent.root_unavailable') from None
        raise
    return fd


def _read_file(directory_fd, name, cap):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory_fd)
    except OSError:
        raise Refusal('intent.file_unavailable') from None
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600 and
             before.st_size <= cap, 'intent.file_identity')
        chunks, total = [], 0
        while total <= cap:
            part = os.read(fd, min(65536, cap + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
        after = os.fstat(fd)
        path_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        need(total == before.st_size and total <= cap and
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
              before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                      after.st_mtime_ns, after.st_ctime_ns) ==
             (path_after.st_dev, path_after.st_ino, path_after.st_size,
              path_after.st_mtime_ns, path_after.st_ctime_ns),
             'intent.file_changed')
        return b''.join(chunks)
    except OSError:
        raise Refusal('intent.file_read_failed') from None
    finally:
        os.close(fd)


def _write_once(directory_fd, name, raw, cap):
    need(type(raw) is bytes and len(raw) <= cap, 'intent.write_cap')
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
    except OSError:
        raise Refusal('intent.file_create_failed') from None
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            need(written > 0, 'intent.short_write')
            view = view[written:]
        os.fsync(fd)
    except OSError:
        raise Refusal('intent.file_write_failed') from None
    finally:
        os.close(fd)
    try:
        os.fsync(directory_fd)
    except OSError:
        raise Refusal('intent.directory_sync_failed') from None


class DurableMacCustody:
    """Opaque receipt produced only after fixed private evidence was fsynced."""
    __slots__ = ('_key', '_journal', '_digest', '_sealed')

    def __setattr__(self,name,value):
        need(not getattr(self,'_sealed',False),'intent.custody_immutable')
        object.__setattr__(self,name,value)

    def __delattr__(self,_name):
        raise Refusal('intent.custody_immutable')

    def __init__(self, key, journal, digest):
        need(key is _CUSTODY_KEY, 'intent.custody_unissued')
        self._key, self._journal, self._digest = key, journal, digest
        self._sealed=True

    def belongs_to(self, journal):
        return self._key is _CUSTODY_KEY and self._journal is journal and \
            self._digest == journal.custody_digest and \
            journal.session_fd is not None and not journal.custody_claimed

    def claimed_for(self,journal):
        return (type(self) is DurableMacCustody and self._key is _CUSTODY_KEY and
            self._journal is journal and self._digest==journal.custody_digest and
            journal.session_fd is not None and journal.custody_claimed and
            journal.pending is None and not journal.uncertain)


class DurableIntent:
    """Exclusive, nonrestartable session journal rooted in a private Mac dir."""
    def __init__(self, root, owner, context_sha256, pins_sha256):
        need(type(owner) is dict and set(owner) == OWNER_KEYS and
             type(owner.get('sessionId')) is str and
             re.fullmatch('[0-9a-f]{32}', owner['sessionId']) and
             all(type(v) is str for v in owner.values()) and
             owner['vmId'] == VM_ID and
             owner['unitName'] == 'ocv-' + owner['sessionId'] + '.service' and
             re.fullmatch('[0-9a-f]{64}', owner['guestSourceSha256']),
             'intent.owner')
        need(type(context_sha256) is str and re.fullmatch('[0-9a-f]{64}', context_sha256) and
             type(pins_sha256) is str and re.fullmatch('[0-9a-f]{64}', pins_sha256),
             'intent.source_pins')
        self.root_path = Path(root)
        self.root_fd = _private_directory(self.root_path)
        self.session_fd = self.evidence_fd = None
        self.owner = dict(owner)
        self.owner_sha256 = sha(canonical(owner))
        self.context_sha256, self.pins_sha256 = context_sha256, pins_sha256
        self.sequence, self.pending, self.uncertain = 0, None, False
        self.evidence, self.custody_digest = {}, None
        self.evidence_bytes, self.custody_claimed = 0, False
        self.final_context_sha256 = None
        self.outer_stop_state = None
        try:
            try:
                os.mkdir(owner['sessionId'], 0o700, dir_fd=self.root_fd)
            except FileExistsError:
                raise Refusal('intent.session_already_exists') from None
            os.fsync(self.root_fd)
            self.session_fd = os.open(owner['sessionId'], os.O_RDONLY | os.O_DIRECTORY |
                                      os.O_NOFOLLOW, dir_fd=self.root_fd)
            need(stat.S_IMODE(os.fstat(self.session_fd).st_mode) == 0o700,
                 'intent.session_mode')
            os.mkdir('evidence', 0o700, dir_fd=self.session_fd)
            os.fsync(self.session_fd)
            self.evidence_fd = os.open('evidence', os.O_RDONLY | os.O_DIRECTORY |
                                       os.O_NOFOLLOW, dir_fd=self.session_fd)
            _write_once(self.session_fd, 'header.json', canonical({
                'schema': 'openclaw.mac-intent-header.v1', 'owner': self.owner,
                'ownerSha256': self.owner_sha256,
                'contextSha256': context_sha256, 'pinsSha256': pins_sha256}), 16384)
        except BaseException as error:
            self.close()
            if isinstance(error, OSError):
                raise Refusal('intent.session_create_failed') from None
            raise

    def close(self):
        for name in ('evidence_fd', 'session_fd', 'root_fd'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _open(self):
        need(self.session_fd is not None and self.evidence_fd is not None,
             'intent.closed')

    def begin(self, sequence, method, request_raw):
        self._open()
        need(not self.uncertain and self.pending is None and
             type(sequence) is int and sequence == self.sequence and sequence < MAX_CALLS and
             type(method) is str and method in METHODS and
             type(request_raw) is bytes and
             len(request_raw) <= MAX_REQUEST, 'intent.replay_or_cap')
        record = {'schema': 'openclaw.mac-intent.v1', 'sequence': sequence,
                  'method': method, 'requestSha256': sha(request_raw),
                  'ownerSha256': self.owner_sha256,
                  'contextSha256': self.context_sha256,
                  'finalContextSha256': self.final_context_sha256,
                  'pinsSha256': self.pins_sha256}
        _write_once(self.session_fd, '%02d-%s.intent.json' % (sequence, method),
                    canonical(record), 16384)
        self.pending = (sequence, method)

    def bind_final_context(self, context_raw):
        """Source-owned staged context is fsynced before guest publication."""
        self._open()
        need(not self.uncertain and self.pending is None and
             self.final_context_sha256 is None and type(context_raw) is bytes and
             len(context_raw) <= 16384, 'intent.final_context_state')
        _write_once(self.session_fd, 'final-context.json', context_raw, 16384)
        self.final_context_sha256 = sha(context_raw)

    def settle(self, sequence, method, response_raw):
        self._open()
        need(not self.uncertain and self.pending == (sequence, method) and
             type(response_raw) is bytes and len(response_raw) <= MAX_RESPONSE,
             'intent.settle_state')
        stem = '%02d-%s' % (sequence, method)
        _write_once(self.session_fd, stem + '.response.bin', response_raw, MAX_RESPONSE)
        _write_once(self.session_fd, stem + '.settled.json', canonical({
            'schema': 'openclaw.mac-intent-settled.v1', 'sequence': sequence,
            'method': method, 'responseSha256': sha(response_raw)}), 16384)
        self.sequence += 1
        self.pending = None

    def mark_uncertain(self, sequence, method, code, raw=None):
        self._open()
        need(self.pending == (sequence, method) and type(code) is str and
             re.fullmatch('[a-z][a-z0-9_.]{0,95}', code), 'intent.uncertain_state')
        self.uncertain = True
        available = type(raw) is bytes and len(raw) <= MAX_RESPONSE
        sample = raw[:MAX_UNCERTAIN_SAMPLE] if available else b''
        if available:
            _write_once(self.session_fd, '%02d-%s.uncertain-response.bin' %
                        (sequence, method), sample, MAX_UNCERTAIN_SAMPLE)
        _write_once(self.session_fd, '%02d-%s.uncertain.json' % (sequence, method),
                    canonical({'schema': 'openclaw.mac-intent-uncertain.v1',
                               'sequence': sequence, 'method': method, 'reason': code,
                               'bytesAvailable': available,
                               'responseBytes': len(raw) if available else None,
                               'responseSha256': sha(raw) if available else None,
                               'sampleBytes': len(sample),
                               'sampleSha256': sha(sample) if available else None,
                               'truncated': available and len(sample) < len(raw)}), 16384)

    def preserve(self, role, raw):
        self._open()
        need(not self.uncertain and role in EVIDENCE_ROLES and role not in self.evidence and
             type(raw) is bytes and len(raw) <= EVIDENCE_CAPS[role] and
             self.evidence_bytes + len(raw) <= MAX_EVIDENCE_AGGREGATE and
             (role != 'report' or len(raw) == EVIDENCE_CAPS['report']),
             'intent.evidence_cap')
        _write_once(self.evidence_fd, role + '.bin', raw, EVIDENCE_CAPS[role])
        _write_once(self.evidence_fd, role + '.json', canonical({
            'schema': 'openclaw.mac-evidence.v1', 'role': role,
            'bytes': len(raw), 'sha256': sha(raw)}), 16384)
        self.evidence[role] = sha(raw)
        self.evidence_bytes += len(raw)

    def custody_ack(self):
        self._open()
        need(not self.uncertain and self.pending is None and
             set(self.evidence) == REQUIRED_CUSTODY and self.custody_digest is None and
             self.final_context_sha256 is not None,
             'intent.custody_incomplete')
        self._verify_evidence()
        receipt = canonical({'schema': 'openclaw.mac-custody-ack.v1',
            'ownerSha256': self.owner_sha256, 'contextSha256': self.context_sha256,
            'finalContextSha256': self.final_context_sha256,
            'roles': dict(sorted(self.evidence.items()))})
        _write_once(self.session_fd, 'custody-ack.json', receipt, 16384)
        self.custody_digest = sha(receipt)
        return DurableMacCustody(_CUSTODY_KEY, self, self.custody_digest)

    def _verify_evidence(self):
        total = 0
        for role, digest in self.evidence.items():
            raw = _read_file(self.evidence_fd, role + '.bin', EVIDENCE_CAPS[role])
            meta_raw = _read_file(self.evidence_fd, role + '.json', 16384)
            need(sha(raw) == digest and json.loads(meta_raw) == {
                'schema': 'openclaw.mac-evidence.v1', 'role': role,
                'bytes': len(raw), 'sha256': digest}, 'intent.custody_changed')
            total += len(raw)
        need(total == self.evidence_bytes and total <= MAX_EVIDENCE_AGGREGATE,
             'intent.custody_changed')

    def claim_custody_for_removal(self, permit):
        """One-use, fsynced claim immediately before the removal RPC intent."""
        self._open()
        need(type(permit) is DurableMacCustody and permit.belongs_to(self) and
             not self.uncertain and self.pending is None and
             set(self.evidence) == REQUIRED_CUSTODY,
             'intent.custody_unissued')
        self._verify_evidence()
        need(sha(_read_file(self.session_fd, 'custody-ack.json', 16384)) ==
             self.custody_digest, 'intent.custody_changed')
        need(sha(_read_file(self.session_fd, 'final-context.json', 16384)) ==
             self.final_context_sha256, 'intent.custody_changed')
        _write_once(self.session_fd, 'custody-removal-claim.json', canonical({
            'schema': 'openclaw.mac-custody-removal-claim.v1',
            'custodySha256': self.custody_digest,
            'ownerSha256': self.owner_sha256}), 16384)
        self.custody_claimed = True

    def begin_outer_stop(self):
        """Separate durable intent; allowed even if the guest RPC is poisoned."""
        self._open()
        need(self.outer_stop_state is None, 'intent.outer_stop_consumed')
        _write_once(self.session_fd, 'outer-stop.intent.json', canonical({
            'schema': 'openclaw.mac-owned-outer-stop-intent.v1',
            'ownerSha256': self.owner_sha256}), 16384)
        self.outer_stop_state = 'pending'

    def settle_outer_stop(self, receipt_raw):
        self._open()
        need(self.outer_stop_state == 'pending' and type(receipt_raw) is bytes and
             len(receipt_raw) <= 16384 and
             _outer_result(_json(receipt_raw, 16384)),
             'intent.outer_stop_state')
        _write_once(self.session_fd, 'outer-stop.receipt.bin', receipt_raw, 16384)
        _write_once(self.session_fd, 'outer-stop.settled.json', canonical({
            'schema': 'openclaw.mac-owned-outer-stop-settled.v1',
            'receiptSha256': sha(receipt_raw)}), 16384)
        self.outer_stop_state = 'settled'

    def mark_outer_stop_uncertain(self):
        self._open()
        need(self.outer_stop_state == 'pending', 'intent.outer_stop_state')
        self.outer_stop_state = 'uncertain'
        _write_once(self.session_fd, 'outer-stop.uncertain.json', canonical({
            'schema': 'openclaw.mac-owned-outer-stop-uncertain.v1',
            'ownerSha256': self.owner_sha256}), 16384)

    @classmethod
    def audit_existing(cls, root, session_id):
        """Read-only crash summary. It can never resume guest dispatch."""
        need(type(session_id) is str and re.fullmatch('[0-9a-f]{32}', session_id),
             'intent.session_id')
        root_fd = _private_directory(root)
        try:
            fd = os.open(session_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=root_fd)
            try:
                identity = os.fstat(fd)
                need(stat.S_ISDIR(identity.st_mode) and identity.st_uid == os.getuid() and
                     stat.S_IMODE(identity.st_mode) == 0o700,
                     'intent.audit_session_identity')
                header = _json(_read_file(fd, 'header.json', 16384), 16384)
                need(type(header) is dict and set(header) ==
                     {'schema','owner','ownerSha256','contextSha256','pinsSha256'} and
                     header.get('schema') ==
                     'openclaw.mac-intent-header.v1' and
                     type(header.get('owner')) is dict and
                     set(header['owner']) == OWNER_KEYS and
                     header['owner'].get('sessionId') == session_id and
                     header['owner'].get('vmId') == VM_ID and
                     header['owner'].get('unitName') ==
                     'ocv-' + session_id + '.service',
                     'intent.audit_header')
                names = []
                with os.scandir(fd) as entries:
                    for item in entries:
                        need(len(names) < MAX_AUDIT_ENTRIES, 'intent.audit_entry_cap')
                        names.append(item.name)
                need(len(set(names)) == len(names), 'intent.audit_duplicate_entry')
                names = set(names)
                evidence_info = os.stat('evidence', dir_fd=fd, follow_symlinks=False)
                need(stat.S_ISDIR(evidence_info.st_mode) and
                     evidence_info.st_uid == os.getuid() and
                     stat.S_IMODE(evidence_info.st_mode) == 0o700,
                     'intent.audit_evidence_dir')
                intents = sorted(name for name in names if name.endswith('.intent.json')
                                 and name != 'outer-stop.intent.json')
                final_sha = sha(_read_file(fd, 'final-context.json', 16384)) if \
                    'final-context.json' in names else None
                need(len(intents) <= MAX_CALLS and
                     header.get('ownerSha256') == sha(canonical(header.get('owner'))) and
                     type(header.get('contextSha256')) is str and
                     re.fullmatch('[0-9a-f]{64}', header['contextSha256']) and
                     type(header.get('pinsSha256')) is str and
                     re.fullmatch('[0-9a-f]{64}', header['pinsSha256']),
                     'intent.audit_header')
                unresolved = []
                for sequence, name in enumerate(intents):
                    stem = name[:-len('.intent.json')]
                    intent = _json(_read_file(fd, name, 16384), 16384)
                    need(type(intent) is dict and set(intent) ==
                         {'schema','sequence','method','requestSha256',
                          'ownerSha256','contextSha256','finalContextSha256',
                          'pinsSha256'} and intent.get('schema') ==
                         'openclaw.mac-intent.v1' and
                         type(intent.get('sequence')) is int and
                         intent['sequence'] == sequence and
                         type(intent.get('method')) is str and
                         intent['method'] in METHODS and
                         type(intent.get('requestSha256')) is str and
                         re.fullmatch('[0-9a-f]{64}', intent['requestSha256']) and
                         intent.get('ownerSha256') == header['ownerSha256'] and
                         intent.get('contextSha256') == header['contextSha256'] and
                         intent.get('finalContextSha256') ==
                         (None if sequence < 3 else final_sha) and
                         intent.get('pinsSha256') == header['pinsSha256'] and
                         stem == '%02d-%s' % (intent['sequence'], intent['method']),
                         'intent.audit_intent')
                    if stem + '.settled.json' not in names or stem + '.uncertain.json' in names:
                        unresolved.append(stem)
                    else:
                        settled = _json(_read_file(fd, stem + '.settled.json', 16384), 16384)
                        response = _read_file(fd, stem + '.response.bin', MAX_RESPONSE)
                        need(settled == {'schema': 'openclaw.mac-intent-settled.v1',
                            'sequence': intent['sequence'], 'method': intent['method'],
                            'responseSha256': sha(response)}, 'intent.audit_settled')
                expected = {'header.json', 'evidence'}
                expected |= set(intents)
                for name in intents:
                    stem = name[:-len('.intent.json')]
                    expected |= {n for n in names if n in {
                        stem + '.response.bin', stem + '.settled.json',
                        stem + '.uncertain.json', stem + '.uncertain-response.bin'}}
                    if stem + '.uncertain.json' in names:
                        uncertain = _json(_read_file(fd, stem + '.uncertain.json', 16384), 16384)
                        need(uncertain.get('schema') == 'openclaw.mac-intent-uncertain.v1' and
                             uncertain.get('sequence') == int(stem[:2]) and
                             uncertain.get('method') == stem[3:] and
                             type(uncertain.get('bytesAvailable')) is bool,
                             'intent.audit_uncertain')
                        if uncertain['bytesAvailable']:
                            sample = _read_file(fd, stem + '.uncertain-response.bin',
                                                MAX_UNCERTAIN_SAMPLE)
                            need(uncertain.get('sampleBytes') == len(sample) and
                                 uncertain.get('sampleSha256') == sha(sample),
                                 'intent.audit_uncertain_sample')
                        else:
                            need(stem + '.uncertain-response.bin' not in names,
                                 'intent.audit_uncertain_sample')
                if 'custody-ack.json' in names:
                    expected.add('custody-ack.json')
                    need('final-context.json' in names, 'intent.audit_custody_claim')
                if 'final-context.json' in names:
                    expected.add('final-context.json')
                    context_raw = _read_file(fd, 'final-context.json', 16384)
                    need(type(_json(context_raw, 16384)) is dict,
                         'intent.audit_final_context')
                if 'custody-removal-claim.json' in names:
                    need('custody-ack.json' in names, 'intent.audit_custody_claim')
                    expected.add('custody-removal-claim.json')
                outer_state = 'not_requested'
                if 'outer-stop.intent.json' in names:
                    expected.add('outer-stop.intent.json')
                    outer_intent = _json(_read_file(fd, 'outer-stop.intent.json', 16384), 16384)
                    need(outer_intent == {
                        'schema': 'openclaw.mac-owned-outer-stop-intent.v1',
                        'ownerSha256': header['ownerSha256']},
                        'intent.audit_outer_intent')
                    outer_state = 'uncertain_no_retry'
                    if 'outer-stop.receipt.bin' in names:
                        expected.add('outer-stop.receipt.bin')
                    if 'outer-stop.uncertain.json' in names:
                        expected.add('outer-stop.uncertain.json')
                        outer_uncertain = _json(_read_file(fd,
                            'outer-stop.uncertain.json', 16384), 16384)
                        need(outer_uncertain == {
                            'schema': 'openclaw.mac-owned-outer-stop-uncertain.v1',
                            'ownerSha256': header['ownerSha256']},
                            'intent.audit_outer_uncertain')
                    if 'outer-stop.settled.json' in names:
                        expected.add('outer-stop.settled.json')
                        need('outer-stop.uncertain.json' not in names,
                             'intent.audit_outer_conflict')
                        settled = _json(_read_file(fd, 'outer-stop.settled.json', 16384), 16384)
                        receipt = _read_file(fd, 'outer-stop.receipt.bin', 16384)
                        need(settled == {'schema': 'openclaw.mac-owned-outer-stop-settled.v1',
                            'receiptSha256': sha(receipt)} and
                            _outer_result(_json(receipt, 16384)),
                            'intent.audit_outer_settled')
                        outer_state = 'settled_no_retry'
                need(names == expected, 'intent.audit_extra_member')
                return {'schema': 'openclaw.mac-intent-audit.v1',
                        'sessionId': session_id, 'intentCount': len(intents),
                        'status': 'uncertain_no_retry' if unresolved else 'settled_no_resume',
                        'unresolved': unresolved, 'dispatchPermitted': False,
                        'ownedOuterStopStatus': outer_state,
                        'requiresOwnedOuterStop': outer_state == 'not_requested',
                        'requiresOwnedOuterReconciliation':
                            outer_state == 'uncertain_no_retry'}
            finally:
                os.close(fd)
        finally:
            os.close(root_fd)


if __name__ == '__main__':
    raise SystemExit('durable_intent_library_only')
