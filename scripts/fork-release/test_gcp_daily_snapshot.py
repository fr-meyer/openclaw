"""Lifecycle boundary proof with synthetic Compute resources and host commands.

No cloud, Docker, systemd, mount, credential, or candidate subprocess runs here.
"""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gcp_daily_snapshot as daily
import release

API = 'https://compute.googleapis.com/compute/v1/'


class FakeCloud:
    def __init__(self, plan):
        self.plan = plan
        self.vm_path = daily.link(plan, 'instances', plan['instance']['name'])
        self.source_path = daily.link(plan, 'disks', plan['sourceDisk']['name'])
        self.boot_path = daily.link(plan, 'disks', 'production-boot')
        self.policy_path = daily.canonical_link(plan['snapshotPolicy'])
        self.snapshot_path = daily.snapshot_link(plan, 'daily-original')
        self.snapshot = {
            'id': '401', 'name': 'daily-original', 'selfLink': API + self.snapshot_path,
            'status': 'READY', 'autoCreated': True, 'creationTimestamp': '2026-10-21T01:00:00Z',
            'sourceDisk': API + self.source_path, 'sourceDiskId': plan['sourceDisk']['id'],
            'sourceSnapshotSchedulePolicy': plan['snapshotPolicy'], 'sourceSnapshotSchedulePolicyId': '501',
            'diskSizeGb': '384',
        }
        self.policy = {'id': '501', 'selfLink': API + self.policy_path,
                       'snapshotSchedulePolicy': {'schedule': {'dailySchedule': {'daysInCycle': 1, 'startTime': '00:00'}}}}
        self.vm = {'id': plan['instance']['id'], 'status': 'RUNNING', 'disks': [
            {'source': API + self.source_path, 'deviceName': 'production-data', 'boot': False,
             'autoDelete': False, 'mode': 'READ_WRITE'},
            {'source': API + self.boot_path, 'deviceName': 'production-boot', 'boot': True,
             'autoDelete': True, 'mode': 'READ_WRITE'},
        ]}
        self.disks = {
            self.source_path: {'id': plan['sourceDisk']['id'], 'selfLink': API + self.source_path,
                               'status': 'READY', 'users': [API + self.vm_path]},
            self.boot_path: {'id': '202', 'selfLink': API + self.boot_path,
                             'status': 'READY', 'users': [API + self.vm_path]},
        }
        self.operations, self.calls, self.mutations = {}, [], []
        self.lose_reply = False
        self.operations_visible = True
        self.fail_created_readback = False
        self.failed_readback_path = None
        self.fail_kind = None
        self.operation_status = 'DONE'

    def request(self, method, path, body=None, query=None, allow_missing=False):
        query = query or {}
        call = {'method': method, 'path': path, 'body': copy.deepcopy(body), 'query': dict(query)}
        self.calls.append(call)
        if method == 'GET':
            if path == self.vm_path:
                result = self.vm
            elif path == self.policy_path:
                result = self.policy
            elif path == self.snapshot_path:
                result = self.snapshot
            elif path == f"projects/{self.plan['project']}/global/snapshots":
                result = {'items': [self.snapshot]}
            elif path.endswith('/operations'):
                request_id = query['filter'].split('"')[1]
                result = {'items': [op for op in self.operations.values()
                                    if self.operations_visible and op['clientOperationId'] == request_id]}
            elif '/operations/' in path:
                result = self.operations.get(path.rsplit('/', 1)[-1]) if self.operations_visible else None
            elif path in self.disks or '/disks/' in path:
                if path == self.failed_readback_path:
                    self.failed_readback_path = None
                    raise release.Refusal('synthetic.readback_unknown')
                result = self.disks.get(path)
            else:
                raise AssertionError('Unexpected read path: ' + path)
            if result is None and not allow_missing:
                raise AssertionError('Unexpected missing resource: ' + path)
            return copy.deepcopy(result)

        self.mutations.append(call)
        request_id = query['requestId']
        if method == 'POST' and path.endswith('/disks'):
            target = path + '/' + body['name']
            if target in self.disks:
                raise AssertionError('Duplicate restore dispatch')
            identity = '301' if body['labels']['openclaw-role'] == 'candidate' else '302'
            if self.fail_kind != 'insert':
                self.disks[target] = {'id': identity, 'selfLink': API + target, 'status': 'READY',
                                      'sourceSnapshot': body['sourceSnapshot'], 'sourceSnapshotId': self.snapshot['id'],
                                      'sizeGb': body['sizeGb'], 'labels': copy.deepcopy(body['labels']), 'users': []}
            kind = 'insert'
            if self.fail_created_readback:
                self.failed_readback_path = target
        elif method == 'POST' and path == self.vm_path + '/attachDisk':
            source = daily.canonical_link(body['source'])
            if self.fail_kind != 'attachDisk':
                self.vm['disks'].append(copy.deepcopy(body))
                self.disks[source]['users'] = [API + self.vm_path]
            target, identity, kind = self.vm_path, self.vm['id'], 'attachDisk'
        elif method == 'POST' and path == self.vm_path + '/detachDisk':
            rows = [item for item in self.vm['disks'] if item['deviceName'] == query['deviceName']]
            if len(rows) != 1 or rows[0]['boot']:
                raise AssertionError('Unexpected or boot detach')
            if self.fail_kind != 'detachDisk':
                self.vm['disks'].remove(rows[0])
                self.disks[daily.canonical_link(rows[0]['source'])]['users'] = []
            target, identity, kind = self.vm_path, self.vm['id'], 'detachDisk'
        elif method == 'DELETE' and path in self.disks:
            if path in (self.source_path, self.boot_path):
                raise AssertionError('Production delete')
            target, identity, kind = path, self.disks[path]['id'], 'delete'
            if self.fail_kind != 'delete':
                del self.disks[path]
        else:
            raise AssertionError('Unexpected mutation: ' + method + ' ' + path)
        native = {'kind': 'compute#operation', 'name': 'operation-' + str(len(self.operations) + 1),
                  'id': str(800 + len(self.operations)), 'clientOperationId': request_id,
                  'operationType': kind, 'targetLink': API + target, 'targetId': identity, 'status': self.operation_status,
                  'warnings': [{'code': 'SYNTHETIC_NONFATAL_NOTICE'}]}
        if self.fail_kind == kind:
            native['error'] = {'errors': [{'code': 'SYNTHETIC_NATIVE_FAILURE'}]}
            if kind == 'insert':
                del native['targetId']
            self.fail_kind = None
        self.operations[native['name']] = native
        if self.lose_reply:
            self.lose_reply = False
            raise release.Refusal('synthetic.reply_lost_after_acceptance')
        return copy.deepcopy(native)


class DailySnapshotTests(unittest.TestCase):
    def setUp(self):
        # A private directory is the artifact boundary under test, not a real disk.
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'control'
        self.root.mkdir(mode=0o700)
        self.op = self.root / ('a' * 32)
        self.op.mkdir(mode=0o700)
        self.plan = {
            'schema': 'openclaw.gcp-daily-snapshot.v1', 'operationId': self.op.name,
            'toolingSha': '1' * 40, 'createdAt': '2026-10-21T00:00:00Z', 'expiresAt': '2026-10-21T23:00:00Z',
            'project': 'synthetic-project', 'zone': 'asia-northeast3-b',
            'instance': {'name': 'production-vm', 'id': '101'},
            'sourceDisk': {'name': 'production-data', 'id': '201'},
            'snapshotPolicy': API + 'projects/synthetic-project/regions/asia-northeast3/resourcePolicies/daily',
            'baselineImage': {'sourceSha': '2' * 40, 'version': '2026.9.4',
                              'indexDigest': 'sha256:' + '3' * 64, 'imageDigest': 'sha256:' + '4' * 64,
                              'configDigest': 'sha256:' + '5' * 64, 'gatewayProbeContract': 'healthz-readyz-v1'},
            'maxSnapshotAgeSeconds': 86400,
            'resources': {'diskType': 'pd-balanced', 'maxDiskGiB': 384, 'estimatedCostMicrousd': 1,
                          'approvedCostMicrousd': 100, 'memoryBytes': 24 << 30, 'cpus': 4,
                          'readBps': 128 << 20, 'writeBps': 32 << 20, 'minMemoryAvailableBytes': 25 << 30,
                          'minRootFreeBytes': 2 << 30, 'minDataFreeBytes': 8 << 30, 'timeoutSeconds': 3600},
        }
        self.cloud = FakeCloud(self.plan)
        _, _, protected = daily.observe_production(self.cloud, self.plan)
        self.run = {'plan': self.plan, 'snapshot': copy.deepcopy(self.cloud.snapshot),
                    'production': protected, 'image': {}, 'ownerUid': 1000, 'ownerGid': 1000}
        daily.record(self.op, 'run.json', self.run)
        self.mounts, self.host_calls = [], []
        self.native_host = daily.host
        for owner, name, value in (
            (daily, 'ROOT', self.root), (daily, 'MOUNTS', self.base / 'mounts'),
        ):
            guard = patch.object(owner, name, value)
            guard.start()
            self.addCleanup(guard.stop)
        for owner, name, effect in (
            (daily, 'load', lambda op: (Path(op), self.run)),
            (daily, 'now', lambda: datetime(2026, 10, 21, 2, tzinfo=timezone.utc)),
            (daily, 'host', self.fake_host),
            (daily, 'mounted', lambda: copy.deepcopy(self.mounts)),
            (daily, 'device_info', lambda run, generation: self.device(generation)),
            (daily.trial, 'docker', lambda args, **kwargs: b''),
        ):
            guard = patch.object(owner, name, side_effect=effect)
            guard.start()
            self.addCleanup(guard.stop)
        # Any unmocked command is a fixture defect, never permission to run it.
        guard = patch.object(daily.subprocess, 'run', side_effect=AssertionError('Unmocked host command'))
        guard.start()
        self.addCleanup(guard.stop)

    def device(self, generation):
        number = '16' if generation == 'candidate' else '32'
        return {'devicePath': '/dev/synthetic-' + generation, 'filesystemPath': '/dev/synthetic-' + generation,
                'deviceMajorMinor': '8:' + number, 'filesystemMajorMinor': '8:' + number,
                'filesystemType': 'ext4'}

    def fake_host(self, args, timeout=30):
        self.host_calls.append(list(args))
        if args[:4] == ['sudo', '-n', 'install', '-d']:
            Path(args[-1]).mkdir(parents=True, mode=0o700)
        elif args[:3] == ['sudo', '-n', 'mount']:
            generation = Path(args[-1]).name
            self.mounts.append({'source': args[-2], 'target': args[-1],
                                'maj:min': self.device(generation)['filesystemMajorMinor']})
        elif args[:3] == ['sudo', '-n', 'umount']:
            self.mounts[:] = [row for row in self.mounts if row['target'] != args[-1]]
        else:
            raise AssertionError('Unexpected host command: ' + repr(args))
        return b''

    def perform(self, verb, generation='candidate'):
        action = daily.action(self.op, self.run, verb, generation, self.cloud)
        return daily.perform(self.op, verb, generation, daily.challenge(action), self.cloud)

    def archive(self, generation='candidate'):
        value = daily.archive_diagnostics(self.op, generation)
        self.assertFalse(value['containsDatabaseCopy'])
        self.assertFalse(value['fullDiskSnapshotCreated'])
        return value

    def test_daily_entry_admits_only_explicit_reviewed_io_pairs(self):
        daily.validate_plan(self.plan)
        self.plan['resources'].update(readBps=256 << 20, writeBps=64 << 20)
        daily.validate_plan(self.plan)
        for key, value in (('readBps', 512 << 20), ('writeBps', 32 << 20), ('memoryBytes', 32 << 30)):
            changed = copy.deepcopy(self.plan)
            changed['resources'][key] = value
            with self.assertRaisesRegex(release.Refusal, 'trial.limits.unreviewed_envelope'):
                daily.validate_plan(changed)
        self.assertFalse(self.cloud.mutations)

    def test_daily_entry_matches_trial_low_memory_admission_before_restore(self):
        self.plan['resources'].update(memoryBytes=16 << 30, readBps=256 << 20,
                                      writeBps=64 << 20, minMemoryAvailableBytes=20 << 30)
        daily.validate_plan(self.plan)
        for gib in (16, 19, 21):
            changed = copy.deepcopy(self.plan)
            changed['resources']['minMemoryAvailableBytes'] = gib << 30
            with self.assertRaisesRegex(release.Refusal, 'daily.resources.native'):
                daily.validate_plan(changed)
        self.assertFalse(self.cloud.mutations)

    def test_daily_entry_requires_explicit_read320_write128_pair(self):
        resources = self.plan['resources']
        resources.update(memoryBytes=16 << 30, readBps=320 << 20,
                         writeBps=128 << 20, minMemoryAvailableBytes=20 << 30)
        daily.validate_plan(self.plan)
        for read, write in ((512, 128), (320, 64), (256, 128)):
            changed = copy.deepcopy(self.plan)
            changed['resources'].update(readBps=read << 20, writeBps=write << 20)
            with self.subTest(read=read, write=write), self.assertRaisesRegex(
                    release.Refusal, 'trial.limits.unreviewed_envelope'):
                daily.validate_plan(changed)
        self.assertFalse(self.cloud.mutations)

    def test_full_snapshot_lifecycle_uses_distinct_sequential_candidate_and_rollback_disks(self):
        protected = copy.deepcopy(self.cloud.vm['disks'])
        snapshot = copy.deepcopy(self.cloud.snapshot)
        restored = self.perform('restore')
        self.assertEqual(restored['resource']['sourceSnapshotId'], snapshot['id'])
        with self.assertRaisesRegex(release.Refusal, 'daily.rollback.candidate_not_deleted'):
            self.perform('restore', 'rollback')
        for verb in ('attach', 'mount', 'unmount', 'detach'):
            self.assertEqual(self.perform(verb)['state'], 'succeeded')
        self.archive()
        self.assertTrue(self.perform('delete')['resource']['deleted'])
        self.assertEqual(self.perform('restore', 'rollback')['resource']['sourceSnapshotId'], snapshot['id'])
        for verb in ('attach', 'mount', 'unmount', 'detach'):
            self.perform(verb, 'rollback')
        self.archive('rollback')
        self.perform('delete', 'rollback')
        creates = [call for call in self.cloud.mutations if call['method'] == 'POST' and call['path'].endswith('/disks')]
        self.assertEqual([call['body']['name'] for call in creates],
                         [daily.disk_name(self.run, generation) for generation in daily.GENERATIONS])
        for call in creates:
            self.assertEqual(call['body']['sourceSnapshot'], snapshot['selfLink'])
            self.assertEqual(call['body']['sizeGb'], snapshot['diskSizeGb'])
            self.assertEqual(set(call['body']), {'name', 'sizeGb', 'type', 'sourceSnapshot', 'labels'})
        self.assertEqual(self.cloud.vm['disks'], protected)
        self.assertEqual(self.cloud.snapshot, snapshot)
        self.assertEqual(set(self.cloud.disks), {self.cloud.source_path, self.cloud.boot_path})
        self.assertEqual([args[2] for args in self.host_calls], ['install', 'mount', 'umount'] * 2)
        self.assertTrue(all('-l' not in args and '-f' not in args for args in self.host_calls))

    def test_lost_restore_reply_reconciles_without_a_second_post(self):
        self.cloud.lose_reply, self.cloud.operations_visible = True, False
        result = self.perform('restore')
        self.assertEqual(result['state'], 'unknown')
        self.assertTrue(daily.action_file(self.op, 'restore-candidate', 'dispatch-unknown').exists())
        self.assertEqual(len(self.cloud.mutations), 1)
        self.cloud.operations_visible = True
        result = daily.perform(self.op, 'restore', 'candidate', 'no-second-approval-or-dispatch', self.cloud)
        self.assertEqual(result['state'], 'succeeded')
        self.assertEqual(len(self.cloud.mutations), 1)
        intent = daily.durable.read_private(daily.action_file(self.op, 'restore-candidate', 'intent'))
        self.assertEqual(result['nativeOperation']['clientOperationId'], intent['requestId'])
        self.assertFalse(result['promotionAuthorized'])

    def test_native_done_receipt_survives_readback_failure_and_operation_expiration(self):
        self.cloud.fail_created_readback = True
        with self.assertRaisesRegex(release.Refusal, 'synthetic.readback_unknown'):
            self.perform('restore')
        terminal = daily.action_file(self.op, 'restore-candidate', 'native-terminal')
        retained = daily.durable.read_private(terminal)
        self.assertEqual(retained['status'], 'DONE')
        self.assertTrue(retained['warnings'])
        self.cloud.operations.clear()
        self.cloud.operations_visible = False
        calls_before = len(self.cloud.calls)
        result = daily.perform(self.op, 'restore', 'candidate', 'reconcile-only', self.cloud)
        self.assertEqual(result['nativeOperation'], retained)
        self.assertEqual(len(self.cloud.mutations), 1)
        self.assertFalse(any('/operations' in call['path'] for call in self.cloud.calls[calls_before:]))

    def test_lost_mount_and_unmount_response_reconciles_native_state_without_redispatch(self):
        self.perform('restore')
        self.perform('attach')
        original_record = daily.record
        for verb in ('mount', 'unmount'):
            with self.subTest(verb=verb):
                lost = []
                def lose_response_once(op, name, value):
                    if name == verb + '-candidate.response.json' and not lost:
                        lost.append(name)
                        raise OSError('Synthetic response write loss after host success')
                    return original_record(op, name, value)
                with patch.object(daily, 'record', side_effect=lose_response_once):
                    result = self.perform(verb)
                self.assertTrue(lost)
                self.assertEqual(result['state'], 'succeeded')
                self.assertTrue(result['resource']['reconciledFromNativeState'])
                intent = daily.durable.read_private(daily.action_file(self.op, verb + '-candidate', 'intent'))
                self.assertEqual(intent['device'], self.device('candidate'))
                self.assertEqual(result['resource']['diskId'], intent['diskId'])
                self.assertEqual(result['resource']['device'], intent['device'])
                calls = copy.deepcopy(self.host_calls)
                replay = daily.perform(self.op, verb, 'candidate', 'observation-only', self.cloud)
                self.assertEqual(replay, result)
                self.assertEqual(self.host_calls, calls)
        self.assertEqual([args[2] for args in self.host_calls], ['install', 'mount', 'umount'])
        self.assertFalse(self.mounts)

    def test_failed_precreate_service_uses_shared_exact_proof_and_refuses_uncertainty(self):
        location = self.base / 'precreate-trial'
        location.mkdir(mode=0o700)
        daily.record(location, 'start-intent.json', {'requested': True})
        daily.record(location, 'intent.json', {'synthetic': 'private-trial-authority'})
        intent_hash = daily.hash_bytes(daily.durable.private_bytes(location / 'intent.json'))
        observed = {'state': 'failed', 'result': {
            'cleanup': 'not_started', 'containerId': None, 'nativeState': None,
        }}
        with patch.object(daily.trial, 'status', return_value=observed), \
             patch.object(daily.trial, 'inspect_container') as inspect, \
             patch.object(daily.durable, 'prove_trial_no_create_failure', return_value=observed['result']) as proof:
            self.assertEqual(daily.settled_check(location), observed)
            proof.assert_called_once_with(location, intent_hash)
            proof.side_effect = release.Refusal('synthetic.create_dispatch_uncertain')
            with self.assertRaisesRegex(release.Refusal, 'synthetic.create_dispatch_uncertain'):
                daily.settled_check(location)
            proof.side_effect = None
            proof.return_value = {**observed['result'], 'containerId': 'a' * 64}
            with self.assertRaisesRegex(release.Refusal, 'daily.native.precreate_proof_changed'):
                daily.settled_check(location)
            inspect.assert_not_called()

    def test_candidate_snapshot_freshness_is_rechecked_after_approval_before_dispatch(self):
        self.plan['maxSnapshotAgeSeconds'] = 3600
        (self.op / 'run.json').write_bytes(daily.durable.encode(self.run))
        approved = daily.challenge(daily.action(self.op, self.run, 'restore', 'candidate', self.cloud))
        with patch.object(daily, 'now', return_value=datetime(2026, 10, 21, 4, tzinfo=timezone.utc)), \
             self.assertRaisesRegex(release.Refusal, 'daily.snapshot.stale_at_restore'):
            daily.perform(self.op, 'restore', 'candidate', approved, self.cloud)
        self.assertFalse(self.cloud.mutations)
        self.assertFalse(daily.action_file(self.op, 'restore-candidate', 'intent').exists())

    def test_rollback_uses_the_original_snapshot_after_its_candidate_age_limit(self):
        self.plan['maxSnapshotAgeSeconds'] = 3600
        (self.op / 'run.json').write_bytes(daily.durable.encode(self.run))
        original_snapshot = copy.deepcopy(self.run['snapshot'])
        self.perform('restore')
        self.archive()
        self.perform('delete')
        with patch.object(daily, 'now', return_value=datetime(2026, 10, 21, 4, tzinfo=timezone.utc)):
            result = self.perform('restore', 'rollback')
        self.assertEqual(result['state'], 'succeeded')
        self.assertEqual(result['resource']['sourceSnapshotId'], original_snapshot['id'])
        self.assertEqual(self.cloud.mutations[-1]['body']['sourceSnapshot'], original_snapshot['selfLink'])

    def test_changed_production_identity_or_protected_attachment_prevents_dispatch(self):
        approved = daily.challenge(daily.action(self.op, self.run, 'restore', 'candidate', self.cloud))
        cases = [(self.cloud.vm, 'id', '999'),
                 (self.cloud.disks[self.cloud.source_path], 'id', '999'),
                 (self.cloud.disks[self.cloud.boot_path], 'id', '999'),
                 (self.cloud.vm['disks'][1], 'deviceName', 'replaced-boot')]
        for owner, field, changed in cases:
            with self.subTest(field=field):
                original = owner[field]
                owner[field] = changed
                try:
                    with self.assertRaises(release.Refusal):
                        daily.perform(self.op, 'restore', 'candidate', approved, self.cloud)
                finally:
                    owner[field] = original
        self.assertFalse(self.cloud.mutations)
        self.assertFalse(daily.action_file(self.op, 'restore-candidate', 'intent').exists())

    def test_same_labels_and_snapshot_cannot_adopt_a_recreated_owned_disk(self):
        self.perform('restore')
        approved = daily.challenge(daily.action(self.op, self.run, 'attach', 'candidate', self.cloud))
        target = daily.link(self.plan, 'disks', daily.disk_name(self.run, 'candidate'))
        self.cloud.disks[target]['id'] = '999'
        with self.assertRaisesRegex(release.Refusal, 'daily.disk.incarnation_changed'):
            daily.perform(self.op, 'attach', 'candidate', approved, self.cloud)
        self.assertEqual(len(self.cloud.mutations), 1)

    def test_delete_requires_diagnostics_and_no_active_attachment_or_container(self):
        self.perform('restore')
        with self.assertRaisesRegex(release.Refusal, 'daily.diagnostics.not_retained'):
            daily.perform(self.op, 'delete', 'candidate', 'cannot-approve-missing-evidence', self.cloud)
        self.archive()
        container = 'a' * 64
        source = str(daily.mount_root(self.op, 'candidate') / 'state')
        def docker(args, **kwargs):
            return (container + '\n').encode() if args[0] == 'ps' else json.dumps([{'Source': source}]).encode()
        with patch.object(daily.trial, 'docker', side_effect=docker), self.assertRaisesRegex(release.Refusal, 'daily.disk.active_container'):
            daily.perform(self.op, 'delete', 'candidate', 'cannot-approve-active-container', self.cloud)
        self.perform('attach')
        with self.assertRaisesRegex(release.Refusal, 'daily.disk.in_use'):
            daily.perform(self.op, 'delete', 'candidate', 'cannot-approve-attached-disk', self.cloud)
        self.assertFalse(any(call['method'] == 'DELETE' for call in self.cloud.mutations))

    def test_delete_rejects_malformed_and_wrong_run_diagnostics(self):
        self.perform('restore')
        file = self.op / 'candidate.diagnostics.json'
        wrong = {'schema': 'openclaw.daily-diagnostics.v1', 'generation': 'candidate',
                 'runSha256': 'f' * 64, 'checks': {}, 'containsDatabaseCopy': False,
                 'fullDiskSnapshotCreated': False, 'at': '2026-10-21T02:00:00Z'}
        for raw in (b'', daily.durable.encode(wrong)):
            with self.subTest(raw=raw):
                file.write_bytes(raw)
                file.chmod(0o600)
                with self.assertRaises((release.Refusal, ValueError)):
                    daily.action(self.op, self.run, 'delete', 'candidate', self.cloud)
        self.assertFalse(any(call['method'] == 'DELETE' for call in self.cloud.mutations))

    def test_completed_restore_must_remain_bound_to_its_original_intent(self):
        self.perform('restore')
        file = daily.action_file(self.op, 'restore-candidate', 'result')
        changed = daily.durable.read_private(file)
        changed['intentSha256'] = 'f' * 64
        file.write_bytes(daily.durable.encode(changed))
        with self.assertRaisesRegex(release.Refusal, 'daily.prerequisite.binding'):
            daily.action(self.op, self.run, 'attach', 'candidate', self.cloud)
        self.assertEqual(len(self.cloud.mutations), 1)

    def test_closed_lifecycle_refuses_a_new_restore_before_dispatch(self):
        closed = daily.close(self.op, self.cloud)
        self.assertEqual(closed['state'], 'closed_without_qualification')
        with self.assertRaisesRegex(release.Refusal, 'daily.operation.closed'):
            daily.perform(self.op, 'restore', 'candidate', 'cannot-reopen-closed-run', self.cloud)
        self.assertFalse(self.cloud.mutations)
        self.assertFalse(daily.action_file(self.op, 'restore-candidate', 'intent').exists())

    def test_failed_insert_is_retained_and_closes_only_after_fresh_disk_absence(self):
        self.cloud.fail_kind = 'insert'
        result = self.perform('restore')
        self.assertEqual(result['state'], 'failed')
        self.assertNotIn('targetId', result['nativeOperation'])
        terminal = daily.durable.read_private(daily.action_file(self.op, 'restore-candidate', 'native-terminal'))
        self.assertEqual(result['nativeOperation'], terminal)
        self.assertEqual(daily.perform(self.op, 'restore', 'candidate', 'observe-only', self.cloud)['state'], 'failed')
        target = daily.link(self.plan, 'disks', daily.disk_name(self.run, 'candidate'))
        self.cloud.disks[target] = {'id': '999'}
        with self.assertRaisesRegex(release.Refusal, 'daily.close.resource_unsettled'):
            daily.close(self.op, self.cloud)
        del self.cloud.disks[target]
        closed = daily.close(self.op, self.cloud)
        self.assertTrue(closed['noOwnedResources'])
        self.assertEqual(closed['state'], 'closed_without_qualification')
        self.assertEqual(len(self.cloud.mutations), 1)

    def test_failed_attach_allows_owned_cleanup_without_a_speculative_detach(self):
        protected = copy.deepcopy(self.cloud.vm['disks'])
        self.perform('restore')
        self.cloud.fail_kind = 'attachDisk'
        self.assertEqual(self.perform('attach')['state'], 'failed')
        self.archive()
        self.assertTrue(self.perform('delete')['resource']['deleted'])
        self.assertEqual(self.cloud.vm['disks'], protected)
        self.assertFalse(any(call['path'].endswith('/detachDisk') for call in self.cloud.mutations))
        self.assertEqual([call['method'] for call in self.cloud.mutations], ['POST', 'POST', 'DELETE'])

    def test_never_mounted_disk_can_detach_and_delete_with_fresh_absence_proof(self):
        self.perform('restore')
        self.perform('attach')
        self.assertEqual(self.perform('detach')['state'], 'succeeded')
        intent = daily.durable.read_private(daily.action_file(self.op, 'detach-candidate', 'intent'))
        self.assertEqual(intent['unmountedObservation']['device'], self.device('candidate'))
        self.assertFalse(intent['unmountedObservation']['mounted'])
        self.archive()
        self.assertTrue(self.perform('delete')['resource']['deleted'])
        self.assertFalse(self.host_calls)
        for verb in ('mount', 'unmount'):
            self.assertFalse(daily.action_file(self.op, verb + '-candidate', 'intent').exists())
        self.assertTrue(daily.close(self.op, self.cloud)['noOwnedResources'])

    def test_native_mount_nonzero_allows_cleanup_and_retains_failed_intent(self):
        self.perform('restore')
        self.perform('attach')
        def fail_mount(args, timeout=30):
            if args[:3] != ['sudo', '-n', 'mount']:
                return self.fake_host(args, timeout)
            self.host_calls.append(list(args))
            exited = SimpleNamespace(returncode=32, stdout=b'', stderr=b'Synthetic mount refusal')
            with patch.object(daily.subprocess, 'run', return_value=exited):
                return self.native_host(args, timeout)
        with patch.object(daily, 'host', side_effect=fail_mount):
            self.assertEqual(self.perform('mount')['state'], 'failed')
        intent_file = daily.action_file(self.op, 'mount-candidate', 'intent')
        failure_file = daily.action_file(self.op, 'mount-candidate', 'host-failed')
        retained_intent, retained_failure = intent_file.read_bytes(), failure_file.read_bytes()
        self.assertEqual(json.loads(retained_failure)['intentSha256'], daily.hash_bytes(retained_intent))
        self.assertFalse(self.mounts)
        self.archive()
        self.assertEqual(self.perform('detach')['state'], 'succeeded')
        self.assertTrue(self.perform('delete')['resource']['deleted'])
        self.assertEqual(intent_file.read_bytes(), retained_intent)
        self.assertEqual(failure_file.read_bytes(), retained_failure)
        self.assertEqual([args[2] for args in self.host_calls], ['install', 'mount'])
        result = daily.durable.read_private(daily.action_file(self.op, 'mount-candidate', 'result'))
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['intentSha256'], daily.hash_bytes(retained_intent))
        self.assertEqual(daily.status(self.op, self.cloud)['actions']['mount-candidate'], result)
        self.assertTrue(daily.close(self.op, self.cloud)['noOwnedResources'])
        successor = self.root / ('b' * 32)
        successor.mkdir(mode=0o700)
        daily.claim(successor)
        self.assertEqual(daily.durable.read_private(self.root / 'owner.json')['operationId'], successor.name)

    def test_uncertain_mount_without_proven_postcondition_cannot_detach_or_redispatch(self):
        self.perform('restore')
        self.perform('attach')
        def timeout_mount(args, timeout=30):
            if args[:3] != ['sudo', '-n', 'mount']:
                return self.fake_host(args, timeout)
            self.host_calls.append(list(args))
            raise daily.subprocess.TimeoutExpired(args, timeout)
        with patch.object(daily, 'host', side_effect=timeout_mount):
            self.assertEqual(self.perform('mount')['state'], 'unknown')
        self.assertTrue(daily.action_file(self.op, 'mount-candidate', 'host-ready').exists())
        self.assertTrue(daily.action_file(self.op, 'mount-candidate', 'dispatch-unknown').exists())
        self.assertFalse(daily.action_file(self.op, 'mount-candidate', 'host-failed').exists())
        calls = copy.deepcopy(self.host_calls)
        self.assertEqual(daily.perform(self.op, 'mount', 'candidate', 'observe-only', self.cloud)['state'], 'unknown')
        self.archive()
        with self.assertRaisesRegex(release.Refusal, 'daily.mount.dispatch_unsettled'):
            daily.perform(self.op, 'detach', 'candidate', 'cannot-approve-uncertain-host-dispatch', self.cloud)
        with self.assertRaisesRegex(release.Refusal, 'daily.retry.teardown_only'):
            daily.retry_prepare(self.op, 'mount', 'candidate', self.cloud)
        self.assertEqual(self.host_calls, calls)
        self.assertFalse(any(call['path'].endswith('/detachDisk') for call in self.cloud.mutations))

    def test_failed_unmount_retry_is_inert_requires_fresh_approval_and_preserves_evidence(self):
        self.perform('restore')
        self.perform('attach')
        self.perform('mount')
        key = 'unmount-candidate'
        old_approval = daily.challenge(daily.action(self.op, self.run, 'unmount', 'candidate', self.cloud))
        def fail_unmount(args, timeout=30):
            self.assertEqual(args[:3], ['sudo', '-n', 'umount'])
            self.host_calls.append(list(args))
            exited = SimpleNamespace(returncode=32, stdout=b'', stderr=b'Synthetic busy mount')
            with patch.object(daily.subprocess, 'run', return_value=exited):
                return self.native_host(args, timeout)
        with patch.object(daily, 'host', side_effect=fail_unmount):
            failed = daily.perform(self.op, 'unmount', 'candidate', old_approval, self.cloud)
        self.assertEqual(failed['state'], 'failed')
        self.assertTrue(self.mounts)
        old_intent = daily.action_file(self.op, key, 'intent')
        old_result = daily.action_file(self.op, key, 'result')
        retained_intent, retained_result = old_intent.read_bytes(), old_result.read_bytes()
        host_calls, mutations = copy.deepcopy(self.host_calls), copy.deepcopy(self.cloud.mutations)
        self.assertEqual(daily.perform(self.op, 'unmount', 'candidate', old_approval, self.cloud), failed)
        retry = daily.retry_prepare(self.op, 'unmount', 'candidate', self.cloud)
        self.assertEqual(daily.retry_prepare(self.op, 'unmount', 'candidate', self.cloud), retry)
        self.assertFalse(retry['cloudMutationDispatched'])
        self.assertEqual(retry['action']['attempt'], 2)
        self.assertEqual(retry['action']['previousFailureSha256'], daily.hash_bytes(retained_result))
        self.assertNotEqual(retry['approvalChallenge'], old_approval)
        new_intent = daily.action_file(self.op, key, 'intent')
        self.assertNotEqual(new_intent, old_intent)
        self.assertFalse(new_intent.exists())
        with self.assertRaisesRegex(release.Refusal, 'daily.action.approval_mismatch'):
            daily.perform(self.op, 'unmount', 'candidate', old_approval, self.cloud)
        self.assertFalse(new_intent.exists())
        self.assertEqual(self.host_calls, host_calls)
        self.assertEqual(self.cloud.mutations, mutations)
        self.assertEqual(daily.perform(self.op, 'unmount', 'candidate', retry['approvalChallenge'], self.cloud)['state'], 'succeeded')
        self.assertFalse(self.mounts)
        self.assertNotEqual(daily.durable.read_private(new_intent)['requestId'], json.loads(retained_intent)['requestId'])
        self.assertEqual(old_intent.read_bytes(), retained_intent)
        self.assertEqual(old_result.read_bytes(), retained_result)
        self.assertEqual([args[2] for args in self.host_calls], ['install', 'mount', 'umount', 'umount'])
        self.perform('detach')
        self.archive()
        self.perform('delete')
        self.assertTrue(daily.close(self.op, self.cloud)['noOwnedResources'])

    def test_failed_detach_and_delete_get_distinct_requests_without_replacing_prior_receipts(self):
        protected = copy.deepcopy(self.cloud.vm['disks'])
        self.perform('restore')
        self.perform('attach')
        self.archive()
        disk_path = daily.link(self.plan, 'disks', daily.disk_name(self.run, 'candidate'))
        for verb, native_kind in (('detach', 'detachDisk'), ('delete', 'delete')):
            with self.subTest(verb=verb):
                key = verb + '-candidate'
                old_approval = daily.challenge(daily.action(self.op, self.run, verb, 'candidate', self.cloud))
                self.cloud.fail_kind = native_kind
                self.assertEqual(daily.perform(self.op, verb, 'candidate', old_approval, self.cloud)['state'], 'failed')
                self.assertIn(disk_path, self.cloud.disks)
                self.assertEqual(bool(self.cloud.disks[disk_path]['users']), verb == 'detach')
                originals = {daily.action_file(self.op, key, suffix): daily.action_file(self.op, key, suffix).read_bytes()
                             for suffix in ('intent', 'response', 'native-terminal', 'result')}
                old_intent = json.loads(originals[daily.action_file(self.op, key, 'intent')])
                prior_result = originals[daily.action_file(self.op, key, 'result')]
                mutations = copy.deepcopy(self.cloud.mutations)
                retry = daily.retry_prepare(self.op, verb, 'candidate', self.cloud)
                self.assertEqual(self.cloud.mutations, mutations)
                self.assertFalse(self.host_calls)
                self.assertFalse(retry['cloudMutationDispatched'])
                self.assertEqual(retry['action']['previousFailureSha256'], daily.hash_bytes(prior_result))
                with self.assertRaisesRegex(release.Refusal, 'daily.action.approval_mismatch'):
                    daily.perform(self.op, verb, 'candidate', old_approval, self.cloud)
                self.assertEqual(self.cloud.mutations, mutations)
                self.assertEqual(daily.perform(self.op, verb, 'candidate', retry['approvalChallenge'], self.cloud)['state'], 'succeeded')
                current = daily.durable.read_private(daily.action_file(self.op, key, 'intent'))
                self.assertEqual(current['attempt'], 2)
                self.assertNotEqual(current['requestId'], old_intent['requestId'])
                self.assertEqual(self.cloud.mutations[-1]['query']['requestId'], current['requestId'])
                for file, raw in originals.items():
                    self.assertEqual(file.read_bytes(), raw)
        self.assertEqual(self.cloud.vm['disks'], protected)
        self.assertNotIn(disk_path, self.cloud.disks)
        self.assertTrue(daily.close(self.op, self.cloud)['noOwnedResources'])

    def test_unknown_unmount_and_non_teardown_actions_cannot_prepare_retries(self):
        self.perform('restore')
        self.perform('attach')
        self.perform('mount')
        def timeout_unmount(args, timeout=30):
            self.assertEqual(args[:3], ['sudo', '-n', 'umount'])
            self.host_calls.append(list(args))
            raise daily.subprocess.TimeoutExpired(args, timeout)
        with patch.object(daily, 'host', side_effect=timeout_unmount):
            self.assertEqual(self.perform('unmount')['state'], 'unknown')
        host_calls, mutations = copy.deepcopy(self.host_calls), copy.deepcopy(self.cloud.mutations)
        with self.assertRaisesRegex(release.Refusal, 'daily.retry.not_proven_failed'):
            daily.retry_prepare(self.op, 'unmount', 'candidate', self.cloud)
        self.assertEqual(daily.perform(self.op, 'unmount', 'candidate', 'observe-only', self.cloud)['state'], 'unknown')
        for verb in ('restore', 'attach', 'mount', 'doctor', 'startup', 'rollback'):
            with self.subTest(verb=verb), self.assertRaises(release.Refusal):
                daily.retry_prepare(self.op, verb, 'candidate', self.cloud)
        self.assertFalse(list(self.op.glob('attempt-current-*.json')))
        self.assertTrue(self.mounts)
        self.assertEqual(self.host_calls, host_calls)
        self.assertEqual(self.cloud.mutations, mutations)

    def test_running_native_teardown_cannot_prepare_a_retry(self):
        self.perform('restore')
        self.perform('attach')
        self.cloud.operation_status = 'RUNNING'
        self.assertEqual(self.perform('detach')['state'], 'running')
        mutations = copy.deepcopy(self.cloud.mutations)
        with self.assertRaisesRegex(release.Refusal, 'daily.retry.not_proven_failed'):
            daily.retry_prepare(self.op, 'detach', 'candidate', self.cloud)
        self.assertFalse((self.op / 'attempt-current-detach-candidate.json').exists())
        self.assertEqual(self.cloud.mutations, mutations)
        self.assertFalse(self.host_calls)

    def test_prepare_uses_daily_policy_and_exact_policy_incarnation_before_admission(self):
        plan = {**self.plan, 'operationId': 'b' * 32}
        plan_path, image_path = self.base / 'plan.json', self.base / 'image.json'
        daily.record(self.base, plan_path.name, plan)
        daily.record(self.base, image_path.name, {'synthetic': 'image'})
        exported = b'# Synthetic tooling export; never executed.\n'
        hashes = {'synthetic.py': daily.hash_bytes(exported)}
        with patch.object(daily, 'HELPERS', ('synthetic.py',)), \
             patch.object(daily, 'LOADED_HELPERS', hashes), \
             patch.object(daily, 'helper_hashes', return_value=hashes), \
             patch.object(daily.durable, 'clean_checkout'), \
             patch.object(daily.subprocess, 'check_output', return_value=exported), \
             patch.object(daily.trial, 'qualified_image'):
            original_policy = copy.deepcopy(self.cloud.policy)
            for policy in (
                {**original_policy, 'snapshotSchedulePolicy': {'schedule': {'hourlySchedule': {'hoursInCycle': 24}}}},
                {**original_policy, 'snapshotSchedulePolicy': {'schedule': {'dailySchedule': {'daysInCycle': 2}}}},
                {**original_policy, 'id': '999'},
            ):
                with self.subTest(policy=policy):
                    self.cloud.policy = policy
                    with self.assertRaises(release.Refusal):
                        daily.prepare(plan_path, image_path, self.base / 'tooling', self.cloud)
                    self.assertFalse((self.root / plan['operationId']).exists())
            self.cloud.policy = original_policy
            op = daily.prepare(plan_path, image_path, self.base / 'tooling', self.cloud)
            prepared = daily.durable.read_private(op / 'run.json')
        self.assertEqual(prepared['snapshot'], self.cloud.snapshot)
        self.assertEqual(prepared['production'], self.run['production'])
        self.assertFalse(self.cloud.mutations)
        self.assertFalse(self.host_calls)


if __name__ == '__main__':
    unittest.main()
