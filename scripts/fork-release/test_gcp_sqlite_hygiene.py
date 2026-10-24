"""Synthetic, filesystem-only proof for the release-triggered hygiene stage."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

import gcp_daily_snapshot as daily
import gcp_sqlite_hygiene as hygiene
import release


class HygieneTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.state = self.root / 'state-mount'
        (self.state / 'state').mkdir(parents=True)
        (self.state / 'agents' / 'main' / 'agent').mkdir(parents=True)
        (self.state / 'state' / 'openclaw.sqlite').write_bytes(b'global')
        self.agent_db = self.state / 'agents' / 'main' / 'agent' / 'openclaw-agent.sqlite'
        self.agent_db.write_bytes(b'agent')
        self.clean = {
            'mountRoot': str(self.root), 'filesystemDevice': self.root.stat().st_dev,
            'mounts': [{'source': str(self.state), 'target': '/home/node/.openclaw', 'readOnly': False}],
            'restoreReceiptSha256': 'a' * 64, 'configSha256': 'b' * 64,
            'restorationState': 'unmigrated', 'integrationsDisabled': True,
        }
        self.run = {
            'image': {'sourceSha': 'c' * 40}, 'imageReceiptSha256': 'd' * 64,
            'plan': {'toolingSha': 'e' * 40, 'operationId': '1' * 32,
                     'expiresAt': '2026-10-23T00:00:00Z',
                     'resources': {'timeoutSeconds': 1800}},
            'snapshot': {'id': '123'}, 'production': {'protectedDisks': []},
        }
        self.op = self.root / ('1' * 32)
        self.op.mkdir(mode=0o700)
        daily.record(self.op, 'run.json', self.run)
        self.raw = json.dumps(self.clean, sort_keys=True).encode()
        inactive = patch.object(daily, 'no_container_users', return_value=None)
        inactive.start()
        self.addCleanup(inactive.stop)

    def test_release_assessment_is_metadata_only_and_disables_all_mutations(self):
        with patch('sqlite3.connect', side_effect=AssertionError('SQLite must not open')):
            receipt = hygiene.assess(self.run, '0' * 64, self.clean, 'f' * 64, 'baseline')
        self.assertEqual([row['owner'] for row in receipt['metrics']['databasePaths']],
                         ['shared', 'agent:main'])
        self.assertFalse(receipt['metrics']['contentVerified'])
        self.assertEqual(receipt['decision']['state'], 'skipped')
        self.assertEqual(receipt['decision']['reason'], 'metadata_cannot_prove_reclaimable_space')
        self.assertFalse(receipt['decision']['mutatingActionDispatched'])
        self.assertIn('sqlite-compact', receipt['decision']['requiresSeparateApproval'])
        self.assertFalse(receipt['promotionAuthorized'])

    def test_orphan_large_wal_is_an_explicit_followup_without_a_scan(self):
        self.agent_db.unlink()
        with open(str(self.agent_db) + '-wal', 'wb') as sparse:
            sparse.truncate(hygiene.LARGE_FILE_BYTES)
        receipt = hygiene.assess(self.run, '0' * 64, self.clean, 'f' * 64, 'baseline')
        self.assertEqual(receipt['decision']['reason'], 'wal_without_database_at_default_path')
        self.assertIn({'owner': 'agent:main', 'kind': 'check-reader-and-wal-on-stopped-clone'},
                      receipt['decision']['followup'])
        self.assertFalse(receipt['decision']['mutatingActionDispatched'])

    def test_exact_generation_reuses_receipt_and_changed_database_refuses(self):
        first = daily.hygiene_assess_locked(self.op, self.run, self.raw, self.clean, 'baseline')
        saved = (self.op / 'hygiene-baseline.json').read_bytes()
        self.assertEqual(daily.hygiene_assess_locked(self.op, self.run, self.raw,
                                                     self.clean, 'baseline'), first)
        self.assertEqual((self.op / 'hygiene-baseline.json').read_bytes(), saved)
        self.agent_db.write_bytes(b'changed')
        with self.assertRaisesRegex(release.Refusal, 'daily.hygiene.generation_changed'):
            daily.hygiene_assess_locked(self.op, self.run, self.raw, self.clean, 'baseline')
        self.assertEqual((self.op / 'hygiene-baseline.json').read_bytes(), saved)

    def test_dispatch_rechecks_generation_without_another_receipt(self):
        daily.hygiene_assess_locked(self.op, self.run, self.raw, self.clean, 'baseline')
        intent = {'clean': self.clean, 'plan': {'cleanInputSha256': daily.hash_bytes(self.raw)},
                  'check': {}}
        receipt = (self.op / 'hygiene-baseline.json').read_bytes()
        daily.hygiene_verify_current(self.op, self.run, intent, 'doctor')
        self.agent_db.write_bytes(b'changed after preparation')
        with self.assertRaisesRegex(release.Refusal, 'daily.hygiene.generation_changed'):
            daily.hygiene_verify_current(self.op, self.run, intent, 'doctor')
        self.assertEqual((self.op / 'hygiene-baseline.json').read_bytes(), receipt)

    def test_image_and_snapshot_binding_change_cannot_reuse_receipt(self):
        daily.hygiene_assess_locked(self.op, self.run, self.raw, self.clean, 'baseline')
        for field, replacement in (('imageReceiptSha256', '9' * 64),
                                   ('snapshot', {'id': '999'})):
            changed = dict(self.run, **{field: replacement})
            with self.subTest(field=field), self.assertRaisesRegex(
                    release.Refusal, 'daily.hygiene.generation_changed'):
                daily.hygiene_assess_locked(self.op, changed, self.raw, self.clean, 'baseline')

    def test_post_doctor_binds_settled_success_and_keeps_baseline(self):
        baseline = daily.hygiene_assess_locked(self.op, self.run, self.raw, self.clean, 'baseline')
        native = self.root / 'native-doctor'
        native.mkdir()
        (native / 'result.json').write_text('{"state":"succeeded"}')
        (native / 'result.json').chmod(0o600)
        with patch.object(daily, 'trial_binding', return_value=(native, {})), patch.object(
                daily, 'settled_check', return_value={'state': 'succeeded'}):
            migrated = dict(self.clean, restorationState='doctor-complete')
            after = daily.hygiene_assess_locked(self.op, self.run,
                                                json.dumps(migrated).encode(), migrated,
                                                'post-doctor')
        self.assertEqual(after['doctorResultSha256'], daily.hash_bytes((native / 'result.json').read_bytes()))
        self.assertNotEqual(after['phase'], baseline['phase'])
        self.assertTrue((self.op / 'hygiene-baseline.json').exists())
        self.assertTrue((self.op / 'hygiene-post-doctor.json').exists())

    def test_symlinks_and_excessive_discovery_refuse_without_mutation(self):
        self.agent_db.unlink()
        self.agent_db.symlink_to(self.state / 'state' / 'openclaw.sqlite')
        with self.assertRaisesRegex(release.Refusal, 'hygiene.file.identity'):
            hygiene.measure(self.clean)
        self.agent_db.unlink()
        for index in range(hygiene.MAX_AGENTS):
            (self.state / 'agents' / f'extra-{index}').mkdir()
        with self.assertRaisesRegex(release.Refusal, 'hygiene.agents.bound'):
            hygiene.measure(self.clean)
        skipped = daily.hygiene_assess_locked(self.op, self.run, self.raw, self.clean, 'baseline')
        self.assertEqual(skipped['decision']['reason'], 'bounded_metadata_unavailable')
        self.assertEqual(daily.hygiene_assess_locked(self.op, self.run, self.raw,
                                                     self.clean, 'baseline'), skipped)
        daily.hygiene_verify_current(self.op, self.run, {
            'clean': self.clean, 'plan': {'cleanInputSha256': daily.hash_bytes(self.raw)},
            'check': {}}, 'doctor')

    def test_changed_during_measurement_records_bounded_skip(self):
        original = hygiene.measure(self.clean)
        altered = dict(original, fingerprint='0' * 64)
        with patch.object(hygiene, 'measure', side_effect=[original, altered]):
            result = daily.hygiene_assess_locked(self.op, self.run, self.raw,
                                                 self.clean, 'baseline')
        self.assertEqual(result['decision']['reason'], 'bounded_metadata_unavailable')
        self.assertFalse(result['decision']['mutatingActionDispatched'])

    def test_daily_prepare_check_records_hygiene_before_native_prepare(self):
        daily.record(self.op, 'image-receipt.json', {'sourceSha': self.run['image']['sourceSha']})
        clean_file = self.op / 'clean.json'
        daily.durable.write_once(clean_file, self.raw)
        location = self.root / 'trial' / uuid.uuid5(uuid.UUID(hex=self.op.name), 'doctor').hex
        def fake_prepare(*args):
            self.assertTrue((self.op / 'hygiene-baseline.json').exists())
            receipt = daily.durable.read_private(self.op / 'hygiene-baseline.json')
            self.assertEqual(receipt['decision']['state'], 'skipped')
            location.mkdir(parents=True, mode=0o700)
            daily.durable.write_once(location / 'intent.json', b'{}')
            return location
        with patch.object(daily, 'load', return_value=(self.op, self.run)), patch.object(
                daily, 'now', return_value=datetime(2026, 10, 22, tzinfo=timezone.utc)), patch.object(
                daily, 'observe_production', return_value=(None, None, None)), patch.object(
                daily, 'clean_binding', return_value=None), patch.object(
                daily.trial, 'validate', return_value=None), patch.object(
                daily.trial, 'prepare', side_effect=fake_prepare), patch.object(
                daily.trial, 'PRIVATE_ROOT', location.parent):
            result = daily.prepare_check(self.op, 'doctor', clean_file, self.root, object())
            preview = daily.hygiene_assess(self.op, 'baseline', clean_file, object())
            self.assertFalse((location / 'start-intent.json').exists())
            daily.durable.write_once(location / 'start-intent.json', b'{}')
            with self.assertRaisesRegex(release.Refusal, 'daily.hygiene.native_already_started'):
                daily.hygiene_assess(self.op, 'baseline', clean_file, object())
        self.assertEqual(result['state'], 'prepared')
        self.assertEqual(preview['state'], 'assessed')
        self.assertTrue((self.op / 'doctor.trial.json').exists())


if __name__ == '__main__':
    unittest.main()
