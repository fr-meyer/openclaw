"""Public daily entry point and its handoff to the existing native owner.

No cloud, Docker, systemd, gateway, or database execution. Native-owner calls
are synthetic; private input bytes and lifecycle receipts use real files.
"""

from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

import gcp_daily_snapshot as daily
import gcp_rehearsal as entry
import release


def write_private(path, value):
    path.write_bytes(value if isinstance(value, bytes) else daily.durable.encode(value))
    path.chmod(0o600)


class DailyEntryTests(unittest.TestCase):
    def invoke(self, argv):
        output = io.StringIO()
        with redirect_stdout(output):
            code = daily.main(argv)
        return code, json.loads(output.getvalue())

    def test_normal_entry_delegates_daily_arguments_and_return_code(self):
        argv = ['run-check', '/private/run', 'startup', '--approve', 'a' * 64]
        with patch.object(entry.sys, 'argv', ['gcp_rehearsal.py', 'daily', *argv]), \
             patch.object(daily, 'main', return_value=7) as dispatch:
            self.assertEqual(entry.main(), 7)
        dispatch.assert_called_once_with(argv)

    def test_prepare_check_interface_passes_exact_private_inputs(self):
        with patch.object(daily, 'Cloud') as cloud, \
             patch.object(daily, 'prepare_check', return_value={'state': 'prepared'}) as prepare:
            code, result = self.invoke(['prepare-check', '/private/run', 'startup',
                '--clean-input', '/private/post-doctor.json', '--tooling', '/private/tooling'])
        self.assertEqual((code, result), (0, {'state': 'prepared'}))
        prepare.assert_called_once_with(Path('/private/run'), 'startup', Path('/private/post-doctor.json'),
                                        Path('/private/tooling'), cloud.return_value)

    def test_check_action_prints_challenge_without_dispatching_native_check(self):
        intended = {'action': 'native-rollback', 'operationId': 'b' * 32,
                    'imageDigest': 'sha256:' + 'c' * 64, 'promotionAuthorized': False}
        with patch.object(daily, 'Cloud') as cloud, \
             patch.object(daily, 'check_action', return_value=intended) as action, \
             patch.object(daily, 'run_check') as run:
            code, result = self.invoke(['check-action', '/private/run', 'rollback'])
        self.assertEqual(code, 0)
        self.assertEqual(result['action'], intended)
        self.assertEqual(result['approvalChallenge'], hashlib.sha256(daily.durable.encode(intended)).hexdigest())
        action.assert_called_once_with(Path('/private/run'), 'rollback', cloud.return_value)
        run.assert_not_called()

    def test_run_check_requires_and_forwards_explicit_approval(self):
        with patch.object(daily, 'Cloud') as cloud, patch.object(daily, 'run_check') as run:
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                daily.main(['run-check', '/private/run', 'doctor'])
            self.assertEqual(failure.exception.code, 2)
            cloud.assert_not_called()
            run.assert_not_called()
            run.return_value = {'state': 'unknown'}
            code, result = self.invoke(['run-check', '/private/run', 'doctor', '--approve', 'd' * 64])
        self.assertEqual((code, result), (0, {'state': 'unknown'}))
        run.assert_called_once_with(Path('/private/run'), 'doctor', 'd' * 64, cloud.return_value)

    def test_entry_refusal_does_not_publish_private_exception_or_offer_retry(self):
        with patch.object(daily, 'Cloud'), patch.object(daily, 'prepare_check',
                side_effect=OSError('private token and /private/dataset')):
            code, result = self.invoke(['prepare-check', '/private/run', 'doctor',
                '--clean-input', '/private/clean.json', '--tooling', '/private/tooling'])
        self.assertEqual(code, 1)
        self.assertEqual(result, {'state': 'refused', 'reason': 'daily.input_or_observation_invalid',
                                 'retryMutation': False, 'promotionAuthorized': False})


class DailyNativeHandoffTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.op = self.root / ('a' * 32)
        self.op.mkdir(mode=0o700)
        self.trials = self.root / 'trials'
        self.trials.mkdir()
        self.tooling = self.root / 'tooling'
        self.cloud = object()
        self.image = {'schema': 'openclaw.fork-release-image.v2', 'sourceSha': '1' * 40,
                      'indexDigest': 'sha256:' + '2' * 64, 'bundledCodexVersion': '0.160.0'}
        self.baseline = {'sourceSha': '3' * 40, 'version': '2026.9.4',
                         'indexDigest': 'sha256:' + '4' * 64, 'imageDigest': 'sha256:' + '5' * 64,
                         'configDigest': 'sha256:' + '6' * 64, 'gatewayProbeContract': 'healthz-readyz-v1'}
        self.run = {'image': self.image, 'production': {'instanceId': '123'},
                    'snapshot': {'id': '456'}, 'plan': {'toolingSha': '7' * 40,
                    'expiresAt': '2026-10-22T00:00:00Z', 'baselineImage': self.baseline,
                    'resources': {'diskType': 'pd-balanced', 'maxDiskGiB': 384,
                        'estimatedCostMicrousd': 1, 'approvedCostMicrousd': 2,
                        'memoryBytes': 24 << 30, 'cpus': 4, 'readBps': 128 << 20,
                        'writeBps': 32 << 20, 'minMemoryAvailableBytes': 24 << 30,
                        'minRootFreeBytes': 2 << 30, 'minDataFreeBytes': 8 << 30,
                        'timeoutSeconds': 960}}}
        # Preserve distinctive original bytes, rather than silently canonicalizing
        # the caller's image or clean-input receipt before binding them.
        write_private(self.op / 'image-receipt.json', (json.dumps(self.image, indent=3) + '\n').encode())
        self.clean = self.root / 'clean.json'
        write_private(self.clean, b'{ "restorationState": "unmigrated", "configSha256": "synthetic" }\n')
        self.states = {}
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        def mock(owner, name, **kwargs):
            return self.patches.enter_context(patch.object(owner, name, **kwargs))
        mock(daily, 'load', return_value=(self.op, self.run))
        mock(daily, 'now', return_value=datetime(2026, 10, 21, tzinfo=timezone.utc))
        mock(daily.durable, 'operation_lock', side_effect=lambda _: nullcontext())
        mock(daily.trial, 'PRIVATE_ROOT', new=self.trials)
        self.observation = mock(daily, 'observe_production')
        self.clean_admission = mock(daily, 'clean_binding')
        self.validation = mock(daily.trial, 'validate')
        self.prepare = mock(daily.trial, 'prepare', side_effect=self.native_prepare)
        mock(daily.trial, 'load', side_effect=self.native_load)
        self.status = mock(daily.trial, 'status', side_effect=lambda location:
                           {'state': self.states.get(location.name, 'prepared')})
        self.prerequisites = mock(daily.trial, 'phase_prerequisites')
        self.claim = mock(daily, 'claim')
        self.start = mock(daily.trial, 'start', side_effect=self.native_start)

    def native_prepare(self, plan_path, image_path, clean_path, tooling, check_path):
        self.assertEqual(tooling, self.tooling)
        values = {name: json.loads(path.read_bytes()) for name, path in
                  (('plan', plan_path), ('image', image_path), ('clean', clean_path), ('check', check_path))}
        location = self.trials / values['plan']['operationId']
        location.mkdir(mode=0o700)
        write_private(location / 'intent.json', values)
        return location

    def native_load(self, location):
        return location, json.loads((location / 'intent.json').read_bytes())

    def native_start(self, location):
        write_private(location / 'start-intent.json', {'operationId': location.name})
        self.states[location.name] = 'unknown'
        return {'state': 'unknown'}

    def prepare_phase(self, phase, path=None):
        return daily.prepare_check(self.op, phase, path or self.clean, self.tooling, self.cloud)

    def settled_doctor(self, state='succeeded'):
        location = Path(self.prepare_phase('doctor')['operation'])
        self.states[location.name] = state
        write_private(location / 'result.json', {'state': state, 'nativeExitCode': 0 if state == 'succeeded' else 137})
        return location

    def test_prepare_binds_exact_input_bytes_and_reuses_one_deterministic_native_operation(self):
        result = self.prepare_phase('doctor')
        expected = uuid.uuid5(uuid.UUID(hex=self.op.name), 'doctor').hex
        location = self.trials / expected
        self.assertEqual(result['operation'], str(location))
        _, intent = daily.trial.load(location)
        plan = intent['plan']
        self.assertEqual(plan['cleanInputSha256'], hashlib.sha256(self.clean.read_bytes()).hexdigest())
        self.assertEqual(plan['imageReceiptSha256'], hashlib.sha256((self.op / 'image-receipt.json').read_bytes()).hexdigest())
        self.assertEqual(plan['checkInputSha256'], hashlib.sha256((self.op / 'doctor-input/check.json').read_bytes()).hexdigest())
        self.assertEqual(intent['clean'], json.loads(self.clean.read_bytes()))
        self.assertNotIn('diskType', plan['limits'])
        self.validation.assert_called_once_with(plan, intent['image'], intent['clean'], intent['check'])
        self.clean_admission.assert_called_once_with(self.op, self.run, 'doctor', intent['clean'], self.cloud)
        self.states[expected] = 'running'
        replay = self.prepare_phase('doctor', self.root / 'not-an-input.json')
        self.assertEqual(replay, {'operation': str(location), 'state': 'running'})
        self.prepare.assert_called_once()
        self.start.assert_not_called()

    def test_interrupted_binding_reuses_prepared_trial_without_duplicate_prepare(self):
        original_record = daily.record
        def interrupted(op, name, value):
            if name == 'doctor.trial.json':
                raise OSError('interrupted before lifecycle binding')
            return original_record(op, name, value)
        with patch.object(daily, 'record', side_effect=interrupted), self.assertRaises(OSError):
            self.prepare_phase('doctor')
        self.assertFalse((self.op / 'doctor.trial.json').exists())
        result = self.prepare_phase('doctor')
        self.assertEqual(result['state'], 'prepared')
        self.prepare.assert_called_once()
        daily.trial_binding(self.op, 'doctor')

    def test_startup_binds_current_clean_bytes_and_retained_doctor_result(self):
        prior = self.settled_doctor()
        post = self.root / 'post-doctor.json'
        write_private(post, {'restorationState': 'doctor-complete', 'configSha256': 'changed-by-doctor'})
        location = Path(self.prepare_phase('startup', post)['operation'])
        _, intent = daily.trial.load(location)
        self.assertEqual(intent['check']['doctorOperationId'], prior.name)
        self.assertEqual(intent['check']['doctorResultSha256'], hashlib.sha256((prior / 'result.json').read_bytes()).hexdigest())
        self.assertEqual(intent['plan']['cleanInputSha256'], hashlib.sha256(post.read_bytes()).hexdigest())
        self.assertNotEqual(intent['plan']['cleanInputSha256'], hashlib.sha256(self.clean.read_bytes()).hexdigest())
        self.assertEqual(intent['image'], self.image)
        self.assertNotIn('doctorResult', intent['check'])

    def test_failed_doctor_refuses_startup_but_rollback_binds_independent_baseline(self):
        prior = self.settled_doctor('failed')
        with self.assertRaisesRegex(release.Refusal, 'daily.check.doctor_unsettled'):
            self.prepare_phase('startup')
        self.prepare.assert_called_once()
        location = Path(self.prepare_phase('rollback')['operation'])
        _, intent = daily.trial.load(location)
        self.assertEqual(intent['image'], {'schema': 'openclaw.rehearsal-baseline-image.v1',
                                         'architecture': 'amd64', **self.baseline})
        self.assertEqual(intent['check']['doctorOperationId'], prior.name)
        self.assertNotEqual(intent['image']['sourceSha'], self.image['sourceSha'])
        self.assertNotIn('bundledCodexVersion', intent['image'])
        self.assertEqual(intent['plan']['imageReceiptSha256'],
                         hashlib.sha256((self.op / 'rollback-input/image.json').read_bytes()).hexdigest())

    def test_exact_check_approval_dispatches_once_and_unknown_replay_only_observes(self):
        location = Path(self.prepare_phase('doctor')['operation'])
        intended = daily.check_action(self.op, 'doctor', self.cloud)
        self.prerequisites.assert_called_once()
        self.assertEqual(intended['operationId'], location.name)
        self.assertEqual(intended['intentSha256'], hashlib.sha256((location / 'intent.json').read_bytes()).hexdigest())
        with self.assertRaisesRegex(release.Refusal, 'daily.action.approval_mismatch'):
            daily.run_check(self.op, 'doctor', '0' * 64, self.cloud)
        self.claim.assert_not_called()
        self.start.assert_not_called()
        self.assertEqual(daily.run_check(self.op, 'doctor', daily.challenge(intended), self.cloud), {'state': 'unknown'})
        self.assertEqual(daily.run_check(self.op, 'doctor', 'invalid-replay-approval', self.cloud), {'state': 'unknown'})
        self.claim.assert_called_once_with(self.op)
        self.start.assert_called_once_with(location)

    def test_changed_native_intent_refuses_before_start_even_if_semantically_equal(self):
        location = Path(self.prepare_phase('doctor')['operation'])
        path = location / 'intent.json'
        write_private(path, path.read_bytes() + b'\n')
        with self.assertRaisesRegex(release.Refusal, 'daily.check.binding'):
            daily.run_check(self.op, 'doctor', '0' * 64, self.cloud)
        self.claim.assert_not_called()
        self.start.assert_not_called()


if __name__ == '__main__':
    unittest.main()
