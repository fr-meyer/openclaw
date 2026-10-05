"""Offline guard/reconciliation tests. Never create a container, mount or worker."""
import copy
import importlib.util
import json
import os
import sys
import time
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qualification_driver', P / 'driver.py')
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
C = json.loads((P / 'contract.json').read_text())

class Admission(unittest.TestCase):
    def setUp(self):
        self.env = {'GITHUB_REPOSITORY': C['repository'], 'GITHUB_REF': C['branch'], 'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '1', 'GITHUB_ACTOR': C['actor'], 'GITHUB_SHA': 'a' * 40, 'QUALIFICATION_MANIFEST_SHA256': 'c' * 64}
        self.event = {'created': True, 'forced': False, 'deleted': False, 'ref': C['branch'], 'before': '0' * 40, 'after': 'a' * 40, 'repository': {'id': C['repository_id'], 'private': False}, 'sender': {'login': C['actor']}}

    def test_exact_first_publication(self): d.validate_event(self.env, self.event, C)

    def test_rerun_refused(self):
        self.env['GITHUB_RUN_ATTEMPT'] = '2'
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)

    def test_existing_branch_update_admitted_at_exact_context(self):
        self.event['created'] = False; self.event['before'] = 'b' * 40
        bound = d.validate_event(self.env, self.event, C)
        self.assertEqual(bound['before'], 'b' * 40); self.assertEqual(bound['tooling_commit'], 'a' * 40)
        self.assertEqual(bound['run_id'], '1'); self.assertEqual(bound['source_commit'], C['source_commit'])
    def test_creation_flag_requires_boolean(self):
        self.event['created'] = 'false'
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_creation_requires_absent_prior_ref(self):
        self.event['before'] = 'b' * 40
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_update_requires_nonzero_prior_ref(self):
        self.event['created'] = False
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_deleted_ref_refused(self):
        self.event['deleted'] = True
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_zero_head_refused(self):
        self.env['GITHUB_SHA'] = self.event['after'] = '0' * 40
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_unchanged_update_refused(self):
        self.event['created'] = False; self.event['before'] = self.event['after']
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_event_ref_mismatch_refused(self):
        self.event['ref'] = 'refs/heads/main'
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_malformed_before_refused(self):
        self.event['before'] = 'not-a-SHA'
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_malformed_run_identity_refused(self):
        for value in ['', '0', '-1', 'one']:
            with self.subTest(value=value):
                self.env['GITHUB_RUN_ID'] = value
                with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)
    def test_admission_persists_across_job_phases(self):
        admission = d.validate_event(self.env, self.event, C)
        state = {'phase': 'init', 'containers': []}; d.bind_admission(state, admission)
        state['phase'] = 'prepared'; d.bind_admission(state, dict(admission))
        self.assertEqual(state['admission'], admission)
    def test_existing_job_without_admission_refused(self):
        with self.assertRaises(d.Refusal): d.bind_admission({'phase': 'prepared', 'containers': []}, d.validate_event(self.env, self.event, C))
    def test_reused_receipt_cannot_change_execution_identity(self):
        admission = d.validate_event(self.env, self.event, C); state = {'phase': 'init', 'containers': []}; d.bind_admission(state, admission)
        for key in ['run_id', 'tooling_commit', 'before', 'source_commit', 'tooling_manifest_sha256']:
            changed = dict(admission); changed[key] = 'different'
            with self.subTest(key=key):
                with self.assertRaises(d.Refusal): d.bind_admission(state, changed)
            self.assertEqual(state['admission'], admission)
    def test_effect_budget_rechecks_bound_receipt(self):
        admission = d.validate_event(self.env, self.event, C); driver = object.__new__(d.Driver)
        driver.admission = admission; driver.state = {'admission': dict(admission)}; driver.state['admission']['run_id'] = '2'
        with self.assertRaisesRegex(d.Refusal, 'identity changed'): driver.budget()
    def test_actual_constructor_seals_context_before_later_job_phase(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); control = root / 'control'; control.mkdir()
            state = control / 'state.json'; state.write_text(json.dumps({'job': '1-1', 'phase': 'init', 'containers': [], 'start_uptime': 10}))
            event = root / 'event.json'; event.write_text(json.dumps(self.event))
            env = dict(self.env, GITHUB_WORKSPACE=str(root), RUNNER_TEMP=str(root), QUALIFICATION_CONTROL=str(control), GITHUB_EVENT_PATH=str(event), QUALIFICATION_MANIFEST_SHA256=d.digest(P / 'manifest.json'))
            with patch.dict(os.environ, env): first = d.Driver()
            saved = json.loads(state.read_text()); self.assertEqual(saved['admission']['tooling_commit'], 'a' * 40)
            saved['phase'] = 'prepared'; state.write_text(json.dumps(saved))
            with patch.dict(os.environ, env): repeated = d.Driver()
            self.assertEqual(first.admission, repeated.admission)
            changed = dict(env, GITHUB_SHA='d' * 40); payload = dict(self.event, after='d' * 40); event.write_text(json.dumps(payload))
            with patch.dict(os.environ, changed):
                with self.assertRaisesRegex(d.Refusal, 'identity changed'): d.Driver()
            self.assertEqual(json.loads(state.read_text())['admission'], first.admission)

    def test_force_push_refused(self):
        self.event['forced'] = True
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)

    def test_wrong_actor_refused(self):
        self.event['sender']['login'] = 'other'
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)

    def test_wrong_repo_identity_refused(self):
        self.event['repository']['id'] += 1
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)

    def test_other_source_branch_refused(self):
        self.env['GITHUB_REF'] = 'refs/heads/candidate/v2026.9.8-current-parity'
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)

    def test_wrong_tooling_head_refused(self):
        self.event['after'] = 'b' * 40
        with self.assertRaises(d.Refusal): d.validate_event(self.env, self.event, C)

    def test_exact_kernel_limits(self):
        d.validate_cgroup({'memory.max': str(12 * d.GIB), 'memory.swap.max': '0', 'pids.max': '512', 'cpu.max': '400000 100000'}, C)

    def test_unlimited_memory_refused(self):
        with self.assertRaises(d.Refusal): d.validate_cgroup({'memory.max': 'max', 'memory.swap.max': '0', 'pids.max': '512', 'cpu.max': '400000 100000'}, C)

    def test_swap_refused(self):
        with self.assertRaises(d.Refusal): d.validate_cgroup({'memory.max': str(12 * d.GIB), 'memory.swap.max': '1', 'pids.max': '512', 'cpu.max': '400000 100000'}, C)

    def test_more_cpu_refused(self):
        with self.assertRaises(d.Refusal): d.validate_cgroup({'memory.max': str(12 * d.GIB), 'memory.swap.max': '0', 'pids.max': '512', 'cpu.max': '800000 100000'}, C)

class Filesystem(unittest.TestCase):
    def setUp(self): self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
    def tearDown(self): self.temp.cleanup()
    def test_regular_private_tree(self):
        (self.root / 'file').write_text('body'); self.assertEqual(len(list(d.contained_walk(self.root))), 2)
    def test_escaping_symlink(self):
        (self.root / 'link').symlink_to('/tmp')
        with self.assertRaises(d.Refusal): list(d.contained_walk(self.root))
    def test_internal_symlink(self):
        (self.root / 'file').write_text('body'); (self.root / 'link').symlink_to('file'); self.assertEqual(len(list(d.contained_walk(self.root))), 3)
    def test_alias_root_refused(self):
        link = self.root / 'link'; link.symlink_to(self.root)
        with self.assertRaises(d.Refusal): list(d.contained_walk(link))
    def test_hardlink_refused(self):
        (self.root / 'file').write_text('body'); os.link(self.root / 'file', self.root / 'alias')
        with self.assertRaises(d.Refusal): list(d.contained_walk(self.root))
    def test_special_refused(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaises(d.Refusal): list(d.contained_walk(self.root))
    def test_cross_device_refused(self):
        with self.assertRaises(d.Refusal): list(d.contained_walk(self.root, self.root.stat().st_dev + 1))
    def test_atomic_receipt_modes(self):
        p = self.root / 'state'; d.atomic(p, {'complete': False}); self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        gate = self.root / 'gate'; d.atomic(gate, {'admitted': True}, 0o644); self.assertEqual(gate.stat().st_mode & 0o777, 0o644)

class Settlement(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
        self.clock = patch.object(d, 'uptime', return_value=10); self.clock.start()
        self.driver = object.__new__(d.Driver); self.driver.c = C; self.driver.control = self.root; self.driver.mount = self.root / 'mount'; self.driver.backing = self.root / 'backing'; self.driver.state = {'job': '1-1', 'phase': 'compiled', 'containers': [], 'complete': False, 'device': 1}; self.driver.state_path = self.root / 'state.json'; self.driver.cleanup_deadline = 1000; self.driver.save = lambda: d.atomic(self.root / 'state.json', self.driver.state)
        self.calls = []; self.driver.docker = lambda *args, **kwargs: self.calls.append(args) or ''
    def tearDown(self): self.clock.stop(); self.temp.cleanup()
    def record(self): return {'name': 'worker', 'id': 'a' * 64, 'kind': 'worker', 'started': True, 'cgroup': str(self.root / 'extinct')}
    def terminal(self): return {'State': {'Running': False, 'Pid': 0, 'Status': 'exited'}}
    def test_terminal_and_extinct_settles(self):
        self.driver.verify_owned = lambda *a, **k: self.terminal(); r = self.record(); self.driver.settle(r); self.assertTrue(r['settled']); self.assertEqual(self.calls, [('rm', 'a' * 64)])
    def test_pid_zero_without_cgroup_custody_refuses(self):
        self.driver.verify_owned = lambda *a, **k: self.terminal(); r = self.record(); del r['cgroup']
        with self.assertRaises(d.Refusal): self.driver.settle(r)
        self.assertFalse(self.calls)
    def test_live_cgroup_refuses(self):
        self.driver.verify_owned = lambda *a, **k: self.terminal(); r = self.record(); Path(r['cgroup']).mkdir()
        with patch.object(d, 'uptime', return_value=1001):
            with self.assertRaises(d.Refusal): self.driver.settle(r)
        self.assertFalse(self.calls)
    def test_created_never_started_export(self):
        self.driver.verify_owned = lambda *a, **k: {'State': {'Running': False, 'Pid': 0, 'Status': 'created'}}
        r = {'name': 'export', 'id': 'a' * 64, 'started': False}; self.driver.settle(r); self.assertTrue(r['settled'])
    def test_unknown_issued_create_cannot_complete(self):
        self.driver.state['containers'] = [{'name': 'uncertain', 'started': True}]
        with self.assertRaises(d.Refusal): self.driver.cleanup()
        self.assertFalse(self.driver.state['complete']); self.assertTrue(self.driver.state['cleanup_issues'])
    def test_umount_failure_never_publishes_success(self):
        self.driver.state['loop'] = '/dev/loop9'; self.driver.state['device'] = 1
        (self.root / 'compiled.tar.gz').write_bytes(b'candidate')
        def command(argv, **kwargs):
            if 'umount' in argv: raise d.Refusal('mount ownership unknown')
            return ''
        self.driver.command = command
        with self.assertRaises(d.Refusal): self.driver.cleanup()
        state = json.loads((self.root / 'upload/state.json').read_text()); self.assertFalse(state['complete']); self.assertFalse((self.root / 'upload/compiled.tar.gz').exists())
    def test_archive_failure_never_publishes_success(self):
        self.driver.command = lambda *a, **k: (_ for _ in ()).throw(d.Refusal('compiled cap exceeded'))
        with self.assertRaises(d.Refusal): self.driver.cleanup()
        self.assertFalse(json.loads((self.root / 'upload/state.json').read_text())['complete'])
    def test_compile_failure_stays_failure_after_clean_settlement(self):
        self.driver.state['phase'] = 'source-owned'
        with self.assertRaises(d.Refusal): self.driver.cleanup()
        self.assertFalse(json.loads((self.root / 'upload/state.json').read_text())['complete'])
    def test_archive_rename_failure_retains_false_receipt_and_original(self):
        archive = self.root / 'compiled.tar.gz'; archive.write_bytes(b'candidate')
        self.driver.command = lambda *a, **k: ''
        rename = d.os.rename
        def fail_archive(source, target):
            if Path(source) == archive: raise OSError('archive retention refused')
            return rename(source, target)
        with patch.object(d.os, 'rename', side_effect=fail_archive):
            with self.assertRaises(OSError): self.driver.cleanup()
        self.assertFalse(json.loads((self.root / 'upload/state.json').read_text())['complete'])
        self.assertEqual(archive.read_bytes(), b'candidate')
    def test_stage_publication_failure_never_exposes_success(self):
        (self.root / 'compiled.tar.gz').write_bytes(b'candidate')
        self.driver.command = lambda *a, **k: ''
        rename = d.os.rename
        def fail_stage(source, target):
            if Path(source) == self.root / 'upload.stage': raise OSError('directory publication refused')
            return rename(source, target)
        with patch.object(d.os, 'rename', side_effect=fail_stage):
            with self.assertRaises(OSError): self.driver.cleanup()
        self.assertFalse(json.loads((self.root / 'upload/state.json').read_text())['complete'])
        self.assertFalse(json.loads((self.root / 'upload.stage/state.json').read_text())['complete'])
        self.assertEqual((self.root / 'upload.stage/compiled.tar.gz').read_bytes(), b'candidate')
    def test_retention_copy_failure_never_exposes_success(self):
        (self.root / 'compiled.tar.gz').write_bytes(b'candidate'); (self.root / 'host.log').write_bytes(b'captured')
        self.driver.command = lambda *a, **k: ''
        write = Path.write_bytes
        def fail_copy(path, body):
            if path == self.root / 'upload.stage/host.log': raise OSError('copy refused')
            return write(path, body)
        with patch.object(Path, 'write_bytes', fail_copy):
            with self.assertRaises(OSError): self.driver.cleanup()
        self.assertFalse(json.loads((self.root / 'upload/state.json').read_text())['complete'])
        self.assertEqual((self.root / 'host.log').read_bytes(), b'captured')
    def test_success_is_last_atomic_receipt_after_complete_publication(self):
        (self.root / 'compiled.tar.gz').write_bytes(b'candidate')
        self.driver.command = lambda *a, **k: ''
        writes = []; atomic = d.atomic
        def observe(path, value, mode=0o600):
            if value.get('complete'):
                self.assertEqual((self.root / 'upload/compiled.tar.gz').read_bytes(), b'candidate')
                self.assertFalse((self.root / 'upload.stage').exists())
            writes.append((path, value['complete'])); atomic(path, value, mode)
        with patch.object(d, 'atomic', side_effect=observe): self.driver.cleanup()
        self.assertEqual(writes[-1], (self.root / 'upload/state.json', True))
    def test_prior_stop_failure_reconciles_before_force(self):
        states = iter([{'State': {'Running': True, 'Pid': 12}}, self.terminal()]); self.driver.verify_owned = lambda *a, **k: next(states)
        def docker(*args, **kwargs):
            self.calls.append(args)
            if args[0] == 'stop': raise d.Refusal('lost stop response')
            return ''
        self.driver.docker = docker; r = self.record(); self.driver.settle(r)
        self.assertTrue(r['settled']); self.assertEqual([x[0] for x in self.calls], ['stop', 'rm'])

class ExecutionGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
        self.driver = object.__new__(d.Driver); self.driver.c = C; self.driver.workspace = self.root; self.driver.control = self.root; self.driver.mount = self.root / 'mount'; self.driver.gates = self.root / 'gates'; self.driver.gates.mkdir()
        self.driver.work_deadline = 1000; self.driver.cleanup_deadline = 2000; self.driver.log_bytes = C['log_cap_bytes']; self.driver.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root)}
        self.driver.admission = {'run_id': 'fixture'}; self.driver.state = {'admission': dict(self.driver.admission)}
    def tearDown(self): self.temp.cleanup()
    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'waitid'), 'native non-reaping waitid requires target Linux host')
    def test_cleanup_query_survives_active_log_limit(self):
        with patch.object(d, 'uptime', return_value=10):
            result = self.driver.command([sys.executable, '-c', 'print("terminal")'], cleanup=True)
        self.assertEqual(result.strip(), 'terminal')
    def test_active_query_stops_at_log_limit(self):
        with patch.object(d, 'uptime', return_value=10):
            with self.assertRaises(d.Refusal): self.driver.command([sys.executable, '-c', 'print("overflow")'])
    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'waitid'), 'native group extinction requires target Linux host')
    def test_parent_exit_does_not_leave_stdout_holding_descendant(self):
        self.driver.log_bytes = 0
        self.driver.work_deadline = time.monotonic() + 5
        self.driver.cleanup_deadline = time.monotonic() + 10
        child = 'import time; time.sleep(5)'
        script = 'import subprocess,sys; p=subprocess.Popen([sys.executable,"-c",' + repr(child) + ']); print(p.pid,flush=True)'
        leaders = []; popen = subprocess.Popen
        def launch(*args, **kwargs):
            p = popen(*args, **kwargs); leaders.append(p); return p
        with patch.object(d, 'uptime', side_effect=time.monotonic), patch.object(d.subprocess, 'Popen', side_effect=launch):
            with self.assertRaisesRegex(d.Refusal, 'host command timeout'):
                self.driver.command([sys.executable, '-c', script], maximum=0.25)
        self.assertEqual(leaders[0].returncode, 0)
        with self.assertRaises(ProcessLookupError): os.killpg(leaders[0].pid, 0)
    def test_reaped_leader_cannot_authorize_group_signal(self):
        class Reaped:
            returncode = 0; pid = 123
        with patch.object(d.os, 'killpg') as kill:
            with self.assertRaisesRegex(d.Refusal, 'reaped'): d.close_owned_group(Reaped())
        kill.assert_not_called()
    def test_group_signals_precede_leader_reaping(self):
        calls = []
        class Owned:
            returncode = None; pid = 123
            def wait(self, timeout): calls.append('reap'); self.returncode = 0
        def kill(pid, sig):
            self.assertEqual(pid, 123)
            if sig == 0:
                calls.append('observe'); raise ProcessLookupError()
            calls.append(sig)
        with patch.object(d.os, 'killpg', side_effect=kill): d.close_owned_group(Owned())
        self.assertEqual(calls, [d.signal.SIGTERM, d.signal.SIGKILL, 'reap', 'observe'])
    def test_cleanup_survives_breached_disk_reserve(self):
        class Full:
            f_bavail = 0; f_frsize = 4096
        with patch.object(d, 'uptime', return_value=10), patch.object(d.os, 'statvfs', return_value=Full()):
            with self.assertRaises(d.Refusal): self.driver.budget()
            self.driver.budget(cleanup=True)
    def test_cleanup_cannot_extend_total_deadline(self):
        with patch.object(d, 'uptime', return_value=2001):
            with self.assertRaises(d.Refusal): self.driver.budget(cleanup=True)
    def test_offline_mount_precedes_entrypoint(self):
        self.driver.state = {'job': '1-1', 'containers': [], 'images': {C['node_image']: 'sha256:' + 'a' * 64}}
        self.driver.save = lambda: None; self.driver.budget = lambda *a: None
        calls = []; self.driver.docker = lambda *args, **kwargs: calls.append(args) or 'a' * 64
        class StopBeforeAnyStart(Exception): pass
        self.driver.verify_owned = lambda *a, **k: (_ for _ in ()).throw(StopBeforeAnyStart())
        with patch.object(d, 'memory_available', return_value=15 * d.GIB):
            with self.assertRaises(StopBeforeAnyStart): self.driver.phase('offline-compile')
        argv = calls[0]
        mount = 'type=bind,src=' + str(self.driver.mount / 'toolchain') + ',dst=/qualification/toolchain,readonly'
        self.assertLess(argv.index(mount), argv.index('--entrypoint'))
        self.assertEqual(argv[argv.index('--network') + 1], 'none')
        self.assertEqual(argv[-4:], ('node', 'sha256:' + 'a' * 64, '/proof/runtime.mjs', 'offline-compile'))
        self.assertFalse(any('TOKEN' in x or 'SECRET' in x for x in argv))

if __name__ == '__main__': unittest.main()
