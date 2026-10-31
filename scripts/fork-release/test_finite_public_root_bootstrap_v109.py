"""Tiny local Git fixtures only; no production origin or application execution."""
from copy import deepcopy
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request

import finite_public_root_bootstrap_v109 as b

HERE = Path(__file__).resolve().parent
REAL_POPEN = subprocess.Popen
REAL_RUN = subprocess.run
HOST_ATTEMPTS = []
LOCAL_GIT_CALLS = []


def local_git_only(argv, *args, **kwargs):
    if not isinstance(argv, (list, tuple)) or argv[0] != '/usr/bin/git':
        HOST_ATTEMPTS.append('non_git'); raise AssertionError('only fixed local Git permitted')
    if 'fetch' in argv and not any(str(value).startswith('file://') for value in argv):
        HOST_ATTEMPTS.append('remote_fetch'); raise AssertionError('remote Git forbidden')
    if any(value in argv for value in ['clone', 'push', 'ls-remote', 'submodule']):
        HOST_ATTEMPTS.append('remote_verb'); raise AssertionError('unowned Git verb forbidden')
    LOCAL_GIT_CALLS.append('fetch' if 'fetch' in argv else 'local_metadata_or_fixture')
    return REAL_POPEN(argv, *args, **kwargs)


def git(root, *args, data=None, check=True):
    env = b.git_environment(os.environ)
    env.update(GIT_AUTHOR_NAME='Synthetic', GIT_AUTHOR_EMAIL='synthetic@example.invalid',
        GIT_COMMITTER_NAME='Synthetic', GIT_COMMITTER_EMAIL='synthetic@example.invalid',
        GIT_AUTHOR_DATE='2026-01-01T00:00:00Z', GIT_COMMITTER_DATE='2026-01-01T00:00:00Z')
    return REAL_RUN(['/usr/bin/git', '-C', str(root), *args], input=data, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


class GitFixture:
    def __init__(self, base):
        self.base = base; self.remote = base / 'remote'; self.remote.mkdir()
        git(self.remote, 'init', '--bare')
        def tree(values):
            rows = []
            for name, text in sorted(values.items()):
                blob = git(self.remote, 'hash-object', '-w', '--stdin', data=text.encode()).stdout.strip()
                rows.append(b'100644 blob ' + blob + b'\t' + name.encode() + b'\n')
            return git(self.remote, 'mktree', data=b''.join(rows)).stdout.strip().decode()
        def commit(values, parents=()):
            tr = tree(values); argv = ['commit-tree', tr]
            for parent in parents: argv.extend(['-p', parent])
            oid = git(self.remote, *argv, data=b'synthetic\n').stdout.strip().decode()
            return oid, tr
        self.common, self.common_tree = commit({'base': 'base'})
        self.target, self.target_tree = commit({'base': 'base', 'target': 'target'}, [self.common])
        self.head, self.head_tree = commit({'base': 'base', 'caller': 'caller'}, [self.common])
        self.merge, _ = commit({'base': 'base', 'target': 'target', 'caller': 'caller'}, [self.target, self.head])
        self.bad_parent, _ = commit({'base': 'base', 'target': 'target', 'caller': 'caller'}, [self.head, self.target])
        self.bad_tree, _ = commit({'base': 'base', 'caller': 'caller'}, [self.target, self.head])
        fork, _ = commit({'fork': 'fork'}, [self.common])
        upstream, _ = commit({'upstream': 'upstream'}, [self.common])
        integration, _ = commit({'integration': 'integration'}, [fork, upstream])
        generated, _ = commit({'generated': 'generated'}, [integration])
        self.source, self.source_tree = commit({'source': 'source'}, [generated])
        self.source_roots = sorted([self.common, fork, upstream, integration, generated, self.source])
        self.unrelated, _ = commit({'unrelated': 'not selected'})
        for name, oid in [('caller', self.head), ('merge', self.merge), ('source', self.source),
                          ('unrelated', self.unrelated), ('wrong-parent', self.bad_parent), ('wrong-tree', self.bad_tree)]:
            git(self.remote, 'update-ref', 'refs/heads/' + name, oid)

    def checkout(self, path):
        path.mkdir(); git(path, 'init'); git(path, 'remote', 'add', 'origin', b.ORIGIN)
        git(path, '-c', 'protocol.file.allow=always', 'fetch', '--depth=1', '--no-tags',
            self.remote.as_uri(), self.head)
        git(path, 'checkout', '--detach', self.head)


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='finite-root-fixture-')
        cls.base = Path(cls.temp.name).resolve()
        with patch.object(subprocess, 'Popen', local_git_only):
            cls.fixture = GitFixture(cls.base)
        cls.runtime, cls.core = b.owners(HERE)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.guards = []
        for target, name, replacement in [(subprocess, 'Popen', local_git_only),
                (socket, 'socket', lambda *a, **k: (_ for _ in ()).throw(AssertionError('network forbidden'))),
                (urllib.request, 'urlopen', lambda *a, **k: (_ for _ in ()).throw(AssertionError('network forbidden')))]:
            guard = patch.object(target, name, replacement); guard.start(); self.addCleanup(guard.stop)
        self.case = Path(tempfile.mkdtemp(prefix='case-', dir=self.base))
        self.root = self.case / 'pipeline'; self.fixture.checkout(self.root)
        self.output = self.case / 'custody'; self.output.mkdir(mode=0o700)
        self.owner = b.OwnedGit(self.root, b.git_environment(os.environ), time.time() + 120,
                                self.output, self.core)
        self.selected = {'source': {'sourceSha': self.fixture.source,
                                    'sourceTree': self.fixture.source_tree}}

    def graph_pins(self):
        f = self.fixture
        return patch.multiple(self.runtime, WORKFLOW_TARGET=f.target, WORKFLOW_TARGET_TREE=f.target_tree,
            WORKFLOW_MERGE_BASE=f.common, WORKFLOW_MERGE_BASE_TREE=f.common_tree)

    def acquire(self, merge=None, selected=None, unshallow=True):
        f = self.fixture; original = b.fetch_argv
        def local(root, m, s, shallow):
            argv = original(root, m, s, shallow and unshallow)
            argv[argv.index(b.ORIGIN)] = f.remote.as_uri()
            argv[argv.index('fetch'):argv.index('fetch')] = ['-c', 'protocol.file.allow=always']
            return argv
        with patch.object(b, 'fetch_argv', local), self.graph_pins():
            return b.acquire(self.owner, self.runtime, self.core, f.head,
                merge or f.merge, selected or self.selected, self.owner.env)

    def test_full_unshallow_two_roots_keeps_headP_and_unrelated_ref_absent(self):
        value = self.acquire()
        self.assertEqual(value['fetchAttempts'], 1)
        self.assertEqual(value['actualWorkflowParents'], [self.fixture.target, self.fixture.head])
        self.assertEqual(value['workflowParentsRawSha256'], hashlib.sha256(
            (self.fixture.target + ' ' + self.fixture.head + '\n').encode()).hexdigest())
        self.assertNotEqual(value['declaredPRBase'], value['actualWorkflowParents'][0])
        self.assertEqual(self.owner.read('rev-parse', 'HEAD').strip().decode(), self.fixture.head)
        self.assertEqual(self.owner.read('rev-parse', '--is-shallow-repository').strip(), b'false')
        for root in self.fixture.source_roots:
            self.assertEqual(self.owner.read('cat-file', '-t', root).strip(), b'commit')
        self.assertNotEqual(git(self.root, 'cat-file', '-e', self.fixture.unrelated, check=False).returncode, 0)
        self.assertFalse(value['sourceQualified'])

    def test_existing_full_graph_uses_same_one_fetch_without_deepening(self):
        self.acquire()
        other = self.case / 'second-custody'; other.mkdir(); self.owner.output = other
        self.assertEqual(self.acquire()['status'], 'full_closure_only')

    def test_unchanged_local_donor_consumes_independent_S_from_narrow_store(self):
        self.acquire()
        f = self.fixture; source = self.case / 'source'; source.mkdir()
        git(source, 'init'); git(source, 'remote', 'add', 'origin', b.ORIGIN)
        git(source, '-c', 'protocol.file.allow=always', 'fetch', '--depth=1', '--no-tags',
            f.remote.as_uri(), f.source)
        git(source, 'checkout', '--detach', f.source)
        source_custody = self.case / 'source-custody'; source_custody.mkdir()
        receiver = b.OwnedGit(source, b.git_environment(os.environ), time.time() + 120,
                              source_custody, self.core)
        def read(root, *args):
            self.assertIn(root, (self.root, source))
            return (self.owner if root == self.root else receiver).read(*args)
        donor = self.core.local_closure_donor_uri(self.case, self.root, source,
            f.head, f.source, f.source_tree, f.source_roots, read)
        self.assertEqual(donor, self.root.as_uri())
        # Exact maintained downstream operation, not a cat-file-only claim.
        git(source, '-c', 'protocol.file.allow=always', '-c', 'credential.helper=',
            '-c', 'maintenance.auto=0', '-c', 'gc.auto=0', 'fetch', '--no-tags',
            '--unshallow', donor, *f.source_roots)
        self.assertEqual(receiver.read('rev-parse', '--is-shallow-repository').strip(), b'false')
        self.assertEqual(self.core.local_closure_donor_uri(self.case, self.root, source,
            f.head, f.source, f.source_tree, f.source_roots, read), donor)
        for root in f.source_roots:
            self.assertEqual(receiver.read('cat-file', '-t', root).strip(), b'commit')

    def test_missing_merge_and_missing_source_refuse_once(self):
        for which in ('merge', 'source'):
            with self.subTest(which=which):
                root = self.case / which; self.fixture.checkout(root)
                self.owner.root = root; out = self.case / (which + '-out'); out.mkdir(); self.owner.output = out
                missing = 'f' * 40
                selected = deepcopy(self.selected)
                if which == 'source': selected['source']['sourceSha'] = missing
                with self.assertRaises(b.Refusal): self.acquire(missing if which == 'merge' else None, selected)
                facts = [json.loads(x.read_bytes()) for x in out.glob('*.status.private.json')]
                self.assertEqual(sum(x['kind'] == 'finite_fetch' for x in facts), 1)

    def test_wrong_workflow_parent_order_and_complete_tree_refuse(self):
        for merge in (self.fixture.bad_parent, self.fixture.bad_tree):
            out = self.case / merge; out.mkdir(); self.owner.output = out
            with self.assertRaises(ValueError): self.acquire(merge)

    def test_wrong_source_tree_refuses(self):
        selected = deepcopy(self.selected); selected['source']['sourceTree'] = 'f' * 40
        with self.assertRaises(b.Refusal): self.acquire(selected=selected)

    def test_missing_source_blob_cannot_supply_complete_closure(self):
        broken = self.case / 'missing-blob-remote'
        shutil.copytree(self.fixture.remote, broken)
        row = git(broken, 'ls-tree', self.fixture.source, '--', 'source').stdout.split()
        oid = row[2].decode(); (broken / 'objects' / oid[:2] / oid[2:]).unlink()
        with patch.object(self.fixture, 'remote', broken), self.assertRaises(ValueError):
            self.acquire()

    def test_remaining_shallow_marker_refuses(self):
        with self.assertRaisesRegex(b.Refusal, 'full_nonshallow'): self.acquire(unshallow=False)

    def test_wrong_origin_partial_or_alternate_refuses_before_fetch(self):
        git(self.root, 'remote', 'set-url', 'origin', 'https://example.invalid/unapproved')
        with self.assertRaisesRegex(b.Refusal, 'fixed_origin'): self.acquire()
        git(self.root, 'remote', 'set-url', 'origin', b.ORIGIN)
        git(self.root, 'config', 'extensions.partialclone', 'origin')
        with self.assertRaisesRegex(b.Refusal, 'partial_or_redirect_config'): self.acquire()
        git(self.root, 'config', '--unset', 'extensions.partialclone')
        (self.root / '.git/objects/info/alternates').write_text('/nonexistent')
        with self.assertRaisesRegex(b.Refusal, 'alternate_objects'): self.acquire()
        self.assertFalse(any(json.loads(x.read_bytes())['kind'] == 'finite_fetch'
                             for x in self.output.glob('*.status.private.json')))

    def test_local_tls_redirect_replacement_and_object_link_overrides_refuse(self):
        git(self.root, 'config', 'http.sslVerify', 'false')
        with self.assertRaisesRegex(b.Refusal, 'partial_or_redirect_config'): self.acquire()
        git(self.root, 'config', '--unset', 'http.sslVerify')
        git(self.root, 'update-ref', 'refs/replace/' + self.fixture.head, self.fixture.head)
        with self.assertRaisesRegex(b.Refusal, 'replacement_or_graft'): self.acquire()
        git(self.root, 'update-ref', '-d', 'refs/replace/' + self.fixture.head)
        objects = self.root / '.git/objects'; original = self.root / '.git/original-objects'
        objects.rename(original); objects.symlink_to(original, target_is_directory=True)
        with self.assertRaisesRegex(b.Refusal, 'owned_objects'): self.acquire()

    def test_production_fetch_argv_has_only_fixed_origin_exactM_S_and_no_wildcards(self):
        argv = b.fetch_argv(self.root, self.fixture.merge, self.fixture.source, True)
        self.assertEqual(argv[-3:], [b.ORIGIN, self.fixture.merge, self.fixture.source])
        self.assertIn('--unshallow', argv)
        self.assertFalse(any('*' in x or 'filter' in x for x in argv))
        self.assertEqual(b.ORIGIN, 'https://github.com/fr-meyer/openclaw')

    def test_bad_root_shape_never_fetches(self):
        with patch.object(self.owner, 'run', side_effect=AssertionError('no child')):
            with self.assertRaises(b.Refusal):
                b.acquire(self.owner, self.runtime, self.core, self.fixture.head, 'missing', self.selected, {})

    def test_token_only_in_ephemeral_fetch_environment_not_argv(self):
        token = 'synthetic-token-' + 'x' * 32
        env, secrets = b.fetch_environment(self.owner.env, token)
        self.assertNotIn('GH_TOKEN', env)
        self.assertIn(token.encode(), secrets)
        self.assertNotIn(token, ' '.join(b.fetch_argv(self.root, self.fixture.merge, self.fixture.source, True)))
        self.assertNotIn('GIT_CONFIG_VALUE_7', b.git_environment(dict(os.environ, GH_TOKEN=token)))

    def test_failure_custody_redacts_complete_and_partial_auth_before_refusal(self):
        token = b'ghs_FAKE_not_a_credential_1234567890abcdef'
        self.owner.secrets = (token,)
        class Child:
            returncode = 1
            def communicate(self, timeout):
                return b'', b'Authorization: basic sensitive\n' + token + b'\n' + token[:9] + b'\nfatal: fixed synthetic refusal\n'
        with patch.object(subprocess, 'Popen', return_value=Child()), contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.owner.run([b.GIT], fetch=True)
        self.assertEqual(result.returncode, 1)
        saved = b''.join(x.read_bytes() for x in self.output.iterdir())
        self.assertNotIn(token[:9], saved); self.assertNotIn(b'basic sensitive', saved)
        self.assertNotIn(token[:9].decode(), output.getvalue())
        self.assertIn(b'fixed synthetic refusal', saved)

    def test_timeout_with_valid_complete_output_is_failure_after_custody(self):
        class Child:
            returncode = None
            def communicate(self, timeout): raise subprocess.TimeoutExpired('git', timeout, output=b'{}', stderr=b'public synthetic')
        def settled(child): child.child.returncode = -9; return child.stdout, True, 'settled'
        with patch.object(subprocess, 'Popen', return_value=Child()), \
             patch.object(self.core, 'settle_owned_timeout_group', side_effect=settled) as cleanup, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(b.Refusal, 'owned_child_incomplete'): self.owner.run([b.GIT], fetch=True)
        cleanup.assert_called_once()
        fact = json.loads(next(self.output.glob('*.status.private.json')).read_bytes())
        self.assertTrue(fact['timedOut']); self.assertTrue(fact['cleanupSettled'])
        self.assertEqual(next(self.output.glob('*.stdout.redacted.private')).read_bytes(), b'{}')

    def test_launch_failure_is_recorded_without_claimed_child(self):
        with patch.object(subprocess, 'Popen', side_effect=PermissionError(13, 'synthetic')):
            with self.assertRaisesRegex(b.Refusal, 'child_launch_refused'): self.owner.run([b.GIT])
        self.assertFalse(json.loads(next(self.output.glob('*.status.private.json')).read_bytes())['childStarted'])

    def test_expired_budget_and_missing_token_refuse_before_child(self):
        self.owner.deadline = time.time() - 1
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('no child')):
            with self.assertRaisesRegex(b.Refusal, 'shared_deadline'): self.owner.run([b.GIT])
        with self.assertRaises(b.Refusal): b.fetch_environment(self.owner.env, None)

    def test_no_cli_fixture_or_origin_fallback_and_disarmed_default(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(b.main([], {}), 0)
        self.assertEqual(json.loads(out.getvalue())['status'], 'DISARMED')
        for flag in ('--origin', '--fixture'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                b.main(['--job', 'source', flag, 'file:///tmp/not-a-route'], {})

    def test_official_tag_fixture_and_existing_materializer_are_unchanged(self):
        raw = (HERE / self.runtime.TAG_FIXTURE.removeprefix('scripts/fork-release/')).read_bytes()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (1028, self.runtime.TAG_SHA256))
        self.assertEqual(self.runtime.policy.UPSTREAM['tagObject'], '88a19e0d8677804d8ec98e30a3a3a3a9308ebee0')

    def test_no_real_network_or_unowned_process_attempt(self): self.assertEqual(HOST_ATTEMPTS, [])

    def config_custody_refuses_without_text(self, body, marker):
        for code in (0, 2):
            output = self.case / ('config-' + str(code)); output.mkdir()
            self.owner.output = output
            err = b'unknown diagnostic ' + marker + b'\n'
            class Child:
                returncode = code
                def communicate(self, timeout): return body, err
            def child(argv, *args, **kwargs):
                if 'config' in argv and '--get-regexp' in argv:
                    return Child()
                return local_git_only(argv, *args, **kwargs)
            with patch.object(subprocess, 'Popen', side_effect=child), \
                 contextlib.redirect_stdout(io.StringIO()) as printed, self.assertRaises(b.Refusal):
                b.repository_state(self.owner, self.fixture.head, True)
            custody = b''.join(path.read_bytes() for path in output.iterdir())
            self.assertNotIn(marker, custody)
            self.assertNotIn(marker.decode(), printed.getvalue())
            facts = [json.loads(path.read_bytes()) for path in output.glob('*.status.private.json')]
            last = max(facts, key=lambda value: value['ordinal'])
            self.assertTrue(last['outputSuppressed'])
            self.assertEqual(last['exitCode'], code)
            self.assertEqual(last['stdout']['bytes'], len(body))
            self.assertEqual(last['stdout']['sha256'], hashlib.sha256(body).hexdigest())
            self.assertEqual(last['stderr']['bytes'], len(err))
            self.assertEqual(last['stdout']['redactedPrefixBytes'], 0)
            self.assertEqual(last['stderr']['redactedPrefixBytes'], 0)

    def test_unknown_credential_helper_value_is_never_persisted_or_printed(self):
        marker = b'FAKE_UNRELATED_HELPER_CREDENTIAL_97cc'
        self.config_custody_refuses_without_text(b'credential.helper !printf ' + marker + b'\n', marker)

    def test_credential_bearing_config_key_is_never_persisted_or_printed(self):
        marker = b'FAKE_CREDENTIAL_IN_URL_KEY_183a'
        self.config_custody_refuses_without_text(
            b'url.https://example.invalid/' + marker + b'.insteadof https://github.com/\n', marker)

    def test_actual_workflow_hash_fixture_selector_and_clock_caps_are_consistent(self):
        root = HERE.parents[1]
        workflow = (root / '.github/workflows/future-v109-source-validation.yml').read_bytes()
        text = workflow.decode()
        helper_hash = hashlib.sha256((HERE / 'finite_public_root_bootstrap_v109.py').read_bytes()).hexdigest()
        self.assertEqual(text.count(helper_hash), 3)
        self.assertEqual(text.count('Checkout exact pipeline bootstrap only'), 3)
        self.assertEqual(text.count('timeout-minutes: 5'), 3)
        self.assertNotIn('fetch-depth: 0', text)
        self.assertEqual(workflow, (HERE / 'fixtures/v109-source-validation-restored.yml').read_bytes())
        import model_diagnostic_v109 as route
        self.assertEqual(route.SOURCE_WORKFLOW_RESTORED, hashlib.sha256(workflow).hexdigest())
        parsed = ast.parse((HERE / 'source_validation_selection_v109.py').read_bytes())
        entries = next(x.value for x in parsed.body if isinstance(x, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'PIPELINE_CONTRACT_TESTS' for t in x.targets))
        self.assertEqual(ast.literal_eval(entries).count('test_finite_public_root_bootstrap_v109.py'), 1)
        import re
        actual = dict((name, int(value)) for name, value in re.findall(
            r'profile: ([a-z0-9-]+)\n\s+minutes: ([0-9]+)', text))
        self.assertEqual(actual, self.runtime.policy.NEXT_PROFILE_MINUTES)

    def test_only_fixed_refusal_codes_may_escape(self):
        self.assertEqual(b.safe_refusal_code(b.Refusal('bootstrap.fixed_origin')), 'bootstrap.fixed_origin')
        self.assertEqual(b.safe_refusal_code(ValueError('private arbitrary error')), 'bootstrap.runtime_refused')
        self.assertEqual(b.safe_refusal_code(subprocess.CalledProcessError(1, ['secret'])), 'bootstrap.runtime_refused')


if __name__ == '__main__': unittest.main()
