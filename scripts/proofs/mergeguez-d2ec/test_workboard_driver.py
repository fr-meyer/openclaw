"""Source-only companion admission fixtures; no Driver, helper, worker or database."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest


P = Path(__file__).resolve().parent
SOURCE = P / 'driver.py'
TREE = ast.parse(SOURCE.read_text())
PROFILE = 'workboard-native-worker-logical-recovery.synthetic.v1'
CONTRACT = json.loads((P / 'contract.json').read_text())
FUNCTIONS = {'need', 'digest', 'validated_tooling_inputs', 'phase_mounts'}
SELECTED = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
assert {node.name for node in SELECTED} == FUNCTIONS
DRIVER = next(node for node in TREE.body if isinstance(node, ast.ClassDef) and node.name == 'Driver')
VERIFY = next(node for node in DRIVER.body if isinstance(node, ast.FunctionDef) and node.name == 'verify_tooling')


class Refusal(RuntimeError):
    pass


class CompanionAdmission(unittest.TestCase):
    """Small synthetic bytes exercise the accepted original validator and mounts."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='workboard-driver-source-')
        self.root = Path(self.temporary.name).resolve()
        self.proof = self.root / 'proof'
        self.proof.mkdir()
        self.calls = []
        self.scope = dict(Path=Path, re=re, stat=stat, hashlib=hashlib,
                          Refusal=Refusal, WORKBOARD_PROFILE=PROFILE, json=json)
        exec(compile(ast.Module(body=[*SELECTED, VERIFY], type_ignores=[]), str(SOURCE), 'exec'), self.scope)
        self.files = []
        for name in ('driver.py', 'runtime.mjs', 'materialize.mjs', 'contract.json'):
            self.input_file(name)
        nested = [self.input_file(entry['path']) for entry in CONTRACT['workboard_companion_inputs']]
        self.contract = dict(qualification_scope=PROFILE, workboard_companion_inputs=nested)
        self.manifest = dict(files=self.files)
        self.loaded_hash = self.files[0]['sha256']

    def tearDown(self):
        self.temporary.cleanup()

    def input_file(self, name):
        path = self.proof / name
        path.parent.mkdir(parents=True, exist_ok=True)
        body = ('synthetic source input: ' + name).encode()
        path.write_bytes(body)
        declaration = dict(path=name, bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        self.files.append(declaration)
        return copy.deepcopy(declaration)

    def validate(self):
        return self.scope['validated_tooling_inputs'](self.proof, self.manifest, self.contract, self.loaded_hash)

    def mounts(self, companion):
        return self.scope['phase_mounts'](self.root / 'volume', self.proof, self.root / 'gates', 'offline-native', companion)

    def verify_tooling(self):
        manifest = self.proof / 'manifest.json'
        manifest.write_text(json.dumps(self.manifest))
        event = self.root / 'event.json'
        event.write_text('{}')
        env = dict(QUALIFICATION_MANIFEST_SHA256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                   GITHUB_EVENT_PATH=str(event), GITHUB_RUN_ID='1')
        self.scope.update(PROOF=self.proof, LOADED_HASH=self.loaded_hash,
                          os=SimpleNamespace(environ=env))
        admission = dict(run_id='1')
        def validate_event(*args):
            self.calls.append('admission')
            return admission
        def bind_admission(state, value):
            self.calls.append('bind')
            state['admission'] = value
        self.scope.update(validate_event=validate_event, bind_admission=bind_admission)
        owner = SimpleNamespace(c=self.contract, state=dict(job='1-1'),
                                save=lambda: self.calls.append('save'))
        self.scope['verify_tooling'](owner)
        return owner

    def test_all_seventeen_inputs_mount_individually_readonly(self):
        companion = self.validate()
        self.assertEqual(len(companion), 17)
        self.assertEqual(companion, tuple(sorted(entry['path'] for entry in self.contract['workboard_companion_inputs'])))
        mounts = self.mounts(companion)
        self.assertEqual(sum(path.startswith('/proof/workboard-custody/') for path in mounts), 17)
        self.assertIn('/proof/manifest.json', mounts)
        self.assertTrue(all(not writable for path, (_, writable) in mounts.items() if path.startswith('/proof/')))
        self.assertNotIn('/proof', mounts)
        self.assertNotIn('/qualification', mounts)
        self.assertEqual({path for path, (_, rw) in mounts.items() if rw},
                         {'/qualification/native-state', '/qualification/native-output', '/tmp'})

    def test_missing_nested_inventory_refuses(self):
        self.manifest['files'].pop()
        with self.assertRaisesRegex(Refusal, 'incomplete companion closure'):
            self.validate()

    def test_changed_nested_bytes_refuse(self):
        (self.proof / 'workboard-custody/worker-custody-bridge.mjs').write_text('changed source')
        with self.assertRaisesRegex(Refusal, 'tooling bytes changed'):
            self.validate()

    def test_duplicate_manifest_path_refuses(self):
        self.manifest['files'].append(copy.deepcopy(self.files[0]))
        with self.assertRaisesRegex(Refusal, 'duplicate tooling path'):
            self.validate()

    def test_parent_traversal_refuses(self):
        self.manifest['files'][0] = dict(self.files[0], path='../escape')
        with self.assertRaisesRegex(Refusal, 'escaping tooling path'):
            self.validate()

    def test_absolute_path_refuses(self):
        self.manifest['files'][0] = dict(self.files[0], path='/escape')
        with self.assertRaisesRegex(Refusal, 'escaping tooling path'):
            self.validate()

    def test_symlink_ancestor_refuses(self):
        vendor = self.proof / 'workboard-custody/vendor'
        vendor.rename(self.proof / 'outside')
        vendor.symlink_to(self.proof / 'outside', target_is_directory=True)
        with self.assertRaisesRegex(Refusal, 'tooling ancestor alias'):
            self.validate()

    def test_hardlink_input_refuses(self):
        os.link(self.proof / 'runtime.mjs', self.root / 'alias')
        with self.assertRaisesRegex(Refusal, 'tooling path alias'):
            self.validate()

    def test_contract_inventory_conflict_refuses(self):
        self.contract['workboard_companion_inputs'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(Refusal, 'unsealed nested tooling path'):
            self.validate()

    def test_workboard_profile_without_closure_refuses(self):
        self.contract.pop('workboard_companion_inputs')
        with self.assertRaisesRegex(Refusal, 'missing frozen companion closure'):
            self.validate()

    def test_legacy_native_mounts_preserved(self):
        self.contract = {}
        self.manifest['files'] = self.files[:4]
        self.assertEqual(self.validate(), ())
        mounts = self.mounts(())
        self.assertEqual({path for path in mounts if path.startswith('/proof/')},
                         {'/proof/runtime.mjs', '/proof/materialize.mjs', '/proof/contract.json'})

    def test_unlisted_source_is_not_a_mount(self):
        (self.proof / 'workboard-custody/unlisted.txt').write_text('unsealed')
        self.assertNotIn('/proof/workboard-custody/unlisted.txt', self.mounts(self.validate()))

    def test_loaded_driver_must_match_declaration(self):
        self.loaded_hash = '0' * 64
        with self.assertRaisesRegex(Refusal, 'loaded driver differs'):
            self.validate()

    def test_tooling_root_alias_refuses(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.proof, target_is_directory=True)
        self.proof = alias
        with self.assertRaisesRegex(Refusal, 'tooling root alias'):
            self.validate()

    def test_verify_tooling_binds_verified_closure_before_phase_mounts(self):
        owner = self.verify_tooling()
        self.assertEqual(self.calls, ['admission', 'bind', 'save'])
        self.assertEqual(owner.workboard_companion_inputs,
                         tuple(sorted(entry['path'] for entry in self.contract['workboard_companion_inputs'])))
        mounts = self.mounts(owner.workboard_companion_inputs)
        self.assertEqual(sum(path.startswith('/proof/workboard-custody/') for path in mounts), 17)
        self.assertEqual(owner.admission, owner.state['admission'])

    def test_invalid_closure_refuses_before_job_admission_or_save(self):
        self.manifest['files'].pop()
        with self.assertRaisesRegex(Refusal, 'incomplete companion closure'):
            self.verify_tooling()
        self.assertEqual(self.calls, [])

    def test_phase_consumes_original_verified_field_without_fallback(self):
        phase = next(node for node in DRIVER.body if isinstance(node, ast.FunctionDef) and node.name == 'phase')
        calls = [node for node in ast.walk(phase) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'phase_mounts']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.dump(calls[0].args[-1]),
                         ast.dump(ast.Attribute(value=ast.Name(id='self', ctx=ast.Load()),
                                                attr='workboard_companion_inputs', ctx=ast.Load())))
        constructor = next(node for node in DRIVER.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')
        verify_calls = [node for node in ast.walk(constructor) if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute) and node.func.attr == 'verify_tooling']
        self.assertEqual(len(verify_calls), 1)
        effect_names = {'phase_mounts', 'phase', 'docker', 'command'}
        self.assertFalse(any(isinstance(node, ast.Call)
                             and isinstance(node.func, (ast.Name, ast.Attribute))
                             and (node.func.id if isinstance(node.func, ast.Name) else node.func.attr) in effect_names
                             for node in ast.walk(constructor)))


if __name__ == '__main__':
    unittest.main()
