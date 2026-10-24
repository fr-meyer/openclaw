"""Bounded workflow contract and synthetic capacity-probe checks; no Docker calls."""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch


WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/fork-release-pipeline.yml'
SOURCE = 'a39cad2d97efae7d0c832af3d71e6ccc86f60e50'


def step(workflow, name):
    return workflow.split('      - name: ' + name + '\n', 1)[1].split('\n      - name:', 1)[0]


def expression(value, **context):
    # Evaluate only the checked-in fixture's simple GitHub comparisons/selection.
    value = value.strip().removeprefix('${{').removesuffix('}}').strip()
    value = value.replace('&&', ' and ').replace('||', ' or ')
    return eval(value, {'__builtins__': {}, 'false': False, 'true': True,
                        'format': lambda fmt, *args: fmt.format(*args),
                        'startsWith': lambda value, prefix: value.startswith(prefix)}, context)


class HostedBuildWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text()
        self.probe = self.workflow.split('  hosted-capacity-assessment:\n', 1)[1].split('\n  pr-intake:', 1)[0]
        self.build = step(self.workflow, 'Build exact candidate once into OCI')

    def source_context(self, source):
        return {'steps': NS(identity=NS(outputs=NS(source_sha=source)))}

    def test_capacity_job_is_exact_fork_pr20_and_selected_events_only(self):
        condition = self.probe.split('    if: >-\n', 1)[1].split('\n    runs-on:', 1)[0]
        condition = ' '.join(condition.split())

        def selected(action='synchronize', number=20, ref='task/v106-merge-binding',
                     repo='fr-meyer/openclaw', head_repo='fr-meyer/openclaw', event='pull_request'):
            github = NS(event_name=event, repository=repo, event=NS(action=action,
                pull_request=NS(number=number, head=NS(ref=ref, repo=NS(full_name=head_repo)))))
            return expression(condition, github=github)

        for action in ('opened', 'reopened', 'synchronize', 'ready_for_review'):
            self.assertTrue(selected(action=action))
        for change in ({'action': 'assigned'}, {'action': 'unassigned'}, {'action': 'edited'},
                       {'action': 'converted_to_draft'}, {'number': 19}, {'number': 21},
                       {'ref': 'candidate/v106'}, {'head_repo': 'other/openclaw'},
                       {'repo': 'other/openclaw'}, {'event': 'workflow_dispatch'}, {'event': 'push'}):
            with self.subTest(change=change):
                self.assertFalse(selected(**change))

    def test_capacity_job_has_no_checkout_install_build_or_upload(self):
        self.assertIn('runs-on: ubuntu-24.04', self.probe)
        self.assertIn('permissions: {}', self.probe)
        self.assertIn('timeout-minutes: 5', self.probe)
        self.assertEqual(self.probe.count('- name:'), 1)
        for forbidden in ('uses:', 'secrets.', 'github.token', 'checkout', 'apt-get',
                          'pip install', 'pnpm', 'buildx create', 'docker run', 'docker build',
                          'upload-artifact', 'cache-from:', 'cache-to:', 'self-hosted', 'larger'):
            self.assertNotIn(forbidden, self.probe)

    def test_build_entrypoint_and_registry_permissions_stay_restricted(self):
        manual = self.workflow.split('  qualify-and-prepare:\n', 1)[1]
        self.assertIn("github.event_name != 'pull_request'", manual)
        self.assertIn("github.ref == 'refs/heads/main'", manual)
        self.assertIn('pr["base"]["ref"] == "main"', manual)
        self.assertIn('pr["head"]["ref"].startswith("candidate/")', manual)
        self.assertIn('parent === sourceSha', (WORKFLOW.parents[2] / 'scripts/fork-release/image.mjs').read_text())
        self.assertIn('permissions:\n  contents: read', self.workflow)
        for forbidden in ('packages: write', 'docker/login-action',
                          'cache-to:', 'cache-from:', 'self-hosted'):
            self.assertNotIn(forbidden, self.workflow)
        self.assertIn('push: false', self.build)

    def test_candidate_execution_has_no_native_actions_cache_authority(self):
        header, jobs = self.workflow.split('\njobs:\n', 1)
        self.assertEqual(re.findall(r'^cache-mode:[ \t]*(.*?)[ \t]*$', header, re.M), ['none'])
        # Job overrides take precedence over the workflow grant. Automatic
        # package-cache settings alone do not restrict the cache service token.
        self.assertTrue(all(mode == 'none' for mode in
                            re.findall(r'^    cache-mode:[ \t]*(.*?)[ \t]*$', jobs, re.M)))
        for name in ('Run focused candidate lifecycle and producer-consumer tests',
                     'Run focused custom patch and producer-consumer gates'):
            candidate_execution = step(self.workflow, name)
            self.assertIn('cd source', candidate_execution)
            self.assertIn('pnpm install --frozen-lockfile', candidate_execution)
            self.assertIn('node scripts/run-vitest.mjs', candidate_execution)

    def run_focused_gate_dispatch(self, name, tests, *, native_exists=True,
                                  vitest_exit=0, native_exit=0):
        candidate_execution = step(self.workflow, name)
        run = textwrap.dedent(candidate_execution.split('        run: |\n', 1)[1])
        dispatch = run[run.index('if [[ -z "${tests[*]-}"'):]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.last_gate_root = str(root)
            stub = root / 'node'
            stub.write_text(f'#!{sys.executable}\n' + textwrap.dedent('''\
                import json, os, sys
                from pathlib import Path
                args = sys.argv[1:]
                with Path(os.environ['GATE_TRACE']).open('a') as trace:
                    trace.write(json.dumps(args) + '\\n')
                native = bool(args and args[0].endswith('/native_tests.mjs'))
                if native:
                    selected = args[args.index('--') + 1:]
                    if any(not Path(arg).is_file() for arg in selected):
                        raise SystemExit(2)
                raise SystemExit(int(os.environ['NATIVE_EXIT' if native else 'VITEST_EXIT']))
                '''))
            stub.chmod(0o755)
            prerequisite = root / 'test/mcp-nowistay-sdk-regression.test.mjs'
            if native_exists:
                prerequisite.parent.mkdir()
                prerequisite.write_text('// Synthetic native runner input.\n')
                for test_path in tests:
                    if test_path.endswith(('.test.mjs', '.e2e.mjs')):
                        selected = root / test_path
                        selected.parent.mkdir(parents=True, exist_ok=True)
                        selected.write_text('// Synthetic selected native input.\n')
            trace = root / 'calls.jsonl'
            env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                   'GATE_TRACE': str(trace), 'VITEST_EXIT': str(vitest_exit),
                   'NATIVE_EXIT': str(native_exit)}
            selection = 'tests=(' + ' '.join(shlex.quote(test) for test in tests) + ')\n'
            result = subprocess.run(['/bin/bash', '-c', 'set -euo pipefail\n' + selection + dispatch],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=10)
            calls = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        return result, calls

    def native_caller(self, name, selected, completed=()):
        owner = 'trusted' if 'lifecycle' in name else 'tooling'
        command = [f'../{owner}/scripts/fork-release/native_tests.mjs',
                   '--source-root', self.last_gate_root]
        for test_path in completed:
            command += ['--completed-vitest', test_path]
        return [*command, '--', *selected]

    def test_selected_mcp_gate_runs_declared_native_nowistay_prerequisite(self):
        descriptor = json.loads((WORKFLOW.parents[2] / 'scripts/fork-release/candidates/'
                                 'v2026.10.5-source-only/native-nowistay-prerequisite.json').read_text())
        self.assertTrue(descriptor['required'])
        native = descriptor['command'][2:]
        tests = ['src/other.test.ts', descriptor['runnerRouting']['vitestProducerGate']]
        for name in ('Run focused candidate lifecycle and producer-consumer tests',
                     'Run focused custom patch and producer-consumer gates'):
            with self.subTest(step=name):
                result, calls = self.run_focused_gate_dispatch(name, tests)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [['scripts/run-vitest.mjs', 'run', *tests],
                                         self.native_caller(name, native, tests)])

    def test_unrelated_gates_do_not_acquire_a_native_nowistay_requirement(self):
        for name in ('Run focused candidate lifecycle and producer-consumer tests',
                     'Run focused custom patch and producer-consumer gates'):
            with self.subTest(step=name):
                result, calls = self.run_focused_gate_dispatch(name, ['src/other.test.ts'],
                                                              native_exists=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [['scripts/run-vitest.mjs', 'run', 'src/other.test.ts']])

    def test_vitest_native_and_missing_native_failures_block_both_gate_steps(self):
        tests = ['src/agents/mcp-http-transport.test.ts']
        for name in ('Run focused candidate lifecycle and producer-consumer tests',
                     'Run focused custom patch and producer-consumer gates'):
            for change, expected, count in (({'vitest_exit': 17}, 17, 1),
                                            ({'native_exit': 19}, 19, 2),
                                            ({'native_exists': False}, 2, 2)):
                with self.subTest(step=name, change=change):
                    result, calls = self.run_focused_gate_dispatch(name, tests, **change)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(len(calls), count)

    def test_native_only_gates_never_start_empty_vitest_collection(self):
        tests = ['test/body-parser-security.test.mjs', 'test/zod-container-bounds.test.mjs']
        for name in ('Run focused candidate lifecycle and producer-consumer tests',
                     'Run focused custom patch and producer-consumer gates'):
            with self.subTest(step=name):
                result, calls = self.run_focused_gate_dispatch(name, tests)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [self.native_caller(name, tests)])

    def test_mixed_gates_separate_frameworks_and_forward_completed_vitest(self):
        tests = ['src/example.test.ts', 'test/a2ui-native-zod-regression.test.mjs',
                 'test/discord-native-zod-regression.test.mjs']
        for name in ('Run focused candidate lifecycle and producer-consumer tests',
                     'Run focused custom patch and producer-consumer gates'):
            with self.subTest(step=name):
                result, calls = self.run_focused_gate_dispatch(name, tests)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [['scripts/run-vitest.mjs', 'run', tests[0]],
                                         self.native_caller(name, tests[1:], tests[:1])])

    def test_explicit_mcp_companion_is_not_added_twice(self):
        tests = ['src/agents/mcp-http-transport.test.ts',
                 'test/mcp-nowistay-sdk-regression.test.mjs']
        name = 'Run focused custom patch and producer-consumer gates'
        result, calls = self.run_focused_gate_dispatch(name, tests)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-1], self.native_caller(name, tests[1:], tests[:1]))

    def test_completed_adapter_fact_is_forwarded_only_after_vitest_success(self):
        name = 'Run focused custom patch and producer-consumer gates'
        tests = ['test/scripts/native-security.test.ts', 'test/body-parser-security.test.mjs']
        result, calls = self.run_focused_gate_dispatch(name, tests)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-1], self.native_caller(name, tests[1:], tests[:1]))
        result, calls = self.run_focused_gate_dispatch(name, tests, vitest_exit=17)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(calls, [['scripts/run-vitest.mjs', 'run', tests[0]]])

    def test_empty_selection_does_not_qualify(self):
        result, calls = self.run_focused_gate_dispatch(
            'Run focused custom patch and producer-consumer gates', [])
        self.assertEqual(result.returncode, 78)
        self.assertEqual(calls, [])

    def test_release_pr_contracts_exclude_default_branch_dispatch(self):
        job = self.workflow.split('  release-pr-contracts:\n', 1)[1].split('\n  qualify-and-prepare:', 1)[0]
        condition = ' '.join(job.split('    if: >-\n', 1)[1].split('\n    needs:', 1)[0].split())
        condition = condition.replace('needs.pr-intake', 'needs.pr_intake')
        github = NS(event_name='pull_request', repository='fr-meyer/openclaw',
                    event=NS(action='synchronize', pull_request=NS(head=NS(
                        repo=NS(full_name='fr-meyer/openclaw'), ref='candidate/v105'))))
        needs = NS(pr_intake=NS(result='success'))
        self.assertTrue(expression(condition, github=github, needs=needs))
        for event in ('workflow_dispatch', 'push', 'schedule'):
            with self.subTest(event=event):
                github.event_name = event
                self.assertFalse(expression(condition, github=github, needs=needs))
        github.event_name = 'pull_request'
        needs.pr_intake.result = 'failure'
        self.assertFalse(expression(condition, github=github, needs=needs))

    def test_buildx_and_node_setup_do_not_request_automatic_cache_operations(self):
        builder = step(self.workflow, 'Set up bounded hosted Docker Buildx')
        self.assertIn('uses: docker/setup-buildx-action@', builder)
        self.assertEqual(re.findall(r'^          cache-binary:\s*(\S+)\s*$', builder, re.M),
                         ['false'])
        node_setups = self.workflow.split('      - name: Setup supported Node runtime\n')[1:]
        self.assertEqual(len(node_setups), 2)
        for setup in node_setups:
            self.assertIn('package-manager-cache: false', setup.split('\n      - name:', 1)[0])

    def test_hosted_builds_use_bounded_worker_and_immutable_context_by_default(self):
        new = step(self.workflow, 'Set up bounded hosted Docker Buildx')
        self.assertNotIn('if:', new)
        self.assertIn('driver: docker-container', new)
        opts = dict(re.findall(r'^            ([a-z-]+)=([0-9]+)$', new, re.M))
        self.assertEqual(opts, {'memory': str(8 << 30), 'memory-swap': str(8 << 30),
                                'cpu-period': '100000', 'cpu-quota': '400000'})
        context = re.search(r'^          context: (.+)$', self.build, re.M).group(1)
        for source in (SOURCE, '7f3ac1fbfd3691546c5b1fd247680a3d00851c76'):
            self.assertEqual(expression(context, **self.source_context(source)),
                'https://github.com/fr-meyer/openclaw.git?fetch-by-commit=true&checksum=' + source + '#' + source)
        for required in ('DOCKER_BUILD_RECORD_UPLOAD: "false"', 'DOCKER_BUILD_SUMMARY: "false"',
                         'OPENCLAW_PARITY_IMAGE=1', 'OPENCLAW_DOCKER_BUILD_TSDOWN_MAX_OLD_SPACE_MB=6144',
                         'platforms: linux/amd64', 'provenance: mode=max,version=v1', 'sbom: true'):
            self.assertIn(required, self.build)

    def test_export_defaults_off_and_requires_manual_storage_decision(self):
        dispatch = self.workflow.split('  workflow_dispatch:', 1)[1].split('\npermissions:', 1)[0]
        for option in ('export_public_artifact', 'artifact_storage_approved'):
            # YAML sibling indentation is checked separately by Actionlint.
            self.assertIn('default: false', dispatch.split('      ' + option + ':', 1)[1].split('type: boolean', 1)[0])
        upload = step(self.workflow, 'Retain the exact tested OCI payload and public receipt')
        condition = ' '.join(upload.split('        if: >-\n', 1)[1].split('\n        uses:', 1)[0].split())
        for event in ('pull_request', 'push', 'workflow_dispatch'):
            for public in (False, True):
                for cost in (False, True):
                    actual = expression(condition, github=NS(event_name=event),
                                        steps=NS(identity=NS(outputs=NS(image_only_build='false'))),
                                        inputs=NS(export_public_artifact=public, artifact_storage_approved=cost))
                    self.assertEqual(actual, event == 'workflow_dispatch' and public and cost)
        self.assertNotIn('always()', upload)
        self.assertIn('retention-days: 1', upload)
        self.assertIn('archive: false', upload)
        self.assertIn('overwrite: false', upload)
        self.assertIn('path: ${{ steps.bundle.outputs.path }}', upload)
        self.assertNotIn('path: ${{ runner.temp }}/fork-release/', upload)
        bundle = step(self.workflow, 'Prepare and verify the bounded public artifact')
        self.assertIn('hosted_bundle.py prepare', bundle)
        self.assertIn('hosted_bundle.py verify', bundle)
        self.assertIn('--output-dir "$RUNNER_TEMP/fork-upload"', bundle)
        self.assertIn('inputs.export_public_artifact &&', bundle)
        self.assertIn('inputs.artifact_storage_approved', bundle)
        digest_check = step(self.workflow, 'Confirm uploaded bytes match the bounded artifact')
        self.assertIn("if: steps.image_artifact.outcome == 'success'", digest_check)
        self.assertIn('steps.image_artifact.outputs.artifact-digest', digest_check)
        self.assertIn('expected != os.environ["UPLOADED_SHA256"]', digest_check)
        admission = step(self.workflow, 'Validate manual candidate identity before checkout')
        self.assertIn('"$PUBLIC_EXPORT" == true && "$STORAGE_APPROVED" != true', admission)

    def test_image_only_branch_job_is_exact_update_once_and_manual_main_guard_is_unchanged(self):
        job = self.workflow.split('  qualify-and-prepare:\n', 1)[1]
        condition = ' '.join(job.split('    if: >-\n', 1)[1].split('\n    runs-on:', 1)[0].split())

        def selected(ref='refs/heads/release-pipeline/v105-image-only-20261024',
                     event='push', created=False, attempt='1', actor='fr-meyer',
                     before='a1c3837ba9d8e33a6964a8208ef74d339d6aa635',
                     repo='fr-meyer/openclaw'):
            return expression(condition, github=NS(ref=ref, event_name=event,
                event=NS(created=created, before=before), run_attempt=attempt, actor=actor, repository=repo))

        self.assertTrue(selected())
        for change in ({'created': True}, {'before': 'b' * 40},
                       {'before': 'e7f32458be156cc489f76fd7cc68d35c5c1e1986'},
                       {'before': 'cf145a4c2afb999f06b3ced1f5a2b69e23929eae'}, {'attempt': '2'}, {'actor': 'someone-else'},
                       {'repo': 'other/openclaw'}, {'event': 'workflow_dispatch'},
                       {'event': 'pull_request'}):
            with self.subTest(change=change):
                self.assertFalse(selected(**change))
        self.assertTrue(selected(event='workflow_dispatch', ref='refs/heads/main'))
        self.assertFalse(selected(event='workflow_dispatch', ref='refs/heads/other'))

    def run_image_only_scope(self, *, environment=None, event=None, manifest=None,
                             history=None, history_error=False, oversized=False,
                             previous_job=None, previous_job_2=None, built_job=None, built_job_2=None,
                             built_job_3=None, built_job_4=None, artifacts=None, artifacts_2=None, artifacts_3=None,
                             artifacts_4=None, current_commit=None, unavailable_endpoint=None):
        identity = step(self.workflow, 'Resolve exact source identity')
        raw = identity.split("          python3 - <<'PY_IMAGE_ONLY'\n", 1)[1].split(
            '\n          PY_IMAGE_ONLY', 1)[0]
        code = textwrap.dedent(raw)
        run = {'id': 1234, 'head_sha': SOURCE, 'run_attempt': 1,
               'head_branch': 'release-pipeline/v105-image-only-20261024', 'event': 'push'}
        prior = {**run, 'id': 40062126779, 'head_sha': 'aee8475917dd29e0ee9a0b4059daf34990cfdbd5',
                 'status': 'completed', 'conclusion': 'failure', 'run_attempt': 1}
        payload = json.dumps(history if history is not None else {
            'total_count': 7, 'workflow_runs': [run, prior, {**prior, 'id': 40062948481,
                'head_sha': '9c2df877355c763ccd9b939250de4384ff80b586'},
                {**prior, 'id': 40063895699,
                 'head_sha': 'e7f32458be156cc489f76fd7cc68d35c5c1e1986'},
                {**prior, 'id': 40067322318,
                 'head_sha': 'cf145a4c2afb999f06b3ced1f5a2b69e23929eae'},
                {**prior, 'id': 40070695622,
                 'head_sha': '0d5edcd62b511ef8b4472d15bbd330f2bf93e6a1'},
                {**prior, 'id': 40075559894,
                 'head_sha': 'a1c3837ba9d8e33a6964a8208ef74d339d6aa635'}]})
        job = {'id': 120777706110, 'run_id': 40062126779, 'name': 'qualify-and-prepare',
               'head_sha': 'aee8475917dd29e0ee9a0b4059daf34990cfdbd5',
               'status': 'completed', 'conclusion': 'failure', 'run_attempt': 1, 'steps': [
                   {'name': name, 'status': 'completed', 'conclusion': conclusion} for name, conclusion in (
                       ('Verify source and run offline pipeline regressions', 'failure'),
                       ('Set up bounded hosted Docker Buildx', 'skipped'),
                       ('Verify hosted worker limits and begin bounded resource observation', 'skipped'),
                       ('Prepare OCI directory', 'skipped'),
                       ('Build exact candidate once into OCI', 'skipped'),
                       ('Inspect all OCI layers and metadata before native smoke or publication', 'skipped'),
                       ('Verify OCI bytes and smoke that exact image', 'skipped'),
                       ('Finish resource observation through export load and native verification', 'skipped'),
                       ('Bind hosted qualification receipts and export decision', 'skipped'),
                       ('Prepare and verify the bounded public artifact', 'skipped'),
                       ('Retain the exact tested OCI payload and public receipt', 'skipped'),
                       ('Confirm uploaded bytes match the bounded artifact', 'skipped'))]}
        job2 = {**job, 'id': 120780156996, 'run_id': 40062948481,
                'head_sha': '9c2df877355c763ccd9b939250de4384ff80b586'}
        built_steps = dict((s['name'], s['conclusion']) for s in job['steps'])
        built_steps.update(self.built_job_step_outcomes())
        job3 = {**job, 'id': 120782979034, 'run_id': 40063895699,
                'head_sha': 'e7f32458be156cc489f76fd7cc68d35c5c1e1986',
                'steps': [{'name': n, 'status': 'completed', 'conclusion': c}
                          for n, c in built_steps.items()]}
        job4 = {**job3, 'id': 120793190410, 'run_id': 40067322318,
                'head_sha': 'cf145a4c2afb999f06b3ced1f5a2b69e23929eae'}
        job5 = {**job3, 'id': 120803275519, 'run_id': 40070695622,
                'head_sha': '0d5edcd62b511ef8b4472d15bbd330f2bf93e6a1'}
        job6 = {**job3, 'id': 120818019684, 'run_id': 40075559894,
                'head_sha': 'a1c3837ba9d8e33a6964a8208ef74d339d6aa635'}
        job.update(previous_job or {})
        job2.update(previous_job_2 or {})
        job3.update(built_job or {})
        job4.update(built_job_2 or {})
        job5.update(built_job_3 or {})
        job6.update(built_job_4 or {})
        artifact_payload = artifacts if artifacts is not None else {'total_count': 0, 'artifacts': []}
        artifact_payload_2 = artifacts_2 if artifacts_2 is not None else {'total_count': 0, 'artifacts': []}
        artifact_payload_3 = artifacts_3 if artifacts_3 is not None else {'total_count': 0, 'artifacts': []}
        artifact_payload_4 = artifacts_4 if artifacts_4 is not None else {'total_count': 0, 'artifacts': []}
        commit_payload = current_commit if current_commit is not None else {
            'sha': SOURCE, 'parents': [{'sha': 'e88b8997b29a2842127cc91a1cec3837b34dcc88'}]}

        wrapper = (
            'import io, json\nfrom unittest.mock import patch\n'
            'def fake_open(request, *, timeout):\n'
            '    assert timeout == 15\n'
            '    history_url = '
            "'https://api.github.com/repos/fr-meyer/openclaw/actions/workflows/' "
            "'fork-release-pipeline.yml/runs?event=push&per_page=7&' "
            "'branch=release-pipeline%2Fv105-image-only-20261024'\n"
            '    commit_url = "https://api.github.com/repos/fr-meyer/openclaw/git/commits/" + ' + repr(SOURCE) + '\n'
            '    job_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/jobs/120777706110"\n'
            '    job2_url = \"https://api.github.com/repos/fr-meyer/openclaw/actions/jobs/120780156996\"\n'
            '    job3_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/jobs/120782979034"\n'
            '    job4_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/jobs/120793190410"\n'
            '    job5_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/jobs/120803275519"\n'
            '    job6_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/jobs/120818019684"\n'
            '    artifacts_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/runs/40063895699/artifacts?per_page=1"\n'
            '    artifacts2_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/runs/40067322318/artifacts?per_page=1"\n'
            '    artifacts3_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/runs/40070695622/artifacts?per_page=1"\n'
            '    artifacts4_url = "https://api.github.com/repos/fr-meyer/openclaw/actions/runs/40075559894/artifacts?per_page=1"\n'
            '    assert request.full_url in (commit_url, history_url, job_url, job2_url, job3_url, job4_url, job5_url, job6_url, artifacts_url, artifacts2_url, artifacts3_url, artifacts4_url)\n'
            '    assert not request.has_header("Authorization")\n'
            '    if request.full_url == ' + repr(unavailable_endpoint) + ': raise OSError("bounded lookup unavailable")\n'
            + ('    raise OSError("bounded lookup unavailable")\n' if history_error else
               '    if request.full_url == commit_url: return io.BytesIO(' + repr(json.dumps(commit_payload).encode()) + ')\n'
               + '    if request.full_url == artifacts_url: return io.BytesIO(' + repr(json.dumps(artifact_payload).encode()) + ')\n'
               + '    if request.full_url == artifacts2_url: return io.BytesIO(' + repr(json.dumps(artifact_payload_2).encode()) + ')\n'
               + '    if request.full_url == artifacts3_url: return io.BytesIO(' + repr(json.dumps(artifact_payload_3).encode()) + ')\n'
               + '    if request.full_url == artifacts4_url: return io.BytesIO(' + repr(json.dumps(artifact_payload_4).encode()) + ')\n'
               + '    if request.full_url == job6_url: return io.BytesIO(' + repr(json.dumps(job6).encode()) + ')\n'
               + '    if request.full_url == job5_url: return io.BytesIO(' + repr(json.dumps(job5).encode()) + ')\n'
               + '    if request.full_url == job4_url: return io.BytesIO(' + repr(json.dumps(job4).encode()) + ')\n'
               + '    if request.full_url == job3_url: return io.BytesIO(' + repr(json.dumps(job3).encode()) + ')\n'
               + '    if request.full_url == job2_url: return io.BytesIO(' + repr(json.dumps(job2).encode()) + ')\n'
               + '    if request.full_url == job_url: return io.BytesIO(' + repr(json.dumps(job).encode()) + ')\n'
               + '    return io.BytesIO(' + ("b'x' * (128 * 1024 + 1)" if oversized else repr(payload.encode())) + ')\n')
            + 'with patch("urllib.request.urlopen", side_effect=fake_open):\n'
            + '    exec(' + repr(code) + ')\n')
        # Linux limits each argv element to 128 KiB: generate oversized HTTP
        # responses inside the child, while preserving the full response check.
        self.assertLess(len(wrapper.encode()), 64 * 1024)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / 'metadata/scripts/fork-release/manifest.json'
            metadata.parent.mkdir(parents=True)
            value = {'repository': 'fr-meyer/openclaw', 'productionEligible': False,
                     'source': {'commit': '85a9bdc1285c338f10f5ca818abc259f6d483b5b',
                                'tree': '3e0d6fbf5bc015063dce3e4f0f353f0eac3aed6a'},
                     'image': {'architecture': 'amd64', 'extensions': 'codex,workboard'}}
            value.update(manifest or {})
            metadata.write_text(json.dumps(value))
            event_file = root / 'event.json'
            event_file.write_text(json.dumps({'created': False,
                'before': 'a1c3837ba9d8e33a6964a8208ef74d339d6aa635',
                'after': SOURCE, **(event or {})}))
            output = root / 'output'
            env = {'PATH': os.environ.get('PATH', ''),
                   'GITHUB_REF': 'refs/heads/release-pipeline/v105-image-only-20261024',
                   'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': 'fr-meyer/openclaw',
                   'GITHUB_ACTOR': 'fr-meyer', 'GITHUB_RUN_ATTEMPT': '1',
                   'GITHUB_RUN_ID': '1234', 'GITHUB_SHA': SOURCE,
                   'ACTUAL_WORKFLOW_SHA': SOURCE, 'APPROVED_PRIVATE_WORKFLOW_SHA': SOURCE,
                   'GITHUB_EVENT_PATH': str(event_file), 'GITHUB_OUTPUT': str(output)}
            env.update(environment or {})
            result = subprocess.run([sys.executable, '-c', wrapper], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=5)
            emitted = output.read_text() if output.exists() else ''
        return result, emitted

    @staticmethod
    def built_job_step_outcomes():
        # The four actual terminal runs consumed physical builds. Their privacy
        # refusals do not grant another attempt without explicit authorization.
        return {
            'Verify source and run offline pipeline regressions': 'success',
            'Run focused custom patch and producer-consumer gates': 'success',
            'Set up bounded hosted Docker Buildx': 'success',
            'Verify hosted worker limits and begin bounded resource observation': 'success',
            'Prepare OCI directory': 'success',
            'Build exact candidate once into OCI': 'success',
            'Inspect all OCI layers and metadata before native smoke or publication': 'failure',
            'Verify OCI bytes and smoke that exact image': 'skipped',
            'Finish resource observation through export load and native verification': 'success',
            'Bind hosted qualification receipts and export decision': 'skipped',
            'Prepare and verify the bounded public artifact': 'skipped',
            'Retain the exact tested OCI payload and public receipt': 'skipped',
            'Confirm uploaded bytes match the bounded artifact': 'skipped',
            'Post Build exact candidate once into OCI': 'success',
            'Post Set up bounded hosted Docker Buildx': 'success',
        }

    def test_image_only_scope_binds_exact_source_nonproduction_and_absent_review(self):
        result, emitted = self.run_image_only_scope()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(emitted, 'image_only_build=true\nprivate_retention=true\nprivate_workflow_sha=' + SOURCE + '\n')
        negatives = (
            {'environment': {'GITHUB_REPOSITORY': 'other/openclaw'}},
            {'environment': {'GITHUB_ACTOR': 'someone-else'}},
            {'environment': {'GITHUB_RUN_ATTEMPT': '2'}},
            {'environment': {'GITHUB_EVENT_NAME': 'workflow_dispatch'}},
            *({'environment': {'APPROVED_PRIVATE_WORKFLOW_SHA': value}} for value in ('', 'not-a-sha', 'b' * 40)),
            {'environment': {'ACTUAL_WORKFLOW_SHA': 'b' * 40}},
            {'event': {'after': 'b' * 40}},
            {'event': {'created': True}}, {'event': {'created': 0}},
            {'event': {'before': 'b' * 40}}, {'event': {'before': None}},
            {'event': {'before': 'e7f32458be156cc489f76fd7cc68d35c5c1e1986'}},
            {'event': {'before': 'cf145a4c2afb999f06b3ced1f5a2b69e23929eae'}},
            {'manifest': {'productionEligible': True}},
            {'manifest': {'productionEligible': 0}},
            {'manifest': {'review': None}},
            {'manifest': {'source': {'commit': SOURCE}}},
            {'manifest': {'image': {'architecture': 'arm64', 'extensions': 'codex,workboard'}}},
            {'manifest': {'image': {'architecture': 'amd64', 'extensions': 'codex'}}},
            {'manifest': {'repository': 'other/openclaw'}},
        )
        for change in negatives:
            with self.subTest(change=change):
                result, emitted = self.run_image_only_scope(**change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('One-shot nonproduction image scope changed', result.stderr)
                self.assertEqual(emitted, '')

    def test_image_only_rejects_recreation_other_run_and_unavailable_history(self):
        run = {'id': 1234, 'head_sha': SOURCE, 'run_attempt': 1,
               'head_branch': 'release-pipeline/v105-image-only-20261024', 'event': 'push'}
        prior = [{**run, 'id': run_id, 'head_sha': sha, 'status': 'completed', 'conclusion': 'failure'}
                 for run_id, sha in ((40062126779, 'aee8475917dd29e0ee9a0b4059daf34990cfdbd5'),
                                     (40062948481, '9c2df877355c763ccd9b939250de4384ff80b586'),
                                     (40063895699, 'e7f32458be156cc489f76fd7cc68d35c5c1e1986'),
                                     (40067322318, 'cf145a4c2afb999f06b3ced1f5a2b69e23929eae'),
                                     (40070695622, '0d5edcd62b511ef8b4472d15bbd330f2bf93e6a1'),
                                     (40075559894, 'a1c3837ba9d8e33a6964a8208ef74d339d6aa635'))]
        for change in (
            {'history': {'total_count': 2, 'workflow_runs': [run, {**run, 'id': 1233}]}},
            {'history': {'total_count': 0, 'workflow_runs': []}},
            {'history': {'total_count': 1, 'workflow_runs': []}},
            {'history': {'total_count': True, 'workflow_runs': [run]}},
            *({'history': {'total_count': 1, 'workflow_runs': [{**run, **field}]}}
              for field in ({'id': 1233}, {'id': '1234'}, {'head_sha': 'b' * 40},
                            {'head_branch': 'other'}, {'event': 'pull_request'})),
            {'history': {'total_count': 7, 'workflow_runs': [run, prior[0], prior[0], prior[2], prior[3], prior[4], prior[5]]}},
            {'history': {'total_count': 5, 'workflow_runs': [run, *prior[:4]]}},
            {'history': {'total_count': 8, 'workflow_runs': [run, *prior, {**run, 'id': 1233}]}},
            *({'history': {'total_count': 7, 'workflow_runs': [{**run, **field}, *prior]}}
              for field in ({'id': 1233}, {'id': '1234'}, {'head_sha': 'b' * 40},
                            {'run_attempt': 2}, {'head_branch': 'other'}, {'event': 'pull_request'})),
            *({'history': {'total_count': 7, 'workflow_runs': [run, *[
                {**p, **field} if p['id'] == selected else p for p in prior]]}}
              for selected in (40062126779, 40062948481, 40063895699, 40067322318, 40070695622, 40075559894)
              for field in ({'head_sha': 'b' * 40}, {'status': 'in_progress'},
                            {'conclusion': 'success'}, {'run_attempt': 2})),
            {'history_error': True}, {'oversized': True},
        ):
            with self.subTest(change=change):
                result, emitted = self.run_image_only_scope(**change)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(emitted, '')
                if change.get('oversized'):
                    self.assertIn('exceeds bounded response', result.stderr)

    def test_prior_started_incomplete_or_other_job_never_grants_another_build(self):
        # Copy the exact expected prior job captured from the completed public
        # run; change one field/step at a time, preserving every other proof.
        expected = (
            ('Verify source and run offline pipeline regressions', 'failure'),
            ('Set up bounded hosted Docker Buildx', 'skipped'),
            ('Verify hosted worker limits and begin bounded resource observation', 'skipped'),
            ('Prepare OCI directory', 'skipped'), ('Build exact candidate once into OCI', 'skipped'),
            ('Inspect all OCI layers and metadata before native smoke or publication', 'skipped'),
            ('Verify OCI bytes and smoke that exact image', 'skipped'),
            ('Finish resource observation through export load and native verification', 'skipped'),
            ('Bind hosted qualification receipts and export decision', 'skipped'),
            ('Prepare and verify the bounded public artifact', 'skipped'),
            ('Retain the exact tested OCI payload and public receipt', 'skipped'),
            ('Confirm uploaded bytes match the bounded artifact', 'skipped'))
        steps = [{'name': n, 'status': 'completed', 'conclusion': c} for n, c in expected]
        for previous in ({'run_id': 42}, {'id': 42}, {'status': 'in_progress'},
                         {'head_sha': 'b' * 40}, {'conclusion': 'success'}, {'steps': []},
                         {'steps': steps + [steps[4]]},
                         *({'steps': [dict(s, conclusion='success') if s['name'] == name else s
                                      for s in steps]} for name, _ in expected),
                         *({'steps': [s for s in steps if s['name'] != name]} for name, _ in expected),
                         {'steps': [dict(s, status='in_progress') if s == steps[4] else s for s in steps]}):
            with self.subTest(previous=previous):
                for key in ('previous_job', 'previous_job_2'):
                    result, emitted = self.run_image_only_scope(**{key: previous})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(emitted, '')

    def test_built_privacy_refusal_requires_exact_failure_and_successful_cleanup(self):
        steps = [{'name': n, 'status': 'completed', 'conclusion': c}
                 for n, c in self.built_job_step_outcomes().items()]
        changes = (
            {'run_id': 42}, {'id': 42}, {'status': 'in_progress'},
            {'head_sha': 'b' * 40}, {'name': 'another-job'},
            {'conclusion': 'success'}, {'run_attempt': 2}, {'run_attempt': True}, {'steps': []},
            *({'steps': steps + [selected]} for selected in steps),
            *({'steps': [s for s in steps if s['name'] != selected['name']]} for selected in steps),
            *({'steps': [dict(s, status='in_progress') if s == selected else s
                         for s in steps]} for selected in steps),
            *({'steps': [dict(s, conclusion='skipped' if s['conclusion'] == 'success' else 'success')
                         if s == selected else s for s in steps]} for selected in steps),
        )
        for change in changes:
            for key in ('built_job', 'built_job_2', 'built_job_3', 'built_job_4'):
                with self.subTest(key=key, change=change):
                    result, emitted = self.run_image_only_scope(**{key: change})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(emitted, '')

    def test_built_privacy_refusal_requires_available_zero_artifact_evidence(self):
        for artifacts in ({}, {'total_count': 1, 'artifacts': [{'id': 1}]},
                          {'total_count': 0, 'artifacts': [{'id': 1}]},
                          {'total_count': False, 'artifacts': []},
                          {'total_count': '0', 'artifacts': []},
                          {'total_count': 0}, {'total_count': 0, 'artifacts': None}):
            for key in ('artifacts', 'artifacts_2', 'artifacts_3', 'artifacts_4'):
                with self.subTest(key=key, artifacts=artifacts):
                    result, emitted = self.run_image_only_scope(**{key: artifacts})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('artifact absence is not established', result.stderr)
                    self.assertEqual(emitted, '')
        for endpoint in ('/actions/jobs/120782979034', '/actions/jobs/120793190410',
                         '/actions/jobs/120803275519', '/actions/jobs/120818019684',
                         '/actions/runs/40063895699/artifacts?per_page=1',
                         '/actions/runs/40067322318/artifacts?per_page=1',
                         '/actions/runs/40070695622/artifacts?per_page=1',
                         '/actions/runs/40075559894/artifacts?per_page=1'):
            with self.subTest(endpoint=endpoint):
                result, emitted = self.run_image_only_scope(unavailable_endpoint=(
                    'https://api.github.com/repos/fr-meyer/openclaw' + endpoint))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('bounded lookup unavailable', result.stderr)
                self.assertEqual(emitted, '')

    def test_other_refs_cannot_enable_image_only_export_and_both_export_stages_agree(self):
        for ref in ('refs/heads/main', 'refs/heads/release-pipeline/other',
                    'refs/heads/release-pipeline/v105-image-only-20261024-extra'):
            result, emitted = self.run_image_only_scope(environment={'GITHUB_REF': ref})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(emitted, 'image_only_build=false\nprivate_retention=false\nprivate_workflow_sha=\n')
        bundle = step(self.workflow, 'Prepare and verify the bounded public artifact')
        upload = step(self.workflow, 'Retain the exact tested OCI payload and public receipt')
        conditions = []
        for selected in (bundle, upload):
            condition = ' '.join(selected.split('        if: >-\n', 1)[1].split(
                '\n        ' + ('uses:' if selected == upload else 'run:'), 1)[0].split())
            conditions.append(condition)
            for event in ('push', 'pull_request', 'workflow_dispatch'):
                for flag in ('false', 'true'):
                    actual = expression(condition, github=NS(event_name=event),
                        inputs=NS(export_public_artifact=False, artifact_storage_approved=False),
                        steps=NS(identity=NS(outputs=NS(image_only_build=flag))))
                    self.assertFalse(actual)
        self.assertEqual(conditions[0], conditions[1])
        gate = step(self.workflow, 'Bind hosted qualification receipts and export decision')
        for name in ('PUBLIC_EXPORT', 'STORAGE_APPROVED'):
            value = re.search(r'^          ' + name + r': (.+)$', gate, re.M).group(1)
            for flag in ('false', 'true'):
                actual = expression(value, github=NS(event_name='push'),
                    inputs=NS(export_public_artifact=False, artifact_storage_approved=False),
                    steps=NS(identity=NS(outputs=NS(image_only_build=flag))))
                self.assertFalse(actual)

    def test_one_shot_route_preserves_all_checks_and_real_execution_binding(self):
        source = step(self.workflow, 'Verify source and run offline pipeline regressions')
        self.assertIn("python3 -m unittest discover -s tooling/scripts/fork-release -p 'test_*.py'", source)
        self.assertIn('source_ancestry.py', source)
        self.assertIn('preflight.py', source)
        self.assertIn("if [[ '${{ steps.identity.outputs.image_only_build }}' == true ]]; then", source)
        self.assertIn("-p 'test_hosted_*.py'", source)
        self.assertIn("-p 'test_private_oci_*.py'", source)
        self.assertIn("-p 'test_image*.py'", source)
        self.assertIn('test_preflight test_release test_source_ancestry test_source_tests', source)
        self.assertIn('test_merge_source test_limited_coverage_gate', source)
        self.assertIn("else\n            python3 -m unittest discover", source)
        self.assertIn('pnpm install --frozen-lockfile', step(
            self.workflow, 'Run focused custom patch and producer-consumer gates'))
        seal = step(self.workflow, 'Verify OCI bytes and smoke that exact image')
        self.assertIn('GITHUB_WORKFLOW_SHA: ${{ github.workflow_sha }}', seal)
        gate = step(self.workflow, 'Bind hosted qualification receipts and export decision')
        self.assertIn('TOOLING_SHA: ${{ github.sha }}', gate)
        self.assertIn('--run-id "$GITHUB_RUN_ID" --attempt "$GITHUB_RUN_ATTEMPT"', gate)
        # Existing resource, native framework, privacy, ZIP and upload tests stay active.
        self.assertNotIn('continue-on-error:', gate)

    def test_private_caller_requires_exact_external_workflow_approval_and_preparation_parent(self):
        identity = step(self.workflow, 'Resolve exact source identity')
        self.assertIn("fromJSON(secrets.OPENCLAW_PRIVATE_OCI_CAPABILITY || '{}').workflowSha", identity)
        before_process = identity.split('        run: |', 1)[0]
        self.assertNotIn('upload-capability:', before_process)
        self.assertNotIn('OCI_UPLOAD', before_process)
        self.assertIn('APPROVED_PRIVATE_WORKFLOW_SHA:', before_process)
        for change in ({'sha': 'b' * 40}, {'parents': []}, {'parents': None},
                       {'parents': [{'sha': 'b' * 40}]},
                       {'parents': [{'sha': 'e88b8997b29a2842127cc91a1cec3837b34dcc88'},
                                    {'sha': 'e88b8997b29a2842127cc91a1cec3837b34dcc88'}]}):
            value = {'sha': SOURCE, 'parents': [{'sha': 'e88b8997b29a2842127cc91a1cec3837b34dcc88'}],
                     **change}
            result, emitted = self.run_image_only_scope(current_commit=value)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('exact reviewed preparation successor', result.stderr)
            self.assertEqual(emitted, '')

    def test_private_retention_survives_privacy_failure_but_not_failed_build_or_cancel(self):
        capture = step(self.workflow, 'Capture original hosted build metadata for private retention')
        retain = step(self.workflow, 'Retain private OCI archive')

        def selected(block, *, private='true', build='success', finish='success',
                     metadata='success', cancelled=False, privacy='failure'):
            condition = ' '.join(block.split('        if: >-\n', 1)[1].split(
                '\n        ' + ('uses:' if block == retain else 'env:'), 1)[0].split())
            condition = condition.replace('!cancelled()', 'not cancelled()')
            return expression(condition, always=lambda: True, cancelled=lambda: cancelled,
                steps=NS(identity=NS(outputs=NS(private_retention=private)),
                    build=NS(outcome=build), resource_finish=NS(outcome=finish),
                    private_metadata=NS(outcome=metadata), privacy=NS(outcome=privacy)))

        self.assertTrue(selected(capture, privacy='failure'))
        self.assertTrue(selected(capture, finish='failure'))
        self.assertTrue(selected(retain, privacy='failure'))
        for block in (capture, retain):
            for change in ({'private': 'false'}, {'build': 'failure'},
                           {'build': 'skipped'}, {'cancelled': True}):
                with self.subTest(block=block[:70], change=change):
                    self.assertFalse(selected(block, **change))
        for outcome in ('skipped', 'cancelled'):
            self.assertFalse(selected(capture, finish=outcome))
        self.assertFalse(selected(retain, metadata='failure'))
        self.assertIn('uses: ./tooling/.github/actions/retain-private-oci', retain)
        self.assertIn('upload-capability: ${{ secrets.OPENCLAW_PRIVATE_OCI_CAPABILITY }}', retain)
        self.assertIn('approved-workflow-sha: ${{ steps.identity.outputs.private_workflow_sha }}', retain)
        self.assertIn('source-tree: 3e0d6fbf5bc015063dce3e4f0f353f0eac3aed6a', retain)
        self.assertIn('output-directory: ${{ runner.temp }}/fork-private-retention', retain)
        self.assertLess(self.workflow.index('      - name: Finish resource observation'),
                        self.workflow.index('      - name: Capture original hosted build metadata'))
        self.assertLess(self.workflow.index('      - name: Capture original hosted build metadata'),
                        self.workflow.index('      - name: Retain private OCI archive'))
        early = self.workflow.split('      - name: Retain private OCI archive', 1)[0]
        self.assertNotIn('upload-capability: ${{ secrets.', early)
        self.assertEqual(early.count('secrets.OPENCLAW_PRIVATE_OCI_CAPABILITY'), 1)

    def test_private_metadata_capture_preserves_original_bytes_and_refuses_overwrite_or_mismatch(self):
        capture = step(self.workflow, 'Capture original hosted build metadata for private retention')
        code = textwrap.dedent(capture.split("<<'PY_PRIVATE_METADATA'\n", 1)[1].split(
            '\n          PY_PRIVATE_METADATA', 1)[0])
        digest = 'sha256:' + 'c' * 64
        raw = '{ "containerimage.digest": "' + digest + '", "original": [1, 2] }\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'fork-release').mkdir()
            env = {'RUNNER_TEMP': directory, 'ORIGINAL_BUILD_METADATA': raw, 'OCI_DIGEST': digest}
            run = lambda **change: subprocess.run([sys.executable, '-I', '-B', '-c', code],
                env={**env, **change}, capture_output=True, text=True, timeout=5)
            bad = run(OCI_DIGEST='sha256:' + 'd' * 64)
            self.assertNotEqual(bad.returncode, 0)
            target = root / 'fork-release/build-metadata.json'
            self.assertFalse(target.exists())
            result = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_bytes(), raw.encode())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(run().returncode, 0)
            self.assertEqual(target.read_bytes(), raw.encode())
            self.assertEqual(result.stdout, '')

    def test_attestation_permissions_are_job_scoped_and_not_registry_authority(self):
        header, jobs = self.workflow.split('\njobs:\n', 1)
        self.assertNotIn('id-token:', header)
        self.assertNotIn('attestations:', header)
        qualification = jobs.split('  qualify-and-prepare:\n', 1)[1]
        permissions = qualification.split('    permissions:\n', 1)[1].split('    steps:', 1)[0]
        self.assertEqual(dict(re.findall(r'^      ([a-z-]+): (read|write)$', permissions, re.M)),
                         {'contents': 'read', 'id-token': 'write', 'attestations': 'write'})
        self.assertNotIn('packages: write', self.workflow)

    def test_public_member_qualification_is_selected_only_for_exact_reviewed_source(self):
        block = step(self.workflow, 'Inspect all OCI layers and metadata before native smoke or publication')
        script = textwrap.dedent(block.split('        run: |\n', 1)[1])
        reviewed = '85a9bdc1285c338f10f5ca818abc259f6d483b5b'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / 'python3'
            fake.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                            'open(os.environ["ARGV_CAPTURE"], "w").write(json.dumps(sys.argv[1:]))\n')
            fake.chmod(0o700)
            for index, source in enumerate((reviewed, reviewed[:-1] + 'a', SOURCE)):
                capture = root / (str(index) + '.json')
                env = {**os.environ, 'PATH': str(root) + ':/usr/bin:/bin',
                       'SOURCE_SHA': source, 'TOOLING_SHA': 'b' * 40,
                       'OCI_DIGEST': 'sha256:' + 'c' * 64, 'RUNNER_TEMP': str(root),
                       'ARGV_CAPTURE': str(capture)}
                result = subprocess.run(['/bin/bash', '-c', script], env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                argv = json.loads(capture.read_bytes())
                self.assertEqual('--qualify-public-members' in argv, source == reviewed)
                self.assertEqual('--public-comparisons' in argv, source == reviewed)
                self.assertEqual(argv[argv.index('--source-sha') + 1], source)
                if source == reviewed:
                    self.assertEqual(argv[argv.index('--public-comparisons') + 1],
                                     'tooling/scripts/fork-release/public-member-comparisons-v105.json')

    def test_privacy_resources_and_native_seal_precede_receipt_gate_and_upload(self):
        names = ('Verify hosted worker limits and begin bounded resource observation',
                 'Build exact candidate once into OCI',
                 'Inspect all OCI layers and metadata before native smoke or publication',
                 'Verify OCI bytes and smoke that exact image',
                 'Finish resource observation through export load and native verification',
                 'Bind hosted qualification receipts and export decision',
                 'Prepare and verify the bounded public artifact',
                 'Retain the exact tested OCI payload and public receipt',
                 'Confirm uploaded bytes match the bounded artifact')
        positions = [self.workflow.index('      - name: ' + name) for name in names]
        self.assertEqual(positions, sorted(positions))
        resource_start = step(self.workflow, names[0])
        self.assertIn('steps.builder.outputs.nodes', resource_start)
        self.assertIn('--source-sha "$SOURCE_SHA" --tooling-sha "$TOOLING_SHA"', resource_start)
        resource_finish = step(self.workflow, names[4])
        self.assertIn("if: always() && steps.resources.outcome == 'success'", resource_finish)
        gate = step(self.workflow, names[5])
        for argument in ('--seal', '--privacy', '--resources', '--source-sha', '--tooling-sha',
                         '--index-digest', '--run-id', '--attempt'):
            self.assertIn(argument, gate)
        self.assertIn('fork-hosted-observation', resource_start)
        self.assertNotIn('fork-hosted-observation', step(self.workflow, names[7]))

    def run_probe(self, docker_results):
        raw = self.probe.split("          python3 - <<'PY_CAPACITY'\n", 1)[1].split('\n          PY_CAPACITY', 1)[0]
        code = textwrap.dedent(raw)
        output = io.StringIO()
        files = {'/proc/meminfo': 'MemTotal: 16000000 kB\nMemAvailable: 12000000 kB\nPrivate: 99 kB\n',
                 '/etc/os-release': 'ID=ubuntu\nVERSION_ID="24.04"\nPRIVATE=never-output\n'}
        with patch('pathlib.Path.read_text', lambda p: files[str(p)]), \
             patch('os.statvfs', return_value=NS(f_blocks=100, f_bavail=25, f_frsize=4096)) as disks, \
             patch('os.cpu_count', return_value=4), patch('platform.machine', return_value='x86_64'), \
             patch('subprocess.run', side_effect=docker_results) as commands, redirect_stdout(output):
            exec(compile(code, '<capacity-probe-fixture>', 'exec'), {})
        self.assertEqual([call.args for call in disks.call_args_list], [('/',), ('/tmp',)])
        self.assertEqual([call.args[0] for call in commands.call_args_list],
                         [['docker', '--version'], ['docker', 'version', '--format', '{{.Server.Version}}'],
                          ['docker', 'buildx', 'version']])
        for call in commands.call_args_list:
            self.assertEqual(call.kwargs['timeout'], 10)
            self.assertIs(call.kwargs['stderr'], subprocess.DEVNULL)
        return json.loads(output.getvalue())

    def test_capacity_probe_emits_only_selected_metadata_and_explicit_units(self):
        result = self.run_probe([NS(returncode=0, stdout='Docker version 28.1.0, build abc123\n'),
                                 NS(returncode=0, stdout='28.0.0\n'),
                                 NS(returncode=0, stdout='github.com/docker/buildx v0.28.0 abc123\n')])
        self.assertEqual(result['architecture'], 'x86_64')
        self.assertEqual(result['logicalCpus'], 4)
        self.assertEqual(result['memory'], {'MemTotalBytes': 16000000 * 1024,
                                             'MemAvailableBytes': 12000000 * 1024})
        self.assertEqual(result['filesystems']['root'], {'totalBytes': 409600, 'availableBytes': 102400})
        self.assertEqual(result['os'], {'ID': 'ubuntu', 'VERSION_ID': '24.04'})
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertEqual(result['dockerCli']['status'], 'ok')
        self.assertEqual(result['dockerServer'], {'status': 'ok', 'version': '28.0.0'})

    def test_capacity_probe_does_not_export_failed_or_multiline_tool_output(self):
        for results in ([NS(returncode=1, stdout='private failure'), OSError('private path'), OSError('no buildx')],
                        [NS(returncode=0, stdout='version\nprivate extra'),
                         subprocess.TimeoutExpired(['docker'], 10), NS(returncode=1, stdout='private version failure')]):
            result = self.run_probe(results)
            self.assertEqual(result['dockerCli'], {'status': 'unavailable'})
            self.assertEqual(result['dockerServer'], {'status': 'unavailable'})
            self.assertEqual(result['buildx'], {'status': 'unavailable'})
            self.assertNotIn('private', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
