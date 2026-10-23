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
    return eval(value, {'__builtins__': {}, 'format': lambda fmt, *args: fmt.format(*args),
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
        for forbidden in ('packages: write', 'id-token: write', 'docker/login-action',
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
        dispatch = run[run.index('OPENCLAW_VITEST_MAX_WORKERS=2 node scripts/run-vitest.mjs'):]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / 'node'
            stub.write_text(f'#!{sys.executable}\n' + textwrap.dedent('''\
                import json, os, sys
                from pathlib import Path
                args = sys.argv[1:]
                with Path(os.environ['GATE_TRACE']).open('a') as trace:
                    trace.write(json.dumps(args) + '\\n')
                native = args[:1] == ['--test']
                if native and not Path(args[1]).is_file():
                    raise SystemExit(2)
                raise SystemExit(int(os.environ['NATIVE_EXIT' if native else 'VITEST_EXIT']))
                '''))
            stub.chmod(0o755)
            prerequisite = root / 'test/mcp-nowistay-sdk-regression.test.mjs'
            if native_exists:
                prerequisite.parent.mkdir()
                prerequisite.write_text('// Synthetic native runner input.\n')
            trace = root / 'calls.jsonl'
            env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                   'GATE_TRACE': str(trace), 'VITEST_EXIT': str(vitest_exit),
                   'NATIVE_EXIT': str(native_exit)}
            selection = 'tests=(' + ' '.join(shlex.quote(test) for test in tests) + ')\n'
            result = subprocess.run(['/bin/bash', '-c', 'set -euo pipefail\n' + selection + dispatch],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=10)
            calls = [json.loads(line) for line in trace.read_text().splitlines()]
        return result, calls

    def test_selected_mcp_gate_runs_declared_native_nowistay_prerequisite(self):
        descriptor = json.loads((WORKFLOW.parents[2] / 'scripts/fork-release/candidates/'
                                 'v2026.10.5-source-only/native-nowistay-prerequisite.json').read_text())
        self.assertTrue(descriptor['required'])
        native = descriptor['command']
        tests = ['src/other.test.ts', descriptor['runnerRouting']['vitestProducerGate']]
        for name in ('Run focused candidate lifecycle and producer-consumer tests',
                     'Run focused custom patch and producer-consumer gates'):
            with self.subTest(step=name):
                result, calls = self.run_focused_gate_dispatch(name, tests)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [['scripts/run-vitest.mjs', *tests], native[1:]])

    def test_unrelated_gates_do_not_acquire_a_native_nowistay_requirement(self):
        for name in ('Run focused candidate lifecycle and producer-consumer tests',
                     'Run focused custom patch and producer-consumer gates'):
            with self.subTest(step=name):
                result, calls = self.run_focused_gate_dispatch(name, ['src/other.test.ts'],
                                                              native_exists=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [['scripts/run-vitest.mjs', 'src/other.test.ts']])

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
                         'platforms: linux/amd64', 'provenance: mode=max', 'sbom: true'):
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
