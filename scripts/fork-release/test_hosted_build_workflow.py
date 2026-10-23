"""Bounded workflow contract and synthetic capacity-probe checks; no Docker calls."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import subprocess
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
    return eval(value, {'__builtins__': {}, 'format': lambda fmt, *args: fmt.format(*args)}, context)


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

    def test_only_exact_source_gets_bounded_builder_and_retained_setup_is_unchanged(self):
        old = step(self.workflow, 'Set up Docker Buildx')
        new = step(self.workflow, 'Set up bounded 10.6 Docker Buildx')
        for source in (SOURCE, '4cf5cb7e256c67a5c98097774cad2d05cd781c01', 'f' * 40):
            context = self.source_context(source)
            old_if = re.search(r'^        if: (.+)$', old, re.M).group(1)
            new_if = re.search(r'^        if: (.+)$', new, re.M).group(1)
            self.assertEqual(expression(old_if, **context), source != SOURCE)
            self.assertEqual(expression(new_if, **context), source == SOURCE)
        self.assertNotIn('with:', old)
        self.assertIn('driver: docker-container', new)
        opts = dict(re.findall(r'^            ([a-z-]+)=([0-9]+)$', new, re.M))
        self.assertEqual(opts, {'memory': str(8 << 30), 'memory-swap': str(8 << 30),
                                'cpu-period': '100000', 'cpu-quota': '400000'})
        pin = 'docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069'
        self.assertIn(pin, old)
        self.assertIn(pin, new)

    def test_exact_source_uses_frozen_git_context_heap_and_no_automatic_build_record(self):
        context = re.search(r'^          context: (.+)$', self.build, re.M).group(1)
        upload = re.search(r'^          DOCKER_BUILD_RECORD_UPLOAD: (.+)$', self.build, re.M).group(1)
        args = re.findall(r'^            (\$\{\{.*\}\})$', self.build, re.M)
        self.assertEqual(len(args), 2)
        for source in (SOURCE, '4cf5cb7e256c67a5c98097774cad2d05cd781c01', 'f' * 40):
            values = self.source_context(source)
            next_source = source == SOURCE
            expected = ('https://github.com/fr-meyer/openclaw.git?fetch-by-commit=true&checksum='
                        + SOURCE + '#' + SOURCE) if next_source else 'source'
            self.assertEqual(expression(context, **values), expected)
            self.assertEqual(expression(upload, **values), 'false' if next_source else 'true')
            self.assertEqual([expression(arg, **values) for arg in args],
                             ['OPENCLAW_PARITY_IMAGE=1', 'OPENCLAW_DOCKER_BUILD_TSDOWN_MAX_OLD_SPACE_MB=6144']
                             if next_source else ['', ''])
        self.assertIn('provenance: mode=max', self.build)
        self.assertIn('sbom: true', self.build)

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
