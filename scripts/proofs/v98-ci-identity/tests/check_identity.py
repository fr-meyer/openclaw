"""Focused synthetic tests. No live network, SDK, credential or signal use."""
import ast
import base64
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'source'))
import ci_auth as A
import ci_common as C
import ci_identity as I

SECRET = 'opaque_SYNTHETIC_GITHUB_REQUEST_SECRET_123456'
MINTED = 'ya29.SYNTHETIC_MINTED_VALUE_123456'
TENANT = 'repo:fr-meyer@26621962/openclaw@1309456040:environment:' + A.ENVIRONMENT


class Clock:
    def __init__(self):
        self.w, self.m = 1800000000.0, 100.0
    def wall(self):
        return self.w
    def mono(self):
        return self.m
    def advance(self, seconds):
        self.w += seconds
        self.m += seconds


class NoAlarm:
    def __init__(self, clock):
        self.clock = clock
    def __enter__(self):
        self.clock.sample()
        return self
    def __exit__(self, *error):
        return False


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='v98-identity-source-')
        self.base = Path(self.tmp.name).resolve()
        self.source = self.base / 'public-source'
        self.source.mkdir(mode=0o700)
        (self.source / 'source').mkdir(mode=0o700)
        for f in (ROOT / 'source').iterdir():
            if f.suffix == '.py':
                shutil.copyfile(f, self.source / 'source' / f.name)
                (self.source / 'source' / f.name).chmod(0o600)
        shutil.copyfile(ROOT / 'identity-source-manifest.json', self.source / 'identity-source-manifest.json')
        (self.source / 'identity-source-manifest.json').chmod(0o600)
        self.runner_temp = self.base / 'runner-temp'
        self.runner_temp.mkdir(mode=0o700)
        self.clock = Clock()
        binding = {'schema': 'v98-ci-issuer-binding/v2', 'repository': A.REPO,
                   'repositoryId': A.REPO_ID, 'repositoryOwnerId': A.OWNER_ID, 'ref': A.REF,
                   'workflow': A.WORKFLOW, 'githubEnvironment': A.ENVIRONMENT,
                   'eventName': 'push', 'provider': A.PROVIDER, 'audience': A.AUDIENCE,
                   'serviceAccount': A.ACCOUNT, 'serviceAccountUniqueId': I.SA_ID,
                   'scope': A.SCOPE, 'runAttempt': 1, 'runId': None, 'runNumber': 1,
                   'toolingCommit': 'a' * 40, 'workflowCommit': 'a' * 40,
                   'oidcSubject': TENANT, 'subjectFormatIndependentlyConfirmed': True,
                   'oidcRequestHost': None,
                   'nativeFallback': False, 'staticKeys': False}
        self.packet = {'schema': 'v98-ci-identity-only-input/v2', 'identity': binding,
                       'platformBinding': dict(I.PLATFORM_BINDING),
                       'sourceManifestSha256': hashlib.sha256((ROOT / 'identity-source-manifest.json').read_bytes()).hexdigest(),
                       'approval': {'schema': 'v98-ci-identity-only-approval/v1', 'approved': True,
                                    'nonce': 'b' * 32, 'approvedAtEpoch': self.clock.w - 1,
                                    'invokeByEpoch': self.clock.w + 60,
                                    'authorityEndEpoch': self.clock.w + 600,
                                    'actions': list(I.ACTIONS), 'cleanupAdmitted': True}}
        b = binding
        self.env = {'GITHUB_REPOSITORY': A.REPO, 'GITHUB_REPOSITORY_ID': A.REPO_ID,
                    'GITHUB_REPOSITORY_OWNER_ID': A.OWNER_ID, 'GITHUB_REF': A.REF,
                    'GITHUB_SHA': b['toolingCommit'], 'GITHUB_WORKFLOW_SHA': b['workflowCommit'],
                    'GITHUB_WORKFLOW_REF': A.REPO + '/' + A.WORKFLOW + '@' + A.REF,
                    'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_NUMBER': '1',
                    'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'identity',
                    'V98_IDENTITY_RUNNER_ENVIRONMENT': 'github-hosted',
                    'V98_IDENTITY_ENVIRONMENT': A.ENVIRONMENT, 'RUNNER_TEMP': str(self.runner_temp),
                    'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://fixture.actions.githubusercontent.com/job/idtoken?api-version=2.0',
                    'ACTIONS_ID_TOKEN_REQUEST_TOKEN': SECRET}
        self.calls, self.core_calls = [], []
        self.network = mock.patch.object(urllib.request.OpenerDirector, 'open', side_effect=AssertionError('NO_LIVE_NETWORK'))
        self.network.start()

    def tearDown(self):
        self.network.stop()
        self.tmp.cleanup()

    def receipt_root(self):
        return self.runner_temp / ('v98-identity-12345-1-' + self.packet['approval']['nonce'])

    def jwt(self, mutations=None):
        b = self.packet['identity']
        claims = {'iss': 'https://token.actions.githubusercontent.com', 'aud': A.AUDIENCE,
                  'repository': A.REPO, 'repository_id': A.REPO_ID, 'repository_owner_id': A.OWNER_ID,
                  'ref': A.REF, 'sha': b['toolingCommit'], 'workflow_sha': b['workflowCommit'],
                  'workflow_ref': A.REPO + '/' + A.WORKFLOW + '@' + A.REF,
                  'event_name': 'push', 'run_id': self.env['GITHUB_RUN_ID'], 'run_number': str(b['runNumber']),
                  'run_attempt': '1', 'runner_environment': 'github-hosted',
                  'environment': A.ENVIRONMENT, 'sub': b['oidcSubject'],
                  'iat': self.clock.w - 1, 'exp': self.clock.w + 300}
        claims.update(mutations or {})
        def b64(v):
            return base64.urlsafe_b64encode(C.encoded(v)).rstrip(b'=').decode()
        return b64({'alg': 'RS256', 'kid': 'synthetic-only'}) + '.' + b64(claims) + '.c3ludGhldGlj'

    def transport(self, mutation=None):
        fixture = self
        class Transport:
            def request(_self, method, url, headers, body, deadline, final_check):
                final_check()
                fixture.calls.append((method, url))
                index = len(fixture.calls)
                if index == 1:
                    result = {'value': fixture.jwt(mutation)}
                elif index == 2:
                    result = {'access_token': 'ya29.SYNTHETIC_STS_VALUE_123456', 'token_type': 'Bearer',
                              'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token', 'expires_in': 3600}
                elif index == 3:
                    expiry = datetime.datetime.fromtimestamp(fixture.clock.w + 600, datetime.timezone.utc).isoformat()
                    result = {'accessToken': MINTED, 'expireTime': expiry}
                else:
                    raise AssertionError('MORE_THAN_ONE_EXCHANGE')
                final_check()
                return result
        return lambda *args: Transport()

    def run_probe(self, factory=None, environment=None):
        return I.run_approved(self.packet, self.env if environment is None else environment,
            self.source, (1800000000.0, 100.0), self.clock.wall, self.clock.mono, NoAlarm,
            factory or self.transport(), lambda: self.core_calls.append('disabled'))

    def test_success_uses_reviewed_issuer_for_exact_three_requests(self):
        value = self.run_probe()
        self.assertEqual(value['status'], 'PASS')
        self.assertEqual(value['issuerAttempts'], 1)
        self.assertEqual(value['resourceRequests'], 0)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.calls[1], ('POST', A.STS))
        self.assertTrue(self.calls[2][1].endswith('/' + I.SA_ID + ':generateAccessToken'))
        self.assertEqual(self.core_calls, ['disabled'])

    def test_secrets_are_read_only_after_durable_intents(self):
        fixture = self
        reads = []
        class Lazy(dict):
            def get(self, key, default=None):
                if key.startswith('ACTIONS_ID_TOKEN_REQUEST_'):
                    fixture.assertTrue((fixture.receipt_root() / 'attempt-intent.json').exists())
                    fixture.assertTrue((fixture.receipt_root() / 'endpoint-admission-intent.json').exists())
                    fixture.assertEqual(fixture.core_calls, ['disabled'])
                    if key.endswith('_TOKEN'):
                        fixture.assertTrue((fixture.receipt_root() / 'platform-binding.json').exists())
                        fixture.assertTrue((fixture.receipt_root() / 'issuer/issue-1-intent.json').exists())
                    reads.append(key)
                return super().get(key, default)
        self.assertEqual(self.run_probe(environment=Lazy(self.env))['status'], 'PASS')
        self.assertEqual(reads, ['ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'])

    def test_repeat_same_attempt_never_replays(self):
        self.run_probe()
        self.calls.clear()
        with self.assertRaises(FileExistsError):
            self.run_probe()
        self.assertEqual(self.calls, [])

    def test_local_activation_marker_refuses_before_any_intent_or_auth(self):
        (self.source / 'ACTIVATION_DISABLED').write_text('inactive')
        with self.assertRaises(C.Refusal):
            self.run_probe()
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_expired_authority_refuses_before_any_intent_or_auth(self):
        self.packet['approval']['authorityEndEpoch'] = self.clock.w - 1
        with self.assertRaises(C.Refusal):
            self.run_probe()
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_source_tamper_refuses_before_any_intent_or_auth(self):
        with (self.source / 'source/ci_auth.py').open('a') as f:
            f.write('\n# tampered fixture\n')
        with self.assertRaises(C.Refusal):
            self.run_probe()
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_unknown_private_input_field_is_rejected(self):
        self.packet['privatePolicy'] = SECRET
        with self.assertRaises(C.Refusal):
            self.run_probe()
        self.assertEqual(self.calls, [])

    def test_other_sa_run_attempt_branch_and_runner_are_rejected(self):
        for key, value in [('serviceAccountUniqueId', '9' * 21), ('runAttempt', 2), ('ref', 'refs/heads/main')]:
            original = self.packet['identity'][key]
            self.packet['identity'][key] = value
            with self.assertRaises(C.Refusal):
                self.run_probe()
            self.packet['identity'][key] = original
        self.env['V98_IDENTITY_RUNNER_ENVIRONMENT'] = 'self-hosted'
        with self.assertRaises(C.Refusal):
            self.run_probe()
        self.assertEqual(self.calls, [])

    def test_clock_regression_is_sticky(self):
        grant = I.IdentityGrant(self.packet['approval'], (self.clock.w, self.clock.m), self.clock.wall, self.clock.mono)
        self.clock.w -= 1
        with self.assertRaises(C.Refusal):
            grant.check()
        self.clock.w += 1
        with self.assertRaises(C.Refusal):
            grant.check()

    def test_sixty_second_attempt_limit_cannot_be_extended(self):
        grant = I.IdentityGrant(self.packet['approval'], (self.clock.w, self.clock.m), self.clock.wall, self.clock.mono)
        self.clock.advance(60)
        with self.assertRaises(C.Refusal):
            grant.check()

    def test_fsync_denial_prevents_secrets_and_network(self):
        with mock.patch.object(I.os, 'fsync', side_effect=PermissionError('synthetic denial')):
            with self.assertRaises(PermissionError):
                self.run_probe()
        self.assertEqual(self.calls, [])

    def test_wrong_signed_claim_precheck_stops_before_sts(self):
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=self.transport({'run_id': '999'}))
        self.assertEqual(len(self.calls), 1)
        self.assertTrue((self.receipt_root() / 'issuer/issuer-halted.json').exists())

    def test_wrong_oidc_host_stops_without_network(self):
        self.env['ACTIONS_ID_TOKEN_REQUEST_URL'] = 'https://actions.githubusercontent.com.evil.invalid/job/idtoken'
        with self.assertRaises(C.Refusal):
            self.run_probe()
        self.assertEqual(self.calls, [])

    def test_same_job_run_and_host_resolve_without_mutating_public_contract(self):
        before = copy.deepcopy(self.packet)
        self.assertEqual(self.run_probe()['status'], 'PASS')
        self.assertEqual(self.packet, before)
        observed = C.read_json((self.receipt_root() / 'platform-binding.json').read_bytes())
        self.assertEqual(observed['runId'], 12345)
        self.assertEqual(observed['oidcRequestHost'], 'fixture.actions.githubusercontent.com')
        self.assertIn('NOT_EXTERNAL_OBSERVATION', observed['basis'])
        self.assertTrue(observed['externalRunAdmissionRequiredBeforeMintTrust'])

    def test_platform_mode_and_pending_fields_are_exact_before_secret_reads(self):
        cases = [('schema', 'v98-ci-identity-only-input/v1'),
                 ('platformBinding', dict(I.PLATFORM_BINDING, extra='unknown'))]
        for key, value in cases:
            with self.subTest(key=key):
                original = self.packet[key]
                self.packet[key] = value
                with self.assertRaises(C.Refusal):
                    self.run_probe()
                self.packet[key] = original
        for key, value in [('runId', 12345), ('oidcRequestHost', 'fixture.actions.githubusercontent.com')]:
            self.packet['identity'][key] = value
            with self.assertRaises(C.Refusal):
                self.run_probe()
            self.packet['identity'][key] = None
        self.assertEqual(list(self.runner_temp.iterdir()), [])
        self.assertEqual(self.calls, [])

    def test_noncanonical_same_job_run_ids_refuse_before_endpoint_or_bearer_read(self):
        fixture = self
        class NoEndpoint(dict):
            def get(self, key, default=None):
                fixture.assertFalse(key.startswith('ACTIONS_ID_TOKEN_REQUEST_'))
                return super().get(key, default)
        for run_id in (None, 12345, '0', '-1', '+12345', '012345', '12345 ',
                       '1e4', '9223372036854775808', '1' * 100):
            with self.subTest(run_id=run_id):
                environment = NoEndpoint(self.env, GITHUB_RUN_ID=run_id)
                with self.assertRaises(C.Refusal):
                    self.run_probe(environment=environment)
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_default_issuer_binding_rejects_pending_platform_values(self):
        with self.assertRaises(C.Refusal):
            A.binding(self.packet['identity'])
        self.assertIs(A.binding(self.packet['identity'], allow_pending_platform=True),
                      self.packet['identity'])
        for host in ('.actions.githubusercontent.com', '-bad.actions.githubusercontent.com',
                     'bad-.actions.githubusercontent.com', 'bad..actions.githubusercontent.com',
                     'x' * 64 + '.actions.githubusercontent.com'):
            resolved = dict(self.packet['identity'], runId=12345, oidcRequestHost=host)
            with self.assertRaises(C.Refusal):
                A.binding(resolved)

    def test_strict_endpoint_rejections_never_read_bearer_or_send(self):
        prefix = 'https://fixture.actions.githubusercontent.com'
        urls = ['http://fixture.actions.githubusercontent.com/token',
                prefix + ':80/token', prefix + ':0443/token', prefix + ':/token',
                'https://user@fixture.actions.githubusercontent.com/token',
                'https://user:password@fixture.actions.githubusercontent.com/token',
                prefix + '/token#', prefix + '/token#fragment',
                prefix + '/token?audience=', prefix + '/token?%61udience=bad',
                prefix + '/token?AUDIENCE=bad', prefix + '/token?bad=%GG',
                prefix + '/token?broken', prefix + '/token?x=1&',
                'https://Fixture.actions.githubusercontent.com/token',
                'https://-bad.actions.githubusercontent.com/token',
                'https://bad..actions.githubusercontent.com/token',
                'https://actions.githubusercontent.com/token',
                'https://fixture.actions.githubusercontent.com.evil.invalid/token',
                'https://[::1]/token', prefix + '\\@evil.invalid/token',
                prefix + '/token\n', prefix + '/töken', prefix + '/token?x=' + 'a' * 8192]
        fixture = self
        class OnlyURL(dict):
            def get(self, key, default=None):
                fixture.assertNotEqual(key, 'ACTIONS_ID_TOKEN_REQUEST_TOKEN')
                return super().get(key, default)
        for index, url in enumerate(urls):
            with self.subTest(index=index):
                receipts = self.base / ('strict-' + str(index))
                receipts.mkdir(mode=0o700)
                grant = I.IdentityGrant(self.packet['approval'], (self.clock.w, self.clock.m),
                                        self.clock.wall, self.clock.mono)
                with self.assertRaises(C.Refusal):
                    I.bind_same_job_endpoint(dict(self.packet['identity'], runId=12345),
                        OnlyURL(self.env, ACTIONS_ID_TOKEN_REQUEST_URL=url), receipts, grant)
                self.assertTrue((receipts / 'endpoint-admission-intent.json').exists())
                self.assertFalse((receipts / 'platform-binding.json').exists())
        self.assertEqual(self.calls, [])

    def test_endpoint_url_is_read_once_and_frozen_for_the_reviewed_issuer(self):
        fixture = self
        initial = self.env['ACTIONS_ID_TOKEN_REQUEST_URL'] + '&opaque=URL_QUERY_SYNTHETIC_123456'
        class ChangingURL(dict):
            reads = 0
            def get(self, key, default=None):
                if key == 'ACTIONS_ID_TOKEN_REQUEST_URL':
                    self.reads += 1
                    fixture.assertEqual(self.reads, 1)
                    return initial
                return super().get(key, default)
        environment = ChangingURL(self.env)
        self.assertEqual(self.run_probe(environment=environment, factory=self.actual_transport())['status'], 'PASS')
        self.assertEqual(environment.reads, 1)
        parsed = urllib.parse.urlsplit(initial)
        query = urllib.parse.parse_qsl(parsed.query) + [('audience', A.AUDIENCE)]
        expected = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
        self.assertEqual(self.calls[0], ('GET', expected))
        retained = b''.join(p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file())
        for omitted in (initial, parsed.query, 'URL_QUERY_SYNTHETIC_123456'):
            self.assertNotIn(omitted.encode(), retained)

    def test_endpoint_intent_fsync_denial_precedes_url_and_bearer_reads(self):
        fixture = self
        class NoEndpoint(dict):
            def get(self, key, default=None):
                fixture.assertFalse(key.startswith('ACTIONS_ID_TOKEN_REQUEST_'))
                return super().get(key, default)
        publish = C.publish
        def deny_endpoint(path, *args, **kwargs):
            if path.name == 'endpoint-admission-intent.json':
                with mock.patch.object(C.os, 'fsync', side_effect=PermissionError('synthetic endpoint fsync denial')):
                    return publish(path, *args, **kwargs)
            return publish(path, *args, **kwargs)
        with mock.patch.object(C, 'publish', side_effect=deny_endpoint):
            with self.assertRaises(PermissionError):
                self.run_probe(environment=NoEndpoint(self.env))
        self.assertEqual(self.calls, [])

    def test_binding_or_issuer_intent_fsync_denial_never_reads_bearer(self):
        fixture = self
        class NoBearer(dict):
            def get(self, key, default=None):
                fixture.assertNotEqual(key, 'ACTIONS_ID_TOKEN_REQUEST_TOKEN')
                return super().get(key, default)
        publish = C.publish
        for index, target in enumerate(('platform-binding.json', 'issue-1-intent.json')):
            with self.subTest(target=target):
                self.packet['approval']['nonce'] = str(index + 1) * 32
                def deny_target(path, *args, **kwargs):
                    if path.name == target:
                        with mock.patch.object(C.os, 'fsync', side_effect=PermissionError('synthetic intent fsync denial')):
                            return publish(path, *args, **kwargs)
                    return publish(path, *args, **kwargs)
                with mock.patch.object(C, 'publish', side_effect=deny_target):
                    with self.assertRaises((PermissionError, C.Refusal)):
                        self.run_probe(environment=NoBearer(self.env))
        self.assertEqual(self.calls, [])

    def test_receipts_and_return_value_never_contain_credentials(self):
        value = self.run_probe()
        all_bytes = b''.join(p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file())
        for credential in (SECRET, MINTED, 'ya29.SYNTHETIC_STS_VALUE_123456', self.jwt()):
            self.assertNotIn(credential.encode(), all_bytes)
            self.assertNotIn(credential, json.dumps(value))
        self.assertLessEqual(len(all_bytes), 65536)
        for path in self.receipt_root().rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def actual_transport(self, failing_stage=None, escaped_error_credentials=False,
                         echo_endpoint=False, echo_endpoint_parts=False):
        fixture = self
        class Response:
            status = 200
            def __init__(self, value):
                self.raw = C.encoded(value)
            def __enter__(self):
                return self
            def read(self, cap):
                return self.raw[:cap]
            def __exit__(self, *error):
                return False
        class Backend:
            def open(_self, request, timeout):
                fixture.calls.append((request.get_method(), request.full_url))
                index = len(fixture.calls)
                if index == failing_stage:
                    error = {'error': {'code': 400, 'status': 'INVALID_ARGUMENT',
                             'message': 'Synthetic auth validation ' + SECRET + ' ' + fixture.jwt(),
                             'details': [{'@type': 'type.googleapis.com/google.rpc.BadRequest',
                                          'fieldViolations': [{'field': 'audience', 'description': 'Synthetic mismatch'}]}]}}
                    if echo_endpoint:
                        endpoint = fixture.env['ACTIONS_ID_TOKEN_REQUEST_URL']
                        parsed = urllib.parse.urlsplit(endpoint)
                        error['error']['message'] += ' ' + endpoint + ' ' + parsed.query
                        error['error']['message'] += ' ' + ' '.join(v for _, v in urllib.parse.parse_qsl(parsed.query))
                    if echo_endpoint_parts:
                        endpoint = urllib.parse.urlsplit(fixture.env['ACTIONS_ID_TOKEN_REQUEST_URL'])
                        values = [part.partition('=')[2] for part in endpoint.query.split('&')]
                        error['error']['message'] = 'Synthetic endpoint segments ' + ' '.join(
                            [endpoint.path, urllib.parse.unquote(endpoint.path), *values])
                    raw = C.encoded(error)
                    if escaped_error_credentials:
                        for secret in (SECRET, fixture.jwt()):
                            escaped = ''.join('\\u%04x' % ord(c) for c in secret).encode('ascii')
                            raw = raw.replace(secret.encode('ascii'), escaped)
                        fixture.assertNotIn(SECRET.encode('ascii'), raw)
                    raise urllib.error.HTTPError(request.full_url, 400, 'synthetic only',
                        {'Authorization': SECRET}, io.BytesIO(raw))
                if index == 1:
                    return Response({'value': fixture.jwt()})
                if index == 2:
                    return Response({'access_token': 'ya29.SYNTHETIC_STS_VALUE_123456',
                         'token_type': 'Bearer', 'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token', 'expires_in': 3600})
                if index == 3:
                    expiry = datetime.datetime.fromtimestamp(fixture.clock.w + 600, datetime.timezone.utc).isoformat()
                    return Response({'accessToken': MINTED, 'expireTime': expiry})
                raise AssertionError('UNEXPECTED_EXTRA_REQUEST')
        def factory(binding, environment, grant, receipts, state):
            # Keep the reviewed HTTPS.request and Issuer code; replace only wire I/O.
            transport = object.__new__(A.HTTPS)
            transport.opener = I.PrivateErrorOpener(Backend(), binding, grant, receipts, state,
                                                   environment.endpoint_redactions)
            return transport
        return factory

    def test_reviewed_https_and_issuer_with_new_endpoint_guard_end_to_end(self):
        value = self.run_probe(factory=self.actual_transport())
        self.assertEqual(value['status'], 'PASS')
        self.assertEqual(len(self.calls), 3)

    def test_auth_error_kept_private_through_reviewed_https_and_issuer(self):
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=self.actual_transport(failing_stage=1))
        files = [p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file()]
        retained = b''.join(files)
        self.assertNotIn(b'Synthetic auth validation', retained)
        self.assertIn(b'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', retained)
        self.assertNotIn(b'fieldViolations', retained)
        self.assertNotIn(SECRET.encode(), retained)
        self.assertNotIn(self.jwt().encode(), retained)
        self.assertEqual(len(self.calls), 1)

    def test_endpoint_raw_url_query_and_decoded_values_are_never_saved_on_http_error(self):
        self.env['ACTIONS_ID_TOKEN_REQUEST_URL'] += '&opaque=URL_QUERY_SYNTHETIC_123456'
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=self.actual_transport(failing_stage=1, echo_endpoint=True))
        retained = b''.join(p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file())
        for omitted in (self.env['ACTIONS_ID_TOKEN_REQUEST_URL'],
                        urllib.parse.urlsplit(self.env['ACTIONS_ID_TOKEN_REQUEST_URL']).query,
                        'URL_QUERY_SYNTHETIC_123456'):
            self.assertNotIn(omitted.encode(), retained)
        self.assertNotIn(b'Synthetic auth validation', retained)
        self.assertIn(b'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', retained)

    def test_endpoint_path_and_encoded_value_echoes_are_redacted_before_private_projection(self):
        decoded = 'SYNTHETIC_ENDPOINT_CAPABILITY_123456'
        encoded = ''.join('%%%02X' % ord(char) for char in decoded)
        raw_path = '/job/' + encoded
        decoded_path = '/job/' + decoded
        self.env['ACTIONS_ID_TOKEN_REQUEST_URL'] = (
            'https://fixture.actions.githubusercontent.com' + raw_path + '?opaque=' + encoded)
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=self.actual_transport(failing_stage=1, echo_endpoint_parts=True))
        retained = b''.join(p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file())
        for omitted in (raw_path, decoded_path, encoded, decoded):
            self.assertNotIn(omitted.encode(), retained)
        self.assertNotIn(b'Synthetic endpoint segments', retained)
        self.assertIn(b'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', retained)
        self.assertEqual(len(self.calls), 1)

    def test_later_stage_error_redacts_all_previous_ephemeral_credentials(self):
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=self.actual_transport(failing_stage=2))
        retained = b''.join(p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file())
        self.assertNotIn(SECRET.encode(), retained)
        self.assertNotIn(self.jwt().encode(), retained)
        self.assertNotIn(b'Synthetic auth validation', retained)
        self.assertIn(b'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', retained)
        self.assertEqual(len(self.calls), 2)

    def test_json_escaped_current_opaque_credential_cannot_enter_error_receipt(self):
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=self.actual_transport(failing_stage=1, escaped_error_credentials=True))
        retained = b''.join(p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file())
        self.assertNotIn(SECRET.encode(), retained)
        self.assertNotIn(b'Synthetic auth validation', retained)
        self.assertIn(b'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', retained)
        self.assertEqual(len(self.calls), 1)

    def test_json_escaped_previous_opaque_credential_cannot_enter_sts_error_receipt(self):
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=self.actual_transport(failing_stage=2, escaped_error_credentials=True))
        retained = b''.join(p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file())
        self.assertNotIn(SECRET.encode(), retained)
        self.assertNotIn(self.jwt().encode(), retained)
        self.assertNotIn(b'Synthetic auth validation', retained)
        self.assertIn(b'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', retained)
        self.assertEqual(len(self.calls), 2)

    def test_json_escaped_previous_opaque_credential_cannot_enter_iam_error_receipt(self):
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=self.actual_transport(failing_stage=3, escaped_error_credentials=True))
        retained = b''.join(p.read_bytes() for p in self.receipt_root().rglob('*') if p.is_file())
        self.assertNotIn(SECRET.encode(), retained)
        self.assertNotIn(self.jwt().encode(), retained)
        self.assertNotIn(b'Synthetic auth validation', retained)
        self.assertIn(b'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', retained)
        self.assertEqual(len(self.calls), 3)

    def test_output_loss_does_not_repeat_exchange_or_destroy_final_receipt(self):
        original = I.run_approved
        fixture = self
        def approved(value, environment, state):
            return original(value, environment, fixture.source, (1800000000.0, 100.0),
                fixture.clock.wall, fixture.clock.mono, NoAlarm, fixture.actual_transport(),
                lambda: fixture.core_calls.append('disabled'), state)
        class LostOutput:
            def write(_self, line):
                raise BrokenPipeError('synthetic output loss')
        environment = dict(self.env, V98_CI_IDENTITY_BINDING=json.dumps(self.packet))
        with mock.patch.object(I, 'run_approved', side_effect=approved):
            self.assertEqual(I.main(['--run-approved-identity-once'], environment, LostOutput()), 0)
        self.assertEqual(len(self.calls), 3)
        final = C.read_json((self.receipt_root() / 'final.json').read_bytes())
        self.assertEqual(final['status'], 'PASS')

    def test_default_cli_inert_and_missing_binding_fail_without_secrets(self):
        class NoSecrets(dict):
            def get(self, key, default=None):
                if key.startswith('ACTIONS_'):
                    raise AssertionError('SECRET_READ')
                return super().get(key, default)
        stream = io.StringIO()
        self.assertEqual(I.main([], NoSecrets(), stream), 0)
        self.assertIn('IDENTITY_PROBE_INACTIVE', stream.getvalue())
        stream = io.StringIO()
        self.assertEqual(I.main(['--run-approved-identity-once'], NoSecrets(), stream), 1)
        self.assertLessEqual(len(stream.getvalue().encode()), 512)

    def test_status_projection_drops_all_unknown_private_fields_and_values(self):
        value = I.public_status({'status': SECRET, 'stage': SECRET, 'issuerAttempts': True,
                                 'authenticationComplete': False, 'privatePolicy': SECRET,
                                 'headers': {'Authorization': SECRET}, 'token': SECRET, 'httpStatus': SECRET})
        self.assertEqual(set(value), {'status', 'stage', 'issuerAttempts', 'httpStatus', 'authenticationComplete', 'resourceRequests'})
        self.assertNotIn(SECRET, json.dumps(value))
        self.assertEqual(value['issuerAttempts'], 0)

    def private_opener(self, backend):
        grant = I.IdentityGrant(self.packet['approval'], (self.clock.w, self.clock.m), self.clock.wall, self.clock.mono)
        receipts = self.base / 'diagnostics'
        receipts.mkdir(mode=0o700)
        binding = dict(self.packet['identity'], runId=12345,
                       oidcRequestHost='fixture.actions.githubusercontent.com')
        return I.PrivateErrorOpener(backend, binding, grant, receipts, {}), receipts

    def test_resource_endpoint_blocked_before_backend(self):
        backend = mock.Mock()
        opener, _ = self.private_opener(backend)
        request = urllib.request.Request('https://compute.googleapis.com/compute/v1/projects/fixture')
        with self.assertRaises(C.Refusal):
            opener.open(request, 10)
        backend.open.assert_not_called()

    def test_other_sa_or_token_lifetime_blocked_before_backend(self):
        backend = mock.Mock()
        opener, _ = self.private_opener(backend)
        for account, lifetime in ((I.SA_ID, '3600s'), (I.SA_ID, '601s'), (I.SA_ID, '7200s'), ('99999999999', '600s')):
            request = urllib.request.Request('https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' + account + ':generateAccessToken',
                data=C.encoded({'scope': [A.SCOPE], 'lifetime': lifetime}), method='POST')
            with self.assertRaises(C.Refusal):
                opener.open(request, 10)
        backend.open.assert_not_called()

    def test_duplicate_stage_blocked_without_second_backend_call(self):
        backend = mock.Mock()
        opener, _ = self.private_opener(backend)
        request = urllib.request.Request('https://fixture.actions.githubusercontent.com/job/idtoken?audience=' + urllib.parse.quote(A.AUDIENCE, safe=''))
        opener.open(request, 10)
        with self.assertRaises(C.Refusal):
            opener.open(request, 10)
        self.assertEqual(backend.open.call_count, 1)

    def test_http_error_private_redaction_and_no_header_retention(self):
        raw = C.encoded({'error': {'code': 400, 'status': 'INVALID_ARGUMENT',
                         'message': 'Synthetic validation ' + SECRET,
                         'details': [{'@type': 'type.googleapis.com/google.rpc.BadRequest',
                                      'fieldViolations': [{'field': 'audience', 'description': 'Synthetic mismatch'}]}]}})
        class Backend:
            def open(_self, request, timeout):
                raise urllib.error.HTTPError(request.full_url, 400, 'fixture',
                    {'Authorization': SECRET}, io.BytesIO(raw))
        opener, receipts = self.private_opener(Backend())
        request = urllib.request.Request('https://fixture.actions.githubusercontent.com/job/idtoken?audience=' + urllib.parse.quote(A.AUDIENCE, safe=''),
                    headers={'Authorization': 'Bearer ' + SECRET})
        with self.assertRaises(urllib.error.HTTPError):
            opener.open(request, 10)
        private = next(receipts.glob('private-error-*.json')).read_bytes()
        self.assertNotIn(SECRET.encode(), private)
        self.assertNotIn(b'Authorization', private)
        self.assertNotIn(b'Synthetic validation', private)
        self.assertNotIn(b'fieldViolations', private)
        self.assertEqual(C.read_json(private), {'stage': 'GITHUB_OIDC', 'httpStatus': 400,
                         'diagnostic': {'captureStatus': 'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', 'privateOnly': True}})

    def test_normalized_query_component_error_body_is_not_read_or_retained(self):
        raw_component = 'SYNTHETIC_ENDPOINT_CAP%2fPART%3dTAIL'
        sent_component = 'SYNTHETIC_ENDPOINT_CAP%2FPART%3DTAIL'
        class NeverRead(io.BytesIO):
            reads = 0
            def read(_self, *args):
                _self.reads += 1
                raise AssertionError('AUTH_ERROR_BODY_MUST_NOT_BE_READ')
        body = NeverRead(C.encoded({'error': {'message': sent_component}}))
        class Backend:
            def open(_self, request, timeout):
                raise urllib.error.HTTPError(request.full_url, 400, SECRET,
                                             {'Authorization': SECRET}, body)
        opener, receipts = self.private_opener(Backend())
        url = 'https://fixture.actions.githubusercontent.com/job/idtoken?opaque=' + raw_component
        url += '&audience=' + urllib.parse.quote(A.AUDIENCE, safe='')
        request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + SECRET})
        with self.assertRaises(urllib.error.HTTPError):
            opener.open(request, 10)
        self.assertEqual(body.reads, 0)
        self.assertTrue(body.closed)
        retained = next(receipts.glob('private-error-*.json')).read_bytes()
        for value in (raw_component, sent_component, SECRET):
            self.assertNotIn(value.encode(), retained)
        self.assertEqual(C.read_json(retained), {'stage': 'GITHUB_OIDC', 'httpStatus': 400,
                         'diagnostic': {'captureStatus': 'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY', 'privateOnly': True}})
        self.assertEqual(next(receipts.glob('private-error-*.json')).stat().st_mode & 0o777, 0o600)

    def test_intended_access_token_request_is_600_seconds(self):
        captured = []
        delegate = self.transport()()
        class Capture:
            def request(_self, method, url, headers, body, deadline, final_check):
                if url.endswith(':generateAccessToken'):
                    captured.append(C.read_json(body))
                return delegate.request(method, url, headers, body, deadline, final_check)
        self.assertEqual(self.run_probe(factory=lambda *args: Capture())['status'], 'PASS')
        self.assertEqual(captured, [{'scope': [A.SCOPE], 'lifetime': '600s'}])
        result = C.read_json(next(self.receipt_root().rglob('issue-1-result.json')).read_bytes())
        self.assertEqual(result['expiresAtEpoch'], self.clock.w + 600)

    def test_returned_access_token_longer_than_600_seconds_is_refused_without_retry(self):
        delegate = self.transport()()
        fixture = self
        class TooLong:
            def request(_self, method, url, headers, body, deadline, final_check):
                value = delegate.request(method, url, headers, body, deadline, final_check)
                if url.endswith(':generateAccessToken'):
                    value['expireTime'] = datetime.datetime.fromtimestamp(
                        fixture.clock.w + 601, datetime.timezone.utc).isoformat()
                return value
        with self.assertRaises(C.Refusal):
            self.run_probe(factory=lambda *args: TooLong())
        self.assertEqual(len(self.calls), 3)
        self.assertFalse((self.receipt_root() / 'final.json').exists())

    def test_manifest_has_only_four_runtime_modules_and_no_owner_imports(self):
        manifest = C.read_json((ROOT / 'identity-source-manifest.json').read_bytes())
        self.assertEqual(set(manifest['files']), I.RUNTIME_FILES)
        forbidden = {'ci_controller', 'ci_entry', 'runner', 'coordination', 'sdk_context', 'subprocess'}
        for name in I.RUNTIME_FILES:
            tree = ast.parse((ROOT / name).read_text())
            imports = {a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            imports |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
            self.assertFalse(imports & forbidden)

    def test_workflow_has_only_source_and_identity_no_resource_or_artifact_steps(self):
        workflow = ROOT.parents[2] / '.github/workflows/v98-public-proof-ci.yml'
        text = workflow.read_text()
        self.assertIn('  source:\n', text)
        self.assertIn('  identity:\n', text)
        self.assertNotIn('  owner:\n', text)
        self.assertIn('    timeout-minutes: 5', text)
        for forbidden in ('upload-artifact@', 'gh api', 'ci_controller.py', 'ssh ', 'gcloud ', 'actions: write'):
            self.assertNotIn(forbidden, text)
        self.assertIn('cancel-in-progress: false', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
