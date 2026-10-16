"""One separately admitted identity exchange. No resource owner or SDK path."""
import time
ORIGINAL_WALL, ORIGINAL_MONOTONIC = time.time(), time.monotonic()
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.parse
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_auth as A
import ci_common as C

ROOT = Path(__file__).resolve().parent.parent
SA_ID = '111373477132848309744'
ACTIONS = ['GITHUB_OIDC_ONCE', 'GOOGLE_STS_ONCE', 'IAM_CREDENTIALS_ONCE']
RUNTIME_FILES = {'source/ci_auth.py', 'source/ci_common.py',
                 'source/private_api_error.py', 'source/ci_identity.py'}
IDENTITY_KEYS = {'schema', 'repository', 'repositoryId', 'repositoryOwnerId', 'ref',
                 'workflow', 'githubEnvironment', 'eventName', 'provider', 'audience',
                 'serviceAccount', 'serviceAccountUniqueId', 'scope', 'runAttempt',
                 'runId', 'runNumber', 'toolingCommit', 'workflowCommit', 'oidcSubject',
                 'subjectFormatIndependentlyConfirmed', 'oidcRequestHost',
                 'nativeFallback', 'staticKeys'}
PLATFORM_BINDING = {'mode': 'SAME_JOB_PLATFORM_ENVIRONMENT_V1',
                    'runIdSource': 'GITHUB_RUN_ID',
                    'oidcRequestHostSource': 'ACTIONS_ID_TOKEN_REQUEST_URL',
                    'externalRunAdmission': 'EXACT_PENDING_DEPLOYMENT_AND_RUN_BEFORE_TRUST'}


def source_bytes(path, cap=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        C.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
               and before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o022
               and 0 < before.st_size <= cap, 'BOUNDED_OWNED_SOURCE')
        raw = os.read(fd, cap + 1)
        after = os.fstat(fd)
        C.need(len(raw) == before.st_size and
               (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
               'STABLE_SOURCE_READ')
        return raw
    finally:
        os.close(fd)


def verify_source(root, expected):
    C.need(type(expected) is str and re.fullmatch('[a-f0-9]{64}', expected) is not None,
           'EXACT_SOURCE_MANIFEST_PIN')
    C.directory(root)
    raw = source_bytes(root / 'identity-source-manifest.json')
    C.need(hashlib.sha256(raw).hexdigest() == expected, 'EXACT_SOURCE_MANIFEST_PIN')
    manifest = C.read_json(raw)
    C.need(set(manifest) == {'schema', 'files'} and manifest['schema'] == 'v98-ci-identity-source/v1'
           and type(manifest['files']) is dict and set(manifest['files']) == RUNTIME_FILES,
           'ONLY_IDENTITY_RUNTIME_SOURCE')
    C.directory(root / 'source')
    for name, item in manifest['files'].items():
        C.need(type(item) is dict and set(item) == {'bytes', 'sha256'}
               and type(item['bytes']) is int and 0 < item['bytes'] <= 65536
               and type(item['sha256']) is str and re.fullmatch('[a-f0-9]{64}', item['sha256']),
               'EXACT_SOURCE_FILE_PIN')
        value = source_bytes(root / name)
        C.need(len(value) == item['bytes'] and hashlib.sha256(value).hexdigest() == item['sha256'],
               'EXACT_SOURCE_FILE_PIN')


def validate_input(value, environment):
    C.need(type(value) is dict and set(value) == {'schema', 'identity', 'sourceManifestSha256', 'approval', 'platformBinding'}
           and value['schema'] == 'v98-ci-identity-only-input/v2'
           and type(value['platformBinding']) is dict
           and value['platformBinding'] == PLATFORM_BINDING, 'ONLY_PUBLIC_IDENTITY_INPUT')
    binding = value['identity']
    C.need(type(binding) is dict and set(binding) == IDENTITY_KEYS, 'ONLY_PUBLIC_IDENTITY_BINDING')
    C.need(binding['runId'] is None and binding['oidcRequestHost'] is None,
           'ONLY_EXPLICIT_SAME_JOB_PLATFORM_BINDING')
    A.binding(binding, allow_pending_platform=True)
    run_id = environment.get('GITHUB_RUN_ID')
    C.need(type(run_id) is str and re.fullmatch('[1-9][0-9]{0,18}', run_id) is not None
           and int(run_id) < 2**63, 'EXACT_SAME_JOB_RUN_ID')
    binding = dict(binding, runId=int(run_id))
    C.need(binding['serviceAccountUniqueId'] == SA_ID
           and all(0 < binding[k] < 2**63 for k in ('runId', 'runNumber')), 'EXACT_NEW_ACCOUNT_AND_RUN')
    expected = {'GITHUB_REPOSITORY': A.REPO, 'GITHUB_REPOSITORY_ID': A.REPO_ID,
                'GITHUB_REPOSITORY_OWNER_ID': A.OWNER_ID, 'GITHUB_REF': A.REF,
                'GITHUB_SHA': binding['toolingCommit'], 'GITHUB_WORKFLOW_SHA': binding['workflowCommit'],
                'GITHUB_WORKFLOW_REF': A.REPO + '/' + A.WORKFLOW + '@' + A.REF,
                'GITHUB_EVENT_NAME': 'push',
                'GITHUB_RUN_NUMBER': str(binding['runNumber']), 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_JOB': 'identity', 'V98_IDENTITY_RUNNER_ENVIRONMENT': 'github-hosted',
                'V98_IDENTITY_ENVIRONMENT': A.ENVIRONMENT}
    C.need(all(environment.get(k) == v for k, v in expected.items()), 'EXACT_PLATFORM_RUN_CONTEXT')
    approval = value['approval']
    keys = {'schema', 'approved', 'nonce', 'approvedAtEpoch', 'invokeByEpoch', 'authorityEndEpoch',
            'actions', 'cleanupAdmitted'}
    C.need(type(approval) is dict and set(approval) == keys
           and approval['schema'] == 'v98-ci-identity-only-approval/v1'
           and approval['approved'] is True and approval['cleanupAdmitted'] is True
           and approval['actions'] == ACTIONS and type(approval['nonce']) is str
           and re.fullmatch('[a-f0-9]{32}', approval['nonce']), 'EXACT_IDENTITY_ONLY_APPROVAL')
    return binding, approval


class FrozenEndpointEnvironment:
    """Freeze one admitted URL in memory; do not reread or expose it in receipts."""
    def __init__(self, environment, raw_url, redactions):
        self.environment, self.raw_url = environment, raw_url
        self.endpoint_redactions = redactions

    def get(self, key, default=None):
        if key == 'ACTIONS_ID_TOKEN_REQUEST_URL':
            return self.raw_url
        return self.environment.get(key, default)

    def __contains__(self, key):
        return key in self.environment


def bind_same_job_endpoint(binding, environment, receipts, grant):
    # Endpoint admission is itself consumed durably before URL access. The URL
    # is a platform-provided capability; neither it nor its query is evidence.
    C.publish(receipts / 'endpoint-admission-intent.json',
              {'schema': 'v98-ci-identity-endpoint-admission/v1',
               'runId': binding['runId'], 'platformBinding': PLATFORM_BINDING,
               'requiredHostSuffix': '.actions.githubusercontent.com',
               'maximumURLBytes': 8192, 'rawURLOrQueryRetained': False,
               'retryAuthorized': False}, grant.check)
    grant.check()
    raw_url = environment.get('ACTIONS_ID_TOKEN_REQUEST_URL')
    C.need(type(raw_url) is str and 0 < len(raw_url) <= 8192
           and all(32 < ord(char) < 127 for char in raw_url)
           and '\\' not in raw_url and '#' not in raw_url
           and re.search(r'%(?![0-9a-fA-F]{2})', raw_url) is None,
           'STRICT_SAME_JOB_REQUEST_URL')
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        host = parsed.hostname
        C.need(parsed.scheme == 'https' and A.github_oidc_host(host)
               and parsed.netloc in (host, host + ':443')
               and parsed.username is None and parsed.password is None
               and not parsed.fragment and parsed.port in (None, 443),
               'STRICT_SAME_JOB_REQUEST_ENDPOINT')
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True,
                                      strict_parsing=True, max_num_fields=64)
        C.need(not any(key.casefold() == 'audience' for key, _ in query),
               'NO_PREEXISTING_AUDIENCE')
    except (ValueError, UnicodeError):
        raise C.Refusal('STRICT_SAME_JOB_REQUEST_ENDPOINT') from None
    resolved = dict(binding, oidcRequestHost=host)
    A.binding(resolved)
    # Error messages may echo a URL/query or a decoded query value. Keep these
    # only in RAM for redaction; do not hash or persist any of them.
    normalized_query = urllib.parse.urlencode(query)
    normalized_url = urllib.parse.urlunsplit(parsed._replace(query=normalized_query))
    redactions = tuple(part for part in (raw_url, parsed.query, normalized_url,
                       normalized_query, parsed.path, urllib.parse.unquote(parsed.path),
                       *(part.partition('=')[2] for part in parsed.query.split('&')),
                       *(value for _, value in query)) if part)
    frozen = FrozenEndpointEnvironment(environment, raw_url, redactions)
    C.publish(receipts / 'platform-binding.json',
              {'schema': 'v98-ci-identity-platform-binding/v1',
               'runId': resolved['runId'], 'runNumber': resolved['runNumber'],
               'oidcRequestHost': host, 'platformBinding': PLATFORM_BINDING,
               'basis': 'SAME_JOB_GITHUB_HOSTED_ENVIRONMENT_NOT_EXTERNAL_OBSERVATION',
               'rawURLOrQueryRetained': False,
               'externalRunAdmissionRequiredBeforeMintTrust': True}, grant.check)
    grant.check()
    return resolved, frozen


class IdentityGrant:
    def __init__(self, approval, original, wall, mono):
        self.wall, self.mono = wall, mono
        self.origin, self.last, self.failed = original, original, False
        approved, invoke, end = (approval[k] for k in ('approvedAtEpoch', 'invokeByEpoch', 'authorityEndEpoch'))
        C.need(all(C.finite(x) for x in (*original, approved, invoke, end))
               and approved <= original[0] <= invoke < end <= approved + 3600,
               'FIXED_APPROVAL_AND_INVOCATION_WINDOW')
        self.deadline = min(end, original[0] + 60)
        self.check()

    def check(self):
        wall, mono = self.wall(), self.mono()
        valid = (not self.failed and C.finite(wall) and C.finite(mono)
                 and self.last[0] <= wall < self.deadline and self.last[1] <= mono
                 and 0 <= mono - self.origin[1] < self.deadline - self.origin[0]
                 and abs(wall - self.origin[0] - (mono - self.origin[1])) <= 2)
        self.failed = not valid
        C.need(valid, 'ORIGINAL_IDENTITY_CLOCK_OR_CUTOFF')
        self.last = wall, mono


def redact_decoded_error_credentials(value, secrets):
    """Remove known credentials after JSON unescaping, before any projection."""
    ordered = sorted((secret for secret in secrets if secret), key=len, reverse=True)
    remaining = 8192
    redacted = False

    def clean(item, depth=0):
        nonlocal remaining, redacted
        remaining -= 1
        C.need(remaining >= 0 and depth <= 32, 'BOUNDED_ERROR_DIAGNOSTIC')
        if isinstance(item, str):
            original = item
            for secret in ordered:
                item = item.replace(secret, '[REDACTED]')
            redacted = redacted or item != original
            return item
        if type(item) is dict:
            return {clean(key, depth + 1): clean(child, depth + 1)
                    for key, child in item.items()}
        if type(item) is list:
            return [clean(child, depth + 1) for child in item]
        return item

    return clean(value), redacted


class PrivateErrorOpener:
    """Three exact auth endpoints, once each; fixed-field private errors only."""
    def __init__(self, backend, binding, grant, receipts, state, endpoint_redactions=()):
        self.backend, self.binding, self.grant = backend, binding, grant
        self.receipts, self.state, self.sent = receipts, state, set()
        self.secrets = set()
        self.endpoint_redactions = endpoint_redactions

    def open(self, request, timeout):
        self.grant.check()
        C.need(C.finite(timeout) and 0 < timeout <= 20, 'IDENTITY_HTTP_TIMEOUT')
        url, method = request.full_url, request.get_method()
        parsed = urllib.parse.urlsplit(url)
        C.need(parsed.scheme == 'https' and not parsed.username and not parsed.password
               and not parsed.fragment and parsed.port in (None, 443), 'IDENTITY_HTTPS_ONLY')
        iam = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' + SA_ID + ':generateAccessToken'
        if method == 'GET' and parsed.hostname == self.binding['oidcRequestHost']:
            query = urllib.parse.parse_qs(parsed.query)
            C.need(query.get('audience') == [A.AUDIENCE] and request.data is None, 'EXACT_OIDC_AUDIENCE')
            stage = 'GITHUB_OIDC'
        elif method == 'POST' and url == A.STS:
            form = urllib.parse.parse_qs(request.data.decode('ascii'), strict_parsing=True)
            expected = {'grant_type': ['urn:ietf:params:oauth:grant-type:token-exchange'],
                        'audience': [A.AUDIENCE], 'scope': [A.SCOPE],
                        'requested_token_type': ['urn:ietf:params:oauth:token-type:access_token'],
                        'subject_token_type': ['urn:ietf:params:oauth:token-type:jwt']}
            C.need(set(form) == set(expected) | {'subject_token'}
                   and all(form.get(k) == v for k, v in expected.items())
                   and len(form['subject_token']) == 1, 'ONLY_EXACT_STS_EXCHANGE')
            stage = 'GOOGLE_STS'
        elif method == 'POST' and url == iam:
            C.need(C.read_json(request.data) == {'scope': [A.SCOPE], 'lifetime': str(A.INTENDED_ACCESS_TOKEN_SECONDS) + 's'},
                   'ONLY_EXACT_ACCOUNT_TOKEN_MINT')
            stage = 'GOOGLE_IAM_CREDENTIALS'
        else:
            raise C.Refusal('NO_RESOURCE_OR_OTHER_HTTP_ENDPOINT')
        C.need(stage not in self.sent, 'ONE_REQUEST_PER_AUTH_STAGE_NO_RETRY')
        header = request.get_header('Authorization')
        if isinstance(header, str) and header.startswith('Bearer '):
            self.secrets.add(header[7:])
        if stage == 'GOOGLE_STS':
            self.secrets.add(form['subject_token'][0])
        C.need(len(self.secrets) <= 3, 'BOUNDED_EPHEMERAL_AUTH_SECRETS')
        self.sent.add(stage)
        self.state['stage'] = stage
        self.grant.check()
        try:
            return self.backend.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            self.state['httpStatus'] = error.code
            try:
                # Do not read or project upstream error prose. Unknown encodings
                # of URL capabilities or credentials must not enter receipts.
                C.publish(self.receipts / ('private-error-' + stage.lower() + '.json'),
                          {'stage': stage,
                           'httpStatus': error.code if type(error.code) is int and 100 <= error.code <= 599 else None,
                           'diagnostic': {'captureStatus': 'ERROR_BODY_NOT_READ_FIXED_FIELDS_ONLY',
                                          'privateOnly': True}},
                          self.grant.check, file_cap=8192)
            finally:
                error.close()
            raise


def recording_transport(binding, environment, grant, receipts, state):
    transport = A.HTTPS(environment)
    transport.opener = PrivateErrorOpener(transport.opener, binding, grant, receipts, state,
                                        environment.endpoint_redactions)
    return transport


def disable_core_dumps():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def prepare_receipts(environment, binding, approval, grant):
    value = environment.get('RUNNER_TEMP')
    C.need(type(value) is str, 'EXACT_RUNNER_TEMP')
    parent = Path(value)
    info = parent.lstat()
    C.need(parent.is_absolute() and parent.resolve() == parent and not parent.is_symlink()
           and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
           and not stat.S_IMODE(info.st_mode) & 0o022, 'OWNED_RUNNER_TEMP')
    path = parent / ('v98-identity-' + str(binding['runId']) + '-1-' + approval['nonce'])
    grant.check()
    os.mkdir(path, 0o700)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    grant.check()
    return C.directory(path)


def public_status(state):
    stages = {'PUBLIC_INPUT', 'ADMISSION', 'ISSUER', 'GITHUB_OIDC', 'GOOGLE_STS',
              'GOOGLE_IAM_CREDENTIALS', 'COMPLETE'}
    status = state.get('status')
    stage = state.get('stage')
    attempts = state.get('issuerAttempts')
    http_status = state.get('httpStatus')
    return {'status': status if type(status) is str and status in ('PASS', 'REFUSED_OR_UNKNOWN') else 'REFUSED_OR_UNKNOWN',
            'stage': stage if type(stage) is str and stage in stages else 'ADMISSION',
            'issuerAttempts': attempts if type(attempts) is int and attempts in (0, 1) else 0,
            'httpStatus': http_status if type(http_status) is int and 100 <= http_status <= 599 else None,
            'authenticationComplete': state.get('authenticationComplete') is True,
            'resourceRequests': 0}


def run_approved(value, environment, source_root=ROOT, original=None,
                 wall=time.time, mono=time.monotonic, alarm=C.SelfAlarm,
                 transport_factory=recording_transport, core_limit=disable_core_dumps, state=None):
    original = (ORIGINAL_WALL, ORIGINAL_MONOTONIC) if original is None else original
    state = {} if state is None else state
    state.update(status='REFUSED_OR_UNKNOWN', stage='ADMISSION', issuerAttempts=0,
                 authenticationComplete=False, resourceRequests=0)
    C.need(not (source_root / 'ACTIVATION_DISABLED').exists(), 'IDENTITY_ACTIVATION_DISABLED')
    binding, approval = validate_input(value, environment)
    grant = IdentityGrant(approval, original, wall, mono)
    clock = C.Deadline(grant.deadline, wall, mono, 60)
    with alarm(clock):
        verify_source(source_root, value['sourceManifestSha256'])
        grant.check()
        core_limit()
        receipts = prepare_receipts(environment, binding, approval, grant)
        return exchange_once(value, binding, approval, environment, receipts, grant,
                             wall, mono, alarm, transport_factory, state)


def exchange_once(value, binding, approval, environment, receipts, grant,
                  wall, mono, alarm, transport_factory, state):
    payload, issuer = None, None
    try:
        C.publish(receipts / 'attempt-intent.json',
                  {'schema': 'v98-ci-identity-attempt/v1', 'nonce': approval['nonce'],
                   'runId': binding['runId'], 'runAttempt': 1,
                   'sourceManifestSha256': value['sourceManifestSha256'],
                   'maximumIssuerCalls': 1, 'resourceRequestsAllowed': 0, 'retryAuthorized': False},
                  grant.check)
        binding, environment = bind_same_job_endpoint(binding, environment, receipts, grant)
        transport = transport_factory(binding, environment, grant, receipts, state)
        issuer = A.Issuer(binding, environment, receipts / 'issuer', grant, grant.deadline,
                          http=transport, wall=wall, mono=mono, alarm=alarm)
        state['stage'] = 'ISSUER'
        payload = issuer.issue(min(wall() + 30, grant.deadline - 1))
        state['issuerAttempts'] = issuer.count
        C.need(issuer.count == 1 and payload['principalUniqueId'] == SA_ID
               and payload['principal'] == A.ACCOUNT and payload['provider'] == A.PROVIDER
               and payload['identityBasis'] == 'TRUSTED_STS_AND_EXACT_IAM_TARGET_TLS'
               and payload['nativeIssuerUsed'] is False, 'EXACT_IDENTITY_RESULT')
        payload = None
        grant.check()
        state.update(status='PASS', stage='COMPLETE', authenticationComplete=True)
        summary = public_status(state)
        C.publish(receipts / 'final.json', {'schema': 'v98-ci-identity-status/v1', **summary}, grant.check)
        return summary
    except BaseException:
        state['issuerAttempts'] = 0 if issuer is None else issuer.count
        state.update(status='REFUSED_OR_UNKNOWN', authenticationComplete=False)
        try:
            C.publish(receipts / 'failed.json', {'schema': 'v98-ci-identity-status/v1', **public_status(state)}, grant.check)
        except BaseException:
            pass
        raise
    finally:
        payload = None
        if issuer is not None:
            issuer.halted = True


def main(argv=None, environment=None, stream=None):
    argv = sys.argv[1:] if argv is None else argv
    stream = sys.stdout if stream is None else stream
    if argv != ['--run-approved-identity-once']:
        stream.write('{"status":"IDENTITY_PROBE_INACTIVE"}\n')
        return 0
    environment = os.environ if environment is None else environment
    state = {'status': 'REFUSED_OR_UNKNOWN', 'stage': 'PUBLIC_INPUT', 'issuerAttempts': 0,
             'authenticationComplete': False, 'resourceRequests': 0}
    try:
        raw = environment.get('V98_CI_IDENTITY_BINDING')
        C.need(type(raw) is str and 0 < len(raw.encode()) <= 8192, 'BOUNDED_PUBLIC_IDENTITY_INPUT')
        value = C.read_json(raw.encode())
        run_approved(value, environment, state=state)
        rc = 0
    except BaseException:
        state['status'] = 'REFUSED_OR_UNKNOWN'
        rc = 1
    line = C.encoded({'schema': 'v98-ci-identity-status/v1', **public_status(state)}).decode()
    C.need(len(line.encode()) <= 512, 'FIXED_PUBLIC_STATUS_CAP')
    try:
        stream.write(line)
    except BaseException:
        pass
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
