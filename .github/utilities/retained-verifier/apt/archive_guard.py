"""Same-context historical Debian APT guard; pure injected logic only.

Normal APT signature and date/expiry checks remain enabled. This extra guard
binds every update/install to the exact reviewed historical fixture; it does
not make it a current security-update OS and never issues execution authority.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import PurePosixPath

import archive_policy as policy

LISTS = '/var/lib/apt/lists'
ETC = '/etc/apt'
KEYRING = '/usr/share/keyrings/debian-archive-keyring.gpg'
RELEASE = 'deb.debian.org_debian_dists_bookworm_InRelease'
PACKAGES = 'deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages'
SECURITY_RELEASE = 'security.debian.org_debian-security_dists_bookworm-security_InRelease'
SECURITY_PACKAGES = 'security.debian.org_debian-security_dists_bookworm-security_main_binary-amd64_Packages'
PACKAGE_SUFFIXES = ('', '.lz4', '.xz', '.gz', '.bz2', '.zst')
SOURCE = (b'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] '
          b'https://deb.debian.org/debian bookworm main\n'
          b'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] '
          b'https://security.debian.org/debian-security bookworm-security main\n')
GUARD_FILE = '90-ocv-archive-guard'
HOOK = '/usr/bin/python3 -I -S -B /etc/apt/ocv/launch.py'
CONFIG = ('''APT::Update::Error-Mode "any";
Acquire::Languages "none";
Acquire::IndexTargets::deb::DEP-11::DefaultEnabled "false";
Acquire::IndexTargets::deb::Translations::DefaultEnabled "false";
Acquire::Check-Date "true";
Acquire::Check-Valid-Until "true";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
APT::Keep-Downloaded-Packages "true";
Binary::apt::APT::Keep-Downloaded-Packages "true";
Binary::apt-get::APT::Keep-Downloaded-Packages "true";
APT::Update::Post-Invoke-Success {"%s update";};
DPkg::Pre-Invoke {"%s install";};
''' % (HOOK, HOOK)).encode()
CONTEXT_KEYS = {'schema', 'runIdentity', 'sourceManifestSha256', 'keyringSha256', 'gpgvSha256', 'aptHelperSha256',
                'sourceRosterSha256', 'guardConfigSha256', 'buildId'}
SHA = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z0-9][a-z0-9+.-]{0,127}\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}\Z')


class Refusal(ValueError):
    def __init__(self,code,facts=None):
        super().__init__(code);self.facts={} if facts is None else facts


def require(ok, reason, facts=None):
    if not ok:
        raise Refusal(reason,facts)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(raw):
    require(type(raw) is bytes, 'apt.bytes')
    return hashlib.sha256(raw).hexdigest()


def parse_json(raw, maximum=65536):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, 'apt.json_size')
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'apt.json_duplicate')
            value[key] = item
        return value
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal('apt.json_number')))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal('apt.json') from error


def context_checked(context):
    require(type(context) is dict and set(context) == CONTEXT_KEYS and
            context['schema'] == 'ocv-apt-guard-context-v1', 'apt.context')
    for key in CONTEXT_KEYS - {'schema', 'buildId', 'runIdentity'}:
        require(type(context[key]) is str and SHA.fullmatch(context[key]), 'apt.context_hash')
    require(re.fullmatch('[0-9a-f]{32}', context['buildId'] or '') is not None, 'apt.build_id')
    run=context['runIdentity']
    require(type(run) is dict and set(run)=={'repository','workflowRef','sourceCommit','runId','runAttempt'} and
            run['repository']=='fr-meyer/openclaw' and
            run['workflowRef']=='fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites' and
            type(run['sourceCommit']) is str and re.fullmatch('[0-9a-f]{40}',run['sourceCommit']) and
            all(type(run[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',run[k]) for k in ('runId','runAttempt')),
            'apt.run_identity')
    require(context['sourceRosterSha256'] == sha(SOURCE) and
            context['guardConfigSha256'] == sha(CONFIG), 'apt.config_pin')
    return context


def project_files():
    """Recognized mkosi20 PackageManagerTrees input paths; no write occurs."""
    return {'etc/apt/sources.list': (SOURCE, 0o444),
            'etc/apt/apt.conf.d/' + GUARD_FILE: (CONFIG, 0o444)}


def project_directories():
    """Empty standard directories required by the closed source roster."""
    return {'etc/apt/sources.list.d':0o755,'etc/apt/preferences.d':0o755}


def _sandbox_account(ops):
    try:value=ops.apt_sandbox_identity()
    except BaseException as error:
        raise Refusal('apt.sandbox_account_read',{'role':'apt-sandbox-account',
          'exceptionType':type(error).__name__,'errno':getattr(error,'errno',None)}) from None
    require(type(value) is dict and set(value)=={'name','uid','rootGroupName','rootGroupGid'} and
            value['name']=='_apt' and type(value['uid']) is int and value['uid']>0 and
            value['rootGroupName']=='root' and type(value['rootGroupGid']) is int and
            value['rootGroupGid']==0,'apt.sandbox_account_identity')
    return value


def _names(ops, path, cap=256):
    try:rows = ops.entries(path, cap)
    except BaseException as error:raise _file_refusal('directory',path,error) from None
    require(type(rows) is list and len(rows) <= cap, 'apt.directory_bound')
    result = {};sandbox=None
    for row in rows:
        require(type(row) is dict and set(row) == {'name', 'kind', 'uid', 'gid', 'mode', 'bytes', 'identity'},
                'apt.directory_row')
        name = row['name']
        require(type(name) is str and name not in ('.', '..') and '/' not in name and
                '\x00' not in name and name not in result, 'apt.directory_name')
        require(row['kind'] in ('file', 'directory') and type(row['uid']) is int and row['uid']>=0 and
                type(row['gid']) is int and row['gid']>=0 and
                type(row['mode']) is int and 0<=row['mode']<=0o7777 and
                type(row['bytes']) is int and row['bytes'] >= 0 and
                type(row['identity']) is list and len(row['identity']) == 5 and
                all(type(v) is int and v >= 0 for v in row['identity']), 'apt.directory_identity')
        if path==LISTS and name in ('partial','auxfiles'):
            if row['uid']!=0 and sandbox is None:sandbox=_sandbox_account(ops)
            expected_mode=0o700 if name=='partial' else 0o755
            allowed_uid=(row['uid']==0 or (sandbox is not None and row['uid']==sandbox['uid']))
            require(row['kind']=='directory' and allowed_uid and
                    row['gid']==0 and row['mode']==expected_mode and
                    row['identity'][-1]>=1,'apt.auxiliary_directory_identity',
                    {'role':name,'kind':row['kind'],'uid':row['uid'],'gid':row['gid'],'mode':row['mode']})
        else:
            require(row['uid']==row['gid']==0 and row['mode']&0o022==0,'apt.directory_identity')
        result[name] = row
    return result


def _read(ops, path, cap):
    try:raw = ops.read_regular(path, cap)
    except BaseException as error:raise _file_refusal('read',path,error) from None
    require(type(raw) is bytes and len(raw) <= cap, 'apt.read_bound')
    return raw


def _file_refusal(operation,path,error):
    roles={ETC:'apt-root',ETC+'/sources.list':'sources',ETC+'/sources.list.d':'source-parts',
      ETC+'/apt.conf.d':'config-parts',ETC+'/apt.conf.d/'+GUARD_FILE:'guard-config',
      ETC+'/preferences.d':'preferences',LISTS:'lists',LISTS+'/partial':'partial',
      LISTS+'/auxfiles':'auxfiles',KEYRING:'keyring','/usr/bin/gpgv':'gpgv-tool',
      '/usr/lib/apt/apt-helper':'apt-helper-tool',LISTS+'/'+RELEASE:'release'}
    role=roles.get(path,'packages' if path.startswith(LISTS+'/'+PACKAGES) else 'unknown')
    facts={'operation':operation,'role':role,'exceptionType':type(error).__name__,
           'errno':getattr(error,'errno',None)}
    if isinstance(error,RuntimeError) and re.fullmatch('apt\\.native_[a-z_]{1,80}',str(error)):
        facts['boundaryCode']=str(error)
    return Refusal('apt.file_boundary',facts)


def _sources(ops):
    require(_read(ops, ETC + '/sources.list', 1024) == SOURCE, 'apt.source_roster')
    require(_names(ops, ETC + '/sources.list.d', 1) == {}, 'apt.extra_source')
    require(set(_names(ops, ETC + '/apt.conf.d', 1)) == {GUARD_FILE}, 'apt.extra_fragment')
    require(_read(ops, ETC + '/apt.conf.d/' + GUARD_FILE, 8192) == CONFIG, 'apt.guard_changed')
    # A main apt.conf is parsed after fragments and may clear/override them.
    etc = _names(ops, ETC, 32)
    require('apt.conf' not in etc, 'apt.main_config_override')
    require(_names(ops, ETC + '/preferences.d', 1) == {}, 'apt.preference_override')
    require('preferences' not in etc, 'apt.preference_override')


def _result_ok(value, cap, *, signature_status=False):
    require(type(value) is dict and {'exitCode', 'timedOut', 'captureComplete',
            'ownedChildExited', 'ownershipRetained', 'stdout', 'stderr'} <= value.keys(), 'apt.command_shape')
    require(type(value['exitCode']) is int and
            value['exitCode'] in ((0, 2) if signature_status else (0,)) and
            value['timedOut'] is False and value['captureComplete'] is True and
            value['ownedChildExited'] is True and value['ownershipRetained'] is False and
            type(value['stdout']) is bytes and len(value['stdout']) <= cap and
            type(value['stderr']) is bytes and len(value['stderr']) <= 16384, 'apt.command_failed')
    return value


def _command(ops, role, argv, maximum, *, signature_status=False):
    try:
        value = ops.run(argv, timeout=30, stdout_cap=maximum, stderr_cap=16384)
    except BaseException as error:
        ops.evidence(role, {'boundaryFailure': type(error).__name__,
                            'errno': getattr(error, 'errno', None)})
        raise Refusal('apt.command_boundary') from None
    # Save the actual bounded cause before interpreting JSON/status/exit.
    ops.evidence(role, value)
    return _result_ok(value, maximum, signature_status=signature_status)


def run_guard(ops, context, phase):
    return _run_dual_guard(ops, context, phase, policy.BOOKWORM)[0]


def _run_guard(ops, context, phase, fixture, *, security=False):
    """Internal byte-fixture seam; native entry always selects BOOKWORM."""
    context_checked(context)
    require(phase in ('update', 'install', 'postinstall'), 'apt.phase')
    _sources(ops)
    rows = _names(ops, LISTS, 8)
    expected = {RELEASE} | {PACKAGES + suffix for suffix in PACKAGE_SUFFIXES}
    candidates = [name for name in rows if name.startswith(PACKAGES)]
    require(len(candidates) == 1 and candidates[0] in expected and RELEASE in rows,
            'apt.lists_missing_or_duplicate')
    permitted = {RELEASE, candidates[0], 'lock', 'partial', 'auxfiles'}
    if security:
        second = [name for name in rows if name.startswith(SECURITY_PACKAGES)]
        require(len(second) == 1 and second[0] in
                {SECURITY_PACKAGES+s for s in PACKAGE_SUFFIXES} and
                SECURITY_RELEASE in rows, 'apt.security_lists_missing_or_duplicate')
        permitted |= {SECURITY_RELEASE,second[0]}
    require(set(rows) <= permitted, 'apt.extra_lists')
    require(rows[RELEASE]['kind'] == rows[candidates[0]]['kind'] == 'file', 'apt.list_type')
    require(rows[RELEASE]['identity'][-1] == rows[candidates[0]]['identity'][-1] == 1 and
            0 < rows[candidates[0]]['bytes'] <= 64*1024*1024, 'apt.list_identity_or_size')
    # APT uses these named directories for its sandbox UID. They are ignored
    # cache state, not metadata inputs: validate their source-defined outer
    # identity above and never open/list their contents.
    if 'lock' in rows:
        require(rows['lock']['kind'] == 'file' and rows['lock']['bytes'] == 0, 'apt.lock')
    release_path, package_path = LISTS + '/' + RELEASE, LISTS + '/' + candidates[0]
    release = _read(ops, release_path, 196608)
    require(len(release) == fixture.release_bytes and sha(release) == fixture.release_sha256,
            'apt.release_pin')
    keyring = _read(ops, KEYRING, 1048576)
    require(sha(keyring) == context['keyringSha256'], 'apt.keyring_pin')
    for executable, key in (('/usr/bin/gpgv', 'gpgvSha256'),
                            ('/usr/lib/apt/apt-helper', 'aptHelperSha256')):
        require(sha(_read(ops, executable, 16777216)) == context[key], 'apt.tool_pin')
    signature = _command(ops, 'gpgv', ('/usr/bin/gpgv', '--status-fd=1', '--keyring', KEYRING,
                                     release_path), 16384, signature_status=True)
    packages = _command(ops, 'packages', ('/usr/lib/apt/apt-helper', 'cat-file', package_path),
                        64 * 1024 * 1024)['stdout']
    # Recheck the underlying roster/bytes after the tools finish. Any concurrent
    # writer/change refuses; no cached pass receipt can admit another state.
    require(_names(ops, LISTS, 8) == rows and _read(ops, release_path, 196608) == release and
            _read(ops, KEYRING, 1048576) == keyring, 'apt.changed_during_verification')
    _sources(ops)
    checked = ops.now()
    try:
        classified = policy.classify(release, packages, returncode=signature['exitCode'],
          timed_out=signature['timedOut'], status=signature['stdout'], checked_at=checked, fixture=fixture)
    except policy.Refusal as error:
        raise Refusal('apt.fixture_' + str(error)) from None
    proof = {'schema': 'ocv-apt-guard-proof-v1', 'phase': phase, 'buildId': context['buildId'],
             'sourceManifestSha256': context['sourceManifestSha256'],
             'releaseSha256': sha(release), 'packagesSha256': sha(packages),
             'keyringSha256': sha(keyring), 'sourceRosterSha256': sha(SOURCE),
             'guardConfigSha256': sha(CONFIG),
             'verifiedPrimaryFingerprints': classified['verifiedPrimaryFingerprints'],
             'checkedAt': checked.astimezone(timezone.utc).isoformat(),
             'freshSecurityUpdateBase': False, 'nativeAuthenticationIssued': False}
    proof['proofSha256'] = sha(canonical(proof))
    return proof, {'InRelease': release, 'Packages': packages, 'keyring.gpg': keyring,
                   'gpgv-status.txt': signature['stdout']}


def _run_dual_guard(ops, context, phase, fixture):
    """Native callers always select main BOOKWORM plus fixed security policy."""
    before = _names(ops,LISTS,8)
    proof,contents = _run_guard(ops,context,phase,fixture,security=True)
    rows = _names(ops,LISTS,8)
    require(rows == before,'apt.changed_during_verification')
    names = [n for n in rows if n.startswith(SECURITY_PACKAGES)]
    require(len(names) == 1 and names[0] in {SECURITY_PACKAGES+s for s in PACKAGE_SUFFIXES}
            and SECURITY_RELEASE in rows,'apt.security_lists_missing_or_duplicate')
    for name in (SECURITY_RELEASE,names[0]):
        require(rows[name]['kind'] == 'file' and rows[name]['identity'][-1] == 1 and
                0 < rows[name]['bytes'] <= 64*1024*1024,'apt.security_list_identity')
    release_path = LISTS+'/'+SECURITY_RELEASE; package_path = LISTS+'/'+names[0]
    release = _read(ops,release_path,196608)
    signature = _command(ops,'gpgv',('/usr/bin/gpgv','--status-fd=1','--keyring',KEYRING,
                                    release_path),16384)
    packages = _command(ops,'packages',('/usr/lib/apt/apt-helper','cat-file',package_path),
                        64*1024*1024)['stdout']
    require(_names(ops,LISTS,8) == rows and _read(ops,release_path,196608) == release and
            _read(ops,LISTS+'/'+RELEASE,196608) == contents['InRelease'] and
            _read(ops,KEYRING,1048576) == contents['keyring.gpg'],
            'apt.changed_during_verification')
    _sources(ops); checked = ops.now()
    try:
        classified = policy.classify_security(release,packages,
            returncode=signature['exitCode'],timed_out=signature['timedOut'],
            status=signature['stdout'],checked_at=checked)
    except policy.Refusal as error:
        raise Refusal('apt.security_'+str(error)) from None
    security_proof = {'schema':'ocv-apt-security-guard-proof-v1','phase':phase,
        'buildId':context['buildId'],'sourceManifestSha256':context['sourceManifestSha256'],
        'keyringSha256':sha(contents['keyring.gpg']),'releaseSha256':sha(release),
        'packagesSha256':sha(packages),'gpgStatusSha256':sha(signature['stdout']),
        'verifiedPrimaryFingerprints':classified['verifiedPrimaryFingerprints'],
        'releaseDate':classified['releaseDate'],'validUntil':classified['validUntil'],
        'checkedAt':checked.astimezone(timezone.utc).isoformat(),
        'nativeAuthenticationIssued':False}
    proof.update(checkedAt=security_proof['checkedAt'],securityReleaseSha256=sha(release),securityPackagesSha256=sha(packages),
        securityVerifiedPrimaryFingerprints=classified['verifiedPrimaryFingerprints'])
    proof['proofSha256'] = sha(canonical({k:v for k,v in proof.items() if k!='proofSha256'}))
    contents.update(SecurityInRelease=release,SecurityPackages=packages,
        **{'security-gpgv-status.txt':signature['stdout'],
           'security-guard-proof.json':canonical(security_proof)})
    return proof,contents


def hook_record(proof, events):
    require(type(events) is list and len(events) <= 8, 'apt.events_bound')
    return {'schema': 'ocv-apt-hook-record-v1', 'outcome': 'passed',
            'phase': proof['phase'], 'proof': proof, 'events': events}


PROOF_KEYS={'schema','phase','buildId','sourceManifestSha256','releaseSha256','packagesSha256',
            'keyringSha256','sourceRosterSha256','guardConfigSha256','verifiedPrimaryFingerprints',
            'checkedAt','freshSecurityUpdateBase','nativeAuthenticationIssued','proofSha256'}
SECURITY_PROOF_FIELDS={'securityReleaseSha256','securityPackagesSha256',
                       'securityVerifiedPrimaryFingerprints'}
SECURITY_GUARD_PROOF_KEYS={'schema','phase','buildId','sourceManifestSha256','keyringSha256',
    'releaseSha256','packagesSha256','gpgStatusSha256','verifiedPrimaryFingerprints',
    'releaseDate','validUntil','checkedAt','nativeAuthenticationIssued'}


def _proof_checked(proof):
    require(type(proof) is dict and set(proof) in (PROOF_KEYS,PROOF_KEYS|SECURITY_PROOF_FIELDS) and
            proof['schema']=='ocv-apt-guard-proof-v1' and proof['phase'] in ('update','install','postinstall'),
            'apt.proof_schema')
    for field in ('sourceManifestSha256','releaseSha256','packagesSha256','keyringSha256',
                  'sourceRosterSha256','guardConfigSha256','proofSha256'):
        require(type(proof[field]) is str and SHA.fullmatch(proof[field]),'apt.proof_hash_type')
    require(type(proof['buildId']) is str and re.fullmatch('[0-9a-f]{32}',proof['buildId']) and
            proof['freshSecurityUpdateBase'] is False and proof['nativeAuthenticationIssued'] is False,
            'apt.proof_identity')
    primaries=proof['verifiedPrimaryFingerprints']
    require(type(primaries) is list and 0<len(primaries)<=16 and
            all(type(v) is str and re.fullmatch('[0-9A-F]{40}',v) for v in primaries) and
            primaries==sorted(set(primaries)) and bool(set(primaries)&policy.BOOKWORM.primaries),
            'apt.proof_primaries')
    if SECURITY_PROOF_FIELDS <= set(proof):
        require(type(proof['securityReleaseSha256'])is str and SHA.fullmatch(proof['securityReleaseSha256']) and
                type(proof['securityPackagesSha256'])is str and SHA.fullmatch(proof['securityPackagesSha256']) and
                proof['securityVerifiedPrimaryFingerprints']==sorted(policy.SECURITY_PRIMARIES),
                'apt.security_proof_identity')
    try:
        checked=datetime.fromisoformat(proof['checkedAt'])
        require(checked.utcoffset() is not None and checked.utcoffset().total_seconds()==0 and
                checked.isoformat()==proof['checkedAt'],'apt.proof_time')
    except (ValueError,TypeError):raise Refusal('apt.proof_time') from None
    require(proof['proofSha256']==sha(canonical({k:v for k,v in proof.items() if k!='proofSha256'})),
            'apt.ledger_proof_hash')
    return checked


def validate_ledger(raw, context, final_proof):
    """Validate provenance joins; this never substitutes for fresh signature."""
    context_checked(context)
    final_time=_proof_checked(final_proof)
    value = parse_json(raw, 1048576)
    require(type(value) is dict and set(value) == {'schema','records'} and
            value['schema'] == 'ocv-apt-first-stage-ledger-v1' and
            type(value['records']) is list and 3 <= len(value['records']) <= 128, 'apt.ledger')
    phases = set();times={'update':[],'install':[],'postinstall':[]}
    for record in value['records']:
        require(type(record) is dict and set(record) == {'schema','outcome','phase','proof','events'} and
                record['schema'] == 'ocv-apt-hook-record-v1' and record['outcome'] == 'passed' and
                record['phase'] in ('update','install','postinstall') and
                type(record['events']) is list and len(record['events']) <= 8, 'apt.ledger_record')
        p = record['proof']
        require(type(p) is dict and set(p) == set(final_proof) and p['phase'] == record['phase'], 'apt.ledger_proof')
        checked=_proof_checked(p)
        stable = {'schema','buildId','sourceManifestSha256','releaseSha256','packagesSha256','keyringSha256',
                  'sourceRosterSha256','guardConfigSha256','verifiedPrimaryFingerprints',
                  'freshSecurityUpdateBase','nativeAuthenticationIssued'}
        if SECURITY_PROOF_FIELDS <= set(final_proof):stable |= SECURITY_PROOF_FIELDS
        require(all(p[k] == final_proof[k] for k in stable) and p['buildId'] == context['buildId'],
                'apt.ledger_identity')
        require(p['freshSecurityUpdateBase'] is False and p['nativeAuthenticationIssued'] is False,
                'apt.ledger_authority')
        phases.add(record['phase'])
        times[record['phase']].append(checked)
    require(phases == {'update','install','postinstall'}, 'apt.ledger_phases')
    require(min(times['update'])<=min(times['install']) and
            max(t for group in times.values() for t in group)<=final_time and
            final_time in times['postinstall'],'apt.ledger_chronology')
    return value


EXPORT_NAMES = ('InRelease','Packages','keyring.gpg','gpgv-status.txt','guard-proof.json','first-stage-ledger.json')
SECURITY_EXPORT_NAMES = ('SecurityInRelease','SecurityPackages','security-gpgv-status.txt',
                         'security-guard-proof.json')
EXPORT_ROOT = '/opt/ocv/control/apt-data'


def export_descriptor(contents, proof, context):
    context_checked(context)
    names=EXPORT_NAMES+(SECURITY_EXPORT_NAMES if SECURITY_PROOF_FIELDS<=set(proof) else ())
    require(type(contents) is dict and set(contents) == set(names), 'apt.export_files')
    files = {name: {'path': EXPORT_ROOT + '/' + name, 'bytes': len(contents[name]),
                    'sha256': sha(contents[name])} for name in names}
    return {'schema': 'ocv-apt-export-v1', 'files': files,
            'sourceRosterSha256': sha(SOURCE), 'guardConfigSha256': sha(CONFIG),
            'buildId': proof['buildId'], 'sourceProofSha256': proof['proofSha256'],
            'guardContext': context}


def validate_export(raw, contents):
    value = parse_json(raw)
    require(type(value) is dict and set(value) == {'schema','files','sourceRosterSha256',
            'guardConfigSha256','buildId','sourceProofSha256','guardContext'} and
            value['schema'] == 'ocv-apt-export-v1' and type(value['files']) is dict and
            set(value['files']) in (set(EXPORT_NAMES),set(EXPORT_NAMES+SECURITY_EXPORT_NAMES)), 'apt.export')
    require(value['sourceRosterSha256'] == sha(SOURCE) and value['guardConfigSha256'] == sha(CONFIG),
            'apt.export_source')
    require(set(contents) == set(value['files']), 'apt.export_contents')
    for name, row in value['files'].items():
        require(type(row) is dict and set(row) == {'path','bytes','sha256'} and
                row == {'path': EXPORT_ROOT + '/' + name, 'bytes': len(contents[name]),
                        'sha256': sha(contents[name])}, 'apt.export_pin')
    proof = parse_json(contents['guard-proof.json'])
    _proof_checked(proof)
    if SECURITY_PROOF_FIELDS<=set(proof):
        require(set(contents)==set(EXPORT_NAMES+SECURITY_EXPORT_NAMES),'apt.security_export_required')
        security=parse_json(contents['security-guard-proof.json'])
        require(type(security)is dict and set(security)==SECURITY_GUARD_PROOF_KEYS and
                contents['security-guard-proof.json']==canonical(security),'apt.security_export_schema')
        require(all(type(security[k])is str and SHA.fullmatch(security[k]) for k in
                ('sourceManifestSha256','keyringSha256','releaseSha256','packagesSha256','gpgStatusSha256')) and
                type(security['buildId'])is str and re.fullmatch('[0-9a-f]{32}',security['buildId']) and
                type(security['verifiedPrimaryFingerprints'])is list and
                security['verifiedPrimaryFingerprints']==sorted(policy.SECURITY_PRIMARIES) and
                all(type(security[k])is str and 0<len(security[k])<=128 for k in
                    ('releaseDate','validUntil','checkedAt')),'apt.security_export_types')
        try:
            when=datetime.fromisoformat(security['checkedAt'])
            require(when.utcoffset() is not None and when.utcoffset().total_seconds()==0 and
                    when.isoformat()==security['checkedAt'],'apt.security_export_time')
            classified=policy.classify_security(contents['SecurityInRelease'],contents['SecurityPackages'],
                returncode=0,timed_out=False,status=contents['security-gpgv-status.txt'],checked_at=when)
        except (ValueError,TypeError):raise Refusal('apt.security_export_time') from None
        require(security['releaseDate']==classified['releaseDate'] and
                security['validUntil']==classified['validUntil'] and
                security['checkedAt']==proof['checkedAt'],'apt.security_export_time_join')
        require(security['schema']=='ocv-apt-security-guard-proof-v1' and
                security['nativeAuthenticationIssued'] is False and
                security['phase']=='postinstall' and security['buildId']==proof['buildId'] and
                security['sourceManifestSha256']==proof['sourceManifestSha256'] and
                security['keyringSha256']==proof['keyringSha256'] and
                security['releaseSha256']==proof['securityReleaseSha256']==sha(contents['SecurityInRelease']) and
                security['packagesSha256']==proof['securityPackagesSha256']==sha(contents['SecurityPackages']) and
                security['gpgStatusSha256']==sha(contents['security-gpgv-status.txt']) and
                security['verifiedPrimaryFingerprints']==proof['securityVerifiedPrimaryFingerprints'],
                'apt.security_export_join')
    else:require(set(contents)==set(EXPORT_NAMES),'apt.security_export_without_proof')
    require(proof['proofSha256'] == value['sourceProofSha256'] and proof['buildId'] == value['buildId'],
            'apt.export_proof')
    context_checked(value['guardContext'])
    return value


def verify_export(descriptor_raw, files, *, expected_keyring_sha256, expected_source_manifest_sha256,
                  expected_build_id):
    """Closed source/digest/ledger joins only; caller must fresh-verify GPG."""
    value = validate_export(descriptor_raw, files)
    proof = parse_json(files['guard-proof.json'])
    context = value['guardContext']
    require(type(expected_build_id) is str and re.fullmatch('[0-9a-f]{32}',expected_build_id) and
            context['buildId']==value['buildId']==proof['buildId']==expected_build_id,'apt.export_external_build')
    require(context['sourceManifestSha256'] == expected_source_manifest_sha256 == proof['sourceManifestSha256'] and
            context['keyringSha256'] == expected_keyring_sha256 == proof['keyringSha256'] and
            sha(files['keyring.gpg']) == expected_keyring_sha256, 'apt.export_external_pin')
    require(context['buildId'] == value['buildId'] == proof['buildId'], 'apt.export_build_id')
    validate_ledger(files['first-stage-ledger.json'], context, proof)
    return {'schema': 'ocv-apt-export-join-v1',
            'firstStageLedgerSha256': sha(files['first-stage-ledger.json']),
            'exportSha256': sha(descriptor_raw), 'guardProofSha256': proof['proofSha256'],
            'sourceManifestSha256': expected_source_manifest_sha256,
            'keyringSha256': expected_keyring_sha256, 'buildId': proof['buildId'],
            'freshSignatureStillRequired': True}


def package_records(packages, *, origin='main'):
    """Parse only the already-authenticated Packages bytes; no dependency solver."""
    require(type(packages) is bytes and 0 < len(packages) <= 64 * 1024 * 1024, 'apt.packages_bound')
    try:
        text = packages.decode('utf-8')
    except UnicodeDecodeError:
        raise Refusal('apt.packages_encoding') from None
    require(origin in ('main','security'),'apt.package_origin')
    result = {}
    for paragraph in text.split('\n\n'):
        if not paragraph.strip():
            continue
        require(len(paragraph) <= 1048576, 'apt.package_paragraph')
        fields = {}
        for line in paragraph.splitlines():
            if line.startswith((' ', '\t')):
                continue
            require(': ' in line, 'apt.package_field')
            key, value = line.split(': ', 1)
            require(key not in fields, 'apt.package_duplicate_field')
            fields[key] = value
        require({'Package', 'Version', 'Architecture', 'Filename', 'SHA256', 'Size'} <= fields.keys(),
                'apt.package_fields')
        name, version, arch = (fields[key] for key in ('Package', 'Version', 'Architecture'))
        require(NAME.fullmatch(name) and VERSION.fullmatch(version) and arch in ('amd64', 'all'),
                'apt.package_identity')
        filename = fields['Filename']
        prefix='pool/main/' if origin=='main' else 'pool/updates/main/'
        require(filename.startswith(prefix) and str(PurePosixPath(filename)) == filename and
                '..' not in PurePosixPath(filename).parts and filename.endswith('.deb'), 'apt.package_filename')
        require(SHA.fullmatch(fields['SHA256']) and re.fullmatch('[1-9][0-9]*', fields['Size']),
                'apt.package_digest')
        key = (name, version, arch)
        require(key not in result and len(result) < 100000, 'apt.package_duplicate_or_count')
        result[key] = {'name': name, 'version': version, 'architecture': arch,
                       'debSha256': fields['SHA256'], 'bytes': int(fields['Size']), 'filename': filename}
        if name=='selinux-utils':
            depends=fields.get('Depends')
            require(type(depends)is str and 0<len(depends)<=4096 and
                    all(32<=ord(c)<127 for c in depends),'apt.repair_depends')
            result[key]['depends']=depends
    return result


def installed_roster(records, raw, proof):
    """Join actual dpkg-query output to signed-index identities, not file proof.

    debSha256 is the expected authenticated-index archive hash. This does not
    replace native APT hash verification or per-file archive-byte comparison.
    """
    require(type(raw) is bytes and len(raw) <= 1048576, 'apt.installed_bound')
    require(type(proof) is dict and proof.get('schema') == 'ocv-apt-guard-proof-v1' and
            type(proof.get('proofSha256')) is str and SHA.fullmatch(proof['proofSha256']), 'apt.proof_join')
    try:
        lines = raw.decode('ascii').splitlines()
    except UnicodeError:
        raise Refusal('apt.installed_encoding') from None
    packages, seen = [], set()
    for line in lines:
        fields = line.split('\t')
        require(len(fields) == 3, 'apt.installed_fields')
        key = tuple(fields)
        require(key in records and fields[0] not in seen, 'apt.installed_unknown_or_duplicate')
        seen.add(fields[0]); row = records[key]
        packages.append({key: row[key] for key in ('name','version','architecture','debSha256')})
    require(packages, 'apt.installed_empty')
    return {'schema': 'ocv-authenticated-installed-packages-v1',
            'sourceProofSha256': proof['proofSha256'], 'packages': packages}


def select_roots(records, names, *, exact_versions=None):
    """Select explicit roots only; dependency resolution remains normal APT."""
    require(type(names) in (tuple,list) and 0 < len(names) <= 64 and
            len(set(names)) == len(names) and all(type(n) is str and NAME.fullmatch(n) for n in names),
            'apt.root_names')
    pins={} if exact_versions is None else exact_versions
    require(type(pins) is dict and set(pins) <= set(names), 'apt.root_version_pins')
    result=[]
    for name in sorted(names):
        matches=[row for (n,v,a),row in records.items() if n==name and
                 (name not in pins or v==pins[name])]
        require(len(matches)==1,'apt.root_missing_or_ambiguous')
        row=matches[0]
        result.append({'name':row['name'],'version':row['version'],'sha256':row['debSha256']})
    return result


def security_python_roots(records):
    """Only four source-pinned u9 archives from an authenticated security index."""
    require(type(records) is dict,'apt.security_records')
    roots=[]
    for name,(size,digest,filename) in sorted(policy.PYTHON_U9.items()):
        row=records.get((name,policy.PYTHON_U9_VERSION,'amd64'))
        require(type(row) is dict and row.get('name')==name and
                row.get('version')==policy.PYTHON_U9_VERSION and row.get('architecture')=='amd64' and
                type(row.get('bytes'))is int and row['bytes']==size and
                row.get('debSha256')==digest and row.get('filename')==filename,
                'apt.security_python_pin')
        roots.append({'name':name,'version':policy.PYTHON_U9_VERSION,'sha256':digest})
    return roots


if __name__ == '__main__':
    raise SystemExit('disarmed_requires_checked_ci_source_launcher')
