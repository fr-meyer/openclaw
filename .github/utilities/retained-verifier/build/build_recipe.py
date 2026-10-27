"""Native mkosi20.2 BUILD ONLY and fixed direct-QEMU construction.

Import and pure builders perform no native operation. The parent host issuer
owns execution authority; no CLI, environment flag or JSON issues it here.
Only the caller's reviewed command/custody port may execute returned argv.
"""
import hashlib
import json
import re
from pathlib import PurePosixPath
from uuid import UUID

SOURCE_ROOT = '/opt/ocv/source'
CONTROL_ROOT = '/opt/ocv/control'
OUTPUT_FILES = ('ocv-test.raw', 'kernel.bin', 'initrd.img')
SYSTEMD_VERSION = '252.39-1~deb12u2'
ROOT_TYPE = '4f68bce3-e8cd-4db1-96e7-fbcaf984b709'
MAX_IMAGE = 6 * 1024**3
MAX_KERNEL = 128 * 1024**2
MAX_INITRD = 512 * 1024**2
SHA = re.compile(r'[0-9a-f]{64}\Z')
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]{0,127}\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}\Z')
REQUIRED_PACKAGES = frozenset((
    'systemd', 'systemd-sysv', 'libsystemd-shared', 'libsystemd0',
    'python3.11', 'gcc-12', 'binutils', 'libc6-dev', 'initramfs-tools',
    'apt', 'gpgv', 'debian-archive-keyring', 'dbus', 'util-linux',
    'selinux-utils',
))


class Refusal(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(raw):
    require(type(raw) is bytes, 'build.bytes')
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    require(type(value) is str and SHA.fullmatch(value), 'build.sha256')
    return value


def path(value):
    require(type(value) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+', value), 'build.path')
    p = PurePosixPath(value)
    require(str(p) == value and '..' not in p.parts and value != '/', 'build.path')
    return value


def unique_json(raw, maximum=32768):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, 'build.json_bound')
    def pairs(rows):
        out = {}
        for key, value in rows:
            require(key not in out, 'build.duplicate_key')
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal('build.nonfinite')))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal('build.json') from exc


def package_specs(rows):
    """Only authenticated package roots supplied by the bootstrap may enter.

    This validates the closed metadata representation; it does not authenticate
    a caller's dict or solve dependencies. The actual issuer must provide the
    already verified signed-index root rows, and APT solves their dependencies.
    """
    require(type(rows) is list and 16 <= len(rows) <= 64, 'build.package_roots')
    selected = {}
    for row in rows:
        require(type(row) is dict and set(row) == {'name', 'version', 'sha256'}, 'build.package_row')
        name, version = row['name'], row['version']
        require(type(name) is str and PACKAGE.fullmatch(name) and name not in selected, 'build.package_name')
        require(type(version) is str and VERSION.fullmatch(version), 'build.package_version')
        digest(row['sha256'])
        selected[name] = version
    require(REQUIRED_PACKAGES <= selected.keys(), 'build.required_packages')
    for name in ('systemd', 'systemd-sysv', 'libsystemd-shared', 'libsystemd0'):
        require(selected[name] == SYSTEMD_VERSION, 'build.systemd_version')
    kernels = [name for name in selected if name.startswith('linux-image-6.1.')]
    require(len(kernels) == 1 and 'linux-image-amd64' not in selected, 'build.single_exact_kernel')
    return tuple(name + '=' + selected[name] for name in sorted(selected))


def recipe_files(rows, *, source_manifest_sha256, build_entry_sha256, build_stage_context_sha256):
    """Return exact project files; write/compile/install nothing."""
    specs = package_specs(rows)
    digest(source_manifest_sha256)
    digest(build_entry_sha256)
    digest(build_stage_context_sha256)
    # mkosi 20.2 discovers the exact mkosi.postinst[.chroot] files. Listing
    # them again under PostInstallationScripts runs each create-only hook twice.
    config = '''[Distribution]
Distribution=debian
Release=bookworm
Architecture=x86-64
RepositoryKeyCheck=yes
PackageManagerTrees=pkgmngr

[Output]
Format=disk
Output=ocv-test
OutputDirectory=out
CacheDirectory=cache
CompressOutput=no
RepartDirectories=repart.d
RepartOffline=yes
ManifestFormat=json

[Content]
Bootable=no
Bootloader=none
Packages={packages}
ExtraTrees=extra
CleanPackageMetadata=no
WithDocs=no
WithRecommends=no
WithNetwork=no

[Host]
Incremental=no
'''.format(packages='\n         '.join(specs))
    partition = '''[Partition]
Type=root-x86-64
Format=ext4
CopyFiles=/
SizeMinBytes=5G
SizeMaxBytes=5G
'''
    unit = '''[Unit]
Description=Public synthetic retained-verifier CI proof
After=local-fs.target dbus.service
Wants=dbus.service
Conflicts=serial-getty@ttyS0.service
Before=serial-getty@ttyS0.service

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3.11 -I -S -B /opt/ocv/source/bootstrap/guest_boot.py
StandardInput=null
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=900
RuntimeMaxSec=900
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
'''
    # The parent supplies the actual frozen build-context issuer. Verify its
    # source bytes before executing it; no JSON pass verdict grants authority.
    shim = '''#!/bin/sh
exec /usr/bin/python3.11 -I -S -B - <<'OCV_BUILD_ENTRY'
import hashlib,json,os,stat
from pathlib import Path
EXPECTED_MANIFEST = {manifest!r}
EXPECTED_ENTRY = {entry!r}
EXPECTED_CONTEXT = {context!r}
ROOT = Path('/opt/ocv/source')
def read_regular(p, cap):
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_mode & 0o222 or not 0<s.st_size<=cap:
            raise RuntimeError('build_source_identity')
        b=os.read(fd,cap+1)
        if len(b)!=s.st_size: raise RuntimeError('build_source_size')
        return b
    finally: os.close(fd)
raw=read_regular(ROOT/'PUBLIC-SOURCE-MANIFEST.json',1048576)
if hashlib.sha256(raw).hexdigest()!=EXPECTED_MANIFEST: raise RuntimeError('build_manifest_changed')
entry=read_regular(ROOT/'host/build_entry.py',1048576)
if hashlib.sha256(entry).hexdigest()!=EXPECTED_ENTRY: raise RuntimeError('build_entry_changed')
header=read_regular(Path('/opt/ocv/control/build-stage-context.json'),1048576)
if hashlib.sha256(header).hexdigest()!=EXPECTED_CONTEXT: raise RuntimeError('build_context_changed')
scope={{'__name__':'ocv_checked_build_entry','__file__':str(ROOT/'host/build_entry.py')}}
exec(compile(entry,str(ROOT/'host/build_entry.py'),'exec'),scope)
scope['invoke'](EXPECTED_MANIFEST,EXPECTED_CONTEXT)
OCV_BUILD_ENTRY
'''.format(manifest=source_manifest_sha256, entry=build_entry_sha256, context=build_stage_context_sha256)
    return {
        'mkosi.conf': (config.encode(), 0o444),
        'repart.d/10-root.conf': (partition.encode(), 0o444),
        'mkosi.postinst.chroot': (shim.encode(), 0o555),
        'extra/etc/systemd/system/ocv-ci-proof.service': (unit.encode(), 0o444),
        'extra/etc/initramfs-tools/conf.d/ocv': (b'MODULES=most\n', 0o444),
    }


def recipe_symlinks():
    return {'extra/etc/systemd/system/multi-user.target.wants/ocv-ci-proof.service':
            '../ocv-ci-proof.service'}


def _public_read(ops, filename, cap, *, immutable=False):
    before = ops.facts(filename)
    require(type(before) is dict and set(before) == {'regular','uid','gid','mode','bytes'}
            and before['regular'] is True and type(before['uid']) is int and type(before['gid']) is int
            and before['uid'] == before['gid'] == 0
            and type(before['mode']) is int and before['mode'] & 0o022 == 0
            and (not immutable or before['mode'] & 0o222 == 0)
            and type(before['bytes']) is int and 0 < before['bytes'] <= cap, 'build.public_identity')
    raw = ops.read(filename, cap)
    require(type(raw) is bytes and len(raw) == before['bytes'] and ops.facts(filename) == before,
            'build.public_changed')
    return raw


def _run_ok(value):
    require(type(value) is dict and {
        'exitCode','timedOut','captureComplete','ownedChildExited','ownershipRetained','stdout','stderr'
    } <= value.keys(), 'build.command_capture')
    require(type(value['exitCode']) is int and value['exitCode'] == 0
            and value['timedOut'] is False and value['captureComplete'] is True
            and value['ownedChildExited'] is True and value['ownershipRetained'] is False
            and type(value['stdout']) is bytes and len(value['stdout']) <= 16384
            and type(value['stderr']) is bytes and len(value['stderr']) <= 4096,
            'build.command_failed')


def run_postinstall(context, ops, compile_helper):
    """One future CI build-chroot transaction; no activation by caller JSON.

    The trusted parent host entry constructs the fixed native Ops after actual
    Linux/root/Debian/source/run/APT/tool checks. It owns command capture and
    must preserve failure evidence before propagating any Refusal. A failure
    consumes this build attempt: there is no retry or fallback in this module.
    """
    require(type(context) is dict and set(context) == {
        'schema','sourceManifestSha256','buildContextSha256','staticEntrySha256',
        'runIdentity','kernel','controlHashes','outputDirectory'}, 'build.context')
    require(context['schema'] == 'ocv-build-chroot-v1' and context['outputDirectory'] == '/work/out',
            'build.context')
    for field in ('sourceManifestSha256','buildContextSha256','staticEntrySha256'):
        digest(context[field])
    hashes = context['controlHashes']
    require(type(hashes) is dict and set(hashes) == {'runtime','tools','imports','apt'}, 'build.controls')
    control_raw = {}
    for name, expected in hashes.items():
        digest(expected)
        raw = _public_read(ops, CONTROL_ROOT + '/' + name + '.json', 8*1024**2, immutable=True)
        require(sha(raw) == expected, 'build.control_changed')
        control_raw[name] = raw
    source = _public_read(ops, SOURCE_ROOT + '/PUBLIC-SOURCE-MANIFEST.json', 1024**2, immutable=True)
    require(sha(source) == context['sourceManifestSha256'], 'build.source_manifest_changed')
    entry = _public_read(ops, SOURCE_ROOT + '/native/static_entry.c', 65536, immutable=True)
    require(sha(entry) == context['staticEntrySha256'], 'build.static_source_changed')
    kernel = context['kernel']
    require(type(kernel) is dict and set(kernel) == {
        'package','version','kernelVersion','path','sha256','bytes'}, 'build.kernel')
    kv = kernel['kernelVersion']
    require(type(kv) is str and re.fullmatch(r'6\.1\.[A-Za-z0-9.+~_-]+', kv)
            and kernel['path'] == '/boot/vmlinuz-' + kv
            and kernel['package'] == 'linux-image-' + kv
            and type(kernel['version']) is str and VERSION.fullmatch(kernel['version']), 'build.kernel')
    digest(kernel['sha256'])
    kernel_raw = _public_read(ops, kernel['path'], MAX_KERNEL)
    require(type(kernel['bytes']) is int and len(kernel_raw) == kernel['bytes']
            and sha(kernel_raw) == kernel['sha256'], 'build.kernel_changed')
    initrd_path = '/boot/initrd.img-' + kv
    try:
        ops.facts(initrd_path)
    except FileNotFoundError:
        initrd_action = '-c'
    else:
        # Signed kernel/initramfs-tools package hooks may already have made
        # this exact file. Update it normally only after a positive identity
        # check; no removal, force flag or adoption of a different target.
        _public_read(ops, initrd_path, MAX_INITRD)
        initrd_action = '-u'
    # Validate run identity by the same literal contract used at QEMU binding.
    identity = context['runIdentity']
    require(type(identity) is dict and set(identity) == {
        'repository','workflowRef','sourceCommit','runId','runAttempt'}, 'build.run_identity')
    require(identity['repository'] == 'fr-meyer/openclaw'
            and identity['workflowRef'] == 'fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites'
            and type(identity['sourceCommit']) is str and re.fullmatch(r'[0-9a-f]{40}', identity['sourceCommit'])
            and type(identity['runId']) is str and re.fullmatch(r'[1-9][0-9]{0,19}',identity['runId'])
            and identity['runAttempt']=='1' and type(identity['runAttempt']) is str, 'build.run_identity')
    cached_helper = _public_read(ops, CONTROL_ROOT + '/static-entry', 1024**2)
    # The parent compiles once before constructing runtime/import controls.
    # Its fixed callback revalidates that cached helper; a second GCC is not
    # permitted here. The argument name is retained for the agreed interface.
    helper = compile_helper(context, ops)
    require(type(helper) is dict and set(helper) == {'path','bytes','sha256'}
            and helper['path'] == CONTROL_ROOT + '/static-entry', 'build.helper')
    digest(helper['sha256'])
    helper_raw = _public_read(ops, helper['path'], 1024**2)
    require(type(helper['bytes']) is int and len(helper_raw) == helper['bytes']
            and sha(helper_raw) == helper['sha256'] and helper_raw == cached_helper, 'build.helper_changed')
    ops.chmod(helper['path'], 0o555)
    _run_ok(ops.run(('/usr/sbin/update-initramfs',initrd_action,'-k',kv), 300))
    initrd_raw = _public_read(ops, initrd_path, MAX_INITRD)
    # Recheck every input after the native work; original public bytes are not
    # rewritten. The parent must fail on any command timeout before this point.
    require(_public_read(ops, kernel['path'], MAX_KERNEL) == kernel_raw, 'build.kernel_changed')
    require(_public_read(ops, SOURCE_ROOT + '/native/static_entry.c', 65536, immutable=True) == entry,
            'build.static_source_changed')
    for name, raw in control_raw.items():
        require(_public_read(ops, CONTROL_ROOT + '/' + name + '.json', 8*1024**2, immutable=True) == raw,
                'build.control_changed')
    for name, raw in (('kernel.bin',kernel_raw), ('initrd.img',initrd_raw)):
        ops.write_once('/work/out/' + name, raw, 0o444)
    control = {
        'schema':'ocv-build-v1','sourceManifestSha256':context['sourceManifestSha256'],
        'runtimeManifestSha256':hashes['runtime'],'toolManifestSha256':hashes['tools'],
        'importManifestSha256':hashes['imports'],'aptMetadataManifestSha256':hashes['apt'],
        'helperSha256':helper['sha256'],'kernelVersion':kv,'systemdVersion':SYSTEMD_VERSION,
        'runIdentity':dict(identity),'fixtureOnly':True,'candidateImage':False,
    }
    raw = canonical(control)
    # Last control write: exact immutable bytes become the boot marker hash.
    ops.write_once(CONTROL_ROOT + '/build.json', raw, 0o444)
    ops.write_once('/work/out/build.json', raw, 0o444)
    return {'schema':'ocv-build-stage-result-v1','buildControlSha256':sha(raw),
            'kernel':{'name':'kernel.bin','bytes':len(kernel_raw),'sha256':sha(kernel_raw)},
            'initrd':{'name':'initrd.img','bytes':len(initrd_raw),'sha256':sha(initrd_raw)},
            'helper':helper,'contextSha256':context['buildContextSha256'],
            'initrdAction':initrd_action}


def mkosi_argv(project):
    project = path(project)
    # Explicitly BUILD ONLY. Parent invokes this once from a curated new tree,
    # with no ambient mkosi.local.conf/env/cache/tools or repository overrides.
    return ('/usr/bin/mkosi', '--directory=' + project, 'build')


def partition_argv(image):
    return ('/usr/sbin/sfdisk', '--json', path(image))


def root_partition(raw, image_path, image_bytes):
    value = unique_json(raw)
    require(type(value) is dict and set(value) == {'partitiontable'}, 'build.partition_wrapper')
    table = value['partitiontable']
    allowed = {'label', 'id', 'device', 'unit', 'firstlba', 'lastlba', 'sectorsize', 'partitions'}
    require(type(table) is dict and {'label', 'device', 'unit', 'sectorsize', 'partitions'} <= table.keys()
            and set(table) <= allowed, 'build.partition_fields')
    require(table['label'] == 'gpt' and table['device'] == path(image_path)
            and table['unit'] == 'sectors', 'build.partition_identity')
    sector = table['sectorsize']
    require(type(sector) is int and sector in (512, 4096) and type(image_bytes) is int
            and 2*1024**3 <= image_bytes <= MAX_IMAGE and image_bytes % sector == 0, 'build.image_size')
    rows = table['partitions']
    require(type(rows) is list and len(rows) == 1, 'build.partition_count')
    row = rows[0]
    require(type(row) is dict and {'node', 'start', 'size', 'type', 'uuid'} <= row.keys()
            and set(row) <= {'node', 'start', 'size', 'type', 'uuid', 'name', 'attrs', 'bootable'}, 'build.partition_row')
    require(row['type'] == ROOT_TYPE and row['node'] == image_path + '1'
            and row.get('attrs', '') == '' and row.get('bootable', False) is False, 'build.root_type')
    for key in ('start', 'size'):
        require(type(row[key]) is int and row[key] > 0, 'build.partition_range')
    require(row['start'] * sector >= 1024**2 and (row['start']+row['size']) * sector < image_bytes,
            'build.partition_bounds')
    try:
        partuuid = str(UUID(row['uuid']))
    except (ValueError, AttributeError, TypeError) as exc:
        raise Refusal('build.partuuid') from exc
    require(partuuid == row['uuid'] and partuuid != str(UUID(int=0)), 'build.partuuid')
    return {'partuuid': partuuid, 'type': ROOT_TYPE, 'start': row['start'], 'sectors': row['size'],
            'sectorBytes': sector, 'sfdiskSha256': sha(raw)}


def artifact_record(name, facts):
    require(name in OUTPUT_FILES and type(facts) is dict and set(facts) == {
        'bytes', 'sha256', 'regular', 'uid', 'gid', 'mode'}, 'build.artifact_record')
    cap = {'ocv-test.raw': MAX_IMAGE, 'kernel.bin': MAX_KERNEL, 'initrd.img': MAX_INITRD}[name]
    require(type(facts['bytes']) is int and 0 < facts['bytes'] <= cap and facts['regular'] is True
            and type(facts['uid']) is int and type(facts['gid']) is int
            and facts['uid'] == facts['gid'] == 0 and type(facts['mode']) is int
            and facts['mode'] in (0o400, 0o444), 'build.artifact_identity')
    digest(facts['sha256'])
    return {'name': name, 'bytes': facts['bytes'], 'sha256': facts['sha256']}


def bind_qemu_inputs(directory, artifacts, partition_json, *, source_sha256, build_sha256,
                     kernel_version, run_identity):
    """Bind actual trusted-port measurements; no caller record is authority."""
    directory = path(directory)
    require(type(artifacts) is dict and set(artifacts) == set(OUTPUT_FILES), 'build.artifact_set')
    bound = {name: artifact_record(name, artifacts[name]) for name in OUTPUT_FILES}
    digest(source_sha256); digest(build_sha256)
    require(type(kernel_version) is str and re.fullmatch(r'6\.1\.[A-Za-z0-9.+~_-]+', kernel_version), 'build.kernel_version')
    require(type(run_identity) is dict and set(run_identity) == {
        'repository', 'workflowRef', 'sourceCommit', 'runId', 'runAttempt'}, 'build.run_identity')
    require(run_identity['repository'] == 'fr-meyer/openclaw'
            and type(run_identity['workflowRef']) is str
            and run_identity['workflowRef'] == 'fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites'
            and type(run_identity['sourceCommit']) is str
            and re.fullmatch(r'[0-9a-f]{40}', run_identity['sourceCommit'])
            and type(run_identity['runId']) is str and re.fullmatch(r'[1-9][0-9]{0,19}',run_identity['runId'])
            and run_identity['runAttempt']=='1' and type(run_identity['runAttempt']) is str,
            'build.run_identity')
    root = root_partition(partition_json, directory + '/ocv-test.raw', bound['ocv-test.raw']['bytes'])
    return {'schema': 'ocv-qemu-input-v1', 'directory': directory, 'artifacts': bound,
            'rootPartition': root, 'sourceManifestSha256': source_sha256,
            'buildControlSha256': build_sha256, 'kernelVersion': kernel_version,
            'systemdVersion': SYSTEMD_VERSION, 'runIdentity': dict(run_identity),
            'fixtureOnly': True, 'candidateImage': False}


def qemu_argv(bound, session):
    require(type(bound) is dict and set(bound) == {
        'schema', 'directory', 'artifacts', 'rootPartition', 'sourceManifestSha256',
        'buildControlSha256', 'kernelVersion', 'systemdVersion', 'runIdentity',
        'fixtureOnly', 'candidateImage'}, 'build.qemu_binding')
    require(bound['schema'] == 'ocv-qemu-input-v1' and bound['systemdVersion'] == SYSTEMD_VERSION
            and bound['fixtureOnly'] is True and bound['candidateImage'] is False, 'build.qemu_binding')
    require(type(session) is str and re.fullmatch(r'[0-9a-f]{32}', session), 'build.session')
    directory = path(bound['directory'])
    digest(bound['sourceManifestSha256']); digest(bound['buildControlSha256'])
    partition = bound['rootPartition']
    require(type(partition) is dict and set(partition) == {
        'partuuid','type','start','sectors','sectorBytes','sfdiskSha256'}, 'build.root_partition')
    require(partition['type'] == ROOT_TYPE and type(partition['sectorBytes']) is int
            and partition['sectorBytes'] in (512,4096)
            and all(type(partition[k]) is int and partition[k] > 0 for k in ('start','sectors')),
            'build.root_partition')
    digest(partition['sfdiskSha256'])
    partuuid = partition['partuuid']
    try:
        valid_uuid = type(partuuid) is str and str(UUID(partuuid)) == partuuid and partuuid != str(UUID(int=0))
    except ValueError:
        valid_uuid = False
    require(valid_uuid, 'build.partuuid')
    require(set(bound['artifacts']) == set(OUTPUT_FILES), 'build.artifact_set')
    for name, rec in bound['artifacts'].items():
        require(type(rec) is dict and set(rec) == {'name', 'bytes', 'sha256'} and rec['name'] == name,
                'build.artifact_record')
        digest(rec['sha256'])
        cap = {'ocv-test.raw':MAX_IMAGE,'kernel.bin':MAX_KERNEL,'initrd.img':MAX_INITRD}[name]
        require(type(rec['bytes']) is int and 0 < rec['bytes'] <= cap, 'build.artifact_size')
    append = ('root=PARTUUID=' + partuuid + ' rootfstype=ext4 rw console=ttyS0,115200 '
              'loglevel=3 systemd.show_status=false systemd.unit=multi-user.target panic=-1 ocv.source=' + bound['sourceManifestSha256'] +
              ' ocv.build=' + bound['buildControlSha256'] + ' ocv.session=' + session)
    return ('/usr/bin/qemu-system-x86_64', '-nodefaults', '-no-user-config',
            '-machine', 'q35', '-accel', 'tcg', '-cpu', 'max', '-smp', '2', '-m', '4096',
            '-nic', 'none', '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
            '-no-reboot', '-snapshot', '-kernel', directory + '/kernel.bin', '-initrd', directory + '/initrd.img',
            '-drive', 'file=' + directory + '/ocv-test.raw,format=raw,if=virtio',
            '-append', append)


if __name__ == '__main__':
    raise SystemExit('build_native_context_unissued')
