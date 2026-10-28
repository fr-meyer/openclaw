"""Pure public fixture/build specifications for the integrated Linux proof.

No image, filesystem, process or guest is created here. The authenticated host
and bootstrap issuers must execute the reviewed specifications and retain the
actual package, file, device and process evidence separately.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
import struct
from uuid import UUID

VM_ID = '1'
DISK_IDS = ('11', '12')
BOOT_SERIAL = 'ocv-integ-boot'
TEST_SERIAL = 'ocv-integ-test'
BOOT_DEVICE_ALIAS = '/dev/disk/by-id/virtio-' + BOOT_SERIAL
BOOT_ABSENT_ALIAS = BOOT_DEVICE_ALIAS + '-absent'
TEST_DISK_ALIAS = '/dev/disk/by-id/virtio-' + TEST_SERIAL
TEST_PARTITION_ALIAS = TEST_DISK_ALIAS + '-part1'
TEST_PARTITION_NUMBER = 1
TEST_PARTITION_REQUIRED = True
# Historical fixture API means the whole device. Exported storage uses the
# explicit TEST_PARTITION_ALIAS; its parent uses TEST_DISK_ALIAS.
TEST_DEVICE_ALIAS = TEST_DISK_ALIAS
TEST_UUID = '56b32afd-9976-4d21-9720-c4d5fcd02751'
RETAINED_RELATIVE = 'retained'
REPORT_RELATIVE = 'report/privacy.json'
OCI_RELATIVE = 'oci/default'
TEST_IMAGE_NAME = 'integrated-test.raw'
TEST_IMAGE_BYTES = 64 * 1024 * 1024
TEST_SECTOR_BYTES = 512
TEST_PARTITION_OFFSET_BYTES = 1024 * 1024
TEST_FILESYSTEM_BYTES = TEST_IMAGE_BYTES - TEST_PARTITION_OFFSET_BYTES
TEST_FILESYSTEM_BLOCK_BYTES = 4096
TEST_DISK_SIGNATURE = 0x4f435654
FIXTURE_CAP = 2 * 1024 * 1024
FIXTURE_FILE_CAP = 262144
FIXTURE_SOURCE = '8770609a78d68f6b53607ce3199baf0aa08687cf'
FIXTURE_SCANNER = 'd658c890f5684b2dbe8468449a7fed17bb46055d'
FIXTURE_INDEX = 'sha256:2577bfdfb50ee4411f69b90bf8b4347b8e476c2bc82bb982005515c46ebe59cc'
FIXTURE_INDEX_FILE_SHA256 = '3fb354bf1e587fdd022abffda59ae8492e73aef1af375e4f7c940d308de5fad8'
FIXTURE_LAYOUT_SHA256 = '18f0797eab35a4597c1e9624aa4f15fd91f6254e5538c1e0d193b2a95dd4acc6'
FIXTURE_BLOBS = frozenset((
    '2577bfdfb50ee4411f69b90bf8b4347b8e476c2bc82bb982005515c46ebe59cc',
    '7ff79d956bc21da41ea2bf9a98b76301959ff249baf954e3f2a0699e6eaed86b',
    'db33411d1d74ffa375a5121ff8bcd2f9581be9af36d8ebdb06127ae1c274157b',
    '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    '04fef0965d3483a2d8e607d9da2a5730f513ce20351c97f54d69b815976b4335',
    'c2eacf0c1d636634540cb06193d367398ebf03b5182d714d8a28e2557c4f162d',
    '17b5d9cc27bc558753e683cd8ae8fe033327a6b891ad6f6c66ecd2f9d0d6394f'))
FIXTURE_REPORT_SHA256 = '0c2019ff9bd14f93681037d9961ac4c80a14600ef0fe0a99a5065a8aedc5b813'
EXTRA_PACKAGE_ROOTS = frozenset(('mount', 'util-linux', 'e2fsprogs', 'udev', 'git'))
STORAGE_TOOL_SPECS = {
    'mount': {'path': '/usr/bin/mount', 'package': 'mount', 'packagePath': '/bin/mount'},
    'umount': {'path': '/usr/bin/umount', 'package': 'mount', 'packagePath': '/bin/umount'},
    'findmnt': {'path': '/usr/bin/findmnt', 'package': 'util-linux', 'packagePath': '/bin/findmnt'},
    'blkid': {'path': '/usr/sbin/blkid', 'package': 'util-linux', 'packagePath': '/sbin/blkid'},
}
EXTRA_TOOL_SPECS = dict(STORAGE_TOOL_SPECS,
    git={'path': '/usr/bin/git', 'package': 'git', 'packagePath': '/usr/bin/git'})
HOST_IMAGE_TOOL = {'role': 'mke2fs', 'path': '/usr/sbin/mke2fs',
                   'package': 'e2fsprogs', 'packagePath': '/sbin/mke2fs'}
CATALOG_ROW_KEYS = frozenset(('role', 'path', 'bytes', 'sha256', 'package', 'version', 'debSha256'))
ALIAS_KEYS = frozenset(('role', 'executionPath', 'packagePath', 'canonicalPath', 'dev', 'ino',
    'executionAliasProofSha256', 'packageAliasProofSha256', 'ownerQuerySha256'))
PHASE_SECONDS = {'source-tests': 60, 'host-admission': 360, 'metadata':270,
    'negative-build': 30, 'positive-build': 400, 'guest': 2000, 'artifact': 120}
JOB_SECONDS = 2700
PRE_QEMU_RESERVE_SECONDS = 2150
PRE_GUEST_POOL_SECONDS = JOB_SECONDS - PRE_QEMU_RESERVE_SECONDS
SHUTDOWN_RESERVE_SECONDS = 30
GUEST_WRAPPER_SECONDS = 2000
GUEST_UNIT_WORKER_SECONDS = 300


class Refusal(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    need(type(raw) is bytes, 'integrated_fixture.bytes')
    return hashlib.sha256(raw).hexdigest()


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _relative(value):
    need(type(value) is str and 0 < len(value) <= 256 and
         re.fullmatch('[A-Za-z0-9_./+-]+', value) and not value.startswith('/') and
         str(PurePosixPath(value)) == value and
         not {'.', '..'} & set(PurePosixPath(value).parts), 'integrated_fixture.path')
    return value


def fixture_layout(files):
    """Return the exact synthetic TEST seed; never accept a private fixture."""
    need(type(files) is dict and set(files) ==
         {'privacy.json', 'oci/index.json', 'oci/oci-layout'} |
         {'oci/blobs/sha256/'+digest for digest in FIXTURE_BLOBS},
         'integrated_fixture.roster')
    total, result = 0, {}
    for name, raw in files.items():
        _relative(name)
        need(name in ('privacy.json', 'oci/index.json', 'oci/oci-layout') or
             re.fullmatch('oci/blobs/sha256/[0-9a-f]{64}', name),
             'integrated_fixture.member')
        need(type(raw) is bytes and 0 < len(raw) <= FIXTURE_FILE_CAP,
             'integrated_fixture.file_cap')
        total += len(raw); need(total <= FIXTURE_CAP, 'integrated_fixture.total_cap')
        if name.startswith('oci/blobs/sha256/'):
            need(sha(raw) == name.rsplit('/', 1)[1], 'integrated_fixture.blob_digest')
        target = RETAINED_RELATIVE + '/' + (REPORT_RELATIVE if name == 'privacy.json'
                                           else OCI_RELATIVE + '/' + name[4:])
        result[target] = (raw, 0o444)
    report = files['privacy.json']
    need(sha(report) == FIXTURE_REPORT_SHA256 and
         sha(files['oci/index.json']) == FIXTURE_INDEX_FILE_SHA256 and
         sha(files['oci/oci-layout']) == FIXTURE_LAYOUT_SHA256 and
         'oci/blobs/sha256/'+FIXTURE_INDEX.split(':')[1] in files,
         'integrated_fixture.source_pin')
    doc = json.loads(report)
    need(type(doc) is dict and doc.get('sourceSha') == FIXTURE_SOURCE and
         doc.get('toolingSha') == FIXTURE_SCANNER and doc.get('status') == 'passed' and
         doc.get('indexDigest') == FIXTURE_INDEX and doc.get('inspectionComplete') is True,
         'integrated_fixture.receipt_origin')
    return result


def project_path(mission):
    """One pure public-CI project grammar; this does not issue host authority."""
    need(type(mission) is str and re.fullmatch('[0-9a-f]{32}', mission),
         'integrated_fixture.mission')
    return '/tmp/ocv-' + mission


def _project_leaf(path, leaf):
    need(type(path) is str and str(PurePosixPath(path)) == path and
         '..' not in PurePosixPath(path).parts,
         'integrated_fixture.project_path')
    parts = PurePosixPath(path).parts
    need(len(parts) == 4 and parts[:2] == ('/', 'tmp') and
         re.fullmatch('ocv-[0-9a-f]{32}', parts[2]) and parts[3] == leaf and
         str(PurePosixPath(path).parent) == project_path(parts[2][4:]),
         'integrated_fixture.project_path')
    return str(PurePosixPath(path).parent)


def image_argv(seed_root, output):
    """Fixed Linux-CI mke2fs vector; caller must authenticate and own its child."""
    project = _project_leaf(seed_root, 'integrated-seed')
    need(output == project + '/out/' + TEST_IMAGE_NAME,
         'integrated_fixture.image_path')
    return (HOST_IMAGE_TOOL['path'], '-q', '-F', '-t', 'ext4', '-b', '4096',
            '-U', TEST_UUID, '-L', 'OCV-SYNTHETIC',
            '-E', 'offset='+str(TEST_PARTITION_OFFSET_BYTES)+',lazy_itable_init=0,lazy_journal_init=0',
            '-d', seed_root, output,
            str(TEST_FILESYSTEM_BYTES // TEST_FILESYSTEM_BLOCK_BYTES))


def test_image_header():
    """Deterministic DOS/MBR partition1; no image or filesystem is created.

    Linux v6.1 include/linux/msdos_partition.h and block/partitions/msdos.c
    define the little-endian start/count fields, type0x83 and0xaa55 magic.
    """
    need(TEST_IMAGE_BYTES % TEST_SECTOR_BYTES == 0 and
         TEST_PARTITION_OFFSET_BYTES % TEST_SECTOR_BYTES == 0 and
         TEST_FILESYSTEM_BYTES % TEST_FILESYSTEM_BLOCK_BYTES == 0,
         'integrated_fixture.partition_alignment')
    raw = bytearray(TEST_SECTOR_BYTES)
    struct.pack_into('<I', raw, 440, TEST_DISK_SIGNATURE)
    struct.pack_into('<B3sB3sII', raw, 446, 0, b'\xfe\xff\xff', 0x83,
        b'\xfe\xff\xff', TEST_PARTITION_OFFSET_BYTES // TEST_SECTOR_BYTES,
        TEST_FILESYSTEM_BYTES // TEST_SECTOR_BYTES)
    raw[510:512] = b'\x55\xaa'
    return bytes(raw)


def initialized_test_image_sha256():
    """Hash the fixed sparse initialization without creating image bytes/files."""
    digest = hashlib.sha256(test_image_header())
    remaining = TEST_IMAGE_BYTES - TEST_SECTOR_BYTES
    block = b'\0' * (1024 * 1024)
    while remaining:
        amount = min(len(block), remaining)
        digest.update(block[:amount]); remaining -= amount
    return digest.hexdigest()


def validate_partitioned_image(prefix, superblock, total_bytes):
    """Check actual fixed image regions; kernel device ancestry remains live.

    ext4 field offsets: https://docs.kernel.org/filesystems/ext4/super.html
    These binary/UUID checks are not a mount, fsck or runtime qualification.
    """
    need(type(total_bytes) is int and total_bytes == TEST_IMAGE_BYTES and
         type(prefix) is bytes and len(prefix) == TEST_PARTITION_OFFSET_BYTES and
         prefix[:TEST_SECTOR_BYTES] == test_image_header() and
         not any(prefix[TEST_SECTOR_BYTES:]), 'integrated_fixture.partition_header')
    need(type(superblock) is bytes and len(superblock) == 1024,
         'integrated_fixture.partition_superblock')
    blocks = struct.unpack_from('<I', superblock, 4)[0] | \
             (struct.unpack_from('<I', superblock, 0x150)[0] << 32)
    need(struct.unpack_from('<H', superblock, 0x38)[0] == 0xef53 and
         struct.unpack_from('<I', superblock, 0x14)[0] == 0 and
         struct.unpack_from('<I', superblock, 0x18)[0] == 2 and
         blocks * TEST_FILESYSTEM_BLOCK_BYTES == TEST_FILESYSTEM_BYTES and
         superblock[0x68:0x78] == UUID(TEST_UUID).bytes,
         'integrated_fixture.partition_filesystem')
    return {'schema':'ocv.partitioned-test-image-checked.v1','partitionNumber':1,
        'diskBytes':TEST_IMAGE_BYTES,'partitionOffsetBytes':TEST_PARTITION_OFFSET_BYTES,
        'filesystemBytes':TEST_FILESYSTEM_BYTES,'filesystemUUID':TEST_UUID,
        'wholeDeviceAlias':TEST_DISK_ALIAS,'partitionDeviceAlias':TEST_PARTITION_ALIAS,
        'nativeAuthority':False}


def validate_test_image(raw):
    need(type(raw) is bytes and len(raw) == TEST_IMAGE_BYTES,
         'integrated_fixture.partition_image_size')
    start = TEST_PARTITION_OFFSET_BYTES + 1024
    return validate_partitioned_image(raw[:TEST_PARTITION_OFFSET_BYTES],
                                      raw[start:start+1024], len(raw))


def qemu_argv(base_argv, *, directory, test_record):
    """Add distinct, real virtio BOOT/readonly TEST devices to a checked vector."""
    need(type(base_argv) in (list, tuple) and all(type(v) is str for v in base_argv) and
         base_argv[:1] in (['/usr/bin/qemu-system-x86_64'], ('/usr/bin/qemu-system-x86_64',)),
         'integrated_fixture.qemu_vector')
    _project_leaf(directory, 'out')
    need(type(test_record) is dict and set(test_record) == {'name', 'bytes', 'sha256'} and
         test_record['name'] == TEST_IMAGE_NAME and test_record['bytes'] == TEST_IMAGE_BYTES and
         _hex(test_record['sha256']), 'integrated_fixture.test_record')
    argv = list(base_argv)
    need(argv.count('-drive') == 1 and argv.count('-nic') == 1 and
         argv[argv.index('-nic') + 1] == 'none' and argv.count('-snapshot') == 1 and
         argv.count('-serial') == 1 and argv[argv.index('-serial') + 1] == 'stdio',
         'integrated_fixture.qemu_guards')
    index = argv.index('-drive')
    need(argv[index + 1] == 'file=' + directory + '/ocv-test.raw,format=raw,if=virtio',
         'integrated_fixture.boot_drive')
    argv[index:index+2] = ['-drive', 'file=' + directory + '/ocv-test.raw,format=raw,if=none,id=ocvboot',
        '-device', 'virtio-blk-pci,drive=ocvboot,serial=' + BOOT_SERIAL,
        '-drive', 'file=' + directory + '/' + TEST_IMAGE_NAME + ',format=raw,if=none,id=ocvtest,readonly=on',
        '-device', 'virtio-blk-pci,drive=ocvtest,serial=' + TEST_SERIAL]
    return tuple(argv)


def validate_tool_catalog(catalog, package_rows, aliases):
    """Pure preflight of actual build evidence, not an authenticity issuer.

    `package_rows` must originate from the authenticated index/Prepared chain.
    This function never turns independently supplied JSON into native authority.
    Both fixed /usr execution names and Debian-owned merged-/usr aliases remain.
    """
    need(type(catalog) is dict and set(catalog) == {'schema', 'tools'} and
         catalog['schema'] == 'ocv-tools-v1' and type(catalog['tools']) is list and
         type(package_rows) is list and type(aliases) is list,
         'integrated_fixture.catalog_schema')
    indexed = {}
    for row in package_rows:
        need(type(row) is dict and set(row) == {'name', 'version', 'architecture', 'debSha256'} and
             row['architecture'] in ('amd64', 'all') and _hex(row['debSha256']) and
             row['name'] not in indexed, 'integrated_fixture.package_row')
        indexed[row['name']] = row
    tools = {}
    for row in catalog['tools']:
        need(type(row) is dict and set(row) == CATALOG_ROW_KEYS and
             type(row['role']) is str and row['role'] not in tools and
             type(row['bytes']) is int and 0 < row['bytes'] <= 64*1024*1024 and
             _hex(row['sha256']) and _hex(row['debSha256']), 'integrated_fixture.tool_row')
        tools[row['role']] = row
    need(set(EXTRA_TOOL_SPECS) <= set(tools), 'integrated_fixture.tools_missing')
    for role, spec in EXTRA_TOOL_SPECS.items():
        row = tools[role]; package = indexed.get(spec['package'])
        need(row['path'] == spec['path'] and row['package'] == spec['package'] and
             package is not None and row['version'] == package['version'] and
             row['debSha256'] == package['debSha256'], 'integrated_fixture.tool_package_join')
        proofs = [a for a in aliases if type(a) is dict and a.get('role') == role]
        need(len(proofs) == 1, 'integrated_fixture.alias_missing')
        proof = proofs[0]
        need(set(proof) == ALIAS_KEYS and proof['executionPath'] == spec['path'] and
             proof['packagePath'] in (spec['path'], spec['packagePath']) and
             proof['canonicalPath'] == spec['path'] and type(proof['dev']) is int and
             proof['dev'] > 0 and type(proof['ino']) is int and proof['ino'] > 0 and
             all(_hex(proof[k]) for k in ('executionAliasProofSha256',
                 'packageAliasProofSha256', 'ownerQuerySha256')),
             'integrated_fixture.alias_join')
    return {'schema': 'ocv.integrated-tool-preflight.v1', 'authenticationPerformedHere': False,
            'nativeAuthority': False, 'toolRoles': sorted(EXTRA_TOOL_SPECS)}


def timing_preflight(phase_seconds=None):
    """Pure conditional ceilings; no native admission or independent clocks.

    All pre-guest phases share the original job's first550 seconds. Their
   1120-second ceiling sum is deliberately not a simultaneous allocation:
    unused time is pooled, and later phases refuse when that pool is spent.
    """
    phases = dict(PHASE_SECONDS if phase_seconds is None else phase_seconds)
    need(set(phases) == set(PHASE_SECONDS) and all(type(v) is int and v > 0 for v in phases.values()),
         'integrated_fixture.phase_budget')
    need(all(phases[name] <= ceiling for name,ceiling in PHASE_SECONDS.items()),
         'integrated_fixture.phase_ceiling')
    total = PRE_GUEST_POOL_SECONDS + phases['guest'] + phases['artifact'] + SHUTDOWN_RESERVE_SECONDS
    need(total == JOB_SECONDS and phases['guest'] == GUEST_WRAPPER_SECONDS and
         phases['artifact'] >= 120 and GUEST_UNIT_WORKER_SECONDS == 300,
         'integrated_fixture.whole_budget')
    return {'jobSeconds': JOB_SECONDS, 'plannedSeconds': total,
            'unallocatedSeconds': JOB_SECONDS-total, 'guestWrapperSeconds': GUEST_WRAPPER_SECONDS,
            'workerSeconds': GUEST_UNIT_WORKER_SECONDS, 'phaseSeconds': phases,
            'phaseCeilingsConditional':True,'preGuestPoolSeconds':PRE_GUEST_POOL_SECONDS,
            'preQemuReserveSeconds':PRE_QEMU_RESERVE_SECONDS,
            'shutdownReserveSeconds':SHUTDOWN_RESERVE_SECONDS,
            'preGuestPhaseNames':['source-tests','host-admission','metadata','negative-build','positive-build'],
            'conditionalPhaseSecondsSum':sum(phases.values()),
            'allConditionalPhaseMaximaFit':sum(phases.values())+SHUTDOWN_RESERVE_SECONDS<=JOB_SECONDS,
            'successGuaranteed':False,
            'nativeAuthority':False}


if __name__ == '__main__':
    raise SystemExit('integrated_fixture_no_native_cli')
