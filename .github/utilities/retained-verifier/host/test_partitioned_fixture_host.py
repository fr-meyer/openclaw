"""Pure partition/factory checks; never creates an image or native permit."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from types import SimpleNamespace
from unittest import mock
from uuid import UUID

HERE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixture_path = HERE/'integrated_fixture.py'
if not fixture_path.is_file():
    fixture_path = HERE/'integrated/integrated_fixture.py'
fixture = load('partitioned_fixture_draft', fixture_path)
context = load('partitioned_host_context_draft', HERE/'host/host_context.py')
ci_host = load('partitioned_ci_host_draft', HERE/'host/ci_host.py')
PROJECT = '/tmp/ocv-'+'a'*32


def metadata():
    """Independent fixed wire vector, not an ext4 image or Linux proof."""
    prefix = bytearray(1048576)
    struct.pack_into('<I', prefix, 440, 0x4f435654)
    struct.pack_into('<B3sB3sII', prefix, 446, 0, b'\xfe\xff\xff', 0x83,
                     b'\xfe\xff\xff', 2048, 129024)
    prefix[510:512] = b'\x55\xaa'
    superblock = bytearray(1024)
    struct.pack_into('<I', superblock, 4, 16128)
    struct.pack_into('<I', superblock, 0x18, 2)
    struct.pack_into('<H', superblock, 0x38, 0xef53)
    superblock[0x68:0x78] = UUID('56b32afd-9976-4d21-9720-c4d5fcd02751').bytes
    return prefix, superblock


class PartitionedFixtureHostTests(unittest.TestCase):
    def test_exact_partition_geometry_and_distinct_aliases(self):
        prefix, _ = metadata()
        header = fixture.test_image_header()
        self.assertEqual(header, bytes(prefix[:512]))
        entry = struct.unpack_from('<B3sB3sII', header, 446)
        self.assertEqual((entry[0], entry[2], entry[4], entry[5]), (0, 0x83, 2048, 129024))
        self.assertEqual((entry[4]+entry[5])*512, 64*1024*1024)
        self.assertEqual(header[462:510], b'\0'*48)
        self.assertEqual(fixture.TEST_PARTITION_NUMBER, 1)
        self.assertIs(fixture.TEST_PARTITION_REQUIRED, True)
        self.assertEqual(fixture.TEST_DEVICE_ALIAS, fixture.TEST_DISK_ALIAS)
        self.assertEqual(fixture.TEST_PARTITION_ALIAS, fixture.TEST_DISK_ALIAS+'-part1')
        self.assertEqual(fixture.BOOT_ABSENT_ALIAS, fixture.BOOT_DEVICE_ALIAS+'-absent')

    def test_actual_region_contract_accepts_fixed_partition_metadata(self):
        prefix, sb = metadata()
        checked = fixture.validate_partitioned_image(bytes(prefix), bytes(sb), 67108864)
        self.assertEqual(checked['partitionOffsetBytes'], 1048576)
        self.assertEqual(checked['filesystemBytes'], 66060288)
        self.assertEqual(checked['partitionDeviceAlias'], fixture.TEST_PARTITION_ALIAS)
        self.assertIs(checked['nativeAuthority'], False)

    def test_partition_header_wrong_geometry_extra_slot_gap_and_magic_refuse(self):
        prefix, sb = metadata()
        for index in (440, 446, 450, 454, 458, 462, 510, 512, 1024):
            bad = bytearray(prefix); bad[index] ^= 1
            with self.subTest(index=index), self.assertRaisesRegex(fixture.Refusal, 'partition_header'):
                fixture.validate_partitioned_image(bytes(bad), bytes(sb), 67108864)
        for size in (True, 67108863, 67108865, 64.0):
            with self.subTest(size=size), self.assertRaisesRegex(fixture.Refusal, 'partition_header'):
                fixture.validate_partitioned_image(bytes(prefix), bytes(sb), size)
        for bad in (bytes(prefix[:-1]), prefix):
            with self.assertRaisesRegex(fixture.Refusal, 'partition_header'):
                fixture.validate_partitioned_image(bad, bytes(sb), 67108864)

    def test_wrong_uuid_superblock_blocksize_count_and_highbits_refuse(self):
        prefix, sb = metadata()
        for index in (4, 0x14, 0x18, 0x38, 0x68, 0x150):
            bad = bytearray(sb); bad[index] ^= 1
            with self.subTest(index=index), self.assertRaisesRegex(fixture.Refusal, 'partition_filesystem'):
                fixture.validate_partitioned_image(bytes(prefix), bytes(bad), 67108864)
        for bad in (bytes(sb[:-1]), sb):
            with self.assertRaisesRegex(fixture.Refusal, 'partition_superblock'):
                fixture.validate_partitioned_image(bytes(prefix), bad, 67108864)
        with self.assertRaisesRegex(fixture.Refusal, 'partition_image_size'):
            fixture.validate_test_image(b'not-an-image')

    def test_fixed_initialization_hash_without_constructing_image(self):
        prefix, _ = metadata()
        digest = hashlib.sha256(bytes(prefix[:512]))
        zero = b'\0'*65536
        for _ in range(1023):
            digest.update(zero)
        digest.update(b'\0'*65024)
        self.assertEqual(fixture.initialized_test_image_sha256(), digest.hexdigest())

    def test_exact_authenticated_mke2fs_vector_and_existing_tool_roster(self):
        argv = fixture.image_argv(PROJECT+'/integrated-seed', PROJECT+'/out/integrated-test.raw')
        self.assertEqual(argv, ('/usr/sbin/mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096',
            '-U', fixture.TEST_UUID, '-L', 'OCV-SYNTHETIC', '-E',
            'offset=1048576,lazy_itable_init=0,lazy_journal_init=0', '-d',
            PROJECT+'/integrated-seed', PROJECT+'/out/integrated-test.raw', '16128'))
        self.assertEqual(context.ROLE_MAP['integrated_test_image'],
                         ('integrated/integrated_fixture.py', 'image_argv'))
        self.assertIn(argv[0], context.PROGRAMS)
        self.assertEqual(context.PROGRAMS, {'/usr/bin/git', '/usr/bin/sudo', '/usr/bin/mkosi',
            '/usr/bin/curl', '/usr/bin/gpgv', '/usr/bin/dpkg-query', '/usr/bin/python3',
            '/usr/sbin/sfdisk', '/usr/bin/qemu-system-x86_64', '/usr/sbin/mke2fs'})
        for seed, output in ((PROJECT+'/wrong', PROJECT+'/out/integrated-test.raw'),
            (PROJECT+'/integrated-seed', '/tmp/elsewhere.raw'),
            ('/tmp/ocv-'+'b'*32+'/integrated-seed', PROJECT+'/out/integrated-test.raw')):
            with self.assertRaises(fixture.Refusal):
                fixture.image_argv(seed, output)

    def test_qemu_readonly_test_raw_and_network_guards_are_preserved(self):
        base = ('/usr/bin/qemu-system-x86_64', '-drive',
            'file='+PROJECT+'/out/ocv-test.raw,format=raw,if=virtio',
            '-nic', 'none', '-snapshot', '-serial', 'stdio')
        record = {'name':'integrated-test.raw', 'bytes':67108864, 'sha256':'a'*64}
        argv = fixture.qemu_argv(base, directory=PROJECT+'/out', test_record=record)
        self.assertIn('file='+PROJECT+'/out/integrated-test.raw,format=raw,if=none,id=ocvtest,readonly=on', argv)
        self.assertIn('virtio-blk-pci,drive=ocvtest,serial=ocv-integ-test', argv)
        self.assertEqual(argv[argv.index('-nic')+1], 'none')
        self.assertEqual(argv.count('-snapshot'), 1)
        self.assertNotIn('ocv-integ-boot-absent', ' '.join(argv))
        with self.assertRaisesRegex(fixture.Refusal, 'qemu_guards'):
            fixture.qemu_argv(tuple('user' if item=='none' else item for item in base),
                              directory=PROJECT+'/out', test_record=record)

    def test_unissued_factory_call_refuses_before_any_io(self):
        # No NativePermit construction or OS monkeypatch; _permit is the first statement.
        with self.assertRaisesRegex(context.Refusal, 'host.permit_unissued'):
            context.initialize_integrated_test_image(object(), PROJECT)
        tree = ast.parse((HERE/'host/host_context.py').read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name=='initialize_integrated_test_image')
        first = function.body[1]
        self.assertIsInstance(first, ast.Assign)
        self.assertEqual(ast.unparse(first.value), '_permit(permit)')

    def test_slow_sealing_cannot_extend_absolute_phase_or_job_budget(self):
        for whole, phase, timeout, wanted in ((200, 50, 100, 50), (70, 100, 100, 40), (200, 100, 5, 25)):
            calls = []
            port = object.__new__(ci_host.NativePort)
            scope = SimpleNamespace(argv=('/synthetic/command',))
            result = {'status':'outer_exit_passed','stdout':b'','stderr':b''}
            ctx = SimpleNamespace(ENV={}, seal_command=lambda *a,**k:scope,
                run_owned=lambda *a,**k:(calls.append(k['deadline']) or result))
            port.m = SimpleNamespace(context=ctx); port.permit = object()
            port.project = Path('/synthetic'); port.deadline = whole; port.phase_deadline = phase
            port.commands = []
            with mock.patch.object(ci_host.time, 'monotonic', side_effect=(1, 1, 20)):
                self.assertIs(port._run('synthetic', {}, timeout), result)
            self.assertEqual(calls, [wanted])

    def test_sealing_exhaustion_refuses_before_owned_execution(self):
        for whole, phase, code in ((50, 100, 'whole_deadline'), (200, 20, 'phase_deadline')):
            port = object.__new__(ci_host.NativePort)
            ctx = SimpleNamespace(ENV={}, seal_command=lambda *a,**k:object(),
                run_owned=lambda *a,**k:self.fail('expired command must not execute'))
            port.m = SimpleNamespace(context=ctx); port.permit = object()
            port.project = Path('/synthetic'); port.deadline = whole; port.phase_deadline = phase
            with mock.patch.object(ci_host.time, 'monotonic', side_effect=(1, 1, 20)):
                with self.assertRaisesRegex(ci_host.Refusal, code):
                    port._run('synthetic', {}, 100)


if __name__=='__main__':
    unittest.main()
