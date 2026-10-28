"""Synthetic public representations only. No Linux/native capability is issued."""
import ast
import json
from pathlib import Path
import unittest

import ci_authority
import copied_bootstrap_probe
import integrated_entry
import integrated_fixture
import integrated_materials
import runtime_sources
from protocol import Refusal, canonical, sha

HERE=Path(__file__).resolve().parent


class FakeIO:
    evidence_kind='synthetic_contract'


class PublicContractTests(unittest.TestCase):
    def test_fixed_fixture_and_profile_are_synthetic_and_closed(self):
        root=HERE/'fixture'
        files={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}
        self.assertEqual(len(integrated_fixture.fixture_layout(files)),10)
        profile=json.loads((HERE/'PROFILE.template.private.json').read_bytes())
        self.assertEqual(set(profile),{'schema','properties','fixtureOnly','candidateImage'})
        self.assertTrue(profile['fixtureOnly']);self.assertEqual(len(profile['properties']),55)
    def test_synthetic_runtime_origin_cannot_join_native_io_or_caller_json(self):
        io=FakeIO();materials={role:role.encode() for role in runtime_sources.MATERIAL_CAPS}
        row={'path':'usr/bin/fixture','archivePath':'runtime/usr/bin/fixture',
             'bytes':1,'mode':0o555,'sha256':sha(b'x')}
        source=runtime_sources.synthetic_source(io,materials,{'files':[row]})
        source.assert_for('synthetic-contract',io)
        for kind in ('private-native','ci-native-proof'):
            with self.assertRaises(Refusal):source.assert_for(kind,io)
        with self.assertRaises(Refusal):source.assert_for('synthetic-contract',FakeIO())
        with self.assertRaises(Refusal):ci_authority.current_runtime_source({}, {}, object())
        with self.assertRaises(Refusal):runtime_sources.ci_build_source({'verified':True})
    def test_packaging_is_deterministic_and_has_no_parent_path_or_symlink_type(self):
        files={'usr/bin/a':(b'a',0o555),'lib/a':(b'b',0o444)}
        self.assertEqual(integrated_materials.archive_bytes(files),
            integrated_materials.archive_bytes(dict(reversed(list(files.items())))))
        with self.assertRaises(integrated_materials.Refusal):
            integrated_materials.archive_bytes({'usr/../a':(b'x',0o444)})
    def test_absolute_budget_retains_bounded_shutdown_and_no_clock_renewal(self):
        value=integrated_fixture.timing_preflight()
        self.assertEqual((value['jobSeconds'],value['plannedSeconds']),(2700,2670))
        self.assertEqual(value['guestWrapperSeconds'],2000)
        self.assertEqual(value['workerSeconds'],300)
    def test_probe_source_measures_children_and_never_mutates_search_path(self):
        source=Path(copied_bootstrap_probe.__file__).read_bytes()
        ast.parse(source)
        self.assertIn(b'bool(children.strip())',source)
        self.assertIn(b"'/proc/self/task/'",source)
        self.assertNotIn(b'sys.path.insert',source)
# Source-owned device appearance contracts.
"""Pure actual readiness-loop contracts. No Linux device is read or created."""
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

import ci_authority as target
from protocol import Refusal


class Clock:
    def __init__(self):self.clock=10.;self.checks=0;self.pauses=[];self.observed=[];self.missing=2;self.owner=0;self.kind=stat.S_IFLNK;self.target_kind=stat.S_IFBLK;self.target_group=6
    def check(self):self.checks+=1
    def now(self):return self.clock
    def pause(self,seconds):self.pauses.append(seconds);self.clock+=seconds
    def lstat(self,path):
        self.observed.append(path)
        if self.missing and path==target._device_appearance_paths()[0]:
            self.missing-=1;raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=self.kind|0o777,st_uid=self.owner,st_gid=0)
    def stat(self,path):return SimpleNamespace(st_mode=self.target_kind|0o660,st_uid=0,st_gid=self.target_group)


class DeviceReadinessTests(unittest.TestCase):
    def run_loop(self,clock,*,paths=None,deadline=40.):
        return target._poll_device_appearance(target._device_appearance_paths() if paths is None else paths,
            check=clock.check,now=clock.now,lstat=clock.lstat,stat_follow=clock.stat,pause=clock.pause,
            begin=10.,deadline=deadline)
    def test_delayed_fixed_aliases_yield_only_appearance_receipt(self):
        clock=Clock();result=self.run_loop(clock)
        self.assertTrue(result['appearanceOnly']);self.assertFalse(result['identityValidated'])
        self.assertEqual(result['attempts'],3);self.assertEqual(clock.checks,4)
        self.assertTrue(set(clock.observed)<=set(target._device_appearance_paths()))
        self.assertLessEqual(sum(clock.pauses),30)
    def test_absent_devices_stop_on_original_deadline_without_renewal(self):
        clock=Clock();clock.missing=1000
        with self.assertRaises(Refusal):self.run_loop(clock)
        self.assertLessEqual(clock.clock,40.000001);self.assertLessEqual(len(clock.pauses),301)
    def test_unexpected_alias_owner_or_type_refuses_immediately(self):
        for field,value in (('owner',1000),('kind',stat.S_IFREG),('target_kind',stat.S_IFREG),('target_group',1000)):
            clock=Clock();clock.missing=0;setattr(clock,field,value)
            with self.subTest(field=field),self.assertRaises(Refusal):self.run_loop(clock)
            self.assertEqual(clock.pauses,[])
    def test_other_os_errors_are_not_retried(self):
        clock=Clock();clock.missing=0
        def denied(_):raise PermissionError(13,'unpublished metadata error')
        clock.lstat=denied
        with self.assertRaises(PermissionError):self.run_loop(clock)
        self.assertEqual(clock.pauses,[])
    def test_parent_check_failure_stops_before_device_metadata(self):
        clock=Clock()
        def refuse():raise Refusal('test.parent_expired')
        clock.check=refuse
        with self.assertRaisesRegex(Refusal,'test.parent_expired'):self.run_loop(clock)
        self.assertEqual(clock.observed,[]);self.assertEqual(clock.pauses,[])
    def test_clock_regression_or_more_than_thirty_seconds_refuses(self):
        clock=Clock();clock.clock=9.
        with self.assertRaises(Refusal):self.run_loop(clock)
        for end in (10.,40.001,float('inf')):
            with self.subTest(end=end),self.assertRaises(Refusal):self.run_loop(Clock(),deadline=end)
    def test_substituted_path_or_duplicate_fixed_alias_never_reaches_metadata(self):
        for paths in (('/dev/other',)+target._device_appearance_paths()[1:],
                      (target._device_appearance_paths()[0],)*3):
            clock=Clock()
            with self.subTest(paths=paths),self.assertRaises(Refusal):self.run_loop(clock,paths=paths)
            self.assertEqual(clock.observed,[]);self.assertEqual(clock.pauses,[])
    def test_native_wrapper_refuses_json_before_stat_or_sleep(self):
        with mock.patch.object(target.os,'lstat',side_effect=AssertionError('device read')),\
             mock.patch.object(target.time,'sleep',side_effect=AssertionError('sleep')):
            with self.assertRaises(Refusal):target.wait_for_device_appearance({'verified':True},{})


if __name__=='__main__':unittest.main()
