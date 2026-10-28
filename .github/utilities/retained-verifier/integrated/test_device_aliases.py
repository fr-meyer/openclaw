"""Generic inert metadata guards; real devices remain a separate Linux proof."""
from contextlib import ExitStack
import copy
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import guest_storage as target
from protocol import Refusal


def ancestry(number,whole,partition):
    return {'majorMinor':number,'wholeMajorMinor':whole,'isPartition':partition}


class SharedDeviceAliasTests(unittest.TestCase):
    def select(self,present,wrong=None,dangling=None):
        io=target.NativeStorageIO();io._root_chain=Mock()
        def device(name):
            if name==dangling:raise FileNotFoundError('inert present dangling target')
            return '8:32' if name==wrong else '8:0'
        io._device=Mock(side_effect=device)
        io._block_ancestry=Mock(side_effect=lambda n:ancestry(n,n,False))
        def lstat(path):
            if str(path)not in present:raise FileNotFoundError('inert true absence')
            return SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0,st_gid=0,st_nlink=1)
        with patch.object(Path,'lstat',autospec=True,side_effect=lstat):return io._boot_aliases('8:0')
    def test_actual_source_policy_requires_real_partition_without_projection_bypass(self):
        self.assertIs(target.TEST_PARTITION_REQUIRED,True)
        self.assertEqual(len(target.BOOT_DEVICE_ALIASES),2)
        self.assertNotEqual(target.TEST_DEVICE_ALIAS,target.TEST_DISK_ALIAS)
    def test_skip_absent_first_candidate_and_keep_actual_candidate(self):
        names=target.BOOT_DEVICE_ALIASES
        self.assertEqual(self.select([names[1]]),[names[1]])
    def test_both_matching_candidates_have_one_identity_and_source_order(self):
        self.assertEqual(self.select(target.BOOT_DEVICE_ALIASES),list(target.BOOT_DEVICE_ALIASES))
    def test_missing_or_present_wrong_or_dangling_cannot_fall_back(self):
        names=target.BOOT_DEVICE_ALIASES
        with self.assertRaises(Refusal):self.select([])
        for wrong in names:
            with self.subTest(wrong=wrong),self.assertRaises(Refusal):self.select(names,wrong=wrong)
            with self.subTest(dangling=wrong),self.assertRaises(Refusal):self.select(names,dangling=wrong)
    def test_fixed_test_uuid_partition_provider_and_whole_parent_join(self):
        for bad in (None,'uuid','parent','whole-is-partition','part-is-whole'):
            io=target.NativeStorageIO()
            mapping={'/dev/disk/by-uuid/'+target.TEST_UUID:'8:17',target.TEST_DEVICE_ALIAS:'8:17',target.TEST_DISK_ALIAS:'8:16'}
            graph={'8:17':ancestry('8:17','8:16',True),'8:16':ancestry('8:16','8:16',False)}
            if bad=='uuid':mapping[target.TEST_DEVICE_ALIAS]='8:33'
            elif bad=='parent':graph['8:17']['wholeMajorMinor']='8:32'
            elif bad=='whole-is-partition':graph['8:16']=ancestry('8:16','8:0',True)
            elif bad=='part-is-whole':graph['8:17']=ancestry('8:17','8:17',False)
            io._device=Mock(side_effect=lambda path:mapping[path]);io._block_ancestry=Mock(side_effect=lambda n:graph[n])
            if bad is None:self.assertEqual(io._test_devices()[:2],('8:17','8:16'))
            else:
                with self.subTest(bad=bad),self.assertRaises(Refusal):io._test_devices()


if __name__=='__main__':unittest.main()
