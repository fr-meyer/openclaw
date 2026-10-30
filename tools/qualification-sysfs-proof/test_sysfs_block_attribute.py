"""Synthetic syscall contracts; importing this file never reads native sysfs."""
import copy
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

_spec=importlib.util.spec_from_file_location('generic_sysfs_reader',Path(__file__).with_name('sysfs_block_attribute.py'))
p=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p)

def info(**changed):
    values=dict(st_dev=5,st_ino=100,st_mode=stat.S_IFREG|0o444,st_uid=0,
                st_gid=0,st_nlink=1,st_size=4096,st_mtime_ns=1,st_ctime_ns=2)
    values.update(changed)
    return SimpleNamespace(**values)

class KernelFixture:
    def __init__(self):
        self.paths={};self.numbers={};self.fd={};self.opens=[];self.requests=[]
        self.closed=[];self.front_changes={};self.open_changes={}
        self.after_changes={};self.final_changes={};self.stats={}
        self.add_disk('8:0','sda');self.add_partition('8:1','sda','sda1','1')
        self.add_disk('8:16','sdb');self.add_partition('8:17','sdb','sdb1','1')
    def add(self,path,raw):
        self.paths[path]=(raw,info(st_ino=100+len(self.paths)))
    def add_disk(self,number,name):
        root='/sys/devices/fixture/block/'+name
        self.numbers[number]=root;self.add(root+'/dev',(number+'\n').encode())
        return root
    def add_partition(self,number,disk,name,part):
        root='/sys/devices/fixture/block/'+disk+'/'+name
        self.numbers[number]=root;self.add(root+'/dev',(number+'\n').encode())
        self.add(root+'/partition',(part+'\n').encode());return root
    def lstat(self,path,*_args,**_kwargs):
        path=str(path)
        if path.startswith('/sys/dev/block/'):
            if path.rsplit('/',1)[1]not in self.numbers:raise FileNotFoundError()
            return info(st_mode=stat.S_IFLNK|0o777)
        if path not in self.paths:raise FileNotFoundError()
        self.stats[path]=self.stats.get(path,0)+1
        value=copy.copy(self.paths[path][1])
        changes=self.final_changes if self.stats[path]>1 else self.front_changes
        for key,item in changes.items():setattr(value,key,item)
        return value
    def opened(self,path,flags,*_args,**_kwargs):
        path=str(path);assert path in self.paths
        self.opens.append((path,flags));number=500+len(self.opens)
        self.fd[number]=[path,0,0];return number
    def fstat(self,fd):
        path,_at,calls=self.fd[fd];self.fd[fd][2]+=1
        value=copy.copy(self.paths[path][1])
        for key,item in(self.open_changes if calls==0 else self.after_changes).items():
            setattr(value,key,item)
        return value
    def read(self,fd,count):
        path,at,_calls=self.fd[fd];self.requests.append(count)
        raw=self.paths[path][0][at:at+count];self.fd[fd][1]+=len(raw);return raw
    def close(self,fd):self.closed.append(fd);self.fd.pop(fd)
    def resolve(self,path,strict=False):
        value=str(path)
        if value.startswith('/sys/dev/block/'):
            number=value.rsplit('/',1)[1]
            if number not in self.numbers:raise FileNotFoundError()
            return Path(self.numbers[number])
        return path
    def __enter__(self):
        self.stack=ExitStack();self.stack.enter_context(patch.object(p,'_directory_chain'))
        for name,fn in(('lstat',self.lstat),('open',self.opened),('fstat',self.fstat),
                       ('read',self.read),('close',self.close)):
            self.stack.enter_context(patch.object(os,name,side_effect=fn))
        self.stack.enter_context(patch.object(Path,'lstat',autospec=True,side_effect=self.lstat))
        self.stack.enter_context(patch.object(Path,'resolve',autospec=True,side_effect=self.resolve))
        return self
    def __exit__(self,*args):self.stack.close()

class Tests(unittest.TestCase):
    def test_nominal_page_size_reproduces_original_failure_and_short_eof_succeeds(self):
        fs=KernelFixture();path=fs.numbers['8:1']+'/dev'
        with fs:
            with self.assertRaisesRegex(p.Refusal,'observer.regular_identity'):
                p._regular(path,128,proc=True)
            self.assertEqual(fs.opens,[])
            self.assertEqual(p._sysfs_block_attribute(path),b'8:1\n')
            self.assertTrue(all(0<count<=129 for count in fs.requests))
            self.assertFalse(fs.fd)
            flags=fs.opens[0][1]
            self.assertEqual(flags&os.O_NOFOLLOW,os.O_NOFOLLOW)
            self.assertEqual(flags&os.O_NONBLOCK,os.O_NONBLOCK)
    def test_whole_and_partition_ancestry_repeats_with_the_exact_shared_reader(self):
        fs=KernelFixture();reader=p.BlockAttributeReader()
        with fs:
            for _ in range(2):
                for own,whole,part in(('8:0','8:0',False),('8:1','8:0',True),
                                       ('8:16','8:16',False),('8:17','8:16',True)):
                    self.assertEqual(reader._block_ancestry(own),
                        {'majorMinor':own,'wholeMajorMinor':whole,'isPartition':part})
            self.assertFalse(fs.fd)
    def test_noncanonical_or_other_attribute_paths_refuse_before_filesystem_access(self):
        bad=('/tmp/dev','/sys/dev/block/8:1/dev','/sys/devices/a/uevent',
             '/sys/devices/a/../b/dev','/sys/devices//a/dev','/sys/devices/a/dev\x00')
        with patch.object(p,'_directory_chain')as chain,patch.object(os,'lstat')as ls,patch.object(os,'open')as opened:
            for path in bad:
                with self.subTest(path=path),self.assertRaises(p.Refusal):
                    p._sysfs_block_attribute(path)
            chain.assert_not_called();ls.assert_not_called();opened.assert_not_called()
    def test_metadata_owner_group_type_links_mode_and_nominal_bound_refuse(self):
        cases=(('st_uid',1),('st_gid',1),('st_nlink',2),('st_mode',stat.S_IFREG|0o666),
               ('st_mode',stat.S_IFLNK|0o777),('st_mode',stat.S_IFDIR|0o555),
               ('st_size',-1),('st_size',4097))
        for key,value in cases:
            fs=KernelFixture();fs.front_changes={key:value}
            with self.subTest(key=key,value=value),fs:
                with self.assertRaisesRegex(p.Refusal,'observer.sysfs_block_identity'):
                    p._sysfs_block_attribute(fs.numbers['8:1']+'/dev')
                self.assertEqual(fs.opens,[])
    def test_open_after_read_and_final_path_identity_changes_refuse_and_close(self):
        for when in('open_changes','after_changes','final_changes'):
            for key,value in(('st_ino',999),('st_uid',1),('st_mode',stat.S_IFREG|0o666),
                              ('st_size',1),('st_nlink',2),('st_mtime_ns',9)):
                fs=KernelFixture();setattr(fs,when,{key:value})
                with self.subTest(when=when,key=key),fs:
                    with self.assertRaisesRegex(p.Refusal,'observer.sysfs_block_changed'):
                        p._sysfs_block_attribute(fs.numbers['8:1']+'/dev')
                    self.assertFalse(fs.fd);self.assertEqual(len(fs.closed),1)
    def test_128_byte_eof_bound_and_read_error_close_without_accepting_partial_data(self):
        for size in(128,129):
            fs=KernelFixture();path=fs.numbers['8:1']+'/dev'
            fs.paths[path]=(b'x'*size,fs.paths[path][1])
            with self.subTest(size=size),fs:
                if size==128:self.assertEqual(p._sysfs_block_attribute(path),b'x'*128)
                else:
                    with self.assertRaisesRegex(p.Refusal,'observer.sysfs_block_changed'):
                        p._sysfs_block_attribute(path)
                self.assertFalse(fs.fd)
        fs=KernelFixture()
        with fs,patch.object(os,'read',side_effect=OSError(5,'synthetic read failure')):
            with self.assertRaises(OSError):p._sysfs_block_attribute(fs.numbers['8:1']+'/dev')
            self.assertFalse(fs.fd);self.assertEqual(len(fs.closed),1)
    def test_ancestry_values_and_parent_relationships_keep_their_semantic_guards(self):
        for case in('wrong-dev','bad-partition','whole-is-partition','outside-sysfs'):
            fs=KernelFixture();node=fs.numbers['8:1'];whole=fs.numbers['8:0']
            if case=='wrong-dev':fs.paths[node+'/dev']=(b'8:2\n',fs.paths[node+'/dev'][1])
            elif case=='bad-partition':fs.paths[node+'/partition']=(b'0\n',fs.paths[node+'/partition'][1])
            elif case=='whole-is-partition':fs.add(whole+'/partition',b'1\n')
            else:fs.numbers['8:1']='/tmp/untrusted'
            with self.subTest(case=case),fs,self.assertRaises(p.Refusal):
                p.BlockAttributeReader()._block_ancestry('8:1')
    def test_regular_file_reader_still_enforces_its_own_metadata_cap(self):
        fs=KernelFixture();path='/var/lib/synthetic-fixture';fs.add(path,b'short')
        with fs:
            with self.assertRaisesRegex(p.Refusal,'observer.regular_identity'):p._regular(path,128)
            with self.assertRaisesRegex(p.Refusal,'observer.sysfs_block_path'):p._sysfs_block_attribute(path)
            self.assertEqual(fs.opens,[])
    def test_parent_directory_root_nonsymlink_and_nonwritable_guards_remain(self):
        path='/sys/devices/fixture/block/sda/dev';directory=info(st_mode=stat.S_IFDIR|0o555)
        for bad in(info(st_mode=stat.S_IFLNK|0o777),info(st_mode=stat.S_IFDIR|0o777),
                   info(st_mode=stat.S_IFDIR|0o555,st_uid=1)):
            def lstat(node,*_args,**_kwargs):return bad if str(node)=='/sys/devices'else directory
            with self.subTest(mode=bad.st_mode,uid=bad.st_uid),patch.object(Path,'lstat',autospec=True,side_effect=lstat),patch.object(os,'open')as opened:
                with self.assertRaisesRegex(p.Refusal,'observer.directory_identity'):
                    p._sysfs_block_attribute(path)
                opened.assert_not_called()

if __name__=='__main__':unittest.main()
