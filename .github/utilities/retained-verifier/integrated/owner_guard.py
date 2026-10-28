"""One source-managed guest owner lease; never a machine-global exclusion claim.

The outer owner establishes the cloud/SSH generation and SDK reservation first.
The lease prevents this source from overlapping another source-managed session.
It neither excludes an unknown root operator nor permits clearing stale leases.
Native construction has no effects; only a purpose-limited issued bootstrap may
acquire the fixed lease, and every later use checks its still-open identity.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import os
from pathlib import Path
import re
import stat

from protocol import Refusal, canonical, decode, require, sha
import native_authority as authority

CONTROL_ROOT = '/var/lib/openclaw-retained-verifier-control'
_KEY = object()


class OwnerGuard:
    __slots__ = ('_key','_owner','_io','_receipt','_sealed')
    def __setattr__(self,name,value):
        require(not getattr(self,'_sealed',False),'owner_guard.immutable')
        object.__setattr__(self,name,value)
    def __delattr__(self,_name):
        raise Refusal('owner_guard.immutable')
    def __init__(self,key,owner,io,receipt):
        require(key is _KEY,'owner_guard.unissued')
        authority.validate_owner(owner)
        self._key,self._owner,self._io=key,canonical(owner),io
        self._receipt=canonical(receipt)
        self._sealed=True
    def verify_for(self,cap):
        require(type(self) is OwnerGuard and self._key is _KEY and
                canonical(cap.owner)==self._owner,'owner_guard.generation')
        authority.require_time(cap,self._io.now(),cleanup=True)
        require(self._io.verify_lease(self._owner,self._receipt) is True,
                'owner_guard.lease_changed')
        return decode(self._receipt,16384)


def acquire(cap,io):
    authority.require_bootstrap_capability(cap,'owner_guard',io)
    authority.require_time(cap,io.now(),reserve=900)
    require(type(io) is NativeOwnerGuardIO,'owner_guard.native_port')
    receipt=io.acquire_once(cap.owner)
    return OwnerGuard(_KEY,cap.owner,io,receipt)


class NativeOwnerGuardIO:
    evidence_kind='native_owner_guard'
    def __init__(self):
        self._attempted=False
        self._fd=self._root_fd=None
        self._identity=self._record=self._name=None
    def now(self):return dt.datetime.now(dt.timezone.utc)
    @staticmethod
    def _root_directory(path):
        current=Path('/')
        for name in path.parts[1:]:
            current/=name
            info=current.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
                    not stat.S_IMODE(info.st_mode)&0o022,'owner_guard.parent')
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            require(os.fstat(fd).st_dev==os.stat('/').st_dev,'owner_guard.boot_filesystem')
            return fd
        except BaseException:
            os.close(fd);raise
    @staticmethod
    def _boot_id():
        fd=os.open('/proc/sys/kernel/random/boot_id',os.O_RDONLY|os.O_NOFOLLOW)
        try:raw=os.read(fd,129)
        finally:os.close(fd)
        require(len(raw)<=128,'owner_guard.boot_id_cap')
        return raw.decode('ascii').strip()
    @staticmethod
    def _source_managed_units_absent():
        # Read-only cgroup ownership scan. No systemd/other measured tool runs.
        root=Path('/sys/fs/cgroup')
        visited=0
        stack=[root]
        while stack:
            path=stack.pop()
            with os.scandir(path) as entries:
                for entry in entries:
                    visited+=1
                    require(visited<=32768,'owner_guard.cgroup_scan_cap')
                    if not entry.is_dir(follow_symlinks=False):continue
                    require(not entry.is_symlink(),'owner_guard.cgroup_symlink')
                    if re.fullmatch('ocv-[0-9a-f]{32}\\.service',entry.name):
                        fd=os.open(Path(entry.path)/'cgroup.procs',os.O_RDONLY|os.O_NOFOLLOW)
                        try:
                            require(stat.S_ISREG(os.fstat(fd).st_mode),'owner_guard.cgroup_type')
                            raw=os.read(fd,65537)
                        finally:os.close(fd)
                        require(len(raw)<=65536 and not raw.strip(),
                                'owner_guard.other_managed_workload')
                    stack.append(Path(entry.path))
    def acquire_once(self,owner):
        require(not self._attempted,'owner_guard.acquire_consumed')
        self._attempted=True
        authority.validate_owner(owner)
        require(os.geteuid()==0 and self._boot_id()==owner['bootId'],
                'owner_guard.boot_generation')
        root=Path(CONTROL_ROOT)
        require(root.is_absolute() and root.parent==Path('/var/lib') and
                root.name=='openclaw-retained-verifier-control','owner_guard.fixed_root')
        parent=self._root_directory(root.parent)
        try:
            try:os.mkdir(root.name,0o700,dir_fd=parent)
            except FileExistsError:pass
            os.fsync(parent)
        finally:os.close(parent)
        self._root_fd=self._root_directory(root)
        require(stat.S_IMODE(os.fstat(self._root_fd).st_mode)==0o700,
                'owner_guard.control_mode')
        self._source_managed_units_absent()
        record={'schema':'openclaw.source-managed-guest-owner.v1','owner':owner,
            'scope':'source-managed qualification lane; not global root exclusion',
            'sourceManagedLeaseExclusive':True,'machineWideExclusivityEstablished':False}
        raw=canonical(record)
        # Prior-boot evidence stays intact. A current boot gets exactly one
        # source-managed lease; a same-boot restart must reconcile, never delete.
        self._name='owner-'+owner['bootId']+'.lease'
        fd=os.open(self._name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,
                   dir_fd=self._root_fd)
        self._fd=fd  # Preserve uncertain/exclusive intent even if a later fsync fails.
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        offset=0
        while offset<len(raw):
            count=os.write(fd,raw[offset:])
            require(type(count) is int and 0<count<=len(raw)-offset,
                    'owner_guard.write_progress')
            offset+=count
        os.fsync(fd);os.fsync(self._root_fd)
        self._identity=self._file_identity(os.fstat(fd));self._record=raw
        return record
    @staticmethod
    def _file_identity(info):
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,
                stat.S_IMODE(info.st_mode),info.st_nlink,info.st_size)
    def verify_lease(self,owner_raw,receipt_raw):
        require(self._fd is not None and self._root_fd is not None and
                self._record==receipt_raw,'owner_guard.lease_unissued')
        expected=decode(owner_raw,16384)
        require(self._boot_id()==expected['bootId'],'owner_guard.boot_changed')
        before=os.fstat(self._fd)
        require(self._name=='owner-'+expected['bootId']+'.lease','owner_guard.lease_name')
        path=os.stat(self._name,dir_fd=self._root_fd,follow_symlinks=False)
        require(stat.S_ISREG(path.st_mode) and
                self._file_identity(before)==self._identity==self._file_identity(path),
                'owner_guard.lease_identity')
        raw=os.pread(self._fd,16385,0)
        require(raw==self._record==receipt_raw and len(raw)<=16384,
                'owner_guard.lease_bytes')
        return True


if __name__=='__main__':raise SystemExit('owner_guard_no_cli')
