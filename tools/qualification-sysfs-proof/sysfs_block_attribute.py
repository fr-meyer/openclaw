"""Bounded Linux sysfs block attributes, with stable root-owned identities.

Sysfs nominal metadata size is separate from the 128-byte EOF read bound.
The strict generic regular-file reader retains its independent metadata cap.
Only standard-library dependencies are used; no device contents are opened.
"""
import os
from pathlib import Path, PurePosixPath
import re
import stat

class Refusal(RuntimeError):
    def __init__(self, code, facts=None):
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_.]{0,95}", code):
            code = "invalid_reason_code"
        super().__init__(code)
        self.code = code
        self.reason = code
        self.facts = {} if facts is None else facts


def require(condition, code, facts=None):
    if not condition:
        raise Refusal(code, facts)


def _identity(info):
    return {k: int(getattr(info,k)) for k in
            ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size',
             'st_mtime_ns','st_ctime_ns')}


def _stable(a,b):
    return _identity(a) == _identity(b)


def _directory_chain(path):
    """Canonical fixed directories only; no inherited symlink path chain."""
    require(type(path) is str and path.startswith('/') and
            str(PurePosixPath(path))==path and '..' not in path.split('/'),
            'observer.directory_path')
    parts=Path(path).parts
    for count in range(1,len(parts)+1):
        current=Path(*parts[:count])
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                not stat.S_IMODE(info.st_mode) & 0o022 and not current.is_symlink(),
                'observer.directory_identity')


def _regular(path, cap, *, executable=False, proc=False):
    """Read bounded fixed-role bytes with inode stability, never follow a link."""
    require(type(path) is str and path.startswith('/') and '\x00' not in path and
            str(PurePosixPath(path)) == path and '..' not in path.split('/'),
            'observer.fixed_path')
    _directory_chain(str(Path(path).parent))
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
            before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o022 and
            0 <= before.st_size <= cap and
            (not executable or bool(stat.S_IMODE(before.st_mode) & 0o111)),
            'observer.regular_identity')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        chunks,total = [],0
        while total <= cap:
            raw = os.read(fd,min(65536,cap+1-total))
            if not raw: break
            chunks.append(raw);total += len(raw)
        after = os.fstat(fd)
    finally: os.close(fd)
    require(total <= cap and (proc or total == before.st_size) and
            _stable(before,opened) and _stable(before,after) and
            _stable(before,os.lstat(path)), 'observer.read_changed')
    return b''.join(chunks),_identity(before)


def _sysfs_block_attribute(path):
    """Fixed block attributes: nominal sysfs size is not the bounded EOF."""
    require(type(path) is str and path.startswith('/sys/devices/') and
            '\x00' not in path and str(PurePosixPath(path))==path and
            '..' not in path.split('/') and Path(path).name in ('dev','partition'),
            'observer.sysfs_block_path')
    _directory_chain(str(Path(path).parent))
    before=os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and
            before.st_nlink==1 and not stat.S_IMODE(before.st_mode)&0o022 and
            0<=before.st_size<=4096,'observer.sysfs_block_identity')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        opened=os.fstat(fd);chunks,total=[],0
        while total<=128:
            raw=os.read(fd,129-total)
            if not raw:break
            chunks.append(raw);total+=len(raw)
        after=os.fstat(fd)
    finally:os.close(fd)
    require(total<=128 and _stable(before,opened) and _stable(before,after) and
            _stable(before,os.lstat(path)),'observer.sysfs_block_changed')
    return b''.join(chunks)


def _major_minor(value):
    return type(value) is str and re.fullmatch(r'(0|[1-9][0-9]*):(0|[1-9][0-9]*)',value) is not None


class BlockAttributeReader:
    def _block_ancestry(self,major_minor):
        require(_major_minor(major_minor),'observer.block_number')
        node=(Path('/sys/dev/block')/major_minor).resolve(strict=True)
        require(str(node).startswith('/sys/devices/'),'observer.block_graph')
        def read(path):return _sysfs_block_attribute(str(path)).strip().decode('ascii')
        require(read(node/'dev')==major_minor,'observer.block_number_changed')
        try:partition=(node/'partition').lstat()
        except FileNotFoundError:partition=None
        if partition is not None:
            require(stat.S_ISREG(partition.st_mode) and partition.st_uid==partition.st_gid==0 and
                    not stat.S_IMODE(partition.st_mode)&0o022 and partition.st_nlink==1,
                    'observer.partition_identity')
            number=read(node/'partition')
            require(re.fullmatch(r'[1-9][0-9]{0,9}',number) and int(number)<2**31,
                    'observer.partition_number')
        whole=node.parent if partition is not None else node
        require(str(whole).startswith('/sys/devices/'),'observer.block_graph')
        if partition is not None:
            try:parent_partition=(whole/'partition').lstat()
            except FileNotFoundError:parent_partition=None
            require(parent_partition is None,'observer.whole_is_partition')
        number=read(whole/'dev');require(_major_minor(number),'observer.block_graph')
        return {'majorMinor':major_minor,'wholeMajorMinor':number,'isPartition':partition is not None}
