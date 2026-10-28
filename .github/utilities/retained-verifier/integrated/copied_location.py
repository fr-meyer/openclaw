"""Pure CI BOOT placement projection and observed metadata checks.

These dictionaries do not issue source, device or execution authority. Native
effects remain behind the genuine authenticated bootstrap in the probe.
Private bootstrap archive-SHA directory semantics are independent and fixed.
"""
from pathlib import PurePosixPath
import re

from protocol import canonical,closed,require,sha

BASE='/var/lib/openclaw-retained-bootstrap'
IDENTITY_SCHEMA='ocv.copied-controller-placement-identity.v1'
META_SCHEMA='ocv.copied-controller-placement-observation.v1'
META_CAP=8192
EXECUTABLES=('lib64/ld-linux-x86-64.so.2','usr/bin/python3.11')


def normalized_rows(rows):
    import copied_bootstrap_probe
    values=copied_bootstrap_probe._rows(rows)
    result=[]
    for path,row in sorted(values.items()):
        archive='static-entry' if path=='code/static-entry' else 'runtime/'+path
        require(row.get('archivePath',archive)==archive,'copied.location_archive_path')
        result.append({'path':path,'archivePath':archive,'bytes':row['bytes'],
            'sha256':row['sha256'],'mode':row['mode']})
    return result


def root_for(rows,session):
    require(type(session) is str and re.fullmatch('[0-9a-f]{32}',session),
            'copied.location_session')
    identity=sha(canonical({'schema':IDENTITY_SCHEMA,'files':normalized_rows(rows)}))
    return BASE+'/'+identity+'/'+session+'/root'


def ancestor_paths(root):
    require(type(root) is str and re.fullmatch(re.escape(BASE)+'/[0-9a-f]{64}/[0-9a-f]{32}/root',root),
            'copied.location_root')
    path=PurePosixPath(root)
    return [str(p) for p in reversed((path,*path.parents))]


def covering_mounts(raw,root):
    import guest_storage
    ancestor_paths(root)
    rows=guest_storage.parse_mountinfo(raw)
    return [row for row in rows if row['target']=='/' or root==row['target'] or
            root.startswith(row['target'].rstrip('/')+'/') or row['target'].startswith(root+'/')]


def _linux_device(value):
    require(type(value) is int and 0<value<2**64,'copied.location_device')
    major=((value&0x00000000000fff00)>>8)|((value&0xfffff00000000000)>>32)
    minor=(value&0xff)|((value&0x00000ffffff00000)>>12)
    return str(major)+':'+str(minor)


def validate(metadata,root,rows,boot_id,*,final):
    closed(metadata,{'schema','metadataOnly','executionObserved','root','bootId','rootDevice',
        'rootMajorMinor','ancestors','mountInfoSha256','mounts','statvfsFlags','executables'},
        'copied.location_metadata')
    require(len(canonical(metadata))<=META_CAP and metadata['schema']==META_SCHEMA and
        metadata['metadataOnly'] is True and metadata['executionObserved'] is False and
        metadata['root']==root and metadata['bootId']==boot_id and
        metadata['rootMajorMinor']==_linux_device(metadata['rootDevice']) and
        type(metadata['mountInfoSha256']) is str and
        re.fullmatch('[0-9a-f]{64}',metadata['mountInfoSha256']), 'copied.location_identity')
    expected=ancestor_paths(root);parents=metadata['ancestors']
    require(type(parents) is list and [r.get('path') for r in parents]==expected[:len(parents)] and
        (len(parents)==len(expected) if final else 3<=len(parents)<=5),
        'copied.location_existing_session_or_ancestor')
    for index,row in enumerate(parents):
        closed(row,{'path','device','inode','uid','gid','mode','directory','symlink'},
            'copied.location_ancestor_schema')
        require(all(type(row[k]) is int for k in ('device','inode','uid','gid','mode')) and
            row['device']==metadata['rootDevice'] and row['inode']>0 and
            row['uid']==row['gid']==0 and row['directory'] is True and row['symlink'] is False and
            type(row['mode']) is int and not row['mode']&0o022 and
            (index<3 or row['mode']==0o700),'copied.location_ancestor')
    mounts=metadata['mounts']
    require(type(mounts) is list,'copied.location_mount_policy')
    for mount in mounts:
        closed(mount,{'id','parent','majorMinor','root','target','options','fstype','source','superOptions'},
               'copied.location_mount_schema')
        require(type(mount['id']) is int and mount['id']>0 and type(mount['parent']) is int and mount['parent']>=0 and
            all(type(mount[k]) is str for k in ('majorMinor','root','target','fstype','source')) and
            all(type(mount[k]) is list and all(type(v) is str for v in mount[k]) for k in ('options','superOptions')),
            'copied.location_mount_types')
    require(type(mounts) is list and len(mounts)==1 and mounts[0]['target']=='/' and
        mounts[0]['root']=='/' and mounts[0]['majorMinor']==metadata['rootMajorMinor'] and
        mounts[0]['fstype']=='ext4' and 'rw' in mounts[0]['options'] and
        all(option not in mounts[0][field] for field in ('options','superOptions')
            for option in ('ro','noexec')),'copied.location_mount_policy')
    require(type(metadata['statvfsFlags']) is int and metadata['statvfsFlags']>=0 and
        not metadata['statvfsFlags']&(1|8),'copied.location_statvfs_policy')
    files=metadata['executables'];roster={r['path']:r for r in normalized_rows(rows)}
    require(type(files) is list and (len(files)==2 if final else files==[]),
            'copied.location_executable_roster')
    for name,row in zip(EXECUTABLES,files):
        closed(row,{'path','device','inode','uid','gid','mode','bytes','sha256','links','executeAccess'},
            'copied.location_executable_schema')
        require(all(type(row[k]) is int for k in ('device','inode','uid','gid','mode','bytes','links')) and
            row['path']==name and row['device']==metadata['rootDevice'] and row['inode']>0 and row['uid']==row['gid']==0 and
            row['mode']==0o555 and row['links']==1 and row['executeAccess'] is True and
            row['bytes']==roster[name]['bytes'] and row['sha256']==roster[name]['sha256'],
            'copied.location_executable')
    return metadata


def validate_pair(placement,root,rows,boot_id):
    closed(placement,{'beforeStage','beforeSpawn'},'copied.location_pair')
    before=validate(placement['beforeStage'],root,rows,boot_id,final=False)
    after=validate(placement['beforeSpawn'],root,rows,boot_id,final=True)
    require(before['rootDevice']==after['rootDevice'] and before['rootMajorMinor']==after['rootMajorMinor'] and
        before['mounts']==after['mounts'] and before['statvfsFlags']==after['statvfsFlags'] and
        before['ancestors']==after['ancestors'][:len(before['ancestors'])],
        'copied.location_generation_changed')
    return placement


if __name__=='__main__':raise SystemExit('copied_location_no_cli')
