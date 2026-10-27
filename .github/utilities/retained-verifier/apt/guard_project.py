"""Pure mkosi20 PackageManagerTrees and ordered outer-hook source generator."""
import hashlib
import json
import re
import archive_guard as guard

POLICY_SHA256='61d13310c96e63277b56a7514c6cf8789db891dad345342d9a5d8529fccad6b9'


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def sha(raw):return hashlib.sha256(raw).hexdigest()


def make_context(*,source_manifest_sha256,build_id,keyring_sha256,gpgv_sha256,apt_helper_sha256,
                 run_identity):
    value={'schema':'ocv-apt-guard-context-v1','sourceManifestSha256':source_manifest_sha256,
      'buildId':build_id,'keyringSha256':keyring_sha256,'gpgvSha256':gpgv_sha256,
      'aptHelperSha256':apt_helper_sha256,'sourceRosterSha256':sha(guard.SOURCE),
      'guardConfigSha256':sha(guard.CONFIG),'runIdentity':run_identity}
    guard.context_checked(value)
    return value


def _launcher(context_sha,guard_sha,policy_sha,entry_sha,*,export):
    # No multi-option Python shebang. APT calls this with explicit interpreter
    # options; the standard outer mkosi shell wrapper does the same.
    target='native_export' if export else 'native_main'
    call=('{ctx!r},{g!r},{p!r}'.format(ctx=context_sha,g=guard_sha,p=policy_sha)+
          ('' if export else ",sys.argv[1] if len(sys.argv)==2 else 'invalid'"))
    return ('''import hashlib,os,stat,sys
from pathlib import Path
ENTRY = Path('/etc/apt/ocv/guard_entry.py')
try:
    if ENTRY.resolve()!=ENTRY: raise RuntimeError('apt.launch_path')
    before=ENTRY.lstat()
    if not(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and
           before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o444 and 0<before.st_size<=131072):
        raise RuntimeError('apt.launch_identity')
    fd=os.open(ENTRY,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        raw=os.read(fd,131073);after=os.fstat(fd)
    finally:os.close(fd)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if len(raw)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(ENTRY.lstat()):
        raise RuntimeError('apt.launch_changed')
    if hashlib.sha256(raw).hexdigest()!={entry!r}:raise RuntimeError('apt.launch_pin')
    module={{'__name__':'ocv_guard_entry','__file__':str(ENTRY)}}
    exec(compile(raw,str(ENTRY),'exec'),module)
    result=module[{target!r}]({call})
except BaseException as error:
    sys.stderr.write('OCV_APT_LAUNCH_REFUSED:'+type(error).__name__+'\\n')
    result=100
raise SystemExit(result)
'''.format(entry=entry_sha,target=target,call=call)).encode()


def project_files(context,*,guard_source,policy_source,entry_source):
    """All returned paths are relative to the pkgmngr tree, not the host."""
    guard.context_checked(context)
    for raw in (guard_source,policy_source,entry_source):
        guard.require(type(raw) is bytes and 0<len(raw)<=131072,'apt.project_source')
    guard.require(sha(policy_source)==POLICY_SHA256,'apt.project_policy_changed')
    ctx=canonical(context);ch=sha(ctx);gh=sha(guard_source);ph=sha(policy_source);eh=sha(entry_source)
    files=guard.project_files()
    files.update({
      'etc/apt/ocv/guard-context.json':(ctx,0o444),
      'etc/apt/ocv/archive_guard.py':(guard_source,0o444),
      'etc/apt/ocv/archive_policy.py':(policy_source,0o444),
      'etc/apt/ocv/guard_entry.py':(entry_source,0o444),
      'etc/apt/ocv/launch.py':(_launcher(ch,gh,ph,eh,export=False),0o444),
      'etc/apt/ocv/export-launcher.py':(_launcher(ch,gh,ph,eh,export=True),0o444),
    })
    return files


def project_directories():
    return guard.project_directories()


def outer_postinstall_script():
    return b'#!/bin/sh\nexec /usr/bin/python3 -I -S -B /etc/apt/ocv/export-launcher.py\n'


if __name__=='__main__':raise SystemExit('disarmed_source_generator_only')
