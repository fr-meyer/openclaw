"""Checked mkosi BUILD-chroot entry, never a booted-PID1 proof.

No operation occurs on import. The only native entry is invoke() called by the
reviewed generated shim with literal source/header hashes. Mac/ordinary CLI
execution refuses. Pure tests may inject files/processes into run_checked().
No source ARM/capability global is assigned or consumed.
"""
import datetime as dt
import hashlib
import importlib.util
import json
import os
import posixpath
from pathlib import PurePosixPath
import re
import selectors
import stat
import subprocess
import sys
import time

ROOT='/opt/ocv/source'
CONTROL='/opt/ocv/control'
OUT='/work/out'
DATA=CONTROL+'/apt-data'
GPG_METADATA=('/usr/bin/gpgv','--status-fd=1','--keyring',DATA+'/keyring.gpg',DATA+'/InRelease')
GPG_SECURITY=('/usr/bin/gpgv','--status-fd=1','--keyring',DATA+'/keyring.gpg',DATA+'/SecurityInRelease')
HEADER=CONTROL+'/build-stage-context.json'
SOURCE_MANIFEST=ROOT+'/PUBLIC-SOURCE-MANIFEST.json'
WORKFLOW='fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites'
TOOLS={'python':'/usr/bin/python3.11','systemd':'/usr/lib/systemd/systemd','gpgv':'/usr/bin/gpgv',
       'busctl':'/usr/bin/busctl','systemctl':'/usr/bin/systemctl','systemd-run':'/usr/bin/systemd-run',
       'selinuxenabled':'/usr/sbin/selinuxenabled','dpkg-query':'/usr/bin/dpkg-query',
       'mount':'/usr/bin/mount','umount':'/usr/bin/umount','findmnt':'/usr/bin/findmnt',
       'blkid':'/usr/sbin/blkid','git':'/usr/bin/git'}
COMPILER={'compiler':'/usr/bin/gcc-12','cc1':'/usr/lib/gcc/x86_64-linux-gnu/12/cc1',
          'collect2':'/usr/lib/gcc/x86_64-linux-gnu/12/collect2','assembler':'/usr/bin/as','linker':'/usr/bin/ld'}
SHOW_FORMAT='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'
FIXED_DATA=('InRelease','Packages','keyring.gpg','gpgv-status.txt','guard-proof.json','first-stage-ledger.json',
            'SecurityInRelease','SecurityPackages','security-gpgv-status.txt','security-guard-proof.json')
HEADER_KEYS={'schema','sourceManifestSha256','runIdentity','keyringSha256','kernelPackage','packageRoots','buildId'}
RETAINED_HELPER_SOURCE_SHA256='29aa405e68a011d81dbf94d4aaf7e39899f62144eaaca6cceac884f183e335fe'
RETAINED_HELPER_SHA256='0039f448059652d87fdfe49cf2de875a38bfe2224c2711c17cc2c837f9c7c88a'
RETAINED_HELPER_BYTES=17888


class Refusal(RuntimeError):
    pass


def need(ok,code):
    if not ok:raise Refusal(code)


def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def digest(x):return type(x)is str and re.fullmatch('[0-9a-f]{64}',x) is not None


def retained_helper_source(source):
    need(type(source)is bytes and len(source)==11765 and sha(source)==RETAINED_HELPER_SOURCE_SHA256,
         'build_entry.retained_helper_source_pin')


def retained_helper_result(helper):
    # runtime.build_helper already authenticated compiler/package/source/ELF.
    # This additional fixed join refuses drift before any guest is booted.
    need(type(helper)is dict and helper.get('path')=='code/static-entry' and
        helper.get('sourceSha256')==RETAINED_HELPER_SOURCE_SHA256 and
        type(helper.get('bytes'))is int and helper['bytes']==RETAINED_HELPER_BYTES and
        helper.get('sha256')==RETAINED_HELPER_SHA256 and type(helper.get('elf'))is dict and
        helper['elf'].get('sha256')==RETAINED_HELPER_SHA256 and
        helper['elf'].get('bytes')==RETAINED_HELPER_BYTES,
        'build_entry.retained_helper_result_pin')


def build_retained_helper(runtime,source,toolchain,ops):
    retained_helper_source(source)
    helper=runtime.build_helper(source,sha(source),toolchain,ops)
    retained_helper_result(helper)
    return helper


def decode(raw,cap=8*1024**2):
    need(type(raw)is bytes and 0<len(raw)<=cap,'build_entry.json_cap')
    def pairs(rows):
        out={}
        for k,v in rows:
            need(k not in out,'build_entry.duplicate_key');out[k]=v
        return out
    try:return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(Refusal('build_entry.nonfinite')))
    except (ValueError,UnicodeError) as exc:raise Refusal('build_entry.json') from exc


def validate_header(raw,expected_source,expected_context):
    need(digest(expected_source) and digest(expected_context) and sha(raw)==expected_context,
         'build_entry.header_hash')
    c=decode(raw)
    need(type(c)is dict and set(c)==HEADER_KEYS and c['schema']=='ocv-host-build-context-v1'
         and c['sourceManifestSha256']==expected_source and digest(c['keyringSha256'])
         and type(c['buildId'])is str and re.fullmatch('[0-9a-f]{32}',c['buildId']), 'build_entry.header')
    r=c['runIdentity']
    need(type(r)is dict and set(r)=={'repository','workflowRef','sourceCommit','runId','runAttempt'}
         and r['repository']=='fr-meyer/openclaw' and r['workflowRef']==WORKFLOW
         and type(r['sourceCommit'])is str and re.fullmatch('[0-9a-f]{40}',r['sourceCommit'])
         and type(r['runId'])is str and re.fullmatch('[1-9][0-9]{0,19}',r['runId'])
         and type(r['runAttempt'])is str and r['runAttempt']=='1', 'build_entry.run_identity')
    k=c['kernelPackage']
    need(type(k)is dict and set(k)=={'name','version'} and type(k['name'])is str
         and re.fullmatch(r'linux-image-6\.1\.[A-Za-z0-9.+~_-]+',k['name'])
         and type(k['version'])is str and re.fullmatch('[A-Za-z0-9.+:~_-]{1,128}',k['version']),
         'build_entry.kernel_header')
    need(type(c['packageRoots'])is list and 16<=len(c['packageRoots'])<=64,'build_entry.package_roots')
    return c


def source_roster(raw,expected_source):
    need(sha(raw)==expected_source,'build_entry.source_manifest_hash')
    value=decode(raw,1024**2)
    need(type(value)is dict and type(value.get('files'))is list and 1<=len(value['files'])<=512,
         'build_entry.source_manifest')
    out={}
    for row in value['files']:
        need(type(row)is dict and set(row)=={'path','bytes','sha256','mode'},'build_entry.source_row')
        p=row['path']
        need(type(p)is str and not p.startswith('/') and str(PurePosixPath(p))==p
             and '..'not in PurePosixPath(p).parts and re.fullmatch('[A-Za-z0-9_./-]{1,256}',p)
             and p not in out and type(row['bytes'])is int and 0<row['bytes']<=4*1024**2
             and digest(row['sha256']) and row['mode']==0o444,'build_entry.source_row')
        out[p]=row
    need({'host/build_entry.py','build/build_recipe.py','runtime/runtime_prepare.py',
          'runtime/package_inventory.py','apt/archive_guard.py','apt/archive_policy.py',
          'native/static_entry.c'}<=set(out),'build_entry.source_required')
    need(sum(r['bytes'] for r in out.values())<=64*1024**2,'build_entry.source_total')
    return out


def command_ok(result, *, signature_status=False):
    need(type(result)is dict and type(result.get('exitCode'))is int and
         result['exitCode'] in ((0, 2) if signature_status else (0,))
         and result.get('timedOut')is False and result.get('captureComplete')is True
         and result.get('ownedChildExited')is True and result.get('ownershipRetained')is False
         and type(result.get('stdout'))is bytes and type(result.get('stderr'))is bytes,
         'build_entry.command_refused')
    return result['stdout']


def regular_read_cap_allowed(path,cap,immutable,header):
    """Match the recipe's larger cap only for its exact generated initrd."""
    if type(cap)is not int or cap<=0:return False
    if cap<=128*1024**2:return True
    if cap>512*1024**2 or immutable is not False or type(header)is not dict:return False
    kernel=header.get('kernelPackage')
    if type(kernel)is not dict or type(kernel.get('name'))is not str:return False
    name=kernel['name']
    return (re.fullmatch(r'linux-image-6\.1\.[A-Za-z0-9.+~_-]+',name) is not None and
            path=='/boot/initrd.img-'+name.removeprefix('linux-image-'))


def required_owner(ops,path,query_path):
    """Keep the first exact public package path when a required owner lookup fails."""
    result=ops.run(('/usr/bin/dpkg-query','--search',query_path),10)
    try:return command_ok(result)
    except Refusal:
        # The path comes only from the public installed Debian package view,
        # parsed ldd output, or the fixed compiler/loader paths. Never print
        # command output, which is not needed to diagnose the failed lookup.
        diagnostic={'schema':'ocv-required-owner-refusal-v1','path':path,
                    'queryPath':query_path,
                    'exitCode':result.get('exitCode') if type(result)is dict and
                               type(result.get('exitCode'))is int else None,
                    'timedOut':result.get('timedOut') if type(result)is dict else None,
                    'captureComplete':result.get('captureComplete') if type(result)is dict else None,
                    'ownedChildExited':result.get('ownedChildExited') if type(result)is dict else None,
                    'ownershipRetained':result.get('ownershipRetained') if type(result)is dict else None,
                    'stdoutBytes':len(result['stdout']) if type(result)is dict and
                                  type(result.get('stdout'))is bytes else None,
                    'stderrBytes':len(result['stderr']) if type(result)is dict and
                                  type(result.get('stderr'))is bytes else None}
        sys.stderr.write(canonical(diagnostic).decode()+'\n')
        raise


def deferred_signature_failure(argv,result,metadata_ready):
    """Keep one complete exit-2 gpgv result for policy classification."""
    return (metadata_ready is False and argv==GPG_METADATA and type(result)is dict and
            type(result.get('exitCode'))is int and result['exitCode']==2 and
            result.get('timedOut') is False and result.get('captureComplete') is True and
            result.get('ownedChildExited') is True and result.get('ownershipRetained') is False and
            not result.get('errors') and type(result.get('stdout'))is bytes and
            type(result.get('stderr'))is bytes)


def capture_command(argv,timeout,capout,caperr,io):
    """One exact-child bounded capture core; all effects injected, no defaults.

    The native owner supplies standard fixed primitives only after admission.
    Synthetic tests supply inert process/selector objects without constructing
    NativeBuildOps or bypassing its actual-context constructor.
    """
    need(set(io)=={'spawn','now','selector','nonblocking','read'},'build_entry.capture_io')
    child=None;selector=None;streams={};raws={'stdout':bytearray(),'stderr':bytearray()}
    result={'exitCode':None,'timedOut':False,'captureComplete':False,'ownedChildExited':False,
            'ownershipRetained':False,'spawnOutcome':'not_attempted','stdout':b'','stderr':b'','errors':[]}
    eof=set();last=None;phase='clock'
    allowed_phases={'clock','spawn','pipes','selector_create','selector_map','selector_select','event_shape',
        'nonblocking_stdout','nonblocking_stderr','register_stdout','register_stderr','read_stdout','read_stderr',
        'unregister_stdout','unregister_stderr','wait_clock','wait','poll','terminate','wait_after_terminate',
        'kill','wait_after_kill','selector_close','pipe_close_stdout','pipe_close_stderr'}
    def now():
        nonlocal last
        value=io['now']()
        need(type(value)in (int,float) and value==value and abs(value)!=float('inf')
             and (last is None or value>=last),'build_entry.capture_clock')
        last=value;return value
    def error(phase,exc):
        need(phase in allowed_phases,'build_entry.capture_phase')
        if len(result['errors'])<16:
            number=exc.errno if isinstance(exc,OSError) and type(exc.errno)is int else None
            code=str(exc) if isinstance(exc,Refusal) and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',str(exc)) else 'native_error'
            result['errors'].append({'phase':phase,'type':type(exc).__name__[:64],
                                    'errno':number,'code':code})
    try:
        deadline=now()+timeout
        phase='spawn';result['spawnOutcome']='unknown';child=io['spawn'](argv)
        result['spawnOutcome']='handle_returned'
        # Register both returned pipes before any subsequent fallible setup.
        phase='pipes';streams={'stdout':child.stdout,'stderr':child.stderr}
        phase='selector_create';selector=io['selector']()
        for label,stream in streams.items():
            phase='nonblocking_'+label;io['nonblocking'](stream.fileno())
            phase='register_'+label;selector.register(stream,selectors.EVENT_READ,label)
        while True:
            phase='selector_map'
            if not selector.get_map():break
            phase='clock'
            left=deadline-now()
            if left<=0:result['timedOut']=True;raise Refusal('build_entry.command_timeout')
            phase='selector_select'
            for key,_ in selector.select(min(left,.05)):
                phase='event_shape';need(key.data in ('stdout','stderr'),'build_entry.capture_stream')
                phase='read_'+key.data
                part=io['read'](key.fileobj.fileno(),65536)
                need(type(part)is bytes,'build_entry.capture_stream')
                if not part:
                    eof.add(key.data);phase='unregister_'+key.data;selector.unregister(key.fileobj);continue
                label=key.data;need(label in raws and type(part)is bytes,'build_entry.capture_stream')
                raws[label].extend(part)
                need(len(raws[label])<=(capout if label=='stdout' else caperr),'build_entry.command_output_cap')
        phase='wait_clock';left=deadline-now()
        if left<=0:result['timedOut']=True;raise Refusal('build_entry.command_timeout')
        phase='wait'
        code=child.wait(timeout=left)
        need(type(code)is int,'build_entry.command_exit');result['exitCode']=code
    except BaseException as exc:
        if isinstance(exc,subprocess.TimeoutExpired):result['timedOut']=True
        error(phase,exc)
    finally:
        settled=child is None
        if child is not None:
            code=None
            try:code=child.poll()
            except BaseException as exc:error('poll',exc)
            if code is None:
                try:child.terminate()
                except BaseException as exc:error('terminate',exc)
                try:code=child.wait(timeout=5)
                except BaseException as exc:error('wait_after_terminate',exc)
            if code is None:
                try:child.kill()
                except BaseException as exc:error('kill',exc)
                try:code=child.wait(timeout=5)
                except BaseException as exc:error('wait_after_kill',exc)
            settled=type(code)is int
            if settled and result['exitCode']is None:result['exitCode']=code
        closed=True
        if selector is not None:
            try:selector.close()
            except BaseException as exc:closed=False;error('selector_close',exc)
        for label,stream in streams.items():
            try:stream.close()
            except BaseException as exc:closed=False;error('pipe_close_'+label,exc)
        result['ownedChildExited']=child is not None and settled
        result['ownershipRetained']=((child is not None and (not settled or not closed)) or
                                    child is None and result['spawnOutcome']=='unknown')
        result['captureComplete']=(child is not None and settled and closed and eof=={'stdout','stderr'}
                                   and not result['errors'] and not result['timedOut'])
        result['stdout']=bytes(raws['stdout'][:capout]);result['stderr']=bytes(raws['stderr'][:caperr])
        result['streamFacts']={k:{'bytes':len(v),'sha256':sha(bytes(v)),'complete':k in eof}
                               for k,v in raws.items()}
    return result


def tool_row(role,path,ops,installed,show,lists,indexed,alias_evidence=None):
    """Join actual owner/list/version and signed-index archive expectation."""
    # Debian Bookworm still records these two files under /bin or /lib. Keep
    # execution on the fixed /usr path and prove each registered alias is the
    # same immutable inode, owned by the exact signed-index package.
    aliases={'/usr/lib/systemd/systemd':'/lib/systemd/systemd',
             '/usr/bin/systemctl':'/bin/systemctl','/usr/bin/mount':'/bin/mount',
             '/usr/bin/umount':'/bin/umount','/usr/bin/findmnt':'/bin/findmnt',
             '/usr/sbin/blkid':'/sbin/blkid'}
    accepted=(path,aliases[path]) if path in aliases else (path,)
    listed=[(name,registered) for name,paths in lists.items() for registered in accepted if registered in paths]
    need(1<=len(listed)<=len(accepted) and len({name for name,_ in listed})==1,'build_entry.tool_filelist')
    original=ops.stat_original(path)
    need(original['type']=='regular' and original['uid']==original['gid']==0
         and original['mode']&0o022==0,'build_entry.tool_identity')
    same=('sourcePath','type','dev','ino','size','uid','gid','mode','mtimeNs','ctimeNs')
    projections=[]
    for name,registered in listed:
        observed=ops.stat_original(registered)
        need(all(observed[k]==original[k] for k in same),'build_entry.tool_alias_identity')
        owner=command_ok(ops.run(('/usr/bin/dpkg-query','--search',registered),10)).decode('utf-8').splitlines()
        need(len(owner)==1 and ': 'in owner[0],'build_entry.tool_owner')
        binary,owned=owner[0].split(': ',1)
        need(owned==registered and binary==show[name]['binaryName'],'build_entry.tool_owner')
        if registered!=path or role in ('mount','umount','findmnt','blkid','git'):
            projections.append({'role':role,'executionPath':path,'packagePath':registered,
                'canonicalPath':original['sourcePath'],'dev':original['dev'],'ino':original['ino'],
                'executionAliasProofSha256':original['aliasProofSha256'],
                'packageAliasProofSha256':observed['aliasProofSha256'],'ownerQuerySha256':sha(canonical(owner))})
    name=listed[0][0];row=show[name]
    key=(name,row['version'],row['architecture'])
    need(key in indexed,'build_entry.tool_unindexed')
    data=ops.read_original(path,64*1024**2)['bytes']
    need(type(data)is bytes and len(data)==original['size'],'build_entry.tool_size')
    need(ops.stat_original(path)==original,'build_entry.tool_changed')
    if alias_evidence is not None:alias_evidence.extend(projections)
    return {'role':role,'path':path,'bytes':len(data),'sha256':sha(data),'package':name,
            'version':row['version'],'debSha256':indexed[key]['sha256']}


def verify_metadata(ops,header,source_sha,leaves):
    """Fresh fixed-call cryptographic verification, never a saved verdict."""
    archive,policy=leaves['archive'],leaves['policy']
    descriptor=ops.read(CONTROL+'/apt-export.json',8*1024**2)
    data={n:ops.read(DATA+'/'+n,64*1024**2 if n in ('Packages','SecurityPackages') else 2*1024**2) for n in FIXED_DATA}
    need(archive.SECURITY_PROOF_FIELDS<=set(decode(data['guard-proof.json'])),
         'build_entry.security_export_required')
    joined=archive.verify_export(descriptor,data,expected_keyring_sha256=header['keyringSha256'],
                                  expected_source_manifest_sha256=source_sha,expected_build_id=header['buildId'])
    result=ops.run(GPG_METADATA,30)
    status=command_ok(result,signature_status=True)
    classified=policy.classify(data['InRelease'],data['Packages'],returncode=result['exitCode'],
        timed_out=result['timedOut'],status=status,checked_at=ops.now())
    second=ops.run(GPG_SECURITY,30);security_status=command_ok(second)
    security=policy.classify_security(data['SecurityInRelease'],data['SecurityPackages'],
        returncode=second['exitCode'],timed_out=second['timedOut'],
        status=security_status,checked_at=ops.now())
    archive.security_python_roots(archive.package_records(data['SecurityPackages'],origin='security'))
    if hasattr(ops,'deferred_gpg_failure'):ops.deferred_gpg_failure=None
    signature={'schema':'ocv-build-signature-v1','exportJoin':joined,'classification':classified,
               'freshGpgStatusSha256':sha(status),'securityClassification':security,
               'freshSecurityGpgStatusSha256':sha(security_status),'sourceManifestSha256':source_sha}
    return data,joined,signature


def parse_installed_filelist(inventory,binary,raw):
    """Preserve the first unexpected public package-list line without admitting it."""
    try:return inventory.parse_listfiles(raw,binary_name=binary)
    except inventory.runtime.Refusal as exc:
        if exc.code in ('inventory.filelist_path','inventory.filelist_diversion'):
            seen=set();previous=None;dash_diversions=set()
            for index,line in enumerate(raw.decode('utf-8','strict').splitlines()):
                if line in ('/.','/'):continue
                if line in inventory.DASH_DIVERSION.values():
                    valid=(binary=='dash' and inventory.DASH_DIVERSION.get(previous)==line and
                           line not in dash_diversions)
                    dash_diversions.add(line)
                else:
                    valid=(line.startswith('/') and '\x00' not in line and
                           posixpath.normpath(line)==line and '..' not in line.split('/') and
                           len(line)<=1024 and line not in seen)
                if not valid:
                    diagnostic={'schema':'ocv-dpkg-filelist-refusal-v1','binaryName':binary,
                                'lineIndex':index,'lineSha256':sha(line.encode()),
                                'line':line if len(line)<=256 and all(32<=ord(c)<127 for c in line) else None}
                    sys.stderr.write(canonical(diagnostic).decode()+'\n')
                    break
                if line not in inventory.DASH_DIVERSION.values():seen.add(line);previous=line
        raise


def export_selinux_repair(ops,data,tools,source_sha,apt_sha,archive):
    """Export one already authenticated cached archive; never install it."""
    records=archive.package_records(data['Packages'])
    row=records.get(('selinux-utils','3.4-1+b6','amd64'))
    filename='pool/main/libs/libselinux/selinux-utils_3.4-1+b6_amd64.deb'
    depends='libc6 (>= 2.34), libpcre2-8-0 (>= 10.22), libselinux1 (>= 3.1~), libsepol2 (>= 3.4)'
    digest='8357d8bfdbde73ff658129c1a6d25a02b4a244bddb2cc444c5a46835e3b8a31f'
    need(type(row)is dict and row['filename']==filename and row['depends']==depends and
         row['bytes']==126432 and row['debSha256']==digest,'build_entry.repair_signed_package')
    matches=[r for r in tools['tools']if r['role']=='selinuxenabled']
    need(len(matches)==1,'build_entry.repair_tool_roster');tool=matches[0]
    need(tool['path']=='/usr/sbin/selinuxenabled' and tool['package']=='selinux-utils' and
         tool['version']=='3.4-1+b6' and tool['debSha256']==digest and tool['bytes']==14576 and
         tool['sha256']=='2d3c6a10650d380fde19ed7e5b0d80d6a8a99a3d950c1d7f424237a17d609148',
         'build_entry.repair_tool_binding')
    raw=ops.read('/var/cache/apt/archives/selinux-utils_3.4-1+b6_amd64.deb',1048576)
    need(type(raw)is bytes and len(raw)==126432 and sha(raw)==digest,'build_entry.repair_archive')
    need(type(source_sha)is str and re.fullmatch('[0-9a-f]{64}',source_sha) is not None and
         type(apt_sha)is str and re.fullmatch('[0-9a-f]{64}',apt_sha) is not None,
         'build_entry.repair_source')
    manifest={'schema':'ocv-offline-selinux-repair-payload-v1','fixtureOnly':True,
        'privateVmInstallationPerformed':False,
        'package':{'name':'selinux-utils','version':'3.4-1+b6','architecture':'amd64',
            'bytes':126432,'sha256':digest,'filename':filename,'origin':'main',
            'packagesSha256':sha(data['Packages']),'inReleaseSha256':sha(data['InRelease']),
            'depends':depends},
        'tool':{k:tool[k]for k in ('role','path','bytes','sha256')},
        'sourceManifestSha256':source_sha,'aptMetadataManifestSha256':apt_sha}
    encoded=canonical(manifest);need(len(encoded)<=8192,'build_entry.repair_manifest_cap')
    ops.write_once(OUT+'/repair/selinux-utils.deb',raw,0o444)
    ops.write_once(OUT+'/repair/manifest.json',encoded,0o444)
    return manifest


def run_checked(ops,header,source_sha,context_sha,leaves):
    """Concrete transaction, injectable for source-faithful no-command tests.

    leaves are the already source-hash-verified fixed modules; no opaque
    successful step or caller verdict substitutes for these actual functions.
    """
    recipe,runtime,inventory,archive,policy=(leaves[k] for k in ('recipe','runtime','inventory','archive','policy'))
    recipe.package_specs(header['packageRoots'])
    # NativeBuildOps has performed this source-owned fresh check before it
    # exposes package/compiler commands. Injected tests may invoke the same
    # concrete verifier directly; no external JSON can set the native phase.
    data,joined,signature=ops.metadata_inputs()
    signature_sha=sha(canonical(signature));install_sha=joined['firstStageLedgerSha256']
    ops.write_once(CONTROL+'/build-signature.json',canonical(signature),0o444)
    raw_show=command_ok(ops.run(('/usr/bin/dpkg-query','--show','--showformat='+SHOW_FORMAT),30))
    show=inventory.parse_show(raw_show)
    indexes={sha(data[name]):data[name] for name in ('Packages','SecurityPackages')}
    indexed=inventory.parse_packages(indexes)
    main_records=leaves['archive'].package_records(data['Packages'])
    security_records=leaves['archive'].package_records(data['SecurityPackages'],origin='security')
    security_roots=leaves['archive'].security_python_roots(security_records)
    actual_roots={row['name']:row for row in header['packageRoots']}
    need(all(actual_roots.get(row['name'])==row for row in security_roots),
         'build_entry.python_security_roots')
    # Positive exact roots and systemd target checks, not just version strings
    # from a caller manifest. The signed index identifies their archive bytes.
    for row in header['packageRoots']:
        need(row['name']in show and show[row['name']]['version']==row['version'],'build_entry.installed_root')
        ir=show[row['name']];signed=indexed.get((row['name'],row['version'],ir['architecture']))
        need(signed is not None and signed['sha256']==row['sha256'],'build_entry.root_archive')
        origin=security_records if row['name'] in policy.PYTHON_U9 else main_records
        bound=origin.get((row['name'],row['version'],ir['architecture']))
        need(bound is not None and bound['debSha256']==row['sha256'],'build_entry.root_origin')
    filelists={r['binaryName']:command_ok(ops.run(('/usr/bin/dpkg-query','--listfiles',r['binaryName']),10))
               for r in show.values()}
    lists={n:parse_installed_filelist(inventory,r['binaryName'],filelists[r['binaryName']])
           for n,r in show.items()}
    need({n for n,paths in lists.items() if inventory.SITE_CUSTOMIZE in paths}==
         {'libpython3.11-minimal'},'build_entry.site_hook_package')
    primary={p for paths in lists.values() for p in paths if p!=inventory.SITE_CUSTOMIZE and
             (p==runtime.PYTHON or p.startswith(runtime.STDLIB) and
              '__pycache__'not in p.split('/') and not p.endswith('.pyc'))}
    regular={p for p in primary if ops.stat_original(p)['type']=='regular'}
    elf_inputs={p for p in regular if p==runtime.PYTHON or p.endswith('.so')}
    resolutions={p:command_ok(ops.run(('/usr/bin/ldd',p),15)) for p in sorted(elf_inputs)}
    required=set(regular)|set(inventory.TOOL_PATHS)|{runtime.LOADER}
    dependency_paths=set()
    for p,raw in resolutions.items():dependency_paths.update(runtime.parse_ldd(raw,allow_no_dependencies=p!=runtime.PYTHON))
    required.update(dependency_paths)
    ownership={p:required_owner(ops,p,inventory.owner_lookup_path(p,lists,dependency_paths))
               for p in sorted(required)}
    proof=inventory.input_binding(indexes,raw_show,filelists,ownership,resolutions,{},
        context_sha256=context_sha,signature_sha256=signature_sha,install_sha256=install_sha)
    installed,evidence=inventory.build_inventory(indexes,raw_show,filelists,ownership,resolutions,ops,proof,{})
    tool_aliases=[]
    toolchain={'schema':'ocv-toolchain-v1','architecture':'linux-amd64',
        'packageProofSha256':sha(canonical(evidence)),
        'tools':[tool_row(r,p,ops,installed,show,lists,indexed,tool_aliases) for r,p in COMPILER.items()]}
    source=ops.read(ROOT+'/native/static_entry.c',32768)
    helper=build_retained_helper(runtime,source,toolchain,RuntimeOps(ops))
    # The static helper is compiled once. All later joins only revalidate it.
    ops.chmod(CONTROL+'/static-entry',0o555)
    runtime_manifest=runtime.collect_runtime(installed,resolutions,ops,helper)
    for row in runtime_manifest['files']:
        copied=ops.read_original('/'+row['path'],32*1024**2)['bytes']
        need(len(copied)==row['bytes'] and sha(copied)==row['sha256'],'build_entry.export_runtime_changed')
        ops.write_runtime(row['path'],copied,row['mode'])
    helper_raw=ops.read(CONTROL+'/static-entry',8*1024**2)
    need(sha(helper_raw)==helper['sha256'],'build_entry.export_helper_changed')
    ops.write_once(OUT+'/static-entry',helper_raw,0o444)
    tools={'schema':'ocv-tools-v1','tools':[tool_row(r,p,ops,installed,show,lists,indexed,tool_aliases) for r,p in TOOLS.items()]}
    codefiles={}
    for target,source_name in (('ci_protocol.py','ci_protocol.py'),('ci_fixture.py','ci_fixture.py'),
                               ('ci_profile.py','ci_profile.py'),('ci_worker_core.py','ci_worker.py')):
        raw=ops.read(ROOT+'/native/'+source_name,4*1024**2)
        codefiles[target]={'bytes':len(raw),'sha256':sha(raw)}
    imports={'schema':'ocv-imports-v1','codeFiles':codefiles}
    apt={'schema':'ocv-apt-v1','paths':{'release':DATA+'/InRelease','packages':DATA+'/Packages',
         'keyring':DATA+'/keyring.gpg','securityRelease':DATA+'/SecurityInRelease',
         'securityPackages':DATA+'/SecurityPackages'},'keyringSha256':header['keyringSha256'],
         'sourceProofSha256':installed['sourceProofSha256']}
    controls={'runtime':runtime_manifest,'tools':tools,'imports':imports,'apt':apt}
    hashes={}
    for name,value in controls.items():
        raw=canonical(value);ops.write_once(CONTROL+'/'+name+'.json',raw,0o444);hashes[name]=sha(raw)
    export_selinux_repair(ops,data,tools,source_sha,hashes['apt'],archive)
    ops.write_once(CONTROL+'/package-inventory.json',canonical(evidence),0o444)
    ops.write_once(CONTROL+'/helper-proof.json',canonical(helper),0o444)
    ops.write_once(CONTROL+'/tool-aliases.json',canonical({'schema':'ocv-tool-alias-proof-v1','rows':tool_aliases}),0o444)
    kernel=header['kernelPackage'];kv=kernel['name'].removeprefix('linux-image-')
    kernel_path='/boot/vmlinuz-'+kv
    need(kernel_path in lists[kernel['name']],'build_entry.kernel_filelist')
    kernel_raw=ops.read_original(kernel_path,128*1024**2)['bytes']
    context={'schema':'ocv-build-chroot-v1','sourceManifestSha256':source_sha,'buildContextSha256':context_sha,
        'staticEntrySha256':sha(source),'runIdentity':header['runIdentity'],
        'kernel':{'package':kernel['name'],'version':kernel['version'],'kernelVersion':kv,'path':kernel_path,
                  'sha256':sha(kernel_raw),'bytes':len(kernel_raw)},
        'controlHashes':hashes,'outputDirectory':OUT}
    def cached_helper(_context,_ops):
        raw=_ops.read(CONTROL+'/static-entry',8*1024**2)
        need(sha(raw)==helper['sha256'] and len(raw)==helper['bytes'],'build_entry.cached_helper_changed')
        runtime.validate_static_elf(raw)
        return {'path':CONTROL+'/static-entry','bytes':len(raw),'sha256':sha(raw)}
    final=recipe.run_postinstall(context,ops,cached_helper)
    # Package source receipt uses hash joins; missing .deb cache is explicit in
    # inventory evidence, never falsely called archive rehash verification.
    for name in ('runtime','tools','imports','apt','package-inventory','helper-proof','build-signature','tool-aliases'):
        raw=ops.read(CONTROL+'/'+name+'.json',16*1024**2)
        ops.write_once(OUT+'/'+name+'.json',raw,0o444)
    ops.write_once(OUT+'/build-stage-result.json',canonical(final),0o444)
    return final


class RuntimeOps:
    def __init__(self,ops):self.ops=ops
    def read(self,p,cap):return self.ops.read_original(p,cap)['bytes']
    def facts(self):return self.ops.platform_facts()
    def run(self,argv,environment,timeout):
        need(environment=={'PATH':'/usr/bin:/bin','HOME':'/','LANG':'C','LC_ALL':'C'},'build_entry.compiler_environment')
        r=self.ops.run(tuple(argv),timeout)
        command_ok(r)
        return {'returncode':r['exitCode'],'timedOut':r['timedOut'],'stdout':r['stdout'],'stderr':r['stderr']}


class NativeBuildOps:
    """Created only by invoke's independent checks; no public default issuer.

    Its constructor itself repeats actual native/root/path facts. It never
    consumes an approved/status boolean or changes a host/daemon setting.
    """
    def __init__(self,expected_source,expected_context):
        need(os.uname().sysname=='Linux' and os.uname().machine=='x86_64'
             and os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'build_entry.native_target')
        need(__file__==ROOT+'/host/build_entry.py' and os.environ.get('BUILDROOT')=='/'
             and os.environ.get('OUTPUTDIR')==OUT,'build_entry.fixed_chroot')
        self.command_count=0;self.command_evidence=[];self.first_failure=None;self.deferred_gpg_failure=None
        self.metadata_ready=False
        self.source_sha=expected_source;self.context_sha=expected_context
        header_raw=self.read(HEADER,1024**2)
        self.header=validate_header(header_raw,expected_source,expected_context)
        raw=self.read(SOURCE_MANIFEST,1024**2);self.roster=source_roster(raw,expected_source)
        for relative,row in self.roster.items():
            actual=self.read(ROOT+'/'+relative,4*1024**2)
            need(sha(actual)==row['sha256'] and len(actual)==row['bytes'],'build_entry.source_changed')
        osrelease=self.read_original('/usr/lib/os-release',65536)['bytes'].decode('utf-8')
        fields=dict(line.split('=',1) for line in osrelease.splitlines() if '='in line and not line.startswith('#'))
        need(fields.get('ID','').strip('"')=='debian' and fields.get('VERSION_CODENAME','').strip('"')=='bookworm',
             'build_entry.debian_root')
        self.leaves=load_leaves(self)
        try:self._metadata=verify_metadata(self,self.header,expected_source,self.leaves)
        except BaseException:
            if self.deferred_gpg_failure is not None:
                self.preserve_failure('build_entry.gpgv_metadata',self.deferred_gpg_failure)
            raise
        self.metadata_ready=True

    def now(self):return dt.datetime.now(dt.timezone.utc)

    def metadata_inputs(self):
        need(self.metadata_ready is True,'build_entry.metadata_not_verified')
        return self._metadata

    def platform_facts(self):
        u=os.uname()
        return {'platform':u.sysname.lower(),'machine':u.machine,'euid':os.geteuid()}

    def _resolve(self,path):
        need(type(path)is str and path.startswith('/') and str(PurePosixPath(path))==path
             and '..'not in PurePosixPath(path).parts and '\x00'not in path,'build_entry.path')
        pending=list(PurePosixPath(path).parts[1:]);parts=[];chain=[];links=0
        while pending:
            item=pending.pop(0);probe='/'+('/'.join(parts+[item]));s=os.lstat(probe)
            need(s.st_uid==s.st_gid==0 and
                 (stat.S_ISLNK(s.st_mode) or stat.S_IMODE(s.st_mode)&0o022==0),'build_entry.path_owner')
            if stat.S_ISLNK(s.st_mode):
                # Symlink mode0777 is conventional and is not access authority.
                target=os.readlink(probe);links+=1;need(links<=32 and '\x00'not in target,'build_entry.alias')
                chain.append({'path':probe,'dev':s.st_dev,'ino':s.st_ino,'target':target,
                              'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns})
                base=[] if target.startswith('/') else parts[:]
                for name in PurePosixPath(target).parts:
                    if name in ('/','.'):continue
                    if name=='..':need(bool(base),'build_entry.alias_escape');base.pop()
                    else:base.append(name)
                pending=base+pending;parts=[]
            else:
                if pending:need(stat.S_ISDIR(s.st_mode),'build_entry.parent_type')
                parts.append(item)
        resolved='/'+('/'.join(parts))
        allowed=(resolved.startswith(('/usr/','/lib/','/lib64/','/boot/','/opt/ocv/','/etc/apt/','/work/out/')) or
                 path==resolved=='/var/cache/apt/archives/selinux-utils_3.4-1+b6_amd64.deb')
        if not allowed and path.startswith('/usr/lib/python3.11/') and len(path)<=1024 and len(resolved)<=1024:
            sys.stderr.write(canonical({'schema':'ocv-build-root-refusal-v1','packagePath':path,
                                        'resolvedPath':resolved}).decode()+'\n')
        need(allowed,'build_entry.source_root')
        s=os.lstat(resolved)
        return resolved,s,sha(canonical(chain))

    def stat_original(self,path):
        resolved,s,chain=self._resolve(path)
        typ='regular' if stat.S_ISREG(s.st_mode) else 'directory' if stat.S_ISDIR(s.st_mode) else 'other'
        need(typ in ('regular','directory'),'build_entry.file_type')
        return {'sourcePath':resolved,'type':typ,'dev':s.st_dev,'ino':s.st_ino,'size':s.st_size,
            'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'nlink':s.st_nlink,
            'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'aliasProofSha256':chain}

    def read_original(self,path,cap):
        before=self.stat_original(path);need(before['type']=='regular' and before['size']<=cap,'build_entry.read_size')
        raw=self._read_regular(before['sourcePath'],cap,immutable=False)
        need(self.stat_original(path)==before and len(raw)==before['size'],'build_entry.file_changed')
        return {'bytes':raw,'sourcePath':before['sourcePath'],'uid':before['uid'],'gid':before['gid'],
                'mode':before['mode'],'regular':True,'symlinkChainSha256':before['aliasProofSha256']}

    def _read_regular(self,path,cap,immutable=True):
        need(regular_read_cap_allowed(path,cap,immutable,getattr(self,'header',None)),
             'build_entry.read_cap')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            a=os.fstat(fd)
            need(stat.S_ISREG(a.st_mode) and a.st_uid==a.st_gid==0 and stat.S_IMODE(a.st_mode)&0o022==0
                 and (not immutable or stat.S_IMODE(a.st_mode)&0o222==0) and 0<=a.st_size<=cap,
                 'build_entry.read_identity')
            out=bytearray()
            while len(out)<=cap:
                raw=os.read(fd,min(65536,cap+1-len(out)))
                if not raw:break
                out.extend(raw)
            b=os.fstat(fd)
            need(len(out)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==
                 (b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'build_entry.read_changed')
            return bytes(out)
        finally:os.close(fd)

    def read(self,path,cap):
        if path=='/var/cache/apt/archives/selinux-utils_3.4-1+b6_amd64.deb':
            need(getattr(self,'metadata_ready',False)is True,'build_entry.metadata_not_verified')
            need(cap==1048576,'build_entry.repair_read_cap')
            before=self.stat_original(path)
            need(before['sourcePath']==path and before['type']=='regular' and
                 before['nlink']==1 and before['size']<=cap,'build_entry.repair_cache_identity')
            raw=self._read_regular(path,cap,immutable=False)
            need(self.stat_original(path)==before and len(raw)==before['size'],
                 'build_entry.repair_cache_changed')
            return raw
        if path.startswith((ROOT+'/',CONTROL+'/',OUT+'/')):
            resolved,_,_=self._resolve(path)
            need(resolved==path,'build_entry.control_alias')
            return self._read_regular(path,cap,immutable=True)
        need(path.startswith(('/usr/','/lib/','/lib64/','/boot/')),'build_entry.control_path')
        return self.read_original(path,cap)['bytes']

    def facts(self,path):
        info=self.stat_original(path)
        return {'regular':info['type']=='regular','uid':info['uid'],'gid':info['gid'],
                'mode':info['mode'],'bytes':info['size']}

    def chmod(self,path,mode):
        need(path==CONTROL+'/static-entry' and mode==0o555,'build_entry.chmod_path')
        before=self.stat_original(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            s=os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0
                 and (s.st_dev,s.st_ino)==(before['dev'],before['ino']),'build_entry.chmod_identity')
            os.fchmod(fd,mode)
        finally:os.close(fd)

    def write_once(self,path,raw,mode):
        names={'runtime.json','tools.json','imports.json','apt.json','package-inventory.json',
               'helper-proof.json','build-signature.json','build.json','kernel.bin','initrd.img',
               'build-stage-result.json','build-first-failure.json','static-entry','tool-aliases.json'}
        repair=path in (OUT+'/repair/selinux-utils.deb',OUT+'/repair/manifest.json')
        need(type(path)is str and (repair or (path.startswith(CONTROL+'/') or path.startswith(OUT+'/'))
             and path.rsplit('/',1)[1]in names and path.rsplit('/',1)[0]in (CONTROL,OUT))
             and type(raw)is bytes and len(raw)<=512*1024**2 and mode==0o444,'build_entry.write_path')
        if repair:
            need(getattr(self,'metadata_ready',False)is True,'build_entry.metadata_not_verified')
            need(len(raw)<=(1048576 if path.endswith('.deb') else 8192),'build_entry.repair_write_cap')
            parent=OUT+'/repair'
            root=os.lstat(OUT)
            need(os.path.realpath(OUT)==OUT and stat.S_ISDIR(root.st_mode) and
                 root.st_uid==root.st_gid==0 and stat.S_IMODE(root.st_mode)&0o022==0,
                 'build_entry.repair_parent')
            if not os.path.lexists(parent):os.mkdir(parent,0o755)
        parent=path.rsplit('/',1)[0];s=os.lstat(parent)
        need(os.path.realpath(parent)==parent and stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0
             and stat.S_IMODE(s.st_mode)&0o022==0,'build_entry.write_parent')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            view=memoryview(raw)
            while view:
                count=os.write(fd,view);need(count>0,'build_entry.short_write');view=view[count:]
            os.fsync(fd);os.fchmod(fd,mode)
        finally:os.close(fd)

    def write_runtime(self,relative,raw,mode):
        need(type(relative)is str and not relative.startswith('/') and str(PurePosixPath(relative))==relative
             and '..'not in PurePosixPath(relative).parts and relative.startswith(('usr/','lib/','lib64/'))
             and type(raw)is bytes and len(raw)<=32*1024**2 and mode in (0o444,0o555),
             'build_entry.runtime_export')
        base=OUT+'/runtime'
        current=OUT
        for part in ('runtime',*PurePosixPath(relative).parts[:-1]):
            current=current+'/'+part
            try:os.mkdir(current,0o755)
            except FileExistsError:pass
            s=os.lstat(current)
            need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o755,
                 'build_entry.runtime_export_parent')
        target=base+'/'+relative
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            view=memoryview(raw)
            while view:
                count=os.write(fd,view);need(count>0,'build_entry.short_write');view=view[count:]
            os.fsync(fd);os.fchmod(fd,mode)
        finally:os.close(fd)

    def _command_cap(self,argv):
        need(type(argv)is tuple and all(type(a)is str and a and '\x00'not in a for a in argv),'build_entry.argv')
        gpg=GPG_METADATA
        if not self.metadata_ready:
            need(argv in (gpg,GPG_SECURITY),'build_entry.metadata_not_verified')
            return 16384,8192
        if argv==('/usr/bin/dpkg-query','--show','--showformat='+SHOW_FORMAT):return 262144,8192
        if len(argv)==3 and argv[:2]==('/usr/bin/dpkg-query','--listfiles'):
            need(re.fullmatch('[a-z0-9][a-z0-9+.-]{0,80}(?::(?:amd64|all))?',argv[2]),'build_entry.package_arg')
            return 4*1024**2,8192
        if len(argv)==3 and argv[:2]==('/usr/bin/dpkg-query','--search'):
            need((argv[2] in ('/bin/systemctl','/bin/mount','/bin/umount','/bin/findmnt','/sbin/blkid')
                 or argv[2].startswith(('/usr/','/lib/','/lib64/','/boot/')))
                 and '..'not in argv[2].split('/'),
                 'build_entry.owner_arg');return 8192,8192
        if len(argv)==2 and argv[0]=='/usr/bin/ldd':
            need(argv[1]=='/usr/bin/python3.11' or argv[1].startswith('/usr/lib/python3.11/') and argv[1].endswith('.so'),
                 'build_entry.ldd_arg');return 65536,8192
        if argv in (gpg,GPG_SECURITY):return 16384,8192
        if argv[0]=='/usr/bin/gcc-12':
            need(argv==tuple(self.leaves['runtime'].compile_argv()),'build_entry.compile_argv');return 65536,65536
        if len(argv)==4 and argv[0]=='/usr/sbin/update-initramfs' and argv[1]in ('-c','-u') and argv[2]=='-k':
            need(argv[3]==self.header['kernelPackage']['name'].removeprefix('linux-image-'),'build_entry.initrd_argv')
            return 16384,4096
        raise Refusal('build_entry.command_not_allowed')

    def run(self,argv,timeout):
        capout,caperr=self._command_cap(argv)
        need(type(timeout)in (int,float) and 0<timeout<=300 and self.command_count<4096,'build_entry.command_bound')
        self.command_count+=1
        environment={'PATH':'/usr/bin:/bin' if argv[0]=='/usr/bin/gcc-12' else '/usr/bin:/bin:/usr/sbin:/sbin',
                     'HOME':'/','LANG':'C','LC_ALL':'C'}
        def spawn(command):
            return subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env=environment,close_fds=True)
        result=capture_command(argv,timeout,capout,caperr,{
            'spawn':spawn,'now':time.monotonic,'selector':selectors.DefaultSelector,
            'nonblocking':lambda fd:os.set_blocking(fd,False),'read':os.read})
        record={'phase':'build-command','index':self.command_count,'executable':argv[0],
            'argvSha256':sha(canonical(argv)),'exitCode':result['exitCode'],'timedOut':result['timedOut'],
            'environmentSha256':sha(canonical(environment)),
            'captureComplete':result['captureComplete'],'ownedChildExited':result['ownedChildExited'],
            'ownershipRetained':result['ownershipRetained'],'errors':result['errors'],
            'streamFacts':result['streamFacts'],'stderr':result['stderr'][-4096:].decode('utf-8','replace')}
        self.command_evidence.append(record)
        if result['exitCode']!=0 or not result['captureComplete']:
            if deferred_signature_failure(argv,result,self.metadata_ready):
                self.deferred_gpg_failure=record
            else:self.preserve_failure('build_entry.command',record)
        return result

    def preserve_failure(self,phase,detail):
        if self.first_failure is not None:return
        self.first_failure={'schema':'ocv-build-first-failure-v1','phase':phase,'detail':detail,
                            'sourceManifestSha256':self.source_sha,'contextSha256':self.context_sha}
        raw=canonical(self.first_failure)
        try:self.write_once(OUT+'/build-first-failure.json',raw,0o444)
        except OSError:
            # Independent bounded stderr custody survives an artifact-write
            # failure; never replace the actual primary cause with that error.
            try:os.write(2,b'OCV_BUILD_CAUSE_V1:'+raw[:16384]+b'\n')
            except OSError:pass


def load_leaves(ops):
    # All roster files were hashed before any leaf executes. Register only fixed
    # verified source paths, with no caller module/class/factory selection.
    fixed={'recipe':('build_recipe','build/build_recipe.py'),
           'runtime':('runtime_prepare','runtime/runtime_prepare.py'),
           'inventory':('package_inventory','runtime/package_inventory.py'),
           'policy':('archive_policy','apt/archive_policy.py'),
           'archive':('archive_guard','apt/archive_guard.py')}
    out={}
    for key in ('recipe','runtime','inventory','policy','archive'):
        name,relative=fixed[key];need(relative in ops.roster,'build_entry.leaf_not_manifested')
        need(name not in sys.modules,'build_entry.ambient_leaf_module')
        spec=importlib.util.spec_from_file_location(name,ROOT+'/'+relative)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        try:spec.loader.exec_module(module)
        except BaseException:sys.modules.pop(name,None);raise
        out[key]=module
    return out


def synthetic_contract_tests():
    """Pure test entry: no NativeBuildOps construction or native primitives."""
    from types import SimpleNamespace
    total=0
    def check(ok):
        nonlocal total
        if not ok:raise AssertionError('synthetic_contract_failed')
        total+=1
    def rejects(fn):
        try:fn()
        except Refusal:check(True)
        else:check(False)
    source='a'*64
    h={'schema':'ocv-host-build-context-v1','sourceManifestSha256':source,'keyringSha256':'b'*64,
       'buildId':'d'*32,
       'runIdentity':{'repository':'fr-meyer/openclaw','workflowRef':WORKFLOW,'sourceCommit':'c'*40,'runId':'1','runAttempt':'1'},
       'kernelPackage':{'name':'linux-image-6.1.0-39-amd64','version':'1'},'packageRoots':[{}]*16}
    raw=canonical(h);check(validate_header(raw,source,sha(raw))==h)
    rejects(lambda:validate_header(raw,source,'d'*64))
    bad=dict(h,approved=True);rejects(lambda:validate_header(canonical(bad),source,sha(canonical(bad))))
    bad=dict(h,buildId='not-a-session');rejects(lambda:validate_header(canonical(bad),source,sha(canonical(bad))))
    for key,value in (('runId',1),('runId','01'),('runId',True),('runAttempt','2'),('runAttempt',1)):
        bad=dict(h,runIdentity=dict(h['runIdentity'],**{key:value}))
        rejects(lambda:validate_header(canonical(bad),source,sha(canonical(bad))))
    rejects(lambda:decode(b'{"x":1,"x":2}'))
    rejects(lambda:command_ok({'exitCode':0,'timedOut':True,'captureComplete':True,'ownedChildExited':True,
                              'ownershipRetained':False,'stdout':b'{}','stderr':b''}))
    signature={'exitCode':2,'timedOut':False,'captureComplete':True,'ownedChildExited':True,
               'ownershipRetained':False,'stdout':b'bounded-status','stderr':b''}
    check(command_ok(signature,signature_status=True)==signature['stdout'])
    rejects(lambda:command_ok(signature))
    rejects(lambda:command_ok(dict(signature,ownershipRetained=True),signature_status=True))
    check(deferred_signature_failure(GPG_METADATA,dict(signature,errors=[]),False))
    check(not deferred_signature_failure(GPG_METADATA,dict(signature,errors=[]),True))
    check(not deferred_signature_failure(('/usr/bin/gpgv','--status-fd=1'),dict(signature,errors=[]),False))
    check(not deferred_signature_failure(GPG_METADATA,dict(signature,errors=[],captureComplete=False),False))
    check(not deferred_signature_failure(GPG_METADATA,dict(signature,errors=[{'phase':'read'}]),False))
    actual={'platform':'not-linux','machine':'not-x86','euid':9}
    check(RuntimeOps(SimpleNamespace(platform_facts=lambda:actual)).facts()==actual)
    class Stream:
        def __init__(self,fd,fail=False):self.fd=fd;self.closed=False;self.fail=fail
        def fileno(self):return self.fd
        def close(self):self.closed=True;need(not self.fail,'test.close_failure')
    class Child:
        def __init__(self,wait_timeout=False):
            self.stdout=Stream(1);self.stderr=Stream(2);self.code=None;self.stopped=False;self.wait_timeout=wait_timeout
        def poll(self):return self.code
        def wait(self,timeout):
            if self.wait_timeout and not self.stopped:raise subprocess.TimeoutExpired('fake',timeout)
            self.code=0;return 0
        def terminate(self):self.stopped=True
        def kill(self):self.stopped=True
    class Selector:
        def __init__(self,fail_register=False):self.rows={};self.closed=False;self.fail_register=fail_register
        def register(self,stream,events,label):
            need(not self.fail_register,'test.register_failure')
            self.rows[stream]=SimpleNamespace(fileobj=stream,data=label)
        def unregister(self,stream):del self.rows[stream]
        def get_map(self):return self.rows
        def select(self,seconds):return [(v,1) for v in list(self.rows.values())]
        def close(self):self.closed=True
    def fixture(child=None,selector=None,clock=None,raw=None):
        child=Child() if child is None else child;selector=Selector() if selector is None else selector
        queue={1:[b'ok',b''],2:[b'',b'']} if raw is None else raw
        def read(fd,_):return queue[fd].pop(0)
        return child,selector,{'spawn':lambda _:child,'now':(lambda:0) if clock is None else clock,
                             'selector':lambda:selector,'nonblocking':lambda _:None,'read':read}
    child,sel,io=fixture();r=capture_command(('fake',),1,16,16,io)
    check(r['captureComplete'] and r['stdout']==b'ok' and child.stdout.closed and child.stderr.closed and sel.closed)
    child,sel,io=fixture(selector=Selector(fail_register=True));r=capture_command(('fake',),1,16,16,io)
    check(not r['captureComplete'] and r['ownedChildExited'] and child.stopped and child.stdout.closed and child.stderr.closed)
    child,sel,io=fixture(child=Child(wait_timeout=True));r=capture_command(('fake',),1,16,16,io)
    check(r['timedOut'] and not r['captureComplete'] and r['ownedChildExited']
          and r['errors'][0]['phase']=='wait' and r['errors'][0]['errno'] is None)
    child,sel,io=fixture(raw={1:[b'x'*17],2:[b'']});r=capture_command(('fake',),1,16,16,io)
    check(not r['captureComplete'] and r['ownedChildExited'] and len(r['stdout'])==16)
    child=Child();child.stdout.fail=True;child,sel,io=fixture(child=child);r=capture_command(('fake',),1,16,16,io)
    check(not r['captureComplete'] and r['ownershipRetained'] and child.stderr.closed)
    def failed_spawn(_):raise OSError('fake')
    _,_,io=fixture();io['spawn']=failed_spawn;r=capture_command(('fake',),1,16,16,io)
    check(r['spawnOutcome']=='unknown' and r['ownershipRetained'] and not r['captureComplete'])
    def denied_spawn(_):raise PermissionError(13,'DO_NOT_RETAIN_THIS_MESSAGE')
    _,_,io=fixture();io['spawn']=denied_spawn;r=capture_command(('fake',),1,16,16,io)
    check(r['errors'][0]=={'phase':'spawn','type':'PermissionError','errno':13,'code':'native_error'}
          and b'DO_NOT_RETAIN'not in canonical(r['errors']))
    def bad_selector():raise OSError(24,'DO_NOT_RETAIN_THIS_MESSAGE')
    child,_,io=fixture();io['selector']=bad_selector;r=capture_command(('fake',),1,16,16,io)
    check(r['errors'][0]['phase']=='selector_create' and r['errors'][0]['errno']==24
          and child.stdout.closed and child.stderr.closed)
    def bad_nonblocking(_):raise OSError(9,'DO_NOT_RETAIN_THIS_MESSAGE')
    child,_,io=fixture();io['nonblocking']=bad_nonblocking;r=capture_command(('fake',),1,16,16,io)
    check(r['errors'][0]['phase']=='nonblocking_stdout' and r['errors'][0]['errno']==9 and r['ownedChildExited'])
    def bad_read(*_):raise OSError(5,'DO_NOT_RETAIN_THIS_MESSAGE')
    child,_,io=fixture();io['read']=bad_read;r=capture_command(('fake',),1,16,16,io)
    check(r['errors'][0]['phase']=='read_stdout' and r['errors'][0]['errno']==5 and r['ownedChildExited'])
    _,_,io=fixture(raw={1:[None],2:[b'']});r=capture_command(('fake',),1,16,16,io)
    check(not r['captureComplete'] and r['ownedChildExited'])
    stub=SimpleNamespace(metadata_ready=False)
    rejects(lambda:NativeBuildOps._command_cap(stub,('/usr/bin/dpkg-query','--show')))
    check(NativeBuildOps._command_cap(stub,('/usr/bin/gpgv','--status-fd=1','--keyring',DATA+'/keyring.gpg',DATA+'/InRelease'))==(16384,8192))
    class ToolOps:
        def __init__(self):self.wrong_inode=False;self.wrong_owner=False
        def stat_original(self,p):
            return {'sourcePath':'/usr/lib/systemd/systemd','type':'regular','dev':1,
                'ino':99 if self.wrong_inode and p.startswith('/lib/') else 2,'size':4,'uid':0,'gid':0,
                'mode':0o755,'mtimeNs':1,'ctimeNs':1,'aliasProofSha256':('a'if p.startswith('/usr/')else'b')*64}
        def read_original(self,p,cap):return {'bytes':b'tool'}
        def run(self,argv,timeout):
            return {'exitCode':0,'timedOut':False,'captureComplete':True,'ownedChildExited':True,
                'ownershipRetained':False,'stdout':b'systemd: '+
                (b'/usr/lib/systemd/systemd'if self.wrong_owner else b'/lib/systemd/systemd')+b'\n','stderr':b''}
    show={'systemd':{'binaryName':'systemd','version':'252.39-1~deb12u2','architecture':'amd64'}}
    lists={'systemd':{'/lib/systemd/systemd'}}
    indexed={('systemd','252.39-1~deb12u2','amd64'):{'sha256':'d'*64}}
    ops=ToolOps();alias=[];row=tool_row('systemd','/usr/lib/systemd/systemd',ops,None,show,lists,indexed,alias)
    check(row['path']=='/usr/lib/systemd/systemd' and alias[0]['packagePath']=='/lib/systemd/systemd')
    ops=ToolOps();ops.wrong_inode=True
    rejects(lambda:tool_row('systemd','/usr/lib/systemd/systemd',ops,None,show,lists,indexed,[]))
    ops=ToolOps();ops.wrong_owner=True
    rejects(lambda:tool_row('systemd','/usr/lib/systemd/systemd',ops,None,show,lists,indexed,[]))
    return {'schema':'ocv-build-entry-synthetic-tests-v1','passed':total,'nativeOpsConstructed':False,
            'nativeCommandExecuted':False,'linuxProof':False}


def invoke(expected_source_sha,expected_context_sha):
    ops=None
    try:
        ops=NativeBuildOps(expected_source_sha,expected_context_sha)
        return run_checked(ops,ops.header,expected_source_sha,expected_context_sha,ops.leaves)
    except BaseException as exc:
        code=str(exc) if isinstance(exc,(Refusal,ValueError,RuntimeError)) and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',str(exc)) else 'build_entry.failure'
        if ops is not None:
            ops.preserve_failure('build-entry',{'code':code,'type':type(exc).__name__})
        else:
            # No NativeBuildOps escaped a failed constructor. Preserve only
            # fixed/redacted admission facts, and only in the actual expected
            # build chroot/output. An ordinary local import/CLI writes nothing.
            try:
                if (os.uname().sysname=='Linux' and os.geteuid()==0 and __file__==ROOT+'/host/build_entry.py'
                    and os.environ.get('BUILDROOT')=='/' and os.environ.get('OUTPUTDIR')==OUT):
                    s=os.lstat(OUT)
                    need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0
                         and stat.S_IMODE(s.st_mode)&0o022==0,'build_entry.failure_output')
                    raw=canonical({'schema':'ocv-build-first-failure-v1','phase':'build-context-admission',
                        'detail':{'code':code,'type':type(exc).__name__},
                        'sourceManifestSha256':expected_source_sha if digest(expected_source_sha) else None,
                        'contextSha256':expected_context_sha if digest(expected_context_sha) else None})
                    fd=os.open(OUT+'/build-first-failure.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                    try:
                        view=memoryview(raw)
                        while view:
                            count=os.write(fd,view);need(count>0,'build_entry.short_write');view=view[count:]
                        os.fsync(fd);os.fchmod(fd,0o444)
                    finally:os.close(fd)
            except BaseException:
                # Root outer command capture separately retains this original
                # exception; a custody error is never success or a retry cue.
                pass
        raise


if __name__=='__main__':
    raise SystemExit('build_entry_requires_literal_checked_mkosi_shim')
