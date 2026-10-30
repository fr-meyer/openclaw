"""Pack only explicit public source/runtime/proof bytes; never an OS image."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path,PurePosixPath
import stat
import tarfile

CONTROLS=('build.json','runtime.json','tools.json','imports.json','apt.json','package-inventory.json',
          'helper-proof.json','build-signature.json','tool-aliases.json','build-stage-result.json','apt-export.json')
APT_FILES=('InRelease','Packages','keyring.gpg','gpgv-status.txt','guard-proof.json','first-stage-ledger.json',
           'SecurityInRelease','SecurityPackages','security-gpgv-status.txt','security-guard-proof.json')
REPAIR_SCHEMA='ocv-offline-selinux-repair-payload-v1'
REPAIR_MANIFEST_CAP=8192
REPAIR_PACKAGE_CAP=1048576
REPAIR_PACKAGE_BYTES=126432
REPAIR_PACKAGE_SHA256='8357d8bfdbde73ff658129c1a6d25a02b4a244bddb2cc444c5a46835e3b8a31f'
REPAIR_PACKAGE_DEPENDS='libc6 (>= 2.34), libpcre2-8-0 (>= 10.22), libselinux1 (>= 3.1~), libsepol2 (>= 3.4)'
REPAIR_TOOL_BYTES=14576
REPAIR_TOOL_SHA256='2d3c6a10650d380fde19ed7e5b0d80d6a8a99a3d950c1d7f424237a17d609148'


class Refusal(ValueError):pass


def require(ok,why):
    if not ok:raise Refusal(why)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def read(path,cap):
    p=Path(path);require(p.is_absolute() and p.resolve()==p,'artifact.path')
    before=p.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid in(0,os.getuid()) and
            not before.st_mode&0o022 and 0<=before.st_size<=cap,'artifact.identity')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(fd);data=b''
        while len(data)<=cap:
            part=os.read(fd,min(1048576,cap+1-len(data)))
            if not part:break
            data+=part
        after=os.fstat(fd)
    finally:os.close(fd)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    require(identity(before)==identity(opened)==identity(after)==identity(p.lstat()) and len(data)==before.st_size,
            'artifact.changed')
    return data


def safe_name(value):
    require(type(value)is str,'artifact.name')
    p=PurePosixPath(value)
    require(not p.is_absolute() and str(p)==value and '..'not in p.parts and value and len(value)<=256,'artifact.name')
    return value


def repair_payload(out,control,apt_data,source_manifest):
    """One public package export, never an installer or a generic file picker.

    The build owner already authenticated the archive bytes against MAIN's
    signed package record. This packaging join binds that same exact returned
    payload/tool record into the existing tooling subject and rejects drift.
    """
    raw=read(out/'repair/manifest.json',REPAIR_MANIFEST_CAP)
    def pairs(items):
        result={}
        for key,item in items:
            require(key not in result,'artifact.repair_duplicate_key')
            result[key]=item
        return result
    try:value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(
        _ for _ in ()).throw(Refusal('artifact.repair_nonfinite')))
    except Refusal:raise
    except (ValueError,UnicodeError):raise Refusal('artifact.repair_manifest')from None
    require(type(value)is dict and set(value)=={'schema','fixtureOnly',
        'privateVmInstallationPerformed','package','tool','sourceManifestSha256',
        'aptMetadataManifestSha256'} and value['schema']==REPAIR_SCHEMA and
        value['fixtureOnly']is True and value['privateVmInstallationPerformed']is False,
        'artifact.repair_manifest')
    package=value['package'];tool=value['tool'];build=json.loads(control['build.json'])
    require(type(package)is dict and set(package)=={'name','version','architecture',
        'bytes','sha256','filename','origin','packagesSha256','inReleaseSha256','depends'} and
        package['name']=='selinux-utils' and package['version']=='3.4-1+b6' and
        package['architecture']=='amd64' and package['origin']=='main' and
        package['filename']=='pool/main/libs/libselinux/selinux-utils_3.4-1+b6_amd64.deb' and
        type(package['bytes'])is int and package['bytes']==REPAIR_PACKAGE_BYTES and
        package['sha256']==REPAIR_PACKAGE_SHA256 and package['depends']==REPAIR_PACKAGE_DEPENDS and
        type(package['depends'])is str and 0<len(package['depends'])<=4096 and
        all(32<=ord(ch)<127 for ch in package['depends']), 'artifact.repair_package')
    require(type(tool)is dict and set(tool)=={'role','path','bytes','sha256'} and
        tool['role']=='selinuxenabled' and tool['path']=='/usr/sbin/selinuxenabled' and
        type(tool['bytes'])is int and tool['bytes']==REPAIR_TOOL_BYTES and
        tool['sha256']==REPAIR_TOOL_SHA256,
        'artifact.repair_tool')
    require(all(type(digest)is str and len(digest)==64 and
        all(ch in '0123456789abcdef'for ch in digest)for digest in
        (package['sha256'],package['packagesSha256'],package['inReleaseSha256'],tool['sha256'])),
        'artifact.repair_hash_shape')
    require(value['sourceManifestSha256']==sha(source_manifest) and
        value['aptMetadataManifestSha256']==build.get('aptMetadataManifestSha256') and
        type(value['aptMetadataManifestSha256'])is str and
        len(value['aptMetadataManifestSha256'])==64 and
        all(ch in '0123456789abcdef'for ch in value['aptMetadataManifestSha256']),
        'artifact.repair_build_join')
    require(package['packagesSha256']==sha(apt_data['Packages']) and
        package['inReleaseSha256']==sha(apt_data['InRelease']), 'artifact.repair_origin_join')
    import archive_guard
    try:records=archive_guard.package_records(apt_data['Packages'])
    except archive_guard.Refusal:raise Refusal('artifact.repair_signed_record')from None
    signed=records.get(('selinux-utils','3.4-1+b6','amd64'))
    require(type(signed)is dict and signed['filename']==package['filename'] and
        signed['bytes']==package['bytes'] and signed['debSha256']==package['sha256'] and
        signed.get('depends')==package['depends'],'artifact.repair_signed_record')
    catalog=json.loads(control['tools.json'])
    require(type(catalog)is dict and catalog.get('schema')=='ocv-tools-v1' and
        type(catalog.get('tools'))is list,'artifact.repair_catalog')
    matches=[row for row in catalog['tools']if type(row)is dict and row.get('role')=='selinuxenabled']
    require(len(matches)==1,'artifact.repair_catalog')
    expected=matches[0]
    require(all(expected.get(key)==tool[key]for key in ('role','path','bytes','sha256')) and
        expected.get('package')==package['name'] and expected.get('version')==package['version'] and
        expected.get('debSha256')==package['sha256'],'artifact.repair_catalog_join')
    package_raw=read(out/'repair/selinux-utils.deb',REPAIR_PACKAGE_CAP)
    require(len(package_raw)==package['bytes'] and sha(package_raw)==package['sha256'],
        'artifact.repair_payload_changed')
    return {'repair/manifest.json':raw,'repair/selinux-utils.deb':package_raw}


class CappedWriter:
    def __init__(self,stream,maximum):self.stream=stream;self.maximum=maximum;self.count=0
    def write(self,raw):
        require(self.count+len(raw)<=self.maximum,'artifact.compressed_cap')
        size=self.stream.write(raw);require(size==len(raw),'artifact.short_write');self.count+=size;return size
    def flush(self):return self.stream.flush()
    def tell(self):return self.count


def package(source,out,destination,*,source_rows,manifest_raw,maximum):
    source,out,destination=Path(source),Path(out),Path(destination)
    require(type(maximum)is int and 0<maximum<=60*1024**2,'artifact.cap')
    require(not destination.exists() and destination.parent.resolve()==destination.parent,'artifact.destination')
    payload={};total=0
    def add(name,data,mode=0o444):
        nonlocal total
        safe_name(name);require(name not in payload and type(data)is bytes and mode in(0o444,0o555),'artifact.row')
        total+=len(data);require(total<=384*1024**2 and len(payload)<10000,'artifact.total')
        payload[name]=(data,mode)
    for name,row in sorted(source_rows.items()):
        safe_name(name);data=read(source/name,row['bytes']+1)
        require(len(data)==row['bytes'] and sha(data)==row['sha256'],'artifact.source_hash')
        add('source/'+name,data)
    add('source/PUBLIC-SOURCE-MANIFEST.json',manifest_raw)
    control={}
    for name in CONTROLS:
        raw=read(out/name,1048576);control[name]=raw;add('control/'+name,raw)
    apt_data={}
    for name in APT_FILES:
        apt_data[name]=read(out/'apt-data'/name,64*1024**2)
        add('control/apt-data/'+name,apt_data[name])
    for name,raw in repair_payload(out,control,apt_data,manifest_raw).items():add(name,raw)
    runtime=json.loads(control['runtime.json'])
    require(type(runtime)is dict and type(runtime.get('files'))is list,'artifact.runtime')
    for row in runtime['files']:
        require(type(row)is dict and {'path','bytes','sha256','mode'}<=set(row),'artifact.runtime_row')
        name=safe_name(row['path']);data=read(out/'runtime'/name,row['bytes']+1)
        require(len(data)==row['bytes'] and sha(data)==row['sha256'],'artifact.runtime_hash')
        add('runtime/'+name,data,row['mode'])
    helper=read(out/'static-entry',1048576);build=json.loads(control['build.json'])
    require(sha(helper)==build['helperSha256'],'artifact.helper_hash');add('static-entry',helper,0o555)
    rows=[{'path':name,'bytes':len(data),'sha256':sha(data),'mode':mode}for name,(data,mode)in sorted(payload.items())]
    manifest=canonical({'schema':'ocv-public-tooling-v1','fixtureOnly':True,'candidateImage':False,'files':rows})
    add('PUBLIC-TOOLING-MANIFEST.json',manifest)
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:
        capped=CappedWriter(stream,maximum)
        with gzip.GzipFile(fileobj=capped,mode='wb',mtime=0,filename='')as compressed:
            with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.PAX_FORMAT)as archive:
                for name,(data,mode)in sorted(payload.items()):
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode;info.uid=info.gid=0;info.mtime=0
                    archive.addfile(info,io.BytesIO(data))
        stream.flush();os.fsync(stream.fileno())
    require(destination.stat().st_size<=maximum,'artifact.compressed_cap')
    return {'schema':'ocv-public-tooling-package-result-v1','files':len(payload),'rawBytes':total,
            'bytes':destination.stat().st_size,'sha256':sha(read(destination,maximum)),
            'toolingManifestSha256':sha(manifest),'OSImageIncluded':False,'candidateImageIncluded':False}


if __name__=='__main__':raise SystemExit('inert_requires_checked_ci_owner')
