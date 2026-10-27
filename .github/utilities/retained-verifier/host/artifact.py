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
APT_FILES=('InRelease','Packages','keyring.gpg','gpgv-status.txt','guard-proof.json','first-stage-ledger.json')


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
    for name in APT_FILES:add('control/apt-data/'+name,read(out/'apt-data'/name,64*1024**2))
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
