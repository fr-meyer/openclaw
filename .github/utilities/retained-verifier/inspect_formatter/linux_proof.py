"""Actual pinned CLI formatters against one synthetic UNIX inspect endpoint.

No Docker daemon, container, image, database or host socket is used. The outer
source-owned host context owns this mount/network/PID namespace and its cleanup.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

DOCKER_BYTES=44260160
DOCKER_SHA='6f7a95d27f98fc8c5f6b220898988bf8f61dd9b040936797917cbdc72c6cabe6'
CID='a'*64
API='1.53'
OUTPUT_CAP=16384
ERROR_CAP=4096
REQUEST_CAP=8192
RESPONSE_CAP=65536
CASE_SECONDS=5
CLEANUP_SECONDS=2
WHOLE_SECONDS=120
NORMAL_SHA='15faa49589584e0c198f6794488e5c3c9855a23ac6e45ff1979a68f3cd4fbde4'
PRIOR_SHA='4bfd502bc12b74ddc66f6c12227ba659490d03b39d68a236309b608bc35aca34'
LEAVES=('linux_proof.py','normal-inspect-template.txt','prior-inspect-template.txt')
HOST_FIELDS=('NetworkMode','ReadonlyRootfs','Privileged','CapDrop','CapAdd','SecurityOpt',
 'PidMode','IpcMode','UTSMode','UsernsMode','Runtime','Binds','VolumesFrom','Devices',
 'DeviceRequests','DeviceCgroupRules','PortBindings','PublishAllPorts','LogConfig',
 'PidsLimit','Memory','MemorySwap','NanoCpus','Tmpfs','Mounts')


def need(value,code):
    if value is not True:raise RuntimeError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def compact(value):return json.dumps(value,separators=(',',':'),allow_nan=False).encode('ascii')


def fixture():
    declared=[];actual=[]
    for n in range(36):
        prefix='/synthetic-owned-source/'+str(n).zfill(2)+'/'
        source=prefix+'s'*(192-len(prefix))
        target='/metadata/db-'+str(n).zfill(2)+'/main.sqlite'
        declared.append({'Type':'bind','Source':source,'Target':target,'ReadOnly':True})
        actual.append({'Type':'bind','Source':source,'Destination':target,'Mode':'ro',
                       'RW':False,'Propagation':'rprivate','Driver':'local','Name':''})
    host={'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],
      'CapAdd':None,'SecurityOpt':['no-new-privileges'],'PidMode':'','IpcMode':'private',
      'UTSMode':'','UsernsMode':'','Runtime':'runc','Binds':None,'VolumesFrom':None,
      'Devices':None,'DeviceRequests':None,'DeviceCgroupRules':None,'PortBindings':{},
      'PublishAllPorts':False,'LogConfig':{'Type':'none','Config':{}},'PidsLimit':64,
      'Memory':268435456,'MemorySwap':268435456,'NanoCpus':1000000000,'Mounts':declared,
      'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'AutoRemove':False}
    return {'Id':CID,'Name':'/synthetic-formatter-fixture','Image':'sha256:'+'b'*64,
      'ImageManifestDescriptor':{'mediaType':'application/vnd.oci.image.manifest.v1+json',
        'digest':'sha256:'+'c'*64,'size':8824,'platform':{'architecture':'amd64','os':'linux'}},
      'Config':{'Hostname':'synthetic','Domainname':'','User':'1000:1000','AttachStdin':False,
        'AttachStdout':True,'AttachStderr':True,'ExposedPorts':{},'Tty':False,'OpenStdin':False,
        'StdinOnce':False,'Env':['PATH=/usr/bin:/bin','LANG=C','LC_ALL=C','HOME=/nonexistent'],
        'Cmd':['/usr/bin/false'],'Image':'synthetic:formatter-fixture','Volumes':None,
        'WorkingDir':'/','Entrypoint':None,'OnBuild':None,
        'Labels':{'synthetic.fixture':'formatter-only','synthetic.padding':'x'*512}},
      'State':{'Status':'created','Running':False,'Paused':False,'Restarting':False,
        'OOMKilled':False,'Dead':False,'Pid':0,'ExitCode':0,'Error':'',
        'StartedAt':'0001-01-01T00:00:00Z','FinishedAt':'0001-01-01T00:00:00Z'},
      'RestartCount':0,'HostConfig':host,'Mounts':actual}


def projected(value,prior=False):
    """Pure expectation for synthetic assertions; never used as CLI evidence."""
    result={key:copy.deepcopy(value[key])for key in
            ('Id','Name','Image','ImageManifestDescriptor','Config','State')}
    result['Mounts']=[[row['Type'],row['Destination'],row['RW'],row['Propagation'],
      any(m['Source']==row['Source'] and m['Target']==row['Destination']
          for m in value['HostConfig']['Mounts'])]for row in value['Mounts']]
    result['HostConfig']={key:copy.deepcopy(value['HostConfig'].get(key))for key in HOST_FIELDS}
    if prior:
        result['RestartCount']=value['RestartCount']
        for key in ('RestartPolicy','AutoRemove'):
            result['HostConfig'][key]=copy.deepcopy(value['HostConfig'][key])
    return result


def request_route(raw):
    need(type(raw)is bytes and len(raw)<=REQUEST_CAP and raw.endswith(b'\r\n\r\n'),
         'formatter.request_bound')
    lines=raw[:-4].split(b'\r\n');first=lines.pop(0).decode('ascii').split(' ')
    need(len(first)==3 and first[2]=='HTTP/1.1','formatter.request_line')
    method,path=first[:2];headers={}
    for line in lines:
        key,sep,value=line.partition(b':');key=key.decode('ascii').lower()
        need(sep==b':' and key and key not in headers,'formatter.request_headers')
        headers[key]=value.strip().decode('ascii')
    need(not any(k in headers for k in ('authorization','proxy-authorization','transfer-encoding'))
         and headers.get('content-length','0')=='0','formatter.request_body_or_auth')
    need((method in ('HEAD','GET') and path=='/_ping') or
         (method=='GET' and path=='/v'+API+'/containers/'+CID+'/json'),
         'formatter.request_route')
    return method,path


class InspectServer:
    """One bounded synthetic resource, not a Docker API implementation."""
    def __init__(self,path,body,end):
        need(len(body)<=RESPONSE_CAP,'formatter.response_bound')
        self.path=path;self.body=body;self.end=end;self.stop=threading.Event()
        self.requests=[];self.errors=[];self.opened=0;self.closed=0
        self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            self.socket.bind(str(path));os.chmod(path,0o600)
            self.socket.listen(4);self.socket.settimeout(.05)
            self.thread=threading.Thread(target=self.serve,name='owned-synthetic-inspect')
            self.thread.start()
        except BaseException:
            self.socket.close()
            if path.exists():path.unlink()
            raise

    def serve(self):
        try:
            while not self.stop.is_set() and time.monotonic()<self.end:
                try:connection,_=self.socket.accept()
                except socket.timeout:continue
                self.opened+=1
                try:
                    need(self.opened<=4,'formatter.request_count');connection.settimeout(.2)
                    raw=b''
                    while not raw.endswith(b'\r\n\r\n'):
                        need(not self.stop.is_set() and time.monotonic()<self.end,
                             'formatter.server_deadline')
                        chunk=connection.recv(min(1024,REQUEST_CAP+1-len(raw)))
                        need(bool(chunk) and len(raw)+len(chunk)<=REQUEST_CAP,'formatter.request_bound')
                        raw+=chunk
                    method,path=request_route(raw);self.requests.append((method,path))
                    if path=='/_ping':
                        body=b'OK';extra=b'Api-Version: 1.53\r\nOstype: linux\r\nDocker-Experimental: false\r\n'
                    else:body=self.body;extra=b'Content-Type: application/json\r\n'
                    response=(b'HTTP/1.1 200 OK\r\nConnection: close\r\n'+extra+
                              b'Content-Length: '+str(len(body)).encode()+b'\r\n\r\n')
                    connection.sendall(response+(b'' if method=='HEAD'else body))
                except BaseException:self.errors.append('formatter.server_refused')
                finally:connection.close();self.closed+=1
        except BaseException:self.errors.append('formatter.server_failed')

    def close(self):
        self.stop.set();self.thread.join(.5);self.socket.close()
        if self.path.exists():self.path.unlink()
        need(not self.thread.is_alive() and self.opened==self.closed and not self.path.exists(),
             'formatter.server_custody')
        need(not self.errors and 1<=len(self.requests)<=4 and
             sum(path.endswith('/json')for _,path in self.requests)==1 and
             self.requests[0][1]=='/_ping' and self.requests[-1]==('GET','/v'+API+'/containers/'+CID+'/json'),
             'formatter.server_requests')


def group_absent(pid):
    try:os.killpg(pid,0)
    except ProcessLookupError:return True
    return False


def cli_capture(argv,environment,end):
    """Only an owned CLI process group; overflow/timeout always refuse."""
    child=None;selector=selectors.DefaultSelector();streams={};data={'stdout':bytearray(),'stderr':bytearray()}
    failed=None;reaped=False;closed=False
    try:
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
          env=environment,start_new_session=True,close_fds=True)
        for name,cap in (('stdout',OUTPUT_CAP),('stderr',ERROR_CAP)):
            stream=getattr(child,name);os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,(name,cap));streams[name]=stream
        while selector.get_map() or child.poll()is None:
            need(time.monotonic()<end,'formatter.cli_deadline')
            for key,_ in selector.select(min(.03,max(0,end-time.monotonic()))):
                name,cap=key.data;raw=os.read(key.fileobj.fileno(),4096)
                if not raw:selector.unregister(key.fileobj);continue
                need(len(data[name])+len(raw)<=cap,'formatter.cli_output_bound');data[name].extend(raw)
        child.wait(timeout=.1);reaped=True
    except BaseException as error:failed=error
    finally:
        cleanup_end=time.monotonic()+CLEANUP_SECONDS
        if child is not None:
            if not group_absent(child.pid):
                try:os.killpg(child.pid,signal.SIGTERM)
                except ProcessLookupError:pass
            try:child.wait(timeout=max(.01,min(.2,cleanup_end-time.monotonic())));reaped=True
            except subprocess.TimeoutExpired:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=max(.01,cleanup_end-time.monotonic()));reaped=True
            # Drain all owned pipes even on refusal; retain at most each cap.
            while selector.get_map() and time.monotonic()<cleanup_end:
                for key,_ in selector.select(.01):
                    name,cap=key.data;raw=os.read(key.fileobj.fileno(),4096)
                    if not raw:selector.unregister(key.fileobj);continue
                    if len(data[name])+len(raw)>cap:failed=RuntimeError('formatter.cli_output_bound')
                    data[name].extend(raw[:max(0,cap-len(data[name]))])
            eof=not selector.get_map()
            for stream in streams.values():stream.close()
            closed=all(stream.closed for stream in streams.values())
            need(reaped and group_absent(child.pid) and eof and closed,'formatter.cli_custody')
        selector.close()
    if failed is not None:raise failed
    need(child is not None and reaped and closed,'formatter.cli_spawn')
    return {'returncode':child.returncode,'stdout':bytes(data['stdout']),'stderr':bytes(data['stderr']),
            'reaped':True,'groupAbsent':True,'streamsEOF':True,'streamsClosed':True}


def run_case(docker,work,template,value,end):
    need(time.monotonic()<end-CLEANUP_SECONDS-1,'formatter.whole_deadline')
    case=work/('case-'+str(len(tuple(work.iterdir()))).zfill(2));case.mkdir(mode=0o700)
    config=case/'config';config.mkdir(mode=0o700);sock=case/'inspect.sock'
    server=InspectServer(sock,compact(value),min(end,time.monotonic()+CASE_SECONDS+CLEANUP_SECONDS))
    try:
        actual=cli_capture([str(docker),'--config',str(config),'--host','unix://'+str(sock),
          'inspect','--format',template,CID],
          {'PATH':'/usr/bin:/bin','HOME':str(config),'LANG':'C','LC_ALL':'C',
           'DOCKER_CLI_HINTS':'false'},min(end-CLEANUP_SECONDS-1,time.monotonic()+CASE_SECONDS))
    finally:server.close()
    need(not tuple(config.iterdir()),'formatter.config_written')
    config.rmdir();case.rmdir()
    return actual


def decode(actual):
    need(actual['returncode']==0 and actual['stderr']==b'' and
         actual['stdout'].endswith(b'\n'),'formatter.positive_capture')
    return json.loads(actual['stdout'])


def verify_source(here,pin):
    raw=(here/'SOURCE-MANIFEST.json').read_bytes();need(len(raw)<=8192 and sha(raw)==pin,'formatter.source_manifest')
    manifest=json.loads(raw);need(type(manifest)is dict and set(manifest)=={'schema','files'} and
       manifest['schema']=='ocv.generic-docker-inspect-formatter-proof-source.v1' and
       [r['path']for r in manifest['files']]==sorted(LEAVES),'formatter.source_roster')
    for row in manifest['files']:
        need(type(row)is dict and set(row)=={'path','bytes','sha256'},'formatter.source_row')
        path=here/row['path'];fact=path.lstat();raw=path.read_bytes()
        need(stat.S_ISREG(fact.st_mode) and not path.is_symlink() and fact.st_nlink==1 and
             fact.st_size==row['bytes']==len(raw) and sha(raw)==row['sha256'],'formatter.source_changed')
    normal=(here/'normal-inspect-template.txt').read_bytes();prior=(here/'prior-inspect-template.txt').read_bytes()
    need(sha(normal)==NORMAL_SHA and sha(prior)==PRIOR_SHA,'formatter.template_identity')
    return normal.decode('ascii'),prior.decode('ascii')


def namespace_facts():
    need(sys.platform=='linux' and os.geteuid()==0 and os.getpid()==1,'formatter.namespace_role')
    devices=Path('/proc/net/dev').read_text();need(len(devices)<=65536,'formatter.net_bound')
    need({line.split(':',1)[0].strip()for line in devices.splitlines()if ':'in line}<={'lo'},'formatter.network')
    routes=Path('/proc/net/route').read_text();need(len(routes)<=65536,'formatter.route_bound')
    need(all(line.split()[0]=='lo' and line.split()[1]=='00000000' and line.split()[2]=='00000000'
             for line in routes.splitlines()[1:]if line.strip()),'formatter.routes')
    routes6=Path('/proc/net/ipv6_route').read_text();need(len(routes6)<=65536,'formatter.route6_bound')
    for line in routes6.splitlines():
        fields=line.split();need(len(fields)==10 and fields[-1]=='lo' and
          fields[0]in('0'*32,'0'*31+'1') and fields[4]=='0'*32,'formatter.routes6')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--docker',required=True)
    parser.add_argument('--source-manifest-sha256',required=True);args=parser.parse_args()
    namespace_facts();end=time.monotonic()+WHOLE_SECONDS
    here=Path(__file__).resolve().parent;normal,prior=verify_source(here,args.source_manifest_sha256)
    docker=Path(args.docker);fact=docker.lstat()
    need(stat.S_ISREG(fact.st_mode) and not docker.is_symlink() and fact.st_nlink==1 and
      fact.st_size==DOCKER_BYTES and stat.S_IMODE(fact.st_mode)==0o555 and
      sha(docker.read_bytes())==DOCKER_SHA,'formatter.docker_identity')
    work=Path(tempfile.mkdtemp(prefix='ocv-fmt-',dir='/tmp'));cases=[];maximum=0
    try:
        for name,template in (('normal',normal),('prior',prior)):
            baseline=fixture()
            for variant,tmpfs in (('omitted',None),('null',None),('empty',{}),('nonempty',{'/synthetic':'rw'}),('wrong_type',[])):
                value=copy.deepcopy(baseline)
                if variant!='omitted':value['HostConfig']['Tmpfs']=tmpfs
                actual=run_case(docker,work,template,value,end)
                if variant=='wrong_type' and actual['returncode']!=0:
                    need(bool(actual['stderr']),'formatter.wrong_type_refusal')
                else:
                    got=decode(actual);need(got==projected(value,name=='prior'),'formatter.projection_mismatch')
                    need(got['HostConfig']['Tmpfs']==tmpfs,'formatter.tmpfs_preservation')
                maximum=max(maximum,len(actual['stdout']))
                cases.append({'template':name,'case':variant,'returncode':actual['returncode'],
                              'stdoutBytes':len(actual['stdout']),'stderrBytes':len(actual['stderr'])})
            required=[('HostConfig',),('HostConfig','Runtime'),('HostConfig','Mounts'),('Mounts',)]
            if name=='prior':required+=[('RestartCount',),('HostConfig','RestartPolicy'),('HostConfig','AutoRemove')]
            for path in required:
                value=copy.deepcopy(baseline);owner=value
                for part in path[:-1]:owner=owner[part]
                del owner[path[-1]]
                actual=run_case(docker,work,template,value,end)
                need(actual['returncode']!=0 and bool(actual['stderr']),'formatter.required_field_accepted')
                cases.append({'template':name,'case':'missing_'+'.'.join(path),'returncode':actual['returncode'],
                              'stdoutBytes':len(actual['stdout']),'stderrBytes':len(actual['stderr'])})
            for variant in ('source','rw'):
                value=copy.deepcopy(baseline)
                if variant=='source':value['Mounts'][0]['Source']='/synthetic-substituted'
                else:value['Mounts'][0]['RW']=True
                actual=run_case(docker,work,template,value,end);got=decode(actual)
                need(got==projected(value,name=='prior') and
                  (got['Mounts'][0][4]is False if variant=='source'else got['Mounts'][0][2]is True),
                  'formatter.negative_atom_lost')
                maximum=max(maximum,len(actual['stdout']))
                cases.append({'template':name,'case':variant,'returncode':actual['returncode'],
                              'stdoutBytes':len(actual['stdout']),'stderrBytes':len(actual['stderr'])})
        old=normal.replace('{{json (index .HostConfig "Tmpfs")}}','{{json .HostConfig.Tmpfs}}')
        need(old!=normal,'formatter.original_template')
        actual=run_case(docker,work,old,fixture(),end)
        need(actual['returncode']!=0 and b'Tmpfs'in actual['stderr'],'formatter.original_error_not_reproduced')
        cases.append({'template':'original','case':'missing_Tmpfs','returncode':actual['returncode'],
                      'stdoutBytes':len(actual['stdout']),'stderrBytes':len(actual['stderr'])})
        need(len(cases)==26 and maximum<=OUTPUT_CAP and time.monotonic()<end,'formatter.proof_bound')
    finally:
        shutil.rmtree(work)
    need(not work.exists(),'formatter.work_retained')
    proof={'schema':'ocv.generic-docker-inspect-formatter-linux-proof.v1','status':'PASS',
      'sourceManifestSha256':args.source_manifest_sha256,'dockerSha256':DOCKER_SHA,
      'dockerBytes':DOCKER_BYTES,'dockerVersion':'29.8.2','normalTemplateSha256':NORMAL_SHA,
      'priorTemplateSha256':PRIOR_SHA,'cases':cases,'maximumFormattedBytes':maximum,
      'formattedCaptureCapBytes':OUTPUT_CAP,'apiVersion':API,'fixedPingAndInspectRoutesOnly':True,
      'maximumRequestsPerCli':4,'syntheticBinds':36,'syntheticSourcePathBytes':192,
      'bothActualCliTemplatesExecuted':True,'originalMissingTmpfsErrorReproduced':True,
      'optionalTmpfsPreserved':True,'requiredFieldsRefused':True,'sourceAndRwNegativesPreserved':True,
      'allCliGroupsReapedAbsentAndPipesClosed':True,'allSyntheticSocketsThreadsAndPathsClosed':True,
      'daemonContainerImageOrDatabaseExecuted':False,'privateDataAccessed':False,
      'officialPublishedChecksumMatched':False,'privateAdmissionEstablished':False}
    raw=compact(proof);need(len(raw)<=OUTPUT_CAP,'formatter.result_bound');print(raw.decode('ascii'))


if __name__=='__main__':main()
