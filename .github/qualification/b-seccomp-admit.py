"""Fixed B-only read-only metadata verification; never launches containers."""
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path
BASE_SHA='a09e3e5e53f0b8e7bb89de0c072a986c77878e60bc5101e1428723cd75769764'
PROFILE_SHA='4ca3e2425639f1d8e1256af6e158e04631554c0c3d06c0d8a8bd034a297ea28c'
COMMIT='6430e49a55babd9b8f4d08e70ecb2b68900770fe'
EXCEPTION={'names':['lsm_list_modules'],'action':'SCMP_ACT_ALLOW','args':[{'index':2,'value':0,'op':'SCMP_CMP_EQ'}],'includes':{'arches':['amd64']}}
def need(ok,reason):
 if not ok:raise ValueError(reason)
def regular(p):
 need(p.is_absolute() and p.resolve()==p and stat.S_ISREG(p.lstat().st_mode),'profile path or type')
 data=p.read_bytes();need(len(data)<=65536,'profile size');return data
def policy(root):
 base=regular(root/'b-seccomp-baseline.json');profile=regular(root/'b-seccomp-lsm.json')
 need(hashlib.sha256(base).hexdigest()==BASE_SHA and hashlib.sha256(profile).hexdigest()==PROFILE_SHA,'seccomp digest')
 b=json.loads(base);p=json.loads(profile);need(p['syscalls'][-1]==EXCEPTION,'exception drift')
 p['syscalls'].pop();need(p==b,'non-exception policy drift')
 return root/'b-seccomp-lsm.json'
def metadata(version,info):
 server=version['Server'];need(server['Version']=='28.0.4' and server['GitCommit'] in (COMMIT,COMMIT[:7]),'unsupported exact Docker server release/commit')
 need(server['Os']=='linux' and server['Arch']=='amd64' and info['OSType']=='linux' and info['Architecture']=='x86_64','daemon architecture')
 need(info['ServerVersion']=='28.0.4' and info['KernelVersion']=='7.0.0-1017-azure','server/kernel metadata')
 sec=[x for x in info['SecurityOptions'] if x.startswith('name=seccomp,')]
 need(sec==['name=seccomp,profile=builtin'],'default built-in seccomp not established')
 need(not any(x in info['SecurityOptions'] for x in ['name=rootless','name=userns']),'unsupported daemon namespace mapping')
 need(not info.get('Swarm',{}).get('ControlAvailable',False),'unsupported swarm control context')
 return {'serverVersion':server['Version'],'gitCommit':server['GitCommit'],'kernel':info['KernelVersion'],'securityOption':sec[0],'baselineSha256':BASE_SHA,'profileSha256':PROFILE_SHA,'exception':'lsm_list_modules flags=0 only','status':'CONDITIONAL_DAEMON_POLICY_ADMITTED_NOT_RUNTIME_LSM_ADMISSION'}
def query(args):
 a=subprocess.run(['docker',*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
 need(len(a.stdout)<=1024*1024,'metadata size');return json.loads(a.stdout)
def main():
 need(len(sys.argv)==1,'no verifier parameters supported')
 root=Path(__file__).absolute().parent;policy(root)
 receipt=metadata(query(['version','--format','{{json .}}']),query(['info','--format','{{json .}}']))
 print(json.dumps(receipt,sort_keys=True),flush=True)
if __name__=='__main__':
 try:main()
 except Exception as error:
  print(json.dumps({'seccompAdmission':'REFUSED','reason':str(error)[:256]},sort_keys=True),flush=True)
  raise
