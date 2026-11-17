#!/usr/bin/env python3
"""Trusted adapter: no candidate imports; create/inspect before start; exact owned cleanup."""
import json,os,pathlib,subprocess,sys
MEMORY=6*2**30

def validate(info,image,token):
 h=info['HostConfig'];c=info['Config']
 if info['Image']!=image or c.get('Labels',{}).get('openclaw.layout.token')!=token:raise ValueError('owned runtime identity mismatch')
 if h.get('NanoCpus')!=2_000_000_000 or h.get('Memory')!=MEMORY or h.get('MemorySwap')!=MEMORY or h.get('PidsLimit')!=512:raise ValueError('actual CPU/RAM/PID quota mismatch')
 if h.get('NetworkMode')!='none' or not h.get('ReadonlyRootfs') or h.get('Privileged') or h.get('Binds') or h.get('CapAdd') or h.get('Devices') or c.get('User')!='1000:1000':raise ValueError('actual sandbox mismatch')
 if h.get('CapDrop')!=['ALL'] or not any(x in ['no-new-privileges','no-new-privileges:true'] for x in h.get('SecurityOpt',[])):raise ValueError('capability/security mismatch')
 return {'id':info['Id'],'image':info['Image'],'memory':h['Memory'],'swap':h['MemorySwap'],'nanoCpus':h['NanoCpus'],'pids':h['PidsLimit'],'network':h['NetworkMode'],'readonly':True,'tmpfs':h.get('Tmpfs',{}),'token':token}

def main(args,runner=subprocess.run):
 settings=json.loads(pathlib.Path(__file__).with_suffix('.json').read_text());docker=settings['docker'];engine_env=settings.get('engine_env')
 if not isinstance(engine_env,dict) or not engine_env.get('DOCKER_HOST','').startswith('unix:///') or engine_env['DOCKER_HOST'] in ['unix:///var/run/docker.sock','unix:///run/docker.sock'] or any(k.endswith('TOKEN') or k in ['DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'] for k in engine_env):raise ValueError('isolated credential-free engine environment required')
 if not docker or pathlib.Path(docker).resolve()!=pathlib.Path(docker) or not pathlib.Path(docker).is_file():raise ValueError('canonical Docker binary missing')
 def cmd(argv,capture=True):
  r=runner([docker,*argv],capture_output=capture,text=True,timeout=330,env=engine_env)
  if r.returncode:raise RuntimeError('Docker lifecycle nonzero: '+str(argv[0]))
  return r.stdout if capture else ''
 if not args or args[0]!='run':
  # Accepted host runner requests only bounded image/container inspect or exact kill.
  if args[:2] not in [['image','inspect'],['container','inspect']] and args[:3]!=['kill','--signal','KILL']:raise ValueError('adapter command not admitted')
  r=runner([docker,*args],timeout=30,env=engine_env);return r.returncode
 image=args[args.index('--entrypoint')+2]
 if not image.startswith('sha256:') or len(image)!=71:raise ValueError('opaque image required')
 token=next(x.split('=',1)[1] for x in args if x.startswith('openclaw.layout.token='))
 name=args[args.index('--name')+1];cid=None;started=False;terminal=False
 create=['create','--cpus','2','--memory',str(MEMORY),'--memory-swap',str(MEMORY),*args[1:]];create.remove('--rm')
 try:
  cid=cmd(create).strip();info=json.loads(cmd(['container','inspect',cid]))[0];proof=validate(info,image,token)
  path=pathlib.Path(settings['proof']);existing=path.stat().st_size if path.exists() else 0
  if existing>65536:raise ValueError('runtime proof budget')
  with path.open('a') as f:f.write(json.dumps(proof)+'\n')
  started=True
  attached=runner([docker,'start','--attach',cid],timeout=330,env=engine_env)
  code=int(cmd(['wait',cid]).strip());after=json.loads(cmd(['container','inspect',cid]))[0]
  validate(after,image,token)
  if after['State']['Running'] or after['State']['ExitCode']!=code:raise ValueError('terminal proof mismatch')
  terminal=True
  with path.open('a') as f:f.write(json.dumps({'id':cid,'image':image,'terminalExit':code,'running':False})+'\n')
  return code
 finally:
  if cid:
   try:
    current=json.loads(cmd(['container','inspect',cid]))[0]
    if current['Image']!=image or current['Config'].get('Labels',{}).get('openclaw.layout.token')!=token:raise ValueError('refuse unowned cleanup')
    if current['State']['Running']:cmd(['kill','--signal','KILL',cid])
    cmd(['rm',cid]);gone=runner([docker,'container','inspect',cid],capture_output=True,text=True,timeout=30,env=engine_env)
    if gone.returncode!=1 or not any(t in gone.stderr for t in ['No such container','No such object']):raise RuntimeError('owned container absence not proved')
   except Exception as e:
    print('TERMINATION_UNVERIFIED: '+str(e),file=sys.stderr);raise
if __name__=='__main__':
 try:sys.exit(main(sys.argv[1:]))
 except Exception as e:print('PHASE1_DOCKER_FAILED_CLOSED: '+str(e),file=sys.stderr);sys.exit(1)
