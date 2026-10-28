"""Exactly one bounded public synthetic custody frame before guest poweroff."""
import base64
from pathlib import Path
from guard import canonical,decode,need,sha

CAPS={'report':86000,'host-result':12288,'staging-manifest':12288,'worker-stdout':4096,'worker-stderr':4096,'host-diagnostics':8192}
EXTRA_CAPS={'controller-context':16384,'consumer-compatibility':12288,'host-expectation':12288,'unit-readback':4096,
 'worker-stderr-raw':8192,'native-isolation-cases':12288}


def custody_files(directory,read,context_raw=None,compatibility_raw=None,observations=None):
 files=[];total=0
 for role,cap in CAPS.items():
  try:
   raw=read(str(Path(directory)/(role+'.private.bin')),cap)
   meta=decode(read(str(Path(directory)/(role+'.private.json')),16384),16384)
  except FileNotFoundError:continue
  need(set(meta)=={'bytes','sha256','truncated','viewBytes','viewSha256'} and meta['viewBytes']==len(raw) and
    meta['viewSha256']==sha(raw),'boot.custody_changed')
  total+=len(raw);need(total<=131072,'boot.custody_total')
  files.append({'role':role,'bytes':len(raw),'sha256':sha(raw),'base64':base64.b64encode(raw).decode(),
                'sourceBytes':meta['bytes'],'sourceSha256':meta['sha256'],'truncated':meta['truncated']})
 extras=dict(observations or {})
 extra_caps=dict(EXTRA_CAPS);binary_roles={'worker-stderr-raw'};raw_cap=131072
 if any(role.startswith('integrated-') for role in extras):
  import integrated_capture
  need(set(integrated_capture.ROLE_CAPS)<=set(extras),'boot.integrated_custody_incomplete')
  extra_caps.update(integrated_capture.ROLE_CAPS)
  binary_roles.update(integrated_capture.BINARY_ROLES)
  raw_cap=integrated_capture.RAW_CAP
 need(set(extras)<=set(extra_caps)-{'controller-context','consumer-compatibility'},'boot.custody_extra_role')
 if context_raw is not None:extras['controller-context']=context_raw
 if compatibility_raw is not None:extras['consumer-compatibility']=compatibility_raw
 for role,raw in extras.items():
  need(type(raw)is bytes,'boot.custody_extra_bytes')
  cap=extra_caps[role]
  if role not in binary_roles:decode(raw,cap)
  if role.startswith('integrated-'):need(len(raw)<=cap,'boot.integrated_role_truncated')
  view=raw if len(raw)<=cap else raw[:cap//2]+raw[-(cap-cap//2):]
  total+=len(view);need(total<=raw_cap,'boot.custody_total')
  files.append({'role':role,'bytes':len(view),'sha256':sha(view),
    'base64':base64.b64encode(view).decode(),'sourceBytes':len(raw),'sourceSha256':sha(raw),'truncated':len(raw)>cap})
 return {'schema':'ocv.custody.v1','rawBytes':total,'files':files}


def require_success_roles(result,custody):
 # R3 deliberately labels success pending independent outer QEMU exit. It must
 # receive the same complete-evidence gate as an ordinary passed status.
 if result.get('unitStatus')=='passed' or result.get('status')in('passed','unit_passed_pending_outer_exit'):
  need(set(EXTRA_CAPS)<={r['role']for r in custody['files']} and all(not r['truncated']for r in custody['files']),
   'boot.custody_success_roles')


class Emitter:
 def __init__(self,plan,read,send,*,capability=None,context_raw=None,compatibility_raw=None,observations=None):
  from issuer import NativeCapability
  if capability is not None:
   need(type(capability)is NativeCapability,'boot.emitter_capability');capability.check(cleanup=True)
  self.plan=plan;self.read=read;self.send=send;self.capability=capability;self.context_raw=context_raw
  self.compatibility_raw=compatibility_raw;self.observations=observations;self.used=False
 def emit(self,adapter_raw,directory):
  need(not self.used,'boot.serial_once');self.used=True
  result=decode(adapter_raw.strip(),16384)
  custody=custody_files(directory,self.read,self.context_raw,self.compatibility_raw,self.observations)
  require_success_roles(result,custody)
  status=result.get('status','refused') if self.capability is not None or result.get('status')=='refused' else 'synthetic_validation'
  value={'schema':'ocv.ci-result.v1','sessionId':self.plan.markers['ocv.session'],'runIdentity':self.plan.build['runIdentity'],
   'sourceManifestSha256':self.plan.markers['ocv.source'],'buildControlSha256':self.plan.markers['ocv.build'],
   'status':status,'adapterResult':result,'custody':custody}
  integrated=any(row['role'].startswith('integrated-') for row in custody['files'])
  raw=canonical(value);need(len(raw)<=(4*1024*1024 if integrated else 262144),'boot.envelope_cap')
  frame=b'OCV_RESULT_V1:'+base64.b64encode(raw)+b'\n';need(len(frame)<=(6*1024*1024 if integrated else 1048576),'boot.serial_cap');self.send(frame)
  return value
