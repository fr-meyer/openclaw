"""Private byte bridge successor. Fixture policy only; no SQLite/startup/network."""
import base64, hashlib, json, os, sys, time
from workboard_private_custody import PrivateCustody
from workboard_acceptance_ledger import DurableLedger, digest, canonical, LOGICAL_ASSURANCE, LOGICAL_ASSURANCE_SHA256, checked_capture_interval
from workboard_private_proof_keeper import PrivateProofKeeper
WIRE_LIMIT=96*1024*1024
FILES={'raw-export.json','snapshot.sqlite','manifest.json','inert.json'}
class WorkerFailure(Exception):
    def __init__(self,code): self.code=code; super().__init__(code)
def error(code): raise WorkerFailure(code)
def sha(value): return hashlib.sha256(value).hexdigest()
def safe_code(exc):
    code=getattr(exc,'code','WORKER_OPERATION_FAILED')
    return code if isinstance(code,str) and 1<=len(code)<=64 and code.isupper() and all(c.isalnum() or c=='_' for c in code) else 'WORKER_OPERATION_FAILED'
def unpack(value):
    if not isinstance(value,str): error('WIRE_BYTES_INVALID')
    try:return base64.b64decode(value,validate=True)
    except Exception:error('WIRE_BYTES_INVALID')
def role_for(kind):
    if kind not in ('capture','restore-quarantine'):error('KIND_INVALID')
    return 'capture' if kind=='capture' else 'quarantine'
def artifact(custody,kind,operation_id,binding):
    result={}
    with custody.open_operation(role_for(kind),operation_id) as directory:
        if set(directory.list_names())!=FILES:error('ARTIFACT_SCOPE_CHANGED')
        for name in sorted(FILES):result[name]=directory.read_bytes(name)
        m=json.loads(result['manifest.json'])
        if m.get('contract') != 'workboard.native-runtime-logical-recovery.v1' or m.get('assurance') != LOGICAL_ASSURANCE or digest(canonical(m.get('assurance'))) != LOGICAL_ASSURANCE_SHA256 or m.get('assuranceSha256') != LOGICAL_ASSURANCE_SHA256:error('LOGICAL_ASSURANCE_REQUIRED')
        interval=checked_capture_interval(m.get('captureInterval'))
        if m.get('captureIntervalSha256') != digest(canonical(interval)) or m.get('captureIntervalSha256') != binding.get('captureIntervalSha256') or m.get('sourceGenerationId') != binding.get('sourceGenerationId'):error('CAPTURE_INTERVAL_INVALID')
        if m.get('synthetic') is not True or m.get('productionAcceptance') is not False or m.get('role')!=role_for(kind):error('ARTIFACT_POLICY_MISMATCH')
        if set(m.get('members',{}))!=FILES-{'manifest.json'}:error('ARTIFACT_SCOPE_CHANGED')
        for name,value in m['members'].items():
            if value!={'sha256':sha(result[name]),'bytes':len(result[name])}:error('ARTIFACT_BYTES_CHANGED')
        if json.loads(result['inert.json'])!={'synthetic':True,'productionAcceptance':False,'runtimeStartAllowed':False,'claimsRearmed':False,'notificationsDelivered':False}:error('ARTIFACT_POLICY_MISMATCH')
    return result,m

def summary(record,storage):
    # Raw proof/nonce and body content never cross this response.
    return {'operationId':record['operationId'],'kind':record['kind'],'state':record['state'],
            'revision':record['revision'],'receipt':record['receipt'],
            'receiptSha256':record['receiptSha256'],'proofSha256':record['proofSha256'],
            'keeperReceiptSha256':digest(canonical(storage)),
            'assuranceContract':LOGICAL_ASSURANCE['contract'],'assuranceSha256':LOGICAL_ASSURANCE_SHA256,
            'privateProofKept':True,'synthetic':True,'productionAcceptance':False}

def record_failure(ledger,p,revision,exc,state='failed'):
    try:
        result=ledger.mark_failure(p['operationId'],revision,p['binding'],state,safe_code(exc))
        return {'recorded':True,'state':result['state'],'revision':result['revision']}
    except Exception as secondary:return {'recorded':False,'code':safe_code(secondary)}

def serve(policy):
    if policy.get('synthetic') is not True or policy.get('uid')!=os.geteuid():error('SYNTHETIC_POLICY_REQUIRED')
    custody=ledger=keeper=None
    try:
        custody=PrivateCustody(policy['root'],policy['uid'],policy['sizeLimit'])
        ledger=DurableLedger(custody,policy['executionBootId'])
        keeper=PrivateProofKeeper(custody,ledger)
        while True:
            line=sys.stdin.buffer.readline(WIRE_LIMIT+1)
            if not line:break
            request_id=None;request={}
            try:
                if len(line)>WIRE_LIMIT:error('WIRE_LIMIT')
                request=json.loads(line);request_id=request['id'];p=request.get('payload',{});action=request['action']
                if action=='close':
                    owners=(keeper,ledger,custody);keeper=ledger=custody=None
                    failures=[];interrupt=None
                    for owner in owners:
                        try:owner.close()
                        except BaseException as exc:
                            failures.append('WORKER_OWNER_CLOSE_FAILED')
                            if not isinstance(exc,Exception) and interrupt is None:interrupt=exc
                    if interrupt is not None:raise interrupt
                    if failures:error('WORKER_OWNER_CLOSE_FAILED')
                    result={'closed':True,'ownersClosed':True}
                elif action=='hello':
                    result={'synthetic':True,'descriptorByteIO':True,'sqlitePathConsumer':False,
                            'assuranceContract':LOGICAL_ASSURANCE['contract'],'assuranceSha256':LOGICAL_ASSURANCE_SHA256,
                            'privateProofKeeper':True,'rawProofWireAllowed':False,
                            'compiledModuleDigests':{name:getattr(sys.modules[name],'__source_sha256__') for name in ('family_publish_io','workboard_private_custody','workboard_acceptance_ledger','workboard_private_proof_keeper','recovery_worker')},
                            'productionAcceptance':False}
                elif action=='stage':
                    if set(p['files'])!=FILES:error('ARTIFACT_SCOPE_CHANGED')
                    stage=None
                    try:
                        stage=ledger.prepare(p['operationId'],p['kind'],p['binding'])
                        if stage['state']!='staged':error('OPERATION_TERMINAL')
                        with custody.allocate(role_for(p['kind']),p['operationId']) as directory:
                            for name,value in p['files'].items():directory.write_bytes(name,unpack(value))
                            directory.verify()
                        data,m=artifact(custody,p['kind'],p['operationId'],p['binding'])
                        if sha(data['manifest.json'])!=p['binding']['manifestSha256']:error('MANIFEST_BINDING_MISMATCH')
                    except Exception as exc:
                        if stage and stage['state']=='staged':exc.failure_disposition=record_failure(ledger,p,stage['revision'],exc)
                        raise
                    result={'revision':stage['revision'],'role':role_for(p['kind']),'operationId':p['operationId']}
                elif action=='accept-and-keep':
                    accepted=False
                    try:
                        data,m=artifact(custody,p['kind'],p['operationId'],p['binding'])
                        if p['binding'].get('assuranceSha256')!=LOGICAL_ASSURANCE_SHA256 or p['receipt'].get('assuranceSha256')!=LOGICAL_ASSURANCE_SHA256 or p['receipt'].get('assuranceContract')!=LOGICAL_ASSURANCE['contract']:error('LOGICAL_ASSURANCE_REQUIRED')
                        if sha(data['manifest.json'])!=p['binding']['manifestSha256'] or p['receipt']['outputSha256']!=sha(data['snapshot.sqlite']):error('ACCEPTANCE_ARTIFACT_MISMATCH')
                        if p['receipt']['manifestSha256']!=sha(data['manifest.json']) or p['receipt']['inputSha256']!=p['binding']['inputSha256']:error('ACCEPTANCE_ARTIFACT_MISMATCH')
                        if not isinstance(p.get('expiresAt'),(int,float)) or p['expiresAt']<=time.time()*1000:error('PRIVATE_CAPABILITY_EXPIRED')
                        ack=ledger.accept(p['operationId'],p['revision'],p['binding'],p['receipt']);accepted=True
                        storage=keeper.save(p['operationId'],p['kind'],p['binding'],ack['acceptance_proof'])
                        result=summary(ack['record'],storage)
                    except Exception as exc:
                        if accepted:exc.failure_disposition={'recorded':False,'state':'indeterminate','code':'PRIVATE_ACKNOWLEDGEMENT_OUTCOME_UNKNOWN'}
                        else:exc.failure_disposition=record_failure(ledger,p,p['revision'],exc,'indeterminate')
                        raise
                elif action in ('read-accepted','resolve-kept'):
                    proof=keeper.load(p['operationId'],p['kind'],p['binding'])
                    record=ledger.resolve(p['operationId'],p['kind'],p['binding'],proof)
                    if action=='resolve-kept':result={'operationId':record['operationId'],'kind':record['kind'],'state':record['state'],'revision':record['revision'],'receiptSha256':record['receiptSha256'],'proofSha256':record['proofSha256'],'assuranceContract':LOGICAL_ASSURANCE['contract'],'assuranceSha256':LOGICAL_ASSURANCE_SHA256,'privateProofKept':True}
                    else:
                        data,m=artifact(custody,p['kind'],p['operationId'],p['binding'])
                        result={'files':{n:base64.b64encode(b).decode() for n,b in data.items()}}
                elif action=='reject-stage':
                    if p.get('code') not in ('PRIVATE_CAPABILITY_EXPIRED','PRIVATE_CAPABILITY_REVOKED'):error('REJECTION_CODE_INVALID')
                    result=ledger.mark_failure(p['operationId'],p['revision'],p['binding'],'failed',p['code'])
                else:error('ACTION_INVALID')
                response={'id':request_id,'ok':True,'result':result}
            except Exception as exc:
                response={'id':request_id,'ok':False,'code':safe_code(exc)}
                if hasattr(exc,'failure_disposition'):response['failureDisposition']=exc.failure_disposition
            wire=json.dumps(response,separators=(',',':'))+'\n'
            if len(wire.encode())>WIRE_LIMIT:wire=json.dumps({'id':request_id,'ok':False,'code':'WIRE_LIMIT'})+'\n'
            sys.stdout.write(wire);sys.stdout.flush()
            if request.get('action')=='close':break
    finally:
        primary=sys.exc_info()[1];failures=[];interrupt=None
        # Detached descriptor owners are closed once; every owner gets attempted.
        for resource in (keeper,ledger,custody):
            if resource is None:continue
            try:resource.close()
            except BaseException as exc:
                failures.append('WORKER_OWNER_CLOSE_FAILED')
                if not isinstance(exc,Exception) and interrupt is None:interrupt=exc
        if primary is not None and failures:setattr(primary,'cleanup_codes',tuple(failures))
        elif interrupt is not None:raise interrupt
        elif failures:error('WORKER_OWNER_CLOSE_FAILED')
