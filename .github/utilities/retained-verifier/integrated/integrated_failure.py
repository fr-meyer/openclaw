"""CI-only memory snapshots of an already failed native chain; no effects.

These diagnostics grant no execution, cleanup, replay or retry authority. They
never inspect environments, private bodies, exception messages or filenames.
"""
import base64
import copy
import re
import types

from protocol import canonical,require,sha

FACTS_CAP=31*1024
CONTROLS=frozenset(('exitCode','timedOut','spawned','spawnOutcome','captureComplete',
    'streamsEOF','streamsClosed','ownedChildExited','ownershipRetained','refusalCode',
    'failurePhase','operationId','errors'))


def source_index(modules):
    """Index only in-memory code from the caller's checked closed module graph."""
    require(type(modules) is dict and 0<len(modules)<=64,'integrated_failure.modules')
    codes={};reasons=set();error_types={}
    def visit(code,name):
        require(type(code) is types.CodeType and len(codes)<8192,'integrated_failure.code_cap')
        if id(code) in codes:
            require(codes[id(code)][0] is code,'integrated_failure.code_identity');return
        codes[id(code)]=(code,name+'.py',code.co_name)
        for value in code.co_consts:
            if type(value) is types.CodeType:visit(value,name)
            elif type(value) is str and re.fullmatch('[a-z][a-z0-9_.]{0,95}',value):
                reasons.add(value)
    for name,module in modules.items():
        require(type(name) is str and re.fullmatch('[a-z][a-z0-9_]{0,63}',name) and
            type(module) is types.ModuleType and module.__name__==name,'integrated_failure.module')
        for value in vars(module).values():
            if type(value) is types.FunctionType and value.__globals__ is vars(module):visit(value.__code__,name)
            elif type(value) is type and value.__module__==name:
                if issubclass(value,BaseException):error_types[value]=name+'.'+value.__name__
                for member in vars(value).values():
                    if type(member) in (staticmethod,classmethod):member=member.__func__
                    if type(member) is types.FunctionType and member.__globals__ is vars(module):visit(member.__code__,name)
    return codes,frozenset(reasons),error_types


def exception_snapshot(error,index):
    """Never stringify an exception or trust a lookalike code/filename."""
    require(isinstance(error,BaseException) and type(index) is tuple and len(index)==3,
            'integrated_failure.exception')
    codes,reasons,error_types=index;rows=[];seen=set();current=error
    builtins={t:t.__name__ for t in (OSError,PermissionError,FileNotFoundError,FileExistsError,
        TimeoutError,ValueError,TypeError,RuntimeError,AssertionError,KeyError,IndexError)}
    for _ in range(32):
        if current is None or id(current) in seen:break
        seen.add(id(current));kind=type(current)
        known=kind in error_types or kind in builtins
        args=BaseException.args.__get__(current,BaseException)
        code=args[0] if known and type(args) is tuple and len(args)>0 and type(args[0]) is str and args[0] in reasons else None
        row={'type':error_types.get(kind,builtins.get(kind,'unlisted-exception-type')),
             'code':code,'messageIncluded':False,'frames':[],'unlistedFrames':0}
        tb=BaseException.__traceback__.__get__(current,BaseException);frames=[]
        for _ in range(64):
            if tb is None:break
            require(type(tb) is types.TracebackType,'integrated_failure.traceback')
            entry=codes.get(id(tb.tb_frame.f_code))
            if entry is not None and entry[0] is tb.tb_frame.f_code:
                _code,name,function=entry
                frames.append({'source':name,'function':function,'line':tb.tb_lineno})
            else:row['unlistedFrames']+=1
            tb=tb.tb_next
        row['frames']=frames[-8:];row['framesTruncated']=len(frames)>8 or tb is not None
        row['framesObserved']=len(frames);row['framesSha256']=sha(canonical(frames))
        if kind in builtins and issubclass(kind,OSError):
            number=OSError.errno.__get__(current,OSError)
            row['errno']=number if type(number) is int and -4096<=number<=4096 else None
        rows.append(row)
        current=BaseException.__context__.__get__(current,BaseException)
    total=len(rows);innermost=next((row['code']for row in reversed(rows)if row['code'] is not None),None)
    if total>8:rows=rows[:4]+rows[-4:]
    return {'exceptions':rows,'contextTruncatedOrCyclic':current is not None or total>8,
        'contextsObserved':total,'contextViewsOmitted':total-len(rows),'innermostObservedCode':innermost}


def command_snapshot(result,operation,owned):
    """A bounded result only; caller must separately prove fixed safe argv."""
    require(type(result) is dict and set(result) in (CONTROLS|{'stdout','stderr','stdoutFacts','stderrFacts'},
        CONTROLS|{'stdout','stderr','stdoutFacts','stderrFacts','childPid'}), 'integrated_failure.capture_schema')
    require(type(operation) is int and 1<=operation<=256 and result['operationId']==operation and
        type(owned) is set and all(type(n) is int and 1<=n<=256 for n in owned),
        'integrated_failure.capture_operation')
    require(result['exitCode'] is None or type(result['exitCode']) is int and -255<=result['exitCode']<=255,
            'integrated_failure.capture_exit')
    for name in ('timedOut','spawned','captureComplete','streamsEOF','streamsClosed','ownedChildExited','ownershipRetained'):
        require(type(result[name]) is bool,'integrated_failure.capture_control')
    require(result['spawnOutcome'] in ('not_attempted','unknown','handle_returned') and
        result['ownershipRetained']==(operation in owned),'integrated_failure.capture_ownership')
    for name in ('refusalCode','failurePhase'):
        require(result[name] is None or type(result[name]) is str and
            re.fullmatch('[a-z][a-z0-9_.]{0,95}',result[name]),'integrated_failure.capture_code')
    require(type(result['errors']) is list and len(result['errors'])<=16,'integrated_failure.capture_errors')
    for error in result['errors']:
        require(type(error) is dict and set(error)=={'phase','type','errno'} and
            all(type(error[k]) is str and re.fullmatch('[A-Za-z0-9_.-]{1,48}',error[k])for k in ('phase','type')) and
            (error['errno'] is None or type(error['errno']) is int),'integrated_failure.capture_error')
    controls={key:result[key]for key in sorted(CONTROLS)}
    if 'childPid' in result:
        require(result['childPid'] is None or type(result['childPid']) is int and 0<result['childPid']<=4194304,
                'integrated_failure.capture_pid')
        controls['childPid']=result['childPid']
    streams={}
    for name,limit in (('stdout',16384),('stderr',4096)):
        raw=result[name];facts=result[name+'Facts']
        require(type(raw) is bytes and len(raw)<=limit and type(facts) is dict and
            set(facts)=={'bytes','sha256','truncated','complete'} and type(facts['bytes']) is int and
            len(raw)<=facts['bytes']<2**63 and type(facts['sha256']) is str and
            re.fullmatch('[0-9a-f]{64}',facts['sha256']) and type(facts['truncated']) is bool and
            type(facts['complete']) is bool,'integrated_failure.capture_stream')
        require(facts['bytes']!=len(raw) or facts['sha256']==sha(raw),'integrated_failure.capture_hash')
        streams[name]={'viewBase64':base64.b64encode(raw).decode('ascii'),'viewBytes':len(raw),
            'viewSha256':sha(raw),'viewTruncated':len(raw)!=facts['bytes'],'captureFacts':dict(facts)}
    return {'capture':controls,'streams':streams,'ownedCommandsRemaining':len(owned)}


def render(primary,cleanup,before,after,command):
    require(type(primary) is dict and type(cleanup) is list and len(cleanup)<=3 and
        type(before) is dict and type(after) is dict and (command is None or type(command) is dict),
        'integrated_failure.render')
    evidence={'schema':'ocv.integrated-native-chain-failure.v1','syntheticOnly':True,
        'privateInputs':False,'environmentIncluded':False,'messagesIncluded':False,
        'retryPermitted':False,'primary':copy.deepcopy(primary),'cleanup':copy.deepcopy(cleanup),
        'stateBeforeCleanup':copy.deepcopy(before),'stateAfterCleanup':copy.deepcopy(after),
        'latestSafeCommand':copy.deepcopy(command)}
    if command is not None:
        stream=evidence['latestSafeCommand']['streams']['stdout'];original=base64.b64decode(stream['viewBase64'],validate=True)
        limit=len(original)
        while len(canonical(evidence))>FACTS_CAP and limit>0:
            limit=max(0,limit-1024);half=limit//2
            view=original[:half]+original[-(limit-half):]if limit else b''
            stream.update(viewBase64=base64.b64encode(view).decode('ascii'),viewBytes=len(view),
                viewSha256=sha(view),viewTruncated=len(view)!=stream['captureFacts']['bytes'])
    # Keep every bounded context's closed code/type and the innermost observed
    # code. Frame rendering may shorten; original observed counts/hash remain.
    for chain in [*reversed(evidence['cleanup']),evidence['primary']]:
        for row in chain.get('exceptions',[]):
            while len(canonical(evidence))>FACTS_CAP and row.get('frames'):
                row['frames'].pop(0);row['framesTruncated']=True
    require(len(canonical(evidence))<=FACTS_CAP,'integrated_failure.facts_cap')
    return evidence
