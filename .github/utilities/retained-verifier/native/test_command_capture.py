"""Actual inherited NativeOps command core + actual Port/Custody, inert I/O.

No native constructor bypass/capability issuance or real subprocess. Frozen R2
method bodies are compiled unchanged into a pure injected source-replay scope.
"""
import ast
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import ci_native_port as native
from ci_protocol import Refusal,canonical,sha
import test_ci_adapter as integration

B=Path(__file__).resolve().parent
R2=B.parent/'native-ci-adapter-r2'
R2_PIN='7129c25351eb76d93190912a8f0bfd84f62fce41fdf02fc2009b44ede96d128e'


class Pipe:
    def __init__(self,io,label,fd):self.io,self.label,self.fd=io,label,fd;self.closed=False
    def fileno(self):return self.fd
    def close(self):self.io.close_stream(self)


class Selector:
    def __init__(self,io):self.io=io;self.rows={};self.closed=False
    def register(self,stream,event,label):return self.io.register(self,stream,label)
    def unregister(self,stream):return self.io.unregister(self,stream)
    def select(self,seconds):return self.io.events(self,seconds)
    def get_map(self):return self.rows
    def close(self):return self.io.close_selector(self)


class Child:
    pid=12345
    def __init__(self,io):
        self.io=io;self.stdout=Pipe(io,'stdout',101);self.stderr=Pipe(io,'stderr',102);self.running=True
    def poll(self):return self.io.poll(self)
    def wait(self,timeout):return self.io.wait(self,timeout)
    def kill(self):return self.io.kill(self)
    def terminate(self):return self.io.terminate(self)


class IO:
    def __init__(self,fault=None,stdout=b'FIRST-PARTIAL-STDOUT',stderr=b'UNIQUE-COMMAND-FAULT'):
        self.fault=fault;self.calls=[];self.seconds=0;self.child=Child(self);self.byfd={101:self.child.stdout,102:self.child.stderr}
        self.pending={'stdout':[stdout,b''],'stderr':[stderr,b'']};self.waits=0;self.reads=0;self.selector_value=None
    def now(self):return self.seconds
    def spawn(self,argv):
        self.calls.append('spawn')
        if self.fault=='spawn':raise OSError(2,'synthetic spawn error')
        return self.child
    def selector(self):
        self.calls.append('selector')
        if self.fault=='selector':raise OSError(12,'synthetic selector error')
        self.selector_value=Selector(self);return self.selector_value
    def nonblocking(self,stream):
        self.calls.append('nonblocking_'+stream.label)
        if self.fault=='nonblocking_'+stream.label:raise OSError(9,'synthetic nonblocking error')
    def register(self,selector,stream,label):
        self.calls.append('register_'+label)
        if self.fault=='register_'+label:raise OSError(22,'synthetic register error')
        selector.rows[stream.fd]=SimpleNamespace(data=label,fileobj=stream)
    def mapped(self,selector):return bool(selector.rows)
    def events(self,selector,seconds):
        self.seconds+=max(.01,seconds);return [(key,1) for key in list(selector.rows.values())]
    def read(self,stream):
        self.calls.append('read_'+stream.label);self.reads+=1
        if self.fault=='drain' and stream.label=='stdout' and len(self.pending['stdout'])==1:
            self.fault='drain_seen';raise OSError(5,'synthetic read error')
        raw=self.pending[stream.label].pop(0) if self.pending[stream.label] else b''
        if not any(self.pending.values()) and self.fault!='uncertain':self.child.running=False
        return raw
    def unregister(self,selector,stream):selector.rows.pop(stream.fd,None)
    def poll(self,child):
        self.calls.append('poll');return None if child.running else 0
    def terminate(self,child):
        self.calls.append('terminate')
        if self.fault=='uncertain':raise OSError(1,'synthetic terminate refusal')
        child.running=False
    def kill(self,child):
        self.calls.append('kill')
        if self.fault=='uncertain':raise OSError(1,'synthetic kill refusal')
        child.running=False
    def wait(self,child,seconds):
        self.calls.append('wait');self.waits+=1
        if self.fault=='uncertain' or (self.fault=='wait' and self.waits==1):raise TimeoutError('synthetic wait timeout')
        child.running=False;return 0
    def close_selector(self,selector):
        self.calls.append('selector_close')
        if self.fault=='selector_close':raise OSError(5,'synthetic selector close error')
        selector.closed=True
    def close_stream(self,stream):
        self.calls.append('close_'+stream.label)
        if self.fault=='close_'+stream.label:raise OSError(5,'synthetic stream close error')
        stream.closed=True


def frozen_r2_command(io):
    raw=(R2/'ci_native_port.py').read_bytes();assert sha(raw)==R2_PIN
    tree=ast.parse(raw);cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='NativeOps')
    method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='command')
    # Unmodified old body, explicit inert globals only. No NativeOps object is
    # created, no __new__, constructor bypass, ARM change or native function.
    namespace={'require':native.require,'hashlib':hashlib,
      'subprocess':SimpleNamespace(Popen=lambda argv,**kw:io.spawn(argv),DEVNULL=-1,PIPE=-2),
      'selectors':SimpleNamespace(DefaultSelector=io.selector,EVENT_READ=1),
      'os':SimpleNamespace(set_blocking=lambda fd,value:io.nonblocking(io.byfd[fd]),read=lambda fd,cap:io.read(io.byfd[fd])),
      'time':SimpleNamespace(monotonic=io.now)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method],type_ignores=[])),str(R2/'ci_native_port.py'),'exec'),namespace)
    return namespace['command']


def old_port_module():
    raw=(R2/'ci_native_port.py').read_bytes();assert sha(raw)==R2_PIN
    spec=importlib.util.spec_from_file_location('frozen_r2_port',R2/'ci_native_port.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class CommandTests(unittest.TestCase):
    def run_new(self,io):
        core=native.CommandCapture(io)
        self.assertIs(native.NativeOps.command,native.CommandCapture.command)
        return core,core.command(('/usr/bin/systemctl','show','fixture.service'),5)
    def test_positive_exact_inherited_core_has_complete_capture_and_no_owner_left(self):
        io=IO();core,result=self.run_new(io)
        self.assertTrue(native.command_capture_ok(result));self.assertEqual(result['stdout'],b'FIRST-PARTIAL-STDOUT')
        self.assertEqual(result['stderr'],b'UNIQUE-COMMAND-FAULT');self.assertEqual(core.owned_commands,{})
        self.assertEqual(io.calls.count('spawn'),1)
    def test_actual_frozen_r2_postspawn_selector_and_nonblocking_fail_old_leaks_new_closes(self):
        for fault in ('selector','nonblocking_stdout','register_stderr'):
            with self.subTest(fault=fault):
                old=IO(fault)
                with self.assertRaises(OSError):frozen_r2_command(old)(None,('/usr/bin/systemctl','show'),5)
                self.assertEqual(old.calls.count('spawn'),1);self.assertNotIn('wait',old.calls)
                self.assertFalse(old.child.stdout.closed);self.assertFalse(old.child.stderr.closed)
                io=IO(fault);core,result=self.run_new(io)
                self.assertEqual(io.calls.count('spawn'),1);self.assertIn('wait',io.calls)
                self.assertTrue(io.child.stdout.closed);self.assertTrue(io.child.stderr.closed)
                self.assertFalse(native.command_capture_ok(result));self.assertTrue(result['ownedChildExited'])
                self.assertTrue(result['failurePhase']);self.assertFalse(result['ownershipRetained'])
    def test_actual_r2_drain_and_wait_raise_discards_old_partial_new_preserves(self):
        for fault in ('drain','wait'):
            with self.subTest(fault=fault):
                old=IO(fault)
                with self.assertRaises((OSError,TimeoutError)):frozen_r2_command(old)(None,('/usr/bin/systemctl','show'),5)
                io=IO(fault);core,result=self.run_new(io)
                self.assertFalse(native.command_capture_ok(result));self.assertIn(b'FIRST-PARTIAL',result['stdout'])
                self.assertIn(b'UNIQUE-COMMAND',result['stderr']);self.assertEqual(io.calls.count('spawn'),1)
                self.assertTrue(result['errors']);self.assertIn(result['failurePhase'],('capture','wait'))
    def test_uncertain_cleanup_retains_exact_child_handle_and_never_respawns(self):
        io=IO('uncertain');core,result=self.run_new(io)
        self.assertTrue(result['ownershipRetained']);self.assertFalse(result['ownedChildExited'])
        self.assertIs(core.owned_commands[result['operationId']]['process'],io.child)
        self.assertIn('terminate',io.calls);self.assertIn('kill',io.calls);self.assertGreaterEqual(io.calls.count('wait'),2)
        self.assertEqual(io.calls.count('spawn'),1);self.assertTrue(io.child.stdout.closed);self.assertTrue(io.child.stderr.closed)
    def test_failed_close_does_not_skip_other_closes_and_keeps_owner(self):
        for fault in ('selector_close','close_stdout'):
            with self.subTest(fault=fault):
                io=IO(fault);core,result=self.run_new(io)
                self.assertTrue(io.child.stderr.closed);self.assertTrue(result['ownershipRetained'])
                self.assertIs(core.owned_commands[result['operationId']]['process'],io.child)
                self.assertFalse(native.command_capture_ok(result))
    def test_large_partial_output_keeps_head_tail_count_hash_without_success(self):
        payload=b'HEAD'+b'x'*20000+b'TAIL';io=IO('drain',stdout=payload)
        _,result=self.run_new(io)
        self.assertEqual(len(result['stdout']),16384);self.assertTrue(result['stdout'].startswith(b'HEAD'))
        self.assertTrue(result['stdout'].endswith(b'TAIL'))
        self.assertEqual(result['stdoutFacts']['bytes'],len(payload));self.assertEqual(result['stdoutFacts']['sha256'],sha(payload))
        self.assertTrue(result['stdoutFacts']['truncated']);self.assertFalse(native.command_capture_ok(result))
    def test_native_capabilities_remain_unissued_for_both_native_classes(self):
        self.assertIsNone(native._ISSUED_CAPABILITY);self.assertIsNone(native.MANIFEST_SHA256)
        with self.assertRaises(Refusal):native.NativeOps(None)
        with self.assertRaises(Refusal):native.NativeCommandIO(None)


class PortCustodyTests(integration.Integration):
    # Reuse real integration preparation, not its inherited test methods.
    def test_actual_command_core_port_adapter_failure_custody_with_healthy_supplementals(self):
        original=self.ops.command;io=IO('drain',stderr=b'UNIQUE-PRIMARY-PARTIAL-ERR');core=native.CommandCapture(io)
        def command(argv,timeout=5):
            if argv[0]=='/usr/bin/systemd-run':return core.command(tuple(argv),timeout)
            return original(argv,timeout)
        self.ops.command=command
        result=self.run_driver();self.assertEqual(result['reason'],'ci.native_command_capture_refused',result)
        raw=(self.root/'custody/host-diagnostics.private.bin').read_bytes();record=json.loads(raw)
        commands=record['boundary']['commands'];self.assertEqual(commands[0]['role'],'primary')
        self.assertIn(b'UNIQUE-PRIMARY-PARTIAL-ERR',base64.b64decode(commands[0]['stderr']['viewBase64']))
        self.assertEqual(record['boundary']['ownedSetup'],{'ExecMainCode':1,'ExecMainStatus':226,'Result':'namespace'})
        self.assertEqual(io.calls.count('spawn'),1);self.assertTrue(io.child.stdout.closed);self.assertIn('shutdown',self.port.effect_intents)
    def test_actual_frozen_r2_healthy_supplementals_evict_first_error_new_preserves(self):
        old=old_port_module();original_port=self.port;self.ops.fail='setup'
        prior=old.Port(self.ops,original_port.manifest,session_root=self.session_root,clock=self.clock,
                       metadata_admission=self.admission)
        prior.unit=self.context['unitName'];prior.context=self.context;prior.unit_issued=True;self.ops.port=prior
        with self.assertRaises(Refusal):prior.command(('/usr/bin/systemd-run','fixture'))
        old_evidence=prior.failure_evidence()
        self.assertEqual(old_evidence['ownedSetup'],{'ExecMainCode':1,'ExecMainStatus':226,'Result':'namespace'})
        self.assertFalse(any(b'UNIQUE-FIRST-SETUP-CAUSE' in base64.b64decode(row['stdout']['viewBase64']) for row in old_evidence['commands']))
        self.ops.port=original_port;original_port.unit=self.context['unitName'];original_port.context=self.context;original_port.unit_issued=True
        with self.assertRaises(Refusal):original_port.command(('/usr/bin/systemd-run','fixture'))
        new_evidence=original_port.failure_evidence()
        self.assertEqual(new_evidence['commands'][0]['role'],'primary')
        self.assertIn(b'UNIQUE-FIRST-SETUP-CAUSE',base64.b64decode(new_evidence['commands'][0]['stdout']['viewBase64']))
    def test_metadata_opaque_command_exception_retains_fixed_bounded_evidence(self):
        original=self.ops.command
        def command(argv,timeout=5):
            if argv[0]=='/usr/bin/gpgv':raise OSError(5,'not copied to public diagnostics')
            return original(argv,timeout)
        self.ops.command=command;result=self.run_driver();self.assertEqual(result['phase'],'metadata')
        record=json.loads((self.root/'custody/host-diagnostics.private.bin').read_bytes())
        row=record['boundary']['commands'][0];self.assertEqual(row['role'],'primary')
        self.assertEqual(row['failurePhase'],'boundary');self.assertEqual(row['errors'][0]['errno'],5)
        self.assertNotIn(b'not copied to public diagnostics',canonical(record));self.assertEqual(self.commands('/usr/bin/systemd-run'),[])


# Avoid inheriting/recounting the original 36 cases; they run in their own file.
for _name in list(integration.Integration.__dict__):
    if _name.startswith('test_') and _name not in PortCustodyTests.__dict__:setattr(PortCustodyTests,_name,None)

if __name__=='__main__':unittest.main()
