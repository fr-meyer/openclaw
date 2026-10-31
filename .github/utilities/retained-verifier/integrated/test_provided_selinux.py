"""Actual generic physical command/capture entry with inert process I/O.

Real Linux host/root/file/ELF execution is mandatory in copied_bootstrap_probe;
these cheap tests exercise parser variants, command ownership and no fallback.
"""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch
import host_admission as h
from protocol import Refusal,sha
from ci_protocol import Refusal as CIRefusal
import test_command_capture as capture_fixture
import ci_native_port

ROOT='/var/lib/openclaw-retained-bootstrap/'+'a'*64+'/'+'b'*32+'/root'


def captured(stdout=b'',stderr=b'',code=0):
    result={'exitCode':code,'captureComplete':True,'streamsEOF':True,'streamsClosed':True,
        'ownedChildExited':True,'ownershipRetained':False,'refusalCode':None,'timedOut':False,
        'stdout':stdout,'stderr':stderr}
    for key in('stdout','stderr'):
        result[key+'Facts']={'bytes':len(result[key]),'sha256':sha(result[key]),'truncated':False,'complete':True}
    return result


def probe():
    value=object.__new__(h.ProvidedSelinuxProbe)
    value.root=ROOT;value.binary=ROOT+'/usr/sbin/selinuxenabled'
    value.loader=ROOT+'/lib64/ld-linux-x86-64.so.2';value.library=ROOT+'/lib/x86_64-linux-gnu'
    value._selected=(value.root,value.binary,value.loader,value.library)
    value._loader_result=value._probe_result=None
    return value


def listing(value,style='standalone'):
    tail=(value.loader if style=='standalone'else '/lib64/ld-linux-x86-64.so.2 => '+value.loader)
    return ('linux-vdso.so.1 (0x1234)\n'+''.join(n+' => '+value.library+'/'+n+' (0x1234)\n'
        for n in('libselinux.so.1','libc.so.6','libpcre2-8.so.0'))+tail+' (0x1234)\n').encode()


class ProvidedPhysicalEntryTests(unittest.TestCase):
    def test_both_exact_loader_formats_and_substituted_alias_refusal(self):
        with patch.object(h.ProvidedSelinuxProbe,'validate',return_value=True):
            for style in('standalone','alias'):
                value=probe();self.assertTrue(value.loader_result(captured(listing(value,style))))
                self.assertTrue(value.probe_result(captured(code=1)))
            for alteration in('alias','target','extra','missing','duplicate'):
                value=probe();raw=listing(value,'alias')
                if alteration=='alias':raw=raw.replace(b'/lib64/ld-linux-x86-64.so.2 =>',b'/evil/interpreter =>')
                if alteration=='target':raw=raw.replace(value.loader.encode(),b'/tmp/loader')
                if alteration=='extra':raw+=b'extra.so => /tmp/extra.so (0x1234)\n'
                if alteration=='missing':raw=b'\n'.join(raw.splitlines()[1:])
                if alteration=='duplicate':raw+=raw.splitlines()[1]+b'\n'
                with self.subTest(alteration=alteration),self.assertRaises(Refusal):value.loader_result(captured(raw))

    def test_loader_error_exit_one_or_incomplete_custody_is_not_disabled_selinux(self):
        with patch.object(h.ProvidedSelinuxProbe,'validate',return_value=True):
            for change in('stderr','stdout','code','eof','truncated','hash'):
                value=probe();value._loader_result=captured(listing(value));result=captured(code=1)
                if change in('stderr','stdout'):result=captured(**{change:b'loader diagnostic'},code=1)
                if change=='code':result['exitCode']=2
                if change=='eof':result['streamsEOF']=False
                if change=='truncated':result['stdoutFacts']['truncated']=True
                if change=='hash':result['stderrFacts']['sha256']='a'*64
                with self.subTest(change=change),self.assertRaises(Refusal):value.probe_result(result)

    def test_real_hostops_commandcapture_receives_actual_argv_and_closes_both_children(self):
        selected=probe();calls=[]
        class IO(capture_fixture.IO):
            def spawn(self,argv):
                calls.append(argv)
                prior=self.seconds
                capture_fixture.IO.__init__(self,stdout=listing(selected)if '--list'in argv else b'',stderr=b'')
                self.seconds=prior
                if '--list'not in argv:self.pending['stdout']=[b'']
                self.pending['stderr']=[b'']
                return super().spawn(argv)
        io=IO();port=ci_native_port.CommandCapture(io,readonly_selinux_commands=selected.commands)
        with patch.object(h.ProvidedSelinuxProbe,'validate',return_value=True):
            ops=h.HostOps('/var/lib/openclaw-retained-verifier/'+'b'*32,'ocv-'+'b'*32+'.service',provided_selinux=selected)
            ops.command_port=port
            ops.command(selected.argv(True),5);ops.command(selected.argv(False),5)
            self.assertEqual(calls,list(selected.commands));self.assertFalse(port.owned_commands)
            self.assertEqual(port.command_sequence,2)
            for result in port.command_results.values():self.assertTrue(h._capture_ok(result))
            for legacy in(lambda:ops.command(('/usr/sbin/selinuxenabled',),5),
                           lambda:ops.read('/usr/sbin/selinuxenabled',1048576)):
                with self.assertRaisesRegex(Refusal,'provided_no_legacy_fallback'):legacy()
            denied=port.command(('/tmp/loader','--list',selected.binary),5)
            self.assertFalse(denied['spawned']);self.assertEqual(len(calls),2);self.assertFalse(port.owned_commands)

    def test_physical_command_registration_refuses_changed_loader_root_or_flags(self):
        selected=probe()
        for change in('path','flags','cross-session','order'):
            commands=list(selected.commands)
            if change=='path':commands[0]=('/tmp/loader',)+commands[0][1:]
            if change=='flags':commands[1]=(commands[1][0],'--inhibit-rpath')+commands[1][2:]
            if change=='cross-session':commands[1]=tuple(x.replace('b'*32,'c'*32)for x in commands[1])
            if change=='order':commands.reverse()
            with self.subTest(change=change),self.assertRaises(CIRefusal):
                ci_native_port.CommandCapture(capture_fixture.IO(),readonly_selinux_commands=tuple(commands))

    def test_actual_subclass_dispatch_hook_authorizes_copied_python_only(self):
        # The real copied-bootstrap source owns this subclass seam. Exercise
        # command() dispatch, not only a direct call to the hook.
        import copied_bootstrap_probe
        selected=probe()
        argv=copied_bootstrap_probe.build_argv(ROOT,b'print(1)')
        seen=[]
        class ProbeCapture(ci_native_port.CommandCapture):
            def _allowed_command(self,supplied):
                seen.append(supplied);return type(supplied)is tuple and supplied==argv
        io=capture_fixture.IO(stdout=b'copied-python-fixture',stderr=b'')
        io.pending['stderr']=[b'']
        capture=ProbeCapture(io)
        result=capture.command(argv,5)
        self.assertTrue(ci_native_port.command_capture_ok(result));self.assertEqual(result['stdout'],b'copied-python-fixture')
        self.assertFalse(capture.owned_commands);self.assertEqual(seen,[argv])
        denied=capture.command(('/tmp/python','-c','print(1)'),5)
        self.assertFalse(denied['spawned']);self.assertFalse(capture.owned_commands)
        ordinary=ci_native_port.CommandCapture(capture_fixture.IO())
        self.assertFalse(ordinary.command(argv,5)['spawned'])

    def test_method_shadowing_cannot_replace_fixed_command_or_validation(self):
        selected=probe()
        for name in('argv','validate','read','host_view'):
            with self.subTest(name=name),self.assertRaises(AttributeError):setattr(selected,name,lambda *a:True)

    def test_mode_contract_matches_exported_executable_and_dso_modes(self):
        self.assertEqual(h.PROVIDED_SELINUX_MODES,{name:(0o555 if name in
            ('usr/sbin/selinuxenabled','lib64/ld-linux-x86-64.so.2')else 0o444)for name in h.PROVIDED_SELINUX_FILES})

if __name__=='__main__':unittest.main()
