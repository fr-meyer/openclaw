"""Injected case observations only. NativeIO is never constructed or run."""
import ast
import copy
import errno
import json
from pathlib import Path
import signal
import types
import unittest
from unittest.mock import patch

import native_cases as n

ROOT=Path(__file__).resolve().parent


class OuterTimeout(RuntimeError):pass


def good_observation(case):
    row={'exitCode':0,'signal':None,'errno':None,'timedOut':False,'reaped':True,
         'outputComplete':True,'stdout':b'','stderr':b'','detail':'blocked','errors':n.empty_errors()}
    if case=='readonly-code':row.update(errno=errno.EROFS,detail='readonly_denied')
    elif case=='management-paths':row['detail']='unavailable:2,2,2,2'
    elif case=='unix-socket':row['errno']=errno.EPERM
    elif case=='mount':row.update(exitCode=None,signal=int(signal.SIGSYS),detail='sigsys')
    elif case in('entry-bad-argv','entry-bad-env'):
        marker=b'entry_refused_args\n' if case=='entry-bad-argv' else b'entry_refused_unknown_key\n'
        row.update(exitCode=111,stderr=marker,detail='exec_refused')
    else:row.update(stdout=n.TIMER_OUTPUT,detail='timer_timeout')
    return row


class FakeIO:
    """Public test helper for bootstrap's synthetic integration only."""
    outer_timeout_type=OuterTimeout
    def __init__(self,pid=77,context_sha='a'*64,overrides=None):
        self.pid=pid;self.context_sha=context_sha;self.overrides=overrides or {};self.calls=[];self.now=0
    def identity(self):return {'pid':self.pid,'contextSha256':self.context_sha}
    def monotonic(self):return self.now
    def import_sources(self):return {name:(ROOT/name).read_bytes()for name in n.IMPORT_PINS}
    def run_child(self,case,timeout):
        self.calls.append((case,timeout));self.now+=.01
        value=self.overrides.get(case,good_observation(case))
        if isinstance(value,BaseException):raise value
        return copy.deepcopy(value)


class InertKernel:
    """All effects are injected values; never calls a host OS primitive."""
    O_CLOEXEC=1;WNOHANG=1
    def __init__(self,faults=None,malformed=False):
        self.faults=dict(faults or {});self.pipe_index=0;self.roles={};self.closed=[];self.active={}
        self.waits=0;self.now=0;self.killed=[];self.reads={};self.malformed=malformed
    def hit(self,phase):
        failure=self.faults.pop(phase,None)
        if failure is not None:raise failure
    def pipe2(self,flags):
        channel=('control','stdout','stderr')[self.pipe_index];self.hit('pipe_'+channel)
        read=10+2*self.pipe_index;write=read+1;self.pipe_index+=1
        self.roles[read]=('read',channel);self.roles[write]=('write',channel)
        return read,write
    def fork(self):self.hit('fork');return 9001
    def close(self,fd=None):
        if fd is None:self.hit('cleanup_selector');return
        side,channel=self.roles[fd];self.hit('close_'+side+'_'+channel);self.closed.append(fd)
    def set_blocking(self,fd,value):self.hit('nonblocking_'+self.roles[fd][1])
    def DefaultSelector(self):self.hit('selector_create');return self
    def register(self,fd,event,channel):self.hit('register_'+channel);self.active[fd]=channel
    def select(self,_timeout):
        self.hit('select')
        return [(types.SimpleNamespace(fd=fd,data=channel),1)for fd,channel in self.active.items()]
    def unregister(self,fd):self.hit('unregister_'+self.roles[fd][1]);self.active.pop(fd)
    def read(self,fd,_size):
        channel=self.roles[fd][1];self.hit('read_'+channel)
        count=self.reads.get(fd,0);self.reads[fd]=count+1
        if channel=='control'and count==0:
            return b'{'if self.malformed else n.canonical({'outcome':'readonly_denied','errno':errno.EROFS})
        return b''
    def waitpid(self,pid,flags):
        role='wait_poll'if self.waits==0 else'cleanup_wait';self.waits+=1;self.hit(role)
        return pid,0
    def kill(self,pid,sig):self.hit('cleanup_kill');self.killed.append(pid)
    def monotonic(self):self.hit('clock');self.now+=.01;return self.now
    def sleep(self,delay):self.hit('cleanup_sleep');self.now+=delay
    def WIFEXITED(self,status):return True
    def WEXITSTATUS(self,status):return status
    def WIFSIGNALED(self,status):return False
    def WTERMSIG(self,status):raise AssertionError('no signal')


def actual_run_child_injected(faults=None,malformed=False):
    """Execute exact source method bytecode with inert syscall/clock objects."""
    kernel=InertKernel(faults,malformed)
    selector=types.SimpleNamespace(DefaultSelector=kernel.DefaultSelector,EVENT_READ=1)
    clock=types.SimpleNamespace(monotonic=kernel.monotonic,sleep=kernel.sleep)
    namespace=dict(n.NativeIO.run_child.__globals__,os=kernel,selectors=selector,time=clock)
    method=types.FunctionType(n.NativeIO.run_child.__code__,namespace)
    owner=types.SimpleNamespace(children={},outer_timeout_type=OuterTimeout)
    observation=method(owner,'readonly-code',3)
    return observation,kernel,owner


class NativeCaseTests(unittest.TestCase):
    def test_native_factory_accepts_only_no_supplementary_group_or_own_gid(self):
        # Exercise the actual factory predicate with injected process facts;
        # the file read is stopped before any native effect.
        class Worker:pass
        class NativeTimer:pass
        core=types.ModuleType('ci_worker_core')
        core.Worker=Worker;core.NativeTimer=NativeTimer;core.WorkerTimeout=OuterTimeout
        files=types.SimpleNamespace(base=types.SimpleNamespace(released=True))
        with patch.object(n.sys,'platform','linux'), \
             patch.object(n.sys,'modules',dict(n.sys.modules,ci_worker_core=core)), \
             patch.object(n,'Path',lambda _:types.SimpleNamespace(resolve=lambda:'/code/native_cases.py')), \
             patch.object(n.os,'uname',return_value=types.SimpleNamespace(machine='x86_64')), \
             patch.object(n.os,'getpid',return_value=77), \
             patch.object(n.os,'getuid',return_value=61200), \
             patch.object(n.os,'geteuid',return_value=61200), \
             patch.object(n.os,'getgid',return_value=61200), \
             patch.object(n.os,'getegid',return_value=61200), \
             patch.object(n.NativeIO,'_file',side_effect=FileNotFoundError):
            for groups,reason in (([],'native.file_missing'),([61200],'native.file_missing'),
                                  ([61201],'native.worker_identity'),
                                  ([61200,61200],'native.worker_identity')):
                with self.subTest(groups=groups),patch.object(n.os,'getgroups',return_value=groups):
                    own={'pid':77,'uid':61200,'euid':61200,'gid':61200,'egid':61200,'groups':groups}
                    job=Worker();job.own=own;job.raw=b'public synthetic context'
                    job.ready_used=True;job.used=True;job.timer=NativeTimer()
                    job.process=types.SimpleNamespace(snapshot=lambda:own)
                    job.context={'consumerCode':{'native_cases.py':{'bytes':0,'sha256':'0'*64}}}
                    with self.assertRaisesRegex(n.Refusal,reason):
                        n.NativeIO.for_checked_worker(job,files)

    def test_actual_pure_runner_and_result_parser_accept_finite_cases(self):
        io=FakeIO();result=n.run_cases(io)
        self.assertEqual(result['status'],'passed')
        self.assertEqual([x[0]for x in io.calls],list(n.CASE_IDS))
        self.assertEqual(len(io.calls),7)
        self.assertIs(n.validate_result(result,expected_pid=77,expected_context_sha='a'*64,allow_synthetic=True),result)
        self.assertLessEqual(len(n.canonical(result)),4096)
    def test_pure_runner_never_invokes_fork_or_native_factory(self):
        with patch('os.fork',side_effect=AssertionError('fork')), \
             patch.object(n.NativeIO,'for_checked_worker',side_effect=AssertionError('native factory')):
            self.assertEqual(n.run_cases(FakeIO())['status'],'passed')
    def test_fake_producer_cannot_clear_default_native_acceptance(self):
        result=n.run_cases(FakeIO())
        self.assertEqual(result['producer'],'synthetic_injected')
        with self.assertRaisesRegex(n.Refusal,'native.synthetic_producer'):n.validate_result(result)
        self.assertIs(n.validate_result(result,allow_synthetic=True),result)
    def test_exact_generic_imports_load_without_scanning_or_files(self):
        sources=FakeIO().import_sources()
        with patch('os.open',side_effect=AssertionError('file')):
            self.assertEqual(n.validate_imports(sources),n.IMPORT_PINS)
        self.assertNotIn('hosted_privacy',n.sys.modules)
        self.assertNotIn('hosted_export',n.sys.modules)
    def test_changed_or_missing_imports_stop_before_any_child(self):
        for missing in (False,True):
            io=FakeIO();sources=io.import_sources()
            if missing:sources.pop('hosted_export.py')
            else:sources['hosted_export.py']+=b'\n'
            io.import_sources=lambda:sources
            result=n.run_cases(io)
            self.assertEqual(result['status'],'failed');self.assertEqual(io.calls,[])
            self.assertFalse(result['importsPassed'])
            n.validate_result(result,allow_failure=True)
    def test_readonly_open_allowed_or_unknown_errno_refuses_and_stops(self):
        for error in (None,errno.ENOENT,errno.ELOOP):
            row=good_observation('readonly-code');row['errno']=error
            if error is None:row['detail']='write_allowed'
            io=FakeIO(overrides={'readonly-code':row});result=n.run_cases(io)
            self.assertEqual(result['status'],'failed');self.assertEqual(len(io.calls),1)
            with self.assertRaises(n.Refusal):n.validate_result(result,allow_synthetic=True)
            n.validate_result(result,allow_failure=True)
    def test_management_presence_does_not_attempt_a_socket_connection(self):
        row=good_observation('management-paths');row['detail']='management_present'
        io=FakeIO(overrides={'management-paths':row});result=n.run_cases(io)
        self.assertEqual(result['status'],'failed');self.assertEqual(len(io.calls),2)
    def test_only_blocked_errno_or_sigsys_clears_socket_and_mount(self):
        for case in('unix-socket','mount'):
            for error in(errno.EPERM,errno.EACCES):
                row=good_observation(case);row.update(exitCode=0,signal=None,errno=error,detail='blocked')
                result=n.run_cases(FakeIO(overrides={case:row}))
                self.assertEqual(result['status'],'passed');n.validate_result(result,allow_synthetic=True)
            for error in(None,errno.EFAULT,errno.EINVAL):
                row=good_observation(case);row.update(exitCode=0,signal=None,errno=error,detail='blocked')
                self.assertEqual(n.run_cases(FakeIO(overrides={case:row}))['status'],'failed')
    def test_compiled_entry_cases_need_actual111_and_fixed_refusal(self):
        for field,value in(('exitCode',0),('stderr',b'entry_exec_failed\n'),('signal',int(signal.SIGKILL))):
            row=good_observation('entry-bad-env');row[field]=value
            self.assertEqual(n.run_cases(FakeIO(overrides={'entry-bad-env':row}))['status'],'failed')
        for case,wrong_marker in (('entry-bad-argv',b'entry_refused_unknown_key\n'),
                                  ('entry-bad-env',b'entry_refused_args\n')):
            row=good_observation(case);row['stderr']=wrong_marker
            self.assertEqual(n.run_cases(FakeIO(overrides={case:row}))['status'],'failed')
    def test_complete_timer_output_and_late_zero_is_refused(self):
        row=good_observation('timer-late-zero');row['detail']='timer_returned'
        result=n.run_cases(FakeIO(overrides={'timer-late-zero':row}))
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['cases'][-1]['stdoutSha256'],n.sha(n.TIMER_OUTPUT))
        self.assertGreater(result['cases'][-1]['stdoutBytes'],0)
        with self.assertRaises(n.Refusal):n.validate_result(result,allow_synthetic=True)
    def test_unreaped_timeout_incomplete_and_unknown_signal_refuse(self):
        for field,value in(('reaped',False),('timedOut',True),('outputComplete',False),('signal',int(signal.SIGTERM))):
            row=good_observation('mount');row[field]=value
            result=n.run_cases(FakeIO(overrides={'mount':row}))
            self.assertEqual(result['status'],'failed');n.validate_result(result,allow_failure=True)
    def test_outer_worker_timeout_is_not_hidden_as_an_ordinary_case_failure(self):
        io=FakeIO(overrides={'mount':OuterTimeout()})
        with self.assertRaises(OuterTimeout):n.run_cases(io)
        self.assertEqual(len(io.calls),4)
    def test_factory_refusal_summary_preserves_fixed_code_not_exception_text(self):
        job=types.SimpleNamespace(own={'pid':77},raw=b'synthetic-context')
        result=n.failure_summary(job,n.Refusal('native.entry_pin'))
        self.assertEqual(result['reason'],'native.entry_pin')
        self.assertEqual(result['contextSha256'],n.sha(job.raw))
        self.assertEqual(result['cases'],[]);n.validate_result(result,allow_failure=True)
        result=n.failure_summary(job,RuntimeError('private arbitrary exception body'))
        self.assertEqual(result['reason'],'factory_refused')
        self.assertNotIn('exception body',json.dumps(result))
    def test_unknown_summary_case_fields_or_false_reap_claim_never_clear(self):
        original=n.run_cases(FakeIO())
        for change in(lambda row:row.update(unknown=True),lambda row:row.update(pid=1),
                      lambda row:row.update(importsPassed=False),lambda row:row.update(status='unknown'),
                      lambda row:row['cases'][0].update(unknown=True),lambda row:row['cases'][0].update(status='failed')):
            result=copy.deepcopy(original);change(result)
            with self.assertRaises(n.Refusal):n.validate_result(result,allow_synthetic=True)
        failed=good_observation('mount');failed['reaped']=False
        result=n.run_cases(FakeIO(overrides={'mount':failed}));result['allChildrenReaped']=True
        with self.assertRaisesRegex(n.Refusal,'native.reap_join'):n.validate_result(result,allow_failure=True)
    def test_missing_case_wrong_pid_context_and_changed_output_hash_refuse(self):
        result=n.run_cases(FakeIO())
        with self.assertRaises(n.Refusal):n.validate_result(result,expected_pid=78,allow_synthetic=True)
        with self.assertRaises(n.Refusal):n.validate_result(result,expected_context_sha='b'*64,allow_synthetic=True)
        for change in(lambda row:row['cases'].pop(),lambda row:row['cases'][0].update(stdoutSha256='f'*64),
                      lambda row:row.update(elapsedMilliseconds=30001)):
            changed=copy.deepcopy(result);change(changed)
            with self.assertRaises(n.Refusal):n.validate_result(changed,allow_synthetic=True)
    def test_actual_run_child_bytecode_healthy_inert_path(self):
        observation,kernel,owner=actual_run_child_injected()
        self.assertTrue(n._classify('readonly-code',observation))
        self.assertEqual(observation['errors'],n.empty_errors())
        self.assertEqual(set(kernel.closed),set(range(10,16)))
        self.assertEqual(owner.children,{})
    def test_actual_run_child_preserves_setup_selector_read_poll_firstcause(self):
        for phase in('pipe_control','fork','selector_create','nonblocking_control','register_control',
                     'select','read_control','read_stdout','read_stderr','unregister_stdout','wait_poll'):
            with self.subTest(phase=phase):
                observation,kernel,owner=actual_run_child_injected({phase:OSError(errno.EIO,'not copied')})
                self.assertEqual(observation['errors']['first'],{'phase':phase,'type':'OSError','errno':errno.EIO})
                self.assertFalse(n._classify('readonly-code',observation))
                result=n.run_cases(FakeIO(overrides={'readonly-code':observation}))
                n.validate_result(result,allow_failure=True)
                self.assertEqual(result['cases'][0]['errors'],observation['errors'])
                self.assertNotIn('not copied',n.canonical(result).decode())
                self.assertEqual(owner.children,{})
    def test_actual_run_child_cleanup_retains_firstcause_and_each_bounded_status(self):
        faults={'select':PermissionError(errno.EACCES,'private'),
                'cleanup_kill':OSError(errno.EBUSY,'private'),
                'cleanup_selector':RuntimeError('private'),
                'close_read_control':OSError(errno.EIO,'private'),
                'close_read_stdout':OSError(errno.EIO,'private')}
        observation,kernel,owner=actual_run_child_injected(faults)
        errors=observation['errors']
        self.assertEqual(errors['first'],{'phase':'select','type':'PermissionError','errno':errno.EACCES})
        self.assertEqual([row['phase']for row in errors['cleanup']],['cleanup_kill','cleanup_selector'])
        self.assertEqual(errors['omitted'],2)
        self.assertFalse(observation['outputComplete'])
        self.assertEqual(owner.children,{})
        self.assertIn(14,kernel.closed)
        self.assertIn(15,kernel.closed)
        result=n.run_cases(FakeIO(overrides={'readonly-code':observation}))
        n.validate_result(result,allow_failure=True)
        self.assertEqual(result['cases'][0]['errors'],errors)
    def test_actual_cleanup_only_fault_and_control_decode_have_distinct_causes(self):
        observation,kernel,owner=actual_run_child_injected({'cleanup_selector':OSError(errno.EBADF,'private')})
        self.assertEqual(observation['errors']['first'],{'phase':'cleanup_selector','type':'OSError','errno':errno.EBADF})
        self.assertEqual(observation['errors']['cleanup'],[observation['errors']['first']])
        self.assertEqual(set(kernel.closed),set(range(10,16)))
        observation,kernel,owner=actual_run_child_injected(malformed=True)
        self.assertEqual(observation['errors']['first'],{'phase':'control_decode','type':'JSONDecodeError','errno':None})
        self.assertFalse(observation['outputComplete'])
    def test_cleanup_wait_failure_retains_unreaped_exact_child(self):
        observation,kernel,owner=actual_run_child_injected({'wait_poll':OSError(errno.EIO,'private'),
                                                         'cleanup_wait':ChildProcessError(errno.ECHILD,'private')})
        self.assertFalse(observation['reaped'])
        self.assertEqual(observation['errors']['first']['phase'],'wait_poll')
        self.assertEqual(observation['errors']['cleanup'][0],{'phase':'cleanup_wait','type':'ChildProcessError','errno':errno.ECHILD})
        self.assertEqual(owner.children,{9001:{'pid':9001,'reaped':False}})
        self.assertEqual(set(kernel.closed),set(range(10,16)))
    def test_actual_method_outer_timeout_still_rethrows_after_independent_cleanup(self):
        with self.assertRaises(OuterTimeout):actual_run_child_injected({'select':OuterTimeout()})
        with patch.object(n.json,'loads',side_effect=OuterTimeout()):
            with self.assertRaises(OuterTimeout):actual_run_child_injected()
    def test_closed_failure_metadata_refuses_unknown_and_false_pass(self):
        original=n.run_cases(FakeIO())
        for change in(lambda v:v['cases'][0]['errors'].update(unknown=True),
                      lambda v:v['cases'][0]['errors'].update(first={'phase':'invented','type':'OSError','errno':5}),
                      lambda v:v['cases'][0]['errors'].update(first={'phase':'select','type':'PrivateMessage','errno':5}),
                      lambda v:v['cases'][0]['errors'].update(first={'phase':'select','type':'OSError','errno':5000}),
                      lambda v:v['cases'][0]['errors'].update(cleanup=[{'phase':'cleanup_wait','type':'OSError','errno':5}]),
                      lambda v:v['cases'][0]['errors'].update(omitted=1)):
            changed=copy.deepcopy(original);change(changed)
            with self.assertRaises(n.Refusal):n.validate_result(changed,allow_synthetic=True)
        row=good_observation('timer-late-zero')
        row['errors']={'first':{'phase':'select','type':'OSError','errno':5},
                       'cleanup':[{'phase':'cleanup_wait','type':'OSError','errno':5}]*2,'omitted':32}
        result=n.run_cases(FakeIO(overrides={'timer-late-zero':row}))
        self.assertEqual(result['status'],'failed')
        self.assertLessEqual(len(n.canonical(result)),4096)
        n.validate_result(result,allow_failure=True)
    def test_native_source_has_no_connect_send_or_real_mount_target(self):
        tree=ast.parse((ROOT/'native_cases.py').read_bytes())
        calls=[node.func for node in ast.walk(tree)if isinstance(node,ast.Call)]
        self.assertFalse(any(isinstance(func,ast.Attribute)and func.attr in('connect','connect_ex','send','sendall','sendto','sendmsg')for func in calls))
        source=(ROOT/'native_cases.py').read_text()
        self.assertNotIn('O_TRUNC',source)
        self.assertNotIn('O_CREAT',source)
        self.assertIn('ctypes.c_void_p(0),ctypes.c_void_p(0),ctypes.c_void_p(0)',source)


if __name__=='__main__':unittest.main()
