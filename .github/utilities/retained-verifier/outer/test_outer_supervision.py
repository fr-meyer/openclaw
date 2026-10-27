"""Synthetic owned-process ports only: no process, signal or VM is started."""
import unittest
import importlib.util
import hashlib
from pathlib import Path
import sys
from unittest.mock import patch
from outer_supervision import NativeOps, Refusal, SpawnedRefusal, STREAM_CAP, supervise


class FakeOps:
    synthetic = True
    def __init__(self, *, polls=(0,), chunks=(), step=0.1, ignore_term=False,
                 ignore_kill=False, wait_error=False, close_error=False,
                 spawn_error=None, straggler=False):
        self.clock=0.0;self.polls=list(polls);self.chunks=list(chunks);self.step=step
        self.ignore_term=ignore_term;self.ignore_kill=ignore_kill;self.wait_error=wait_error
        self.close_error=close_error;self.spawn_error=spawn_error;self.straggler=straggler
        self.calls=[];self.group=True;self.code=None;self.process=object();self.closed=False;self.retained=True;self.drain_failures=0;self.group_failures=0;self.term_failures=0
    def now(self):return self.clock
    def spawn(self,argv,cwd,environment):
        self.calls.append(('spawn',argv,cwd,environment))
        if self.spawn_error=='before':raise RuntimeError('fixed fake')
        if self.spawn_error=='after':raise SpawnedRefusal(self.process)
        return self.process
    def drain(self,p,duration):
        assert p is self.process
        self.clock+=self.step
        if self.drain_failures:
            self.drain_failures-=1;raise OSError('fake capture failure')
        return self.chunks.pop(0) if self.chunks else []
    def pause(self,dt):self.clock+=dt
    def eof(self,p):return type(self.code) is int and not self.chunks
    def poll(self,p):
        assert p is self.process
        value=self.polls.pop(0) if self.polls else None
        if type(value) is int:
            self.code=value
            if not self.straggler:self.group=False
        return value
    def group_alive(self,p):
        assert p is self.process
        if self.group_failures:
            self.group_failures-=1;raise OSError('fake group failure')
        return self.group
    def signal_group(self,p,signal):
        assert p is self.process
        self.calls.append(('signal',signal))
        if signal=='TERM' and self.term_failures:
            self.term_failures-=1;raise OSError('fake signal failure')
        if (signal=='TERM' and not self.ignore_term) or (signal=='KILL' and not self.ignore_kill):
            self.group=False
            if self.code is None:self.code=-15 if signal=='TERM' else -9
    def wait(self,p,timeout):
        assert p is self.process
        self.calls.append(('wait',timeout))
        if self.wait_error:raise TimeoutError('fake')
        return self.code
    def close(self,p,*,settled=True):
        assert p is self.process
        self.calls.append(('close',));self.closed=True
        if self.close_error:raise OSError('fake')
        self.retained=not settled
        return True


class SupervisionTests(unittest.TestCase):
    def run_one(self,ops,**kw):
        return supervise(ops,('/pinned/mkosi','vm'),cwd='/synthetic/public',
                         environment={'PATH':'/usr/bin:/bin'},deadline=kw.get('deadline',2),grace=1)
    def test_native_constructor_remains_disarmed_before_any_process_call(self):
        with patch('outer_supervision.subprocess.Popen') as start:
            with self.assertRaisesRegex(Refusal,'unissued_ci_scope'):NativeOps(None)
        start.assert_not_called()
    def test_parent_wait_and_empty_owned_group_are_required(self):
        ops=FakeOps(chunks=([('stdout',b'{"unitStatus":"passed"}\n')],))
        got=self.run_one(ops)
        self.assertEqual(got['status'],'outer_exit_passed')
        self.assertIs(got['outerExited'],True);self.assertIs(got['ownedGroupGone'],True)
        self.assertIs(got['shutdownRequestedByGuest'],None)
        self.assertTrue(got['synthetic']);self.assertTrue(ops.closed)
    def test_nonzero_complete_pass_json_is_not_success(self):
        got=self.run_one(FakeOps(polls=(1,),chunks=([('stdout',b'{"status":"passed"}')],)))
        self.assertEqual(got['stdout'],b'{"status":"passed"}')
        self.assertEqual(got['status'],'refused');self.assertEqual(got['reason'],'command_exit_nonzero')
    def test_timeout_retains_bounded_bytes_and_closes_exact_spawn_once(self):
        ops=FakeOps(polls=(None,),chunks=([('stderr',b'phase:guest\n')],))
        got=self.run_one(ops,deadline=0.2)
        self.assertTrue(got['timedOut']);self.assertEqual(got['status'],'refused')
        self.assertEqual(got['stderr'],b'phase:guest\n');self.assertTrue(got['outerExited'])
        self.assertEqual(sum(c[0]=='spawn' for c in ops.calls),1)
        self.assertEqual([c for c in ops.calls if c[0]=='signal'],[('signal','TERM')])
    def test_late_zero_with_complete_json_cannot_pass(self):
        got=self.run_one(FakeOps(polls=(0,),step=2,chunks=([('stdout',b'{"status":"passed"}')],)),deadline=1)
        self.assertEqual(got['returncode'],0);self.assertTrue(got['timedOut'])
        self.assertEqual(got['status'],'refused')
    def test_oversize_output_is_bounded_refusal_and_stops_early(self):
        ops=FakeOps(polls=(None,),chunks=([('stdout',b'x'*(STREAM_CAP+1))],))
        got=self.run_one(ops)
        self.assertEqual(len(got['stdout']),STREAM_CAP);self.assertTrue(got['truncated'])
        self.assertEqual(got['reason'],'output_limit');self.assertLess(ops.clock,2)
    def test_term_ignored_gets_one_owned_kill_without_new_spawn(self):
        ops=FakeOps(polls=(None,),ignore_term=True)
        got=self.run_one(ops,deadline=0.2)
        self.assertEqual([c for c in ops.calls if c[0]=='signal'],[('signal','TERM'),('signal','KILL')])
        self.assertTrue(got['ownedGroupGone']);self.assertEqual(got['status'],'refused')
        self.assertEqual(sum(c[0]=='spawn' for c in ops.calls),1)
    def test_group_surviving_kill_never_reports_closed(self):
        got=self.run_one(FakeOps(polls=(None,),ignore_term=True,ignore_kill=True),deadline=0.2)
        self.assertFalse(got['ownedGroupGone']);self.assertEqual(got['status'],'refused')
    def test_parent_zero_with_straggler_is_not_normal_guest_exit(self):
        ops=FakeOps(polls=(0,),straggler=True)
        got=self.run_one(ops)
        self.assertEqual(got['reason'],'owned_group_straggler');self.assertEqual(got['status'],'refused')
        self.assertTrue(got['ownedGroupGone'])
    def test_spawn_failure_before_effect_has_no_owned_signal(self):
        ops=FakeOps(spawn_error='before');got=self.run_one(ops)
        self.assertFalse(got['spawned']);self.assertFalse(got['outerExited'])
        self.assertEqual(len(ops.calls),1)
    def test_postspawn_setup_failure_preserves_owned_closeout(self):
        ops=FakeOps(spawn_error='after');got=self.run_one(ops)
        self.assertTrue(got['spawned']);self.assertTrue(got['outerExited']);self.assertTrue(ops.closed)
        self.assertEqual(got['status'],'refused')
        self.assertEqual([c for c in ops.calls if c[0]=='signal'],[('signal','TERM')])
    def test_wait_or_close_failure_cannot_be_reported_success(self):
        for kw in ({'wait_error':True},{'close_error':True}):
            with self.subTest(kw=kw):
                ops=FakeOps(**kw);got=self.run_one(ops)
                self.assertEqual(got['status'],'refused');self.assertTrue(ops.closed)
                self.assertIn('outer_cleanup_',got['reason'])
    def test_noninteger_poll_does_not_imply_no_effect_or_skip_cleanup(self):
        ops=FakeOps(polls=('0',));got=self.run_one(ops)
        self.assertEqual(got['status'],'refused');self.assertTrue(got['outerExited'])
        self.assertTrue(ops.closed)
    def test_invalid_deadline_refuses_before_spawn(self):
        for deadline in (0,-1,None,True,float('inf'),float('nan'),1801):
            with self.subTest(deadline=deadline):
                ops=FakeOps()
                with self.assertRaisesRegex(Refusal,'deadline'):self.run_one(ops,deadline=deadline)
                self.assertEqual(ops.calls,[])

    def test_all_queued_output_is_drained_to_both_eof_after_parent_exit(self):
        ops=FakeOps(chunks=([('stdout',b'first\n')],[('stderr',b'middle\n')],
                           [('stderr',b'late-cause\n')]))
        got=self.run_one(ops)
        self.assertEqual(got['stderr'],b'middle\nlate-cause\n')
        self.assertTrue(got['streamsEOF']);self.assertFalse(got['ownershipRetained'])

    def test_capture_error_does_not_skip_kill_wait_or_uncertain_owner_retention(self):
        ops=FakeOps(polls=(None,),ignore_term=True,ignore_kill=True)
        ops.drain_failures=4
        got=self.run_one(ops,deadline=0.2)
        self.assertIn(('signal','KILL'),ops.calls)
        self.assertTrue(any(c[0]=='wait' for c in ops.calls))
        self.assertTrue(ops.retained);self.assertTrue(got['ownershipRetained'])
        self.assertEqual(got['status'],'refused')

    def test_group_and_term_errors_do_not_skip_remaining_owned_cleanup(self):
        ops=FakeOps(polls=(None,),ignore_term=True)
        ops.group_failures=1;ops.term_failures=1
        got=self.run_one(ops,deadline=0.2)
        self.assertIn(('signal','KILL'),ops.calls)
        self.assertTrue(any(c[0]=='wait' for c in ops.calls))
        self.assertTrue(got['outerExited']);self.assertTrue(got['ownedGroupGone'])
        self.assertFalse(ops.retained);self.assertEqual(got['status'],'refused')

    def test_incomplete_eof_refuses_despite_zero_parent_and_closed_group(self):
        ops=FakeOps();ops.eof=lambda p:False
        got=self.run_one(ops)
        self.assertTrue(got['outerExited']);self.assertTrue(got['ownedGroupGone'])
        self.assertFalse(got['streamsEOF']);self.assertEqual(got['status'],'refused')

    def test_wait_uncertainty_keeps_reconciliation_handle(self):
        ops=FakeOps(wait_error=True)
        got=self.run_one(ops)
        self.assertFalse(got['outerExited']);self.assertTrue(ops.retained)
        self.assertTrue(got['ownershipRetained'])

    def test_close_failure_keeps_reconciliation_handle(self):
        ops=FakeOps(close_error=True)
        got=self.run_one(ops)
        self.assertTrue(ops.retained);self.assertTrue(got['ownershipRetained'])

    def test_queued_overflow_during_eof_drain_still_refuses(self):
        ops=FakeOps(chunks=([],[('stderr',b'x'*(STREAM_CAP+1))]))
        got=self.run_one(ops)
        self.assertTrue(got['truncated']);self.assertEqual(got['reason'],'output_limit')
        self.assertEqual(got['status'],'refused')

    def test_both_review_findings_reproduce_on_actual_preserved_r1_supervisor(self):
        path=Path(__file__).resolve().parents[1]/'outer-supervision-r1/outer_supervision.py'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
            '201a3fc19f994b20ee6d93e21dd7bbb5013cbf98e718491cb08efab665f8f16d')
        spec=importlib.util.spec_from_file_location('preserved_outer_r1',path)
        old=importlib.util.module_from_spec(spec);sys.modules[spec.name]=old;spec.loader.exec_module(old)
        def call(ops):return old.supervise(ops,('/pinned/mkosi','vm'),cwd='/synthetic/public',
            environment={'PATH':'/usr/bin:/bin'},deadline=0.2,grace=1)
        capture=FakeOps(chunks=([('stdout',b'first\n')],[('stderr',b'middle\n')],
                               [('stderr',b'late-cause\n')]),step=0.01)
        prior=call(capture)
        self.assertNotIn(b'late-cause',prior['stderr'])
        self.assertEqual(prior['status'],'outer_exit_passed')
        stranded=FakeOps(polls=(None,),ignore_term=True,ignore_kill=True)
        stranded.drain_failures=4
        call(stranded)
        self.assertNotIn(('signal','KILL'),stranded.calls)
        self.assertFalse(any(c[0]=='wait' for c in stranded.calls))
        self.assertFalse(stranded.retained) # R1 close contract discarded it.


if __name__=='__main__':unittest.main()
