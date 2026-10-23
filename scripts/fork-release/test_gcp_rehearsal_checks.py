"""Startup payload contracts; native fixtures use synthetic Node owners only."""

import copy
import json
import shutil
import subprocess
import sys
import unittest

import gcp_rehearsal_checks as checks
import gcp_snapshot_trial as trial
import release


def successful(phase="candidate-startup", contract=checks.PROBES[1]):
    return {"schema": "openclaw.rehearsal-native-check.v1", "phase": phase,
            "probeContract": contract, "healthz": {"status": 200, "ok": True, "statusText": "live"},
            "startupz": {"status": 200, "ok": True, "statusText": "started"} if contract == checks.PROBES[1] else None,
            "readyz": {"status": 200, "ready": True}, "ready": True, "nativeExitCode": 0,
            "nativeSignal": None, "shutdown": "exited", "escalated": False, "failure": None}


class RehearsalCheckContracts(unittest.TestCase):
    def candidate(self):
        image = {**trial.QUALIFIED_IMAGE, "producer": {"kind": "gcp", "toolingSha": trial.QUALIFIED_PRODUCER}}
        clean = {"restorationState": "doctor-complete", "integrationsDisabled": True}
        check = {"imageReceiptSha256": "a" * 64, "cleanInputSha256": "b" * 64}
        check["doctorResult"] = {**check, "operationId": "c" * 32, "state": "succeeded",
            "doctorComplete": True, "nativeExitCode": 0, "oomKillDelta": 0,
            "cgroupSettlementObserved": True, "cleanup": "owned_container_stopped_retained",
            "nativeState": {"Running": False, "Pid": 0, "ExitCode": 0, "OOMKilled": False}}
        return image, clean, check

    def baseline(self):
        image = {"schema": "openclaw.rehearsal-baseline-image.v1", "sourceSha": "d" * 40,
            "version": "2026.9.4", "architecture": "amd64", "indexDigest": "sha256:" + "e" * 64,
            "imageDigest": "sha256:" + "f" * 64, "configDigest": "sha256:" + "1" * 64,
            "gatewayProbeContract": checks.PROBES[0]}
        clean = {"restorationState": "unmigrated", "integrationsDisabled": True,
                 "baselineSourceSha": image["sourceSha"], "baselineImageDigest": image["imageDigest"]}
        return image, clean, {"imageReceiptSha256": "2" * 64, "cleanInputSha256": "3" * 64}

    def test_candidate_requires_qualified_image_and_settled_successful_doctor(self):
        image, clean, check = self.candidate()
        self.assertEqual(checks.validate_phase("candidate-startup", image, clean, check), checks.PROBES[1])
        for key, value in (("state", "running"), ("oomKillDelta", 1), ("nativeExitCode", False),
                           ("cgroupSettlementObserved", False), ("imageReceiptSha256", "9" * 64),
                           ("cleanInputSha256", "9" * 64), ("doctorComplete", False)):
            changed = copy.deepcopy(check)
            changed["doctorResult"][key] = value
            with self.subTest(field=key), self.assertRaises(release.Refusal):
                checks.validate_phase("candidate-startup", image, clean, changed)
        for key, value in (("Running", True), ("Pid", 23), ("ExitCode", 137), ("OOMKilled", True)):
            changed = copy.deepcopy(check)
            changed["doctorResult"]["nativeState"][key] = value
            with self.subTest(native=key), self.assertRaises(release.Refusal):
                checks.validate_phase("candidate-startup", image, clean, changed)
        with self.assertRaises(release.Refusal):
            checks.validate_phase("candidate-startup", {**image, "sourceSha": "9" * 40}, clean, check)
        with self.assertRaises(release.Refusal):
            checks.validate_phase("candidate-startup", image, {**clean, "restorationState": "unmigrated"}, check)

    def test_baseline_is_independent_and_bound_to_original_data_build(self):
        image, clean, check = self.baseline()
        self.assertEqual(checks.validate_phase("rollback-startup", image, clean, check), checks.PROBES[0])
        for key, value in (("baselineSourceSha", "8" * 40), ("baselineImageDigest", "sha256:" + "8" * 64),
                           ("restorationState", "doctor-complete"), ("integrationsDisabled", False)):
            with self.subTest(field=key), self.assertRaises(release.Refusal):
                checks.validate_phase("rollback-startup", image, {**clean, key: value}, check)
        for key, value in (("gatewayProbeContract", "assume-ready"), ("version", "latest"),
                           ("indexDigest", "openclaw:2026.9.4"), ("schema", "openclaw.fork-release-image.v2")):
            with self.subTest(image=key), self.assertRaises(release.Refusal):
                checks.validate_phase("rollback-startup", {**image, key: value}, clean, check)

    def test_command_has_fixed_gateway_and_finite_native_budgets(self):
        argv = checks.command("candidate-startup", 940)
        self.assertEqual(argv[:2], ["node", "-e"])
        self.assertIn('"startupMs":600000', argv[2])
        self.assertIn('"shutdownMs":330000', argv[2])
        self.assertIn('"gateway":' + json.dumps(checks.GATEWAY, separators=(",", ":")), argv[2])
        for phase, timeout, contract in (("candidate-startup", 939, None), ("exec", 940, None),
                                         ("candidate-startup", 940, checks.PROBES[0]),
                                         ("rollback-startup", 940, None)):
            with self.subTest(phase=phase, timeout=timeout, contract=contract), self.assertRaises(release.Refusal):
                checks.command(phase, timeout, contract)

    def test_exact_long_timeline_window_preserves_retained_and_ordinary_budgets(self):
        def settings(argv):
            return json.loads(argv[2].split("const settings = ", 1)[1].split(";", 1)[0])

        operation = "a" * 32
        ordinary = settings(checks.command("candidate-startup", 3000))
        traced = settings(checks.command("candidate-startup", 3000, diagnostic_trace=True))
        retained = settings(checks.command("candidate-startup", 1200,
                                           diagnostic_timeline_op=operation))
        long = settings(checks.command("candidate-startup", 3000,
                                       diagnostic_timeline_op=operation))
        self.assertEqual(ordinary["startupMs"], 600000)
        self.assertEqual(traced["startupMs"], 600000)
        self.assertNotIn("unmatchedMs", ordinary)
        self.assertNotIn("unmatchedMs", traced)
        self.assertEqual((retained["startupMs"], retained["unmatchedMs"]),
                         (600000, 180000))
        self.assertEqual((long["startupMs"], long["unmatchedMs"], long["shutdownMs"]),
                         (2400000, 1800000, 330000))
        self.assertLessEqual(long["startupMs"] + long["shutdownMs"] + 10000, 3000000)
        with self.assertRaisesRegex(release.Refusal, "check.diagnostic_timeline_timeout"):
            checks.command("candidate-startup", 3001, diagnostic_timeline_op=operation)

    def test_timeline_unmatched_stop_remains_fatal_at_selected_bound(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node is unavailable")
        for outer, expected in ((1200, 180000), (3000, 1800000)):
            with self.subTest(outer=outer):
                argv = checks.command("candidate-startup", outer,
                                      diagnostic_timeline_op="a" * 32)
                settings = json.loads(argv[2].split("const settings = ", 1)[1].split(";", 1)[0])
                self.assertEqual(settings["unmatchedMs"], expected)
                fixture = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const regular = {isFile:()=>true,nlink:1,uid:1000,mode:0o600,size:0};
const exact = {...regular,dev:11n,ino:13n};
const directory = {isDirectory:()=>true,uid:1000n,dev:11n,ino:12n};
const fs = {fstatSync:(_fd,options)=>options?.bigint ? exact : regular,
  lstatSync:(path,options)=>path === 'directory' ? directory :
    options?.bigint ? exact : regular};
const context = {settings:SETTINGS,result:{healthz:{status:200},
  startupz:{status:503},failure:null},now:0,kills:0,Buffer,assert,
  require:name=>name === 'node:fs' ? fs : crypto};
context.performance = {now:()=>context.now};
context.child = {kill:()=>{context.kills++;return true;}};
context.exited = false;
context.fail = reason=>{context.result.failure ||= reason;};
vm.runInNewContext(RUNTIME + `
timeline={status:'observed',fd:1,path:'file',dir:'directory',position:0,
  directoryDevice:'11',directoryInode:'12',fileDevice:'11',fileInode:'13',
  starts:new Map([['service',{at:0}]]),pending:Buffer.alloc(0)};
now=settings.unmatchedMs-1;
assert.equal(pollTimeline(),null);
assert.equal(result.failure,null);
now=settings.unmatchedMs;
const status=pollTimeline();
assert.equal(status,'early-stop');
stopOnTimelineStatus(status);
assert.equal(result.failure,'diagnostic_timeline_unmatched_service');
assert.equal(kills,1);`, context);
"""
                script = fixture.replace("SETTINGS", json.dumps(settings), 1).replace(
                    "RUNTIME", json.dumps(checks._TIMELINE_RUNTIME), 1)
                observed = subprocess.run([node, "-"], input=script, text=True,
                                          capture_output=True, timeout=5)
                self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_endpoint_success_cannot_hide_failed_or_forced_shutdown(self):
        for key, value in (("ready", False), ("nativeExitCode", 1), ("nativeExitCode", False),
                           ("nativeSignal", "SIGTERM"), ("shutdown", "killed"), ("escalated", True),
                           ("failure", "shutdown_deadline"), ("phase", "rollback-startup")):
            with self.subTest(field=key), self.assertRaises(release.Refusal):
                checks.validate_result({**successful(), key: value}, "candidate-startup")
        bad = successful()
        bad["startupz"] = {"status": 200, "ok": True, "statusText": "starting"}
        with self.assertRaisesRegex(release.Refusal, "check.result.startup"):
            checks.validate_result(bad, "candidate-startup")
        checks.validate_result(successful(), "candidate-startup")
        checks.validate_result(successful("rollback-startup", checks.PROBES[0]), "rollback-startup", checks.PROBES[0])

    def test_marker_parser_rejects_embedded_native_log_and_multiple_lines(self):
        line = checks.RESULT_PREFIX + json.dumps(successful()) + "\n"
        checks.validate_result(checks.parse_result(line), "candidate-startup")
        for bad in ("gateway log " + line, line + line, checks.RESULT_PREFIX + "x", "x" * 5000):
            with self.subTest(line=bad[:40]), self.assertRaises(release.Refusal):
                checks.parse_result(bad)


@unittest.skipUnless(sys.platform == "linux" and shutil.which("node"), "native fixture requires Linux Node")
class NativePayloadTests(unittest.TestCase):
    def test_actual_payload_with_synthetic_gateway_http_and_clock(self):
        # Run the actual emitted script in a VM with bounded fake process/HTTP
        # owners. No real gateway, ports, sleeps, datasets or cloud operations.
        fixture = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const scripts = SCRIPTS;
async function run(mode, script) {
  let now = 0, output = '', spawned, liveTimers = new Set(), requests = [];
  const proc = new EventEmitter(); proc.env = {PATH:'/usr/bin'};
  proc.stdout = {write: value => {output += value;}};
  const child = new EventEmitter();
  child.kill = signal => {
    if (mode === 'shutdown-timeout' && signal === 'SIGTERM') return true;
    queueMicrotask(() => child.emit('exit', signal === 'SIGKILL' ? null : 0,
      signal === 'SIGKILL' ? 'SIGKILL' : null)); return true;
  };
  function timer(callback, ms) {
    const token = setImmediate(() => {liveTimers.delete(token); now += ms; callback();});
    liveTimers.add(token); return token;
  }
  const modules = {
    'node:child_process': {spawn: (binary, argv, options) => {
      spawned = {binary, argv, options};
      assert.equal(options.shell, false); assert.equal(options.detached, false);
      assert.equal(JSON.stringify(options.stdio), '["ignore",2,2]');
      assert.equal(options.env.OPENCLAW_DISABLE_BONJOUR, '1');
      assert.equal(options.env.OPENCLAW_GATEWAY_TOKEN.length, 64);
      if (mode === 'premature-exit') queueMicrotask(() => child.emit('exit', 2, null));
      return child;
    }},
    'node:crypto': {randomBytes: n => Buffer.alloc(n, 1)},
    'node:perf_hooks': {performance: {now: () => now}},
    'node:http': {get: (options, callback) => {
      requests.push(options.path);
      assert.equal(options.hostname, '127.0.0.1'); assert.equal(options.port, 18789);
      const request = new EventEmitter(); request.destroy = () => {};
      if (mode === 'request-timeout') return request;
      queueMicrotask(() => {
        const response = new EventEmitter(); response.destroy = () => {};
        response.statusCode = 200; callback(response);
        const body = options.path === '/readyz' ? {ready:true} :
          {ok:true, status:options.path === '/healthz' ? 'live' :
            mode === 'startup-pending' ? 'starting' : 'started'};
        response.emit('data', Buffer.from(mode === 'oversized' ? 'x'.repeat(17000) : JSON.stringify(body)));
        response.emit('end');
      }); return request;
    }},
  };
  await vm.runInNewContext(script, {require: name => {
    assert.ok(name in modules, name); return modules[name];
  }, process:proc, Buffer, setTimeout:timer, clearTimeout: token => {
    clearImmediate(token); liveTimers.delete(token);
  }});
  assert.ok(spawned); assert.ok(spawned.argv.includes('--bind'));
  assert.equal(liveTimers.size, 0);
  return {mode, result:JSON.parse(output.trim().split('OPENCLAW_REHEARSAL_CHECK_RESULT=')[1]),
    exitCode:proc.exitCode, requests:[...new Set(requests)]};
}
(async () => {
  const output = [];
  for (const mode of ['success','premature-exit','startup-pending','shutdown-timeout','request-timeout','oversized'])
    output.push(await run(mode, scripts.candidate));
  output.push(await run('baseline', scripts.baseline));
  process.stdout.write(JSON.stringify(output));
})().catch(error => {process.stderr.write(error.stack); process.exitCode = 1;});
"""
        scripts = {"candidate": checks.command("candidate-startup", 940)[2],
                   "baseline": checks.command("rollback-startup", 940, checks.PROBES[0])[2]}
        result = subprocess.run([shutil.which("node"), "-e", fixture.replace("SCRIPTS", json.dumps(scripts), 1)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr[:8192])
        rows = {row["mode"]: row for row in json.loads(result.stdout)}
        checks.validate_result(rows["success"]["result"], "candidate-startup")
        self.assertEqual(rows["success"]["exitCode"], 0)
        self.assertEqual(set(rows["success"]["requests"]), {"/healthz", "/startupz", "/readyz"})
        checks.validate_result(rows["baseline"]["result"], "rollback-startup", checks.PROBES[0])
        self.assertEqual(set(rows["baseline"]["requests"]), {"/healthz", "/readyz"})
        for mode in ("premature-exit", "startup-pending", "shutdown-timeout", "request-timeout", "oversized"):
            with self.subTest(mode=mode):
                self.assertEqual(rows[mode]["exitCode"], 1)
                with self.assertRaises(release.Refusal):
                    checks.validate_result(rows[mode]["result"], "candidate-startup")
        self.assertEqual(rows["shutdown-timeout"]["result"]["failure"], "shutdown_deadline")
        self.assertEqual(rows["shutdown-timeout"]["result"]["shutdown"], "killed")


if __name__ == "__main__":
    unittest.main()
