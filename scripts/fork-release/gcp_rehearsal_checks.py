"""Native startup check payload for the admitted snapshot-trial supervisor.

This module never launches Docker, acquires a lease, or restores a dataset.
The trial owner must validate retained prior-operation evidence and actual
container settlement before calling these helpers. An embedded result alone
is not authority. The same owner captures stdout separately from native logs,
checks the cgroup after this child exits, and retains/stops its exact CID.
"""

import json
import re

import release

need = release.need
HEX = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
OP = re.compile(r"[0-9a-f]{32}\Z")
PHASES = ("candidate-startup", "rollback-startup")
PROBES = ("healthz-readyz-v1", "healthz-startupz-readyz-v1")
RESULT_PREFIX = "OPENCLAW_REHEARSAL_CHECK_RESULT="
STARTUP_SECONDS = 600
SHUTDOWN_SECONDS = 330
MIN_TIMEOUT_SECONDS = STARTUP_SECONDS + SHUTDOWN_SECONDS + 10
GATEWAY = ["node", "/app/openclaw.mjs", "gateway", "run", "--bind", "loopback",
           "--port", "18789", "--tailscale", "off", "--auth", "token"]


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names.split()), code)


def probe_contract(phase, contract=None):
    need(phase in PHASES, "check.phase")
    if phase == "candidate-startup":
        need(contract in (None, PROBES[1]), "check.candidate.probe_contract")
        return PROBES[1]
    need(contract in PROBES, "check.baseline.probe_contract")
    return contract


def validate_phase(phase, image, clean, check, *, dd_final_startup=False):
    """Validate already observed evidence; caller owns its file/live binding.

    Candidate check.cleanInputSha256 identifies the original Doctor input.
    The current post-Doctor clean receipt has its own hash and config binding.
    The caller must prove both refer to the same actual device/mount roots.
    Rollback's clean receipt must be a fresh generation from the same selected
    immutable daily snapshot, proven by the lifecycle owner before this call.
    """
    need(phase in PHASES and type(image) is dict and type(clean) is dict, "check.phase")
    names = "imageReceiptSha256 cleanInputSha256" + (" doctorResult" if phase == PHASES[0] else "")
    fields(check, names, "check.input.fields")
    need(all(matches(HEX, check[k]) for k in ("imageReceiptSha256", "cleanInputSha256")),
         "check.input.hash")
    need(clean.get("integrationsDisabled") is True, "check.integrations")
    if phase == PHASES[0]:
        # Lazy import keeps the trial's single supervisor/helper bundle owner.
        import gcp_snapshot_trial as trial
        trial.qualified_image(image, dd_final_startup=dd_final_startup)
        need(clean.get("restorationState") == "doctor-complete", "check.candidate.data_state")
        result = check["doctorResult"]
        need(type(result) is dict and matches(OP, result.get("operationId")) and
             result.get("state") == "succeeded" and result.get("doctorComplete") is True and
             result.get("nativeExitCode") == 0 and type(result.get("nativeExitCode")) is int and
             result.get("oomKillDelta") == 0 and type(result.get("oomKillDelta")) is int and
             result.get("cgroupSettlementObserved") is True and
             result.get("cleanup") == "owned_container_stopped_retained" and
             all(result.get(k) == check[k] for k in ("imageReceiptSha256", "cleanInputSha256")),
             "check.candidate.doctor")
        state = result.get("nativeState", {})
        need(type(state) is dict and state.get("Running") is False and type(state.get("Pid")) is int and
             state.get("Pid") == 0 and type(state.get("ExitCode")) is int and
             state.get("ExitCode") == 0 and state.get("OOMKilled") is False,
             "check.candidate.doctor_not_stopped")
        return PROBES[1]
    need(image.get("schema") == "openclaw.rehearsal-baseline-image.v1" and
         image.get("architecture") == "amd64" and matches(SHA, image.get("sourceSha")) and
         type(image.get("version")) is str and
         re.fullmatch(r"2026\.[0-9]+\.[0-9]+", image["version"]) is not None and
         all(matches(DIGEST, image.get(k)) for k in ("indexDigest", "imageDigest", "configDigest")),
         "check.baseline.image")
    need(clean.get("restorationState") == "unmigrated" and
         clean.get("baselineSourceSha") == image["sourceSha"] and
         clean.get("baselineImageDigest") in {image[k] for k in ("indexDigest", "imageDigest", "configDigest")},
         "check.baseline.data_binding")
    return probe_contract(phase, image.get("gatewayProbeContract"))


NATIVE = r"""
const {spawn} = require('node:child_process');
const http = require('node:http');
const {randomBytes} = require('node:crypto');
const {performance} = require('node:perf_hooks');
const settings = SETTINGS;
const prefix = 'OPENCLAW_REHEARSAL_CHECK_RESULT=';
const result = {schema:'openclaw.rehearsal-native-check.v1', phase:settings.phase,
  probeContract:settings.contract, healthz:null, startupz:null, readyz:null,
  ready:false, nativeExitCode:null, nativeSignal:null, shutdown:'not_started',
  escalated:false, failure:null};
let child, exited = false, interrupted = false, resolveExit;
const exit = new Promise(resolve => {resolveExit = resolve;});
function fail(reason) {result.failure ||= reason;}
function delay(ms) {return new Promise(resolve => setTimeout(resolve, ms));}
async function within(promise, ms) {
  let timer;
  try {return await Promise.race([promise.then(() => true),
    new Promise(resolve => {timer = setTimeout(() => resolve(false), ms);})]);}
  finally {clearTimeout(timer);}
}
function probe(path) {
  return new Promise(resolve => {
    let settled = false, timer, response;
    const finish = value => {
      if (settled) return;
      settled = true; clearTimeout(timer); resolve(value);
    };
    const request = http.get({hostname:'127.0.0.1', port:18789, path:'/' + path,
      method:'GET', agent:false}, incoming => {
      response = incoming;
      let bytes = 0, chunks = [];
      incoming.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 16384) {finish({status:incoming.statusCode, error:'body_limit'});
          incoming.destroy(); request.destroy(); return;}
        chunks.push(chunk);
      });
      incoming.once('error', () => finish({status:incoming.statusCode, error:'response'}));
      incoming.once('end', () => {
        try {
          const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
          const statusText = ['live','started','starting','draining'].includes(value.status) ? value.status : null;
          finish(path === 'readyz' ? {status:incoming.statusCode, ready:value.ready === true} :
            {status:incoming.statusCode, ok:value.ok === true, statusText});
        } catch {finish({status:incoming.statusCode, error:'json'});}
      });
    });
    request.once('error', () => finish({status:null, error:'connection'}));
    // Absolute deadline covers connection and a peer slowly streaming the body.
    timer = setTimeout(() => {finish({status:null, error:'deadline'});
      response?.destroy(); request.destroy();}, 2000);
  });
}
function stopSignal() {
  interrupted = true; fail('interrupted');
  if (child && !exited) child.kill('SIGTERM');
}
process.on('SIGTERM', stopSignal); process.on('SIGINT', stopSignal);
(async () => {
  try {
    const argv = settings.gateway;
    child = spawn(argv[0], argv.slice(1), {shell:false, detached:false,
      // Separate native logs from the one trusted harness result on stdout.
      stdio:['ignore', 2, 2], env:{...process.env,
        OPENCLAW_GATEWAY_TOKEN:randomBytes(32).toString('hex'), OPENCLAW_DISABLE_BONJOUR:'1'}});
    child.once('error', () => {fail('spawn'); exited = true; resolveExit();});
    child.once('exit', (code, signal) => {
      result.nativeExitCode = code; result.nativeSignal = signal;
      exited = true; resolveExit();
    });
    const end = performance.now() + settings.startupMs;
    while (!exited && !interrupted && performance.now() < end) {
      const paths = settings.contract === 'healthz-startupz-readyz-v1' ?
        ['healthz','startupz','readyz'] : ['healthz','readyz'];
      const observed = await Promise.all(paths.map(probe));
      paths.forEach((path, index) => {result[path] = observed[index];});
      const health = result.healthz, startup = result.startupz, ready = result.readyz;
      if (!exited && !interrupted && health.status === 200 && health.ok &&
          ready.status === 200 && ready.ready &&
          (settings.contract === 'healthz-readyz-v1' ||
            (startup.status === 200 && startup.ok && startup.statusText === 'started'))) {
        result.ready = true; break;
      }
      if (!exited && !interrupted) await delay(1000);
    }
    if (!result.ready) fail(interrupted ? 'interrupted' : exited ? 'premature_exit' : 'startup_deadline');
  } catch {fail('harness');}
  finally {
    if (child && !exited) {
      child.kill('SIGTERM');
      if (!await within(exit, settings.shutdownMs)) {
        fail('shutdown_deadline'); result.escalated = true; child.kill('SIGKILL');
        result.shutdown = await within(exit, 5000) ? 'killed' : 'unsettled';
      } else result.shutdown = 'exited';
    } else if (child) result.shutdown = 'exited';
    if (result.nativeExitCode !== 0 || result.nativeSignal !== null) fail('native_exit');
    process.removeListener('SIGTERM', stopSignal); process.removeListener('SIGINT', stopSignal);
    process.stdout.write(prefix + JSON.stringify(result) + '\n');
    process.exitCode = result.failure === null && result.ready && result.shutdown === 'exited' ? 0 : 1;
  }
})().catch(() => {process.exitCode = 1;});
"""


def command(phase, timeout_seconds, contract=None):
    contract = probe_contract(phase, contract)
    need(type(timeout_seconds) is int and MIN_TIMEOUT_SECONDS <= timeout_seconds <= 86400,
         "check.timeout")
    settings = {"phase": phase, "contract": contract, "gateway": GATEWAY,
                "startupMs": STARTUP_SECONDS * 1000, "shutdownMs": SHUTDOWN_SECONDS * 1000}
    return ["node", "-e", NATIVE.replace("SETTINGS", json.dumps(settings, separators=(",", ":")), 1)]


def parse_result(line):
    """Parse a complete stdout line, never an application stderr log marker."""
    need(type(line) is str and len(line) <= 4096 and line.startswith(RESULT_PREFIX) and
         line.count("\n") <= 1 and ("\n" not in line or line.endswith("\n")), "check.result.marker")
    try:
        return json.loads(line[len(RESULT_PREFIX):])
    except (ValueError, TypeError):
        raise release.Refusal("check.result.json") from None


def validate_result(result, phase, contract=None):
    contract = probe_contract(phase, contract)
    fields(result, "schema phase probeContract healthz startupz readyz ready nativeExitCode nativeSignal "
           "shutdown escalated failure", "check.result.fields")
    need(result["schema"] == "openclaw.rehearsal-native-check.v1" and result["phase"] == phase and
         result["probeContract"] == contract, "check.result.binding")
    need(result["failure"] is None and result["ready"] is True and result["shutdown"] == "exited" and
         result["escalated"] is False and type(result["nativeExitCode"]) is int and
         result["nativeExitCode"] == 0 and result["nativeSignal"] is None, "check.result.native")
    health, startup, ready = (result[k] for k in ("healthz", "startupz", "readyz"))
    need(type(health) is dict and health.get("status") == 200 and health.get("ok") is True and
         type(ready) is dict and ready.get("status") == 200 and ready.get("ready") is True,
         "check.result.endpoints")
    if contract == PROBES[1]:
        need(type(startup) is dict and startup.get("status") == 200 and startup.get("ok") is True and
             startup.get("statusText") == "started", "check.result.startup")
    else:
        need(startup is None, "check.result.baseline_unrequested_probe")
    return result
