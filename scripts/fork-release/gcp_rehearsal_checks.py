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
DECIMAL_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
TOP_LEVEL_SHA256 = "40362bd95ae899d78f82d69726537398b16773d0793f16a705c106697327e215"
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


_TRACE_ENV_ANCHOR = "OPENCLAW_DISABLE_BONJOUR:'1'}});"
need(NATIVE.count(_TRACE_ENV_ANCHOR) == 1, "check.diagnostic_trace_anchor")
NATIVE_TRACE = NATIVE.replace(
    _TRACE_ENV_ANCHOR,
    "OPENCLAW_DISABLE_BONJOUR:'1', OPENCLAW_GATEWAY_STARTUP_TRACE:'1'}});",
    1,
)


_TIMELINE_RUNTIME = r"""
const fs = require('node:fs');
const {createHash} = require('node:crypto');
const timelineLimit = 8 * 1024 * 1024;
const topLevelSpan = 'sidecars.plugin-services';
// Exactly two encoded registration segments. Plugin-supplied child spans have
// additional segments and are deliberately excluded from this projection.
const serviceSpan = /^sidecars\.plugin-services\.[A-Za-z0-9_~-]+\.[A-Za-z0-9_~-]+$/;
let timeline, timelineTimer, diagnosticStop = null;
function timelineProjection(status) {
  const t = timeline;
  // rawRetained describes the native projection instant. The supervisor's
  // separate timeline-cleanup receipt is authoritative for later custody.
  const starts = t?.starts ?? new Map();
  const topLevelUnmatchedCount = Array.from(starts.values(), item => item.topLevel)
    .filter(Boolean).length;
  const oldest = starts.size ? Math.max(0, Math.floor((performance.now() -
    Math.min(...Array.from(starts.values(), item => item.at))) / 1000)) : null;
  return {schema:'openclaw.rehearsal-plugin-service-timeline.v1', status,
    directoryDevice:t?.directoryDevice ?? null, directoryInode:t?.directoryInode ?? null,
    fileDevice:t?.fileDevice ?? null, fileInode:t?.fileInode ?? null,
    fileBytes:t?.fileBytes ?? 0, observedBytes:t?.position ?? 0,
    sha256:t ? t.hash.digest('hex') : null,
    topLevelNameSha256:t?.topLevelHash ?? null,
    serviceNameSha256:t?.lastServiceHash ?? null,
    startCount:t?.startCount ?? 0, endCount:t?.endCount ?? 0,
    errorCount:t?.errorCount ?? 0, unmatchedCount:starts.size,
    topLevelStartCount:t?.topLevelStartCount ?? 0,
    topLevelEndCount:t?.topLevelEndCount ?? 0,
    topLevelErrorCount:t?.topLevelErrorCount ?? 0,
    topLevelUnmatchedCount,
    oldestUnmatchedSeconds:oldest, rawRetained:true};
}
function createTimeline(op) {
  if (!/^[0-9a-f]{32}$/.test(op) || process.getuid() !== 1000) throw Error('owner');
  const parent = '/rehearsal/cache';
  const base = fs.lstatSync(parent);
  if (!base.isDirectory() || base.isSymbolicLink() ||
      fs.realpathSync(parent) !== parent) throw Error('parent');
  const dir = parent + '/startup-timeline-' + op;
  fs.mkdirSync(dir, {mode:0o700});
  const directory = fs.lstatSync(dir);
  if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== 1000 ||
      (directory.mode & 0o777) !== 0o700 || fs.realpathSync(dir) !== dir) throw Error('directory');
  const directoryExact = fs.lstatSync(dir, {bigint:true});
  const path = dir + '/events.jsonl';
  const fd = fs.openSync(path, fs.constants.O_RDWR | fs.constants.O_CREAT |
    fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  const info = fs.fstatSync(fd);
  if (!info.isFile() || info.nlink !== 1 || info.uid !== 1000 ||
      (info.mode & 0o777) !== 0o600) {fs.closeSync(fd); throw Error('file');}
  const fileExact = fs.fstatSync(fd, {bigint:true});
  return {path, dir, fd, directoryDevice:directoryExact.dev.toString(),
    directoryInode:directoryExact.ino.toString(), fileDevice:fileExact.dev.toString(),
    fileInode:fileExact.ino.toString(), position:0, fileBytes:0,
    hash:createHash('sha256'), pending:Buffer.alloc(0), starts:new Map(),
    topLevelHash:null, lastServiceHash:null, startCount:0, endCount:0,
    errorCount:0, topLevelStartCount:0, topLevelEndCount:0,
    topLevelErrorCount:0, status:'observed'};
}
function consumeTimelineLine(t, raw) {
  if (!raw.length || raw.length > 8192) {t.status='limit'; return;}
  let event;
  try {event=JSON.parse(raw.toString('utf8'));} catch {t.status='unavailable'; return;}
  const topLevel = event?.name === topLevelSpan;
  if (!event || event.schemaVersion !== 'openclaw.diagnostics.v1' ||
      !['span.start','span.end','span.error'].includes(event.type) ||
      typeof event.name !== 'string' || (!topLevel && !serviceSpan.test(event.name))) return;
  if (event.phase !== 'startup' || typeof event.spanId !== 'string' ||
      !/^gateway-startup-[1-9][0-9]{0,8}$/.test(event.spanId)) {
    t.status='unavailable'; return;
  }
  const hash = createHash('sha256').update(event.name).digest('hex');
  if (topLevel) t.topLevelHash = hash;
  else t.lastServiceHash = hash;
  if (event.type === 'span.start') {
    if (t.starts.size >= 256 || t.starts.has(event.spanId)) {t.status='limit'; return;}
    t.starts.set(event.spanId, {hash, topLevel, at:performance.now()});
    t.startCount++;
    if (topLevel) t.topLevelStartCount++;
  } else {
    const started=t.starts.get(event.spanId);
    if (!started || started.hash !== hash || started.topLevel !== topLevel) {
      t.status='unavailable'; return;
    }
    t.starts.delete(event.spanId);
    if (event.type === 'span.end') {
      t.endCount++;
      if (topLevel) t.topLevelEndCount++;
    } else {
      t.errorCount++;
      if (topLevel) t.topLevelErrorCount++;
    }
  }
}
function pollTimeline() {
  const t = timeline;
  if (!t || t.status !== 'observed') return t?.status ?? 'unavailable';
  try {
    const info=fs.fstatSync(t.fd), name=fs.lstatSync(t.path);
    const directory=fs.lstatSync(t.dir,{bigint:true});
    const exact=fs.fstatSync(t.fd,{bigint:true}), exactName=fs.lstatSync(t.path,{bigint:true});
    if (!info.isFile() || !name.isFile() || info.nlink !== 1 || name.nlink !== 1 ||
        info.uid !== 1000 || name.uid !== 1000 ||
        !directory.isDirectory() || directory.uid !== 1000n ||
        directory.dev.toString() !== t.directoryDevice ||
        directory.ino.toString() !== t.directoryInode ||
        exact.dev.toString() !== t.fileDevice || exact.ino.toString() !== t.fileInode ||
        exactName.dev.toString() !== t.fileDevice || exactName.ino.toString() !== t.fileInode ||
        (name.mode & 0o777) !== 0o600 || info.size < t.position) {
      t.status='unavailable'; return t.status;
    }
    t.fileBytes=info.size;
    if (info.size > timelineLimit) {t.status='limit'; return t.status;}
    while (t.position < info.size && t.status === 'observed') {
      const buffer=Buffer.allocUnsafe(Math.min(4096, info.size-t.position));
      const count=fs.readSync(t.fd, buffer, 0, buffer.length, t.position);
      if (!count) {t.status='unavailable'; break;}
      const bytes=buffer.subarray(0,count);
      t.hash.update(bytes);t.position+=count;
      t.pending=Buffer.concat([t.pending,bytes]);
      if (t.pending.length > 8192 && !t.pending.includes(10)) {t.status='limit'; break;}
      let newline;
      while ((newline=t.pending.indexOf(10)) >= 0 && t.status === 'observed') {
        consumeTimelineLine(t,t.pending.subarray(0,newline));
        t.pending=t.pending.subarray(newline+1);
      }
      if (t.pending.length > 8192) t.status='limit';
    }
    if (t.status !== 'observed') return t.status;
    if (t.starts.size && result.healthz?.status === 200 &&
        result.startupz?.status === 503) {
      const oldest=Math.min(...Array.from(t.starts.values(), item => item.at));
      if (performance.now()-oldest >= 180000) t.status='early-stop';
    }
    return t.status === 'observed' ? null : t.status;
  } catch {t.status='unavailable'; return t.status;}
}
function stopOnTimelineStatus(status) {
  if (!status || diagnosticStop) return;
  diagnosticStop=status;
  fail('diagnostic_timeline_' + (status === 'early-stop' ? 'unmatched_service' : status));
  if (child && !exited) child.kill('SIGTERM');
}
"""


def _timeline_script():
    """Build the distinct diagnostic harness without changing legacy NATIVE."""
    anchors = (
        ("const prefix = 'OPENCLAW_REHEARSAL_CHECK_RESULT=';",
         "const prefix = 'OPENCLAW_REHEARSAL_CHECK_RESULT=';\n" + _TIMELINE_RUNTIME),
        ("    child = spawn(argv[0], argv.slice(1), {shell:false, detached:false,",
         "    timeline = createTimeline(settings.timelineOp);\n"
         "    timelineTimer = setInterval(() => stopOnTimelineStatus(pollTimeline()), 1000).unref();\n"
         "    child = spawn(argv[0], argv.slice(1), {shell:false, detached:false,"),
        (_TRACE_ENV_ANCHOR,
         "OPENCLAW_DISABLE_BONJOUR:'1', OPENCLAW_DIAGNOSTICS:'timeline', "
         "OPENCLAW_DIAGNOSTICS_TIMELINE_PATH:timeline.path}});"),
        ("      const health = result.healthz, startup = result.startupz, ready = result.readyz;",
         "      const health = result.healthz, startup = result.startupz, ready = result.readyz;\n"
         "      stopOnTimelineStatus(pollTimeline());\n"
         "      if (diagnosticStop) break;"),
        ("    if (!result.ready) fail(interrupted ? 'interrupted' : exited ? 'premature_exit' : 'startup_deadline');",
         "    if (!result.ready && !result.failure) fail(interrupted ? 'interrupted' : exited ? 'premature_exit' : 'startup_deadline');"),
        ("    process.removeListener('SIGTERM', stopSignal); process.removeListener('SIGINT', stopSignal);",
         "    if (timelineTimer) clearInterval(timelineTimer);\n"
         "    stopOnTimelineStatus(pollTimeline());\n"
         "    if (timeline?.status === 'observed' && timeline.pending.length) {\n"
         "      timeline.status='unavailable';stopOnTimelineStatus('unavailable');\n"
         "    }\n"
         "    if (timeline) {try {fs.closeSync(timeline.fd);} catch {\n"
         "      timeline.status='unavailable';fail('diagnostic_timeline_unavailable');\n"
         "    }}\n"
         "    try {result.timeline = timelineProjection(timeline?.status ?? 'unavailable');}\n"
         "    catch {fail('diagnostic_timeline_unavailable');result.timeline={\n"
         "      schema:'openclaw.rehearsal-plugin-service-timeline.v1',status:'unavailable',\n"
         "      directoryDevice:null,directoryInode:null,fileDevice:null,fileInode:null,\n"
         "      fileBytes:0,observedBytes:0,sha256:null,\n"
         "      topLevelNameSha256:null,serviceNameSha256:null,\n"
         "      startCount:0,endCount:0,errorCount:0,unmatchedCount:0,\n"
         "      topLevelStartCount:0,topLevelEndCount:0,topLevelErrorCount:0,\n"
         "      topLevelUnmatchedCount:0,\n"
         "      oldestUnmatchedSeconds:null,rawRetained:true};}\n"
         "    process.removeListener('SIGTERM', stopSignal); process.removeListener('SIGINT', stopSignal);"),
    )
    script = NATIVE
    for before, after in anchors:
        need(script.count(before) == 1, "check.diagnostic_timeline_anchor")
        script = script.replace(before, after, 1)
    return script


NATIVE_TIMELINE = _timeline_script()


def command(phase, timeout_seconds, contract=None, *, diagnostic_trace=False,
            diagnostic_timeline_op=None):
    contract = probe_contract(phase, contract)
    need(type(timeout_seconds) is int and MIN_TIMEOUT_SECONDS <= timeout_seconds <= 86400,
         "check.timeout")
    need(type(diagnostic_trace) is bool and (not diagnostic_trace or phase == "candidate-startup"),
         "check.diagnostic_trace_scope")
    need(diagnostic_timeline_op is None or
         (matches(OP, diagnostic_timeline_op) and phase == "candidate-startup" and not diagnostic_trace),
         "check.diagnostic_timeline_scope")
    settings = {"phase": phase, "contract": contract, "gateway": GATEWAY,
                "startupMs": STARTUP_SECONDS * 1000, "shutdownMs": SHUTDOWN_SECONDS * 1000}
    if diagnostic_timeline_op is not None:
        settings["timelineOp"] = diagnostic_timeline_op
    script = NATIVE_TIMELINE if diagnostic_timeline_op is not None else (NATIVE_TRACE if diagnostic_trace else NATIVE)
    return ["node", "-e", script.replace("SETTINGS", json.dumps(settings, separators=(",", ":")), 1)]


def parse_result(line):
    """Parse a complete stdout line, never an application stderr log marker."""
    need(type(line) is str and len(line) <= 4096 and line.startswith(RESULT_PREFIX) and
         line.count("\n") <= 1 and ("\n" not in line or line.endswith("\n")), "check.result.marker")
    try:
        return json.loads(line[len(RESULT_PREFIX):])
    except (ValueError, TypeError):
        raise release.Refusal("check.result.json") from None


def validate_timeline_projection(timeline):
    """Validate the bounded, path-free projection, including failed checks."""
    fields(timeline, "schema status directoryDevice directoryInode fileDevice fileInode "
           "fileBytes observedBytes sha256 topLevelNameSha256 serviceNameSha256 "
           "startCount endCount errorCount unmatchedCount topLevelStartCount "
           "topLevelEndCount topLevelErrorCount topLevelUnmatchedCount "
           "oldestUnmatchedSeconds rawRetained",
           "check.result.timeline_fields")
    counts = ("startCount", "endCount", "errorCount", "unmatchedCount",
              "topLevelStartCount", "topLevelEndCount", "topLevelErrorCount",
              "topLevelUnmatchedCount")
    need(timeline["schema"] == "openclaw.rehearsal-plugin-service-timeline.v1" and
         timeline["status"] in ("observed", "early-stop", "limit") and
         timeline["rawRetained"] is True and
         all(matches(DECIMAL_ID, timeline[k]) for k in
             ("directoryDevice", "directoryInode", "fileDevice", "fileInode")) and
         type(timeline["fileBytes"]) is int and 0 <= timeline["fileBytes"] <= 2**53 - 1 and
         type(timeline["observedBytes"]) is int and
         0 <= timeline["observedBytes"] <= min(timeline["fileBytes"], 8 * 1024 * 1024) and
         matches(HEX, timeline["sha256"]) and
         all(type(timeline[k]) is int and 0 <= timeline[k] <= 100000 for k in counts) and
         timeline["endCount"] + timeline["errorCount"] +
             timeline["unmatchedCount"] == timeline["startCount"] and
         timeline["topLevelStartCount"] <= timeline["startCount"] and
         timeline["topLevelEndCount"] <= timeline["endCount"] and
         timeline["topLevelErrorCount"] <= timeline["errorCount"] and
         timeline["topLevelUnmatchedCount"] <= timeline["unmatchedCount"] and
         timeline["topLevelEndCount"] + timeline["topLevelErrorCount"] +
             timeline["topLevelUnmatchedCount"] == timeline["topLevelStartCount"] and
         ((timeline["topLevelStartCount"] == 0 and timeline["topLevelNameSha256"] is None) or
          (timeline["topLevelStartCount"] > 0 and
           timeline["topLevelNameSha256"] == TOP_LEVEL_SHA256)) and
         ((timeline["startCount"] == timeline["topLevelStartCount"] and
           timeline["serviceNameSha256"] is None) or
          (timeline["startCount"] > timeline["topLevelStartCount"] and
           matches(HEX, timeline["serviceNameSha256"]))) and
         ((timeline["unmatchedCount"] == 0 and timeline["oldestUnmatchedSeconds"] is None) or
          (timeline["unmatchedCount"] > 0 and
           type(timeline["oldestUnmatchedSeconds"]) is int and
           0 <= timeline["oldestUnmatchedSeconds"] <= 86400)) and
         (timeline["status"] != "observed" or
          timeline["observedBytes"] == timeline["fileBytes"]) and
         (timeline["status"] != "early-stop" or
          (timeline["unmatchedCount"] > 0 and
           timeline["oldestUnmatchedSeconds"] >= 180)),
         "check.result.timeline_binding")
    return {key: timeline[key] for key in timeline}


def validate_diagnostic_timeline_failure(native_check, phase, contract=None):
    """Return only a validated fixed projection from a failed diagnostic."""
    contract = probe_contract(phase, contract)
    need(phase == "candidate-startup", "check.result.timeline_scope")
    fields(native_check, "schema phase probeContract healthz startupz readyz ready "
           "nativeExitCode nativeSignal shutdown escalated failure timeline",
           "check.result.fields")
    timeline = validate_timeline_projection(native_check["timeline"])
    failures = {"observed": {"spawn", "harness", "interrupted", "premature_exit",
                             "startup_deadline", "shutdown_deadline", "native_exit"},
                "early-stop": {"diagnostic_timeline_unmatched_service"},
                "limit": {"diagnostic_timeline_limit"}}
    need(native_check["schema"] == "openclaw.rehearsal-native-check.v1" and
         native_check["phase"] == phase and native_check["probeContract"] == contract and
         native_check["failure"] in failures[timeline["status"]] and
         type(native_check["ready"]) is bool and
         type(native_check["escalated"]) is bool and
         native_check["shutdown"] in ("not_started", "exited", "killed", "unsettled") and
         (native_check["nativeExitCode"] is None or
          type(native_check["nativeExitCode"]) is int) and
         (native_check["nativeSignal"] is None or
          (type(native_check["nativeSignal"]) is str and
           re.fullmatch(r"SIG[A-Z]+", native_check["nativeSignal"]))) and
         all(native_check[k] is None or type(native_check[k]) is dict for k in
             ("healthz", "startupz", "readyz")),
         "check.result.timeline_failure_binding")
    return timeline


def validate_result(result, phase, contract=None, *, diagnostic_timeline=False):
    contract = probe_contract(phase, contract)
    need(type(diagnostic_timeline) is bool and
         (not diagnostic_timeline or phase == "candidate-startup"),
         "check.result.timeline_scope")
    fields(result, "schema phase probeContract healthz startupz readyz ready nativeExitCode nativeSignal "
           "shutdown escalated failure" + (" timeline" if diagnostic_timeline else ""),
           "check.result.fields")
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
    if diagnostic_timeline:
        timeline = validate_timeline_projection(result["timeline"])
        need(timeline["status"] == "observed", "check.result.timeline_success_status")
    return result
