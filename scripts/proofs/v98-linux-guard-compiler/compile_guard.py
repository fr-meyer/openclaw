"""Future Linux CI compiler only; never loads the output or launches Node.

Publication/execution requires a new exact approval. This file is not run during
local preparation. Public runner toolchain versions are checked, not installed.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time

# BEGIN_OPERATOR_JOB_GATE
def job_admission(phase, environment=None, now=None):
    env = os.environ if environment is None else environment
    now = time.time() if now is None else now
    raw = env.get("V98_COMPILER_BINDING", "")
    if not isinstance(raw, str) or len(raw) > 2048:
        raise ValueError("JOB_BINDING_REFUSED")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_BINDING_KEY")
            result[key] = value
        return result

    binding = json.loads(raw, object_pairs_hook=pairs)
    keys = {"schema", "mode", "nonce", "operatorStartEpoch", "queueBeforeEpoch",
            "compileBeforeEpoch", "uploadBeforeEpoch", "remoteEndEpoch", "commit",
            "runNumber", "repository", "repositoryId", "ownerId", "branch"}
    if type(binding) is not dict or set(binding) != keys:
        raise ValueError("EXACT_JOB_BINDING_KEYS")
    if (binding["schema"] != "v98-compiler-job-binding/v1" or
            binding["mode"] != "EXACT_ONE_LINUX_GUARD_COMPILE" or
            not isinstance(binding["nonce"], str) or
            re.fullmatch("[a-f0-9]{32}", binding["nonce"]) is None or
            not isinstance(binding["commit"], str) or
            re.fullmatch("[a-f0-9]{40}", binding["commit"]) is None or
            type(binding["runNumber"]) is not int or binding["runNumber"] != 1):
        raise ValueError("EXACT_JOB_BINDING")
    for key, offset in (("operatorStartEpoch", 0), ("queueBeforeEpoch", 840),
                        ("compileBeforeEpoch", 960), ("uploadBeforeEpoch", 1020),
                        ("remoteEndEpoch", 1080)):
        if (type(binding[key]) is not int or type(binding["operatorStartEpoch"]) is not int or
                binding[key] != binding["operatorStartEpoch"] + offset):
            raise ValueError("EXACT_OPERATOR_OFFSETS")
    expected = {"GITHUB_REPOSITORY": "fr-meyer/openclaw", "GITHUB_REPOSITORY_ID": "1309456040",
                "GITHUB_REPOSITORY_OWNER_ID": "26621962", "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/heads/candidate/v2026.9.8-runtime-qualification",
                "GITHUB_SHA": binding["commit"], "GITHUB_RUN_NUMBER": "1",
                "GITHUB_RUN_ATTEMPT": "1", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
                "GITHUB_WORKFLOW_REF": "fr-meyer/openclaw/.github/workflows/v98-guard-compiler-only.yml@refs/heads/candidate/v2026.9.8-runtime-qualification"}
    if (binding["repository"] != expected["GITHUB_REPOSITORY"] or
            binding["repositoryId"] != expected["GITHUB_REPOSITORY_ID"] or
            binding["ownerId"] != expected["GITHUB_REPOSITORY_OWNER_ID"] or
            binding["branch"] != expected["GITHUB_REF"].removeprefix("refs/heads/") or
            any(env.get(key) != value for key, value in expected.items()) or
            re.fullmatch("[1-9][0-9]{0,14}", env.get("GITHUB_RUN_ID", "")) is None):
        raise ValueError("EXACT_HOSTED_PUSH_CONTEXT")
    cutoffs = {"queue": "queueBeforeEpoch", "compile": "compileBeforeEpoch",
               "upload": "uploadBeforeEpoch"}
    if (phase not in cutoffs or type(now) not in (int, float) or
            not binding["operatorStartEpoch"] <= now < binding[cutoffs[phase]]):
        raise ValueError("OPERATOR_JOB_WINDOW_CLOSED")
    return binding
# END_OPERATOR_JOB_GATE

ROOT = Path(__file__).resolve().parent
EXPECTED_INPUTS = {"source/strict_guard.c", "source/policy.generated.h", "LICENSE.node"} | {
    "include/node/" + name for name in
    ("node_api.h", "node_api_types.h", "js_native_api.h", "js_native_api_types.h")}
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1792195200"}
MAX_ARTIFACT = 1024 * 1024
MAX_READ_ELF_TOTAL = 64 * 1024


def need(condition):
    if not condition:
        raise ValueError("COMPILER_ONLY_ADMISSION_REFUSED")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class OriginalDeadline:
    """One own-process timer; the original wall/monotonic origin never resets."""
    def __init__(self, end, wall=time.time, mono=time.monotonic):
        self.wall, self.mono, self.end = wall, mono, end
        self.wall0, self.mono0 = wall(), mono()
        self.last_wall, self.last_mono = self.wall0, self.mono0

    def remaining(self, reserve=0):
        wall, mono = self.wall(), self.mono()
        need(wall >= self.last_wall and mono >= self.last_mono and
             abs((wall - self.wall0) - (mono - self.mono0)) <= 2)
        self.last_wall, self.last_mono = wall, mono
        remaining = min(self.end - wall, self.end - self.wall0 - (mono - self.mono0)) - reserve
        need(remaining > 0)
        return remaining


def supervise(argv, guard, stream, timeout=30):
    """Only newly owned trusted-tool children; never signals another process."""
    seconds = min(timeout, guard.remaining(reserve=6))
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
        stderr=subprocess.DEVNULL, env=ENV, cwd=ROOT, start_new_session=True)
    try:
        result = process.wait(timeout=seconds)
        guard.remaining()
        return result
    finally:
        if process.poll() is None:
            # This group was created by this exact Popen, with its PID as PGID.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def admit_upload():
    job_admission("upload")
    path = ROOT / "guard-build/v98-guard-compiler-only.tar.gz"
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_ARTIFACT)


def main():
    binding = job_admission("compile")
    guard = OriginalDeadline(binding["compileBeforeEpoch"])
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0))
    def expire(*_):
        raise TimeoutError("COMPILER_ORIGINAL_ABSOLUTE_END")
    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, guard.remaining())
    need(sys.platform == "linux" and platform.machine() == "x86_64" and
         sys.version_info[:2] == (3, 12))
    need(not any(os.environ.get(key) for key in ("LD_PRELOAD", "LD_AUDIT", "NODE_OPTIONS")))
    manifest_path = ROOT / "inputs.json"
    need(manifest_path.stat().st_size <= 16384)
    manifest = json.loads(manifest_path.read_text())
    need(manifest["schema"] == "v98-public-guard-compiler-inputs/v1" and
         set(manifest["inputs"]) == EXPECTED_INPUTS)
    for name, expected in manifest["inputs"].items():
        path = ROOT / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size <= 262144)
        raw = path.read_bytes()
        need(len(raw) == expected["bytes"] and sha(raw) == expected["sha256"])
    output = ROOT / "guard-build"
    output.mkdir(mode=0o700)
    # Applies to this compiler supervisor and its trusted tool children. The
    # original absolute timer and bounded owned-child waits also apply.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARTIFACT, MAX_ARTIFACT))

    def command(argv, label, cap=32768):
        dest = output / label
        with dest.open("xb") as stream:
            status = supervise(argv, guard, stream)
        need(status == 0 and dest.stat().st_size <= cap)
        return dest.read_bytes()

    gcc = command(["/usr/bin/gcc-13", "-dumpfullversion", "-dumpversion"], "gcc-version.txt", 128).decode("ascii").strip()
    readelf = command(["/usr/bin/readelf", "--version"], "readelf-version.txt", 1024).decode("ascii")
    need(gcc == manifest["toolchain"]["gccFullVersion"] == "13.3.0")
    need(readelf.splitlines()[0].startswith("GNU readelf ") and
         readelf.splitlines()[0].endswith(" " + manifest["toolchain"]["binutilsVersion"]) and
         manifest["toolchain"]["binutilsVersion"] == "2.42")
    library = output / "v98-strict-guard.so"
    args = ["/usr/bin/gcc-13", "-std=c11", "-O2", "-shared", "-fPIC",
            "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-Wall", "-Wextra", "-Werror",
            "-ffile-prefix-map=" + str(ROOT) + "=/public-v98-guard", "-frandom-seed=v98-linux-guard",
            "-I", str(ROOT / "include/node"), "-I", str(ROOT / "source"),
            "-Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none",
            str(ROOT / "source/strict_guard.c"), "-o", str(library)]
    # Exactly one shared-library compile/link. No output object is executed,
    # dlopen'ed, preloaded, passed to Node, or checked with executable ldd.
    status = supervise(args, guard, subprocess.DEVNULL)
    need(status == 0 and 0 < library.stat().st_size <= 524288)
    binary = library.read_bytes()
    need(binary[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<HH", binary, 16) == (3, 62))
    outputs = {}
    for flag, name in (("-hW", "elf-header.txt"), ("-dW", "elf-dynamic.txt"),
                       ("-VW", "elf-versions.txt"), ("-sW", "elf-symbols.txt"),
                       ("-lW", "elf-program.txt"), ("-SW", "elf-sections.txt")):
        outputs[name] = command(["/usr/bin/readelf", flag, str(library)], name)
    need(sum(map(len, outputs.values())) <= MAX_READ_ELF_TOTAL)
    dynamic = outputs["elf-dynamic.txt"].decode("ascii")
    need(re.findall(r"\(NEEDED\).*\[([^]]+)\]", dynamic) == ["libc.so.6"])
    need(not any(word in dynamic for word in ("(RPATH)", "(RUNPATH)", "(TEXTREL)")))
    versions = outputs["elf-versions.txt"].decode("ascii")
    need("GLIBC_PRIVATE" not in versions)
    glibc = sorted(set(re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", versions)))
    need(glibc and all(tuple(map(int, version.split("."))) <= (2, 36) for version in glibc))
    symbols = outputs["elf-symbols.txt"].decode("ascii")
    need(all(re.search(r"\bGLOBAL\s+DEFAULT\s+\d+\s+" + symbol + r"\b", symbols)
             for symbol in ("napi_register_module_v1", "node_api_module_get_api_version_v1")))
    stack = [line for line in outputs["elf-program.txt"].decode("ascii").splitlines() if "GNU_STACK" in line]
    need(len(stack) == 1 and " E " not in stack[0] and "RWE" not in stack[0])
    need(".init_array" in outputs["elf-sections.txt"].decode("ascii"))
    guard.remaining()
    receipt = {"schema": "v98-public-compiler-only-result/v1", "status": "PASS_COMPILE_AND_STATIC_ELF_ONLY",
        "operatorStartEpoch": binding["operatorStartEpoch"], "compileBeforeEpoch": binding["compileBeforeEpoch"],
        "publicAttemptNonce": binding["nonce"], "commit": binding["commit"],
        "runId": os.environ["GITHUB_RUN_ID"], "runNumber": 1, "runAttempt": 1,
        "inputManifestSha256": sha(manifest_path.read_bytes()), "compilerDriverSha256": sha(Path(__file__).read_bytes()),
        "gcc": gcc, "binutils": "2.42", "target": "linux/amd64", "glibcRequiredVersions": glibc,
        "maximumAdmittedGlibc": "2.36", "sharedObjectBytes": len(binary), "sharedObjectSha256": sha(binary),
        "productImageChanged": False, "guardLoaded": False, "nodeFixtureExecuted": False,
        "kernelOrRuntimeQualification": "NEVER_RUN", "noNewDependencyInstall": True,
        "systemHeadersAndRunner": "Existing public ubuntu-24.04 toolchain; exact versions gated, runner provenance retained by hosted job"}
    payload = {"v98-strict-guard.so": binary, "compile-receipt.json": (json.dumps(receipt, sort_keys=True) + "\n").encode(),
               "LICENSE.node": (ROOT / "LICENSE.node").read_bytes(), **outputs}
    bundle = output / "v98-guard-compiler-only.tar.gz"
    with bundle.open("xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as tar:
                for name, data in sorted(payload.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    tar.addfile(info, io.BytesIO(data))
    need(0 < bundle.stat().st_size <= MAX_ARTIFACT)
    guard.remaining()
    print(json.dumps({"status": receipt["status"], "artifactBytes": bundle.stat().st_size,
                      "guardLoaded": False, "runtimeQualified": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--admit-upload"]:
            admit_upload()
        else:
            need(sys.argv[1:] == [])
            main()
    except Exception:
        print("V98_COMPILER_ONLY_REFUSED", file=sys.stderr)
        raise SystemExit(2) from None
