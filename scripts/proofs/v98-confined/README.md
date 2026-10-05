# Confined current-behavior qualification executor

This proof tooling preserves product commit
`bc8b82b2cbbbb81f5abe6093e1bb3af4f1f70cdf` and tree
`ba825f670dc5ba943f7893cb267225d1f68d3110`. It consumes the existing retained
Linux amd64 image; it does not rebuild, patch, install dependencies into, or
start the image's Gateway entrypoint. No fixture phase has run locally.

Publication and hosted execution require approval of the final local commit,
workflow and packet. Earlier approvals of artifact builds or source CI do not
authorize this native runtime attempt. The proposed destination is
`fr-meyer/openclaw`, branch `candidate/v2026.9.8-runtime-admission-3`, using one
15-minute Ubuntu 24.04 Actions job and seven-day evidence retention. No main
merge, force push, production access, provider data, new VM, registry
publication or production deployment is included.

The old no-child test profile was agent-defined. This executor proposes a
separate test profile that permits exactly one source-bound snapshot helper in
migration phase 3. It does not remove the local Node Permission Model, reroute a
denied local execution, or modify a platform sandbox. The previously retained
`ERR_ACCESS_DENIED` fsync failure remains valid failure evidence. Any host
kernel, Docker, ptrace, seccomp, Landlock or platform refusal in the hosted
attempt stops the attempt; no broader-profile fallback is permitted.

The first approved attempt, run `37209287864` at commit `83079b31`, stopped
before image verification or runtime: GitHub rejected the artifact request's
`Accept: application/octet-stream` header with HTTP 415. Its logs and receipts
remain failure evidence; all six phases stayed `NEVER_RUN`. This correction uses
`Accept: application/json` with the same `gh api` download path that successfully
retrieved the failed attempt's evidence. The CLI follows GitHub's temporary
download redirect and strips authorization on the cross-host artifact-storage redirect; no token or
signed URL is supplied manually or written to evidence.

The second approved attempt, run `37243845981` at commit `9d118e87`, passed
acquisition and image/selected-file verification. Docker then rejected log
compression with `max-file=1` before task/PID1 startup. That failed receipt
reports the exact created container non-running, a retained scratch mount, and
unproved cgroup extinction; all six phases remain `NEVER_RUN`.

This successor combines the reviewed `compress=false` correction with static
host prerequisites, pre-start configuration inspection, explicit no-pull policy,
bounded overflow retention and distinct stopped-container cleanup observations.
The new workflow `v98-confined-runtime-3.yml` and branch identify a separately
approved attempt, with run-number/attempt guards still fixed at one. The retained
artifact, native profile, input bytes, resource limits and retention are unchanged.

## Execution contract

1. Authenticate the original successful artifact run and seven-day artifact;
   verify its ZIP digest, clean product source, config, all saved layer digests,
   required compiled identities, exact selected read files and namespace
   bindings without importing or executing image code.
2. Verify the source manifest and exact tooling checkout. Compile the reviewed
   native supervisor and constructor with the existing hosted compiler; bind
   compiler identity, flags and resulting binary hashes. ELF checks require a
   static x86-64 supervisor and a preload with no external imports or libraries.
   No compiler/package acquisition or `ldd` execution is allowed.
3. Run separate capability, forced-deadline and six-phase containers, once each,
   under the same reviewed profile. A failed prerequisite prevents the fixture.
   The supervisor emits the host gate before any Node tracee exists. The host
   binds the actual inspected container PID1 to its host-observed cgroup, checks
   all resource limits, then writes the root-owned one-use admission marker.
4. Join capability results with native denial, thread, fsync and exit
   observations. Exercise scratch file/directory fsync, SQLite WAL/backup/close,
   a real Worker requesting the product's 512 MiB old-generation option, network denial and
   filesystem denial against a private writable sentinel outside scratch.
   Force the deadline container to stop, and prove extinction of its bound
   cgroup before allowing the fixture.
5. The supervisor owns six immutable Node invocations: prepare; predecessor
   assertion; migrate through the original Doctor; candidate assertion;
   restore; rollback assertion. It derives the helper entitlement from its
   internal phase counter. JavaScript output cannot authorize a role or phase.

Each container uses UID/GID 1000, a read-only image, no network, all capabilities
dropped, default Docker seccomp/AppArmor, private PID/IPC/cgroup namespaces,
disabled healthcheck, one CPU, 1 GiB memory with zero swap, 128 PIDs and a private
1 MiB shm. Only a read-only proof bundle and one task-owned 16 MiB tmpfs scratch
are mounted. No home, source checkout, host settings, Docker socket, credentials
or provider state enters the container. Scratch is retained after failures.
Aggregate CPU and wall limits are respectively 5/15 seconds for capability,
1/2 for the deliberate deadline, and 30/60 for the six-phase fixture.
The deadline monitor has a disclosed 100 ms sampling tolerance: the control must
observe both a kill request and its signal within 2.1 seconds, or the fixture
stays blocked. Cleanup has a separate bounded join grace.
Whole cgroup extinction is required; an exited initial process alone is insufficient.

## Snapshot helper boundary

The unchanged product uses `execFile(process.execPath, ...)`, its original
native Worker path and real process-close/cancellation behavior. The helper is
allowed only once, with exact executable, argv, environment, candidate SQLite
family and an owned staging directory. Its constructor tightens writes to that
staging directory before helper JavaScript. It cannot start grandchildren or
re-exec. At most three anonymous AF_UNIX socket pairs provide the actual libuv
stdio protocol; their descriptor identities, options and generations are
tracked. Socket creation for networking, ancillary descriptor transfers,
unreviewed process creation and descriptor-stealing syscalls remain denied.
All tracees sharing mutable argument/FD state are stopped through relevant
syscall completion. Control descriptors are closed before Node or helper JS.
Stage ancestry is walked without following symlinks; the directory inode and
regular, single-link source-owner token family are bound before exec.
This metadata census does not authenticate the SQLite ownership token; the
unchanged product remains its authority. Writers
stay stopped through verified Landlock installation. Parent namespace changes
remain denied while the helper is alive, preventing inode-alias replacement;
the parent keeps running its original IPC and cancellation handling. This
transient constraint must pass the actual frozen migration, or qualification
fails without changing the product or widening the profile.

The owned Node invocation and `NODE_OPTIONS` retain the 128 MiB heap setting.
Node documents that the command-line heap limit overrides a Worker's
`maxOldGenerationSizeMb` option. The probe records both requested Worker limits
and actual V8 heap limits; requesting 512 MiB is not a claim that 512 MiB becomes
effective. See the [Node 24 Worker options](https://nodejs.org/docs/latest-v24.x/api/worker_threads.html#new-workerfilename-options).

The image read policy grants 1,547 exact regular-file inodes and no image
directory reads. Landlock does not restrict `stat`, `access` or `readlink` metadata
lookups; the native profile allows those calls. This is a disclosed adjustment
to the agent-defined test profile, not an assertion of identical Node Permission
Model metadata restrictions. Private image, PID and mount scopes exclude host
and provider state.
The conservative import graph is not a complete Node resolver
proof. Its 36 computed selectors are classified; musl fallback and unexpected
reads remain denied. Kernel errno denials can be caught by product code; they
are not themselves a claim that every unexpected access aborts the attempt.
Required checks, native owner failures and resource violations stop it.
Selected aliases and directory metadata are bound without
granting their contents. The GNU loader, fs-safe and Koffi native add-ons still
need successful loading under the actual Linux policy. A conditional second
product helper cannot be created; missing required behavior fails qualification.

## Evidence limits

Container logging configures one 1 MiB file with Docker's `local` driver and
explicit `compress=false`. Compression is enabled by default and conflicts with
`max-file=1`, preventing the container from starting. This setting preserves the
single-file rotation budget; see the [Docker local logging options](https://docs.docker.com/engine/logging/drivers/local/#options).
Docker record and metadata overhead can exceed the nominal rotation threshold.
Host-retained stdout/stderr prefixes remain strictly bounded even on overflow;
overflow refuses the attempt, and the total evidence upload stays at 20 MiB.

Before loading the image, a bounded `host-preflight.json` records the local rootful
Linux amd64 Docker API, default runc, seccomp/AppArmor, cgroup v2 controllers,
Yama own-child prerequisites, executable proof mount/permissions and free disk.
Missing prerequisites refuse; this observation does not admit execution.
After create, configuration/ownership and the stopped PID are inspected before
start. `--pull never` forbids implicit image acquisition. These are supported
[Docker create options](https://docs.docker.com/reference/cli/docker/container/create/).
The created AppArmor field may be empty because Moby assigns the default profile
[during start](https://github.com/moby/moby/blob/v28.0.4/daemon/start.go#L160-L162).
After start, the inspected profile and actual PID1 `/proc` profile must both
prove `docker-default` enforcement; the native gate remains closed until then.

On an unbound failed start, the exact ownership-validated final Docker state and
attach return code are retained separately from whole-cgroup extinction. A
non-running Docker container with PID 0 does not grant cgroup proof. Stopped
container metadata, loaded image and uncertain-cgroup scratch remain in runner
custody; no force removal or unmount is attempted under uncertain ownership.
Docker-create timeout without a returned ID remains UNKNOWN. Abrupt runner loss,
SIGINT/SIGTERM, job cancellation and teardown have no proved cleanup/retention
guarantee. Static checks do not prove disk capacity for unpacked image storage,
native tracing, Landlock, loaders, dynamic imports or the six fixture phases.

Portable C decision/BPF/SHA tests, Python adversarial archive/descriptor/host
tests and syntax checks are offline evidence. They do not prove Linux syscall
translation, ptrace support under default Docker protections, Landlock
inheritance, native loader compatibility, Worker/fsync fidelity, migration,
restore or rollback. Those gates remain `NEVER_RUN` until the separately
approved hosted attempt. Retained failed receipts are never converted to passes.

`source-manifest.json` binds executable tooling, policies and frozen inputs.
The final external approval packet binds that manifest, exact Git commit/tree,
workflow, independent review and local test receipts. The workflow must run at
that approved commit, once. The first-run and first-attempt guards refuse later
workflow runs or UI reruns, using GitHub's [run counters](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).
It must not silently fetch a replacement artifact
or retry with a wider profile. Binary digests are recorded after the approved
host compilation, before any container execution, rather than invented locally.
