#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_WORKSPACE:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GITHUB_SHA:?}" "${PROJECT:?}"
[[ $GITHUB_RUN_ATTEMPT == 1 && ${GITHUB_REPOSITORY} == fr-meyer/openclaw ]]
[[ ${GITHUB_REF} == refs/heads/ci/offline-provider-regressions-20261116 ]]
cd "$GITHUB_WORKSPACE"
tools=$GITHUB_WORKSPACE/tooling/.github/offline-provider-regressions
export GIT_NO_LAZY_FETCH=1 GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gc.auto GIT_CONFIG_VALUE_0=0
python3 - "$tools/sources.json" "$PROJECT" <<'PY'
import gzip,hashlib,json,pathlib,subprocess,sys
x=json.load(open(sys.argv[1]))[sys.argv[2]]
def git(root,*args): return subprocess.check_output(['git','-C',root,*args],text=True).strip()
assert git('tooling','rev-parse','HEAD') == __import__('os').environ['GITHUB_SHA']
assert git('carrier','rev-parse','HEAD') == x['carrierSha']
assert git('candidate','rev-parse','HEAD') == x['base']
p=pathlib.Path(x['patchPath']); assert not p.is_absolute() and '..' not in p.parts
patch=pathlib.Path('carrier')/p
assert patch.is_file() and not patch.is_symlink()
assert x['patchEncoding']=='gzip'
raw=gzip.decompress(patch.read_bytes())
assert hashlib.sha256(raw).hexdigest()==x['patchSha256']
subprocess.run(['git','-C','candidate','apply','--index','--whitespace=error'],input=raw,check=True)
names=subprocess.check_output(['git','-C','candidate','diff','--cached','--name-only','-z'])
assert names.endswith(bytes([0])), 'missing git NUL terminator'
paths=[p.decode('utf-8') for p in names[:-1].split(bytes([0]))]
assert set(paths)==set(x['files']), 'materialized changed-path set mismatch'
for name,digest in x['files'].items():
 f=pathlib.Path('candidate')/name
 assert f.is_file() and not f.is_symlink() and hashlib.sha256(f.read_bytes()).hexdigest()==digest, 'source pin mismatch: '+name
assert git('candidate','write-tree') == x['expectedCandidateTree'], 'materialized original-candidate tree mismatch'
print('SOURCE_IDENTITY',json.dumps({k:x[k] for k in ['carrierSha','base','patchSha256','expectedCandidateTree']},sort_keys=True),flush=True)
print('TOOLING_SHA',__import__('os').environ['GITHUB_SHA'],flush=True)
PY
# Only dependency manifests, inert configuration and patches enter networked setup.
context=$(mktemp -d "$RUNNER_TEMP/offline-provider-deps.XXXXXX")
trap 'rm -rf "$context"' EXIT
cd candidate
for f in .pnpmfile.cjs pnpmfile.cjs .pnpmfile.mjs; do [[ ! -e $f ]] || { echo 'Unreviewed pnpm hook'; exit 1; }; done
for f in package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc; do cp --parents "$f" "$context/"; done
for dir in packages/* extensions/* examples/* ui; do
  [[ -f $dir/package.json ]] || continue
  [[ ! -L $dir/package.json && ! -L $dir ]] || exit 1
  cp --parents "$dir/package.json" "$context/"
done
[[ ! -d patches ]] || cp -R patches "$context/patches"
# Fail if future patches introduce executable setup hooks or symlink escapes.
[[ -z $(find "$context" -type l -print -quit) ]]
sha256sum package.json pnpm-lock.yaml pnpm-workspace.yaml
cd "$GITHUB_WORKSPACE"
docker build --no-cache --progress plain --iidfile "$RUNNER_TEMP/offline-provider-image.id" -f "$tools/Dockerfile" "$context"
image=$(cat "$RUNNER_TEMP/offline-provider-image.id")
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]]
printf 'IMMUTABLE_IMAGE=%s\n' "$image"
export OPENCLAW_WORKTREE_ROOT=$GITHUB_WORKSPACE
status=0
run_check() {
  local label=$1 seconds=$2 rc
  shift 2
  printf 'CHECK_BEGIN=%s COMMAND=' "$label"; printf '%q ' "$@"; printf '\n'
  # timeout is INSIDE the isolated container, so termination does not detach docker.
  set +e
  bash "$tools/openclaw-worktree-test-isolated" "$GITHUB_WORKSPACE/candidate" --image "$image" --command -- env CI=true COREPACK_ENABLE_NETWORK=0 PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false timeout --signal=TERM --kill-after=15 "$seconds" bash -c 'node --import ./scripts/tsx.mjs scripts/generate-kysely-types.mts && exec "$@"' isolated-check "$@" 2>&1 | awk 'BEGIN { n=0; limit=524288 } { if(n<limit) { text=substr($0,1,4096); print text; n+=length(text)+1 } else if(!cut) { print "OUTPUT_TRUNCATED"; cut=1 } }'
  rc=${PIPESTATUS[0]}
  set -e
  printf 'CHECK_END=%s EXIT=%s\n' "$label" "$rc"
  [[ $rc == 0 ]] || status=1
}
mapfile -t tests < <(python3 - "$tools/sources.json" "$PROJECT" <<'PY'
import json,sys
for p in json.load(open(sys.argv[1]))[sys.argv[2]]['tests']: print(p)
PY
)
[[ ${#tests[@]} -gt 1 ]]
for f in "${tests[@]}"; do [[ -f candidate/$f ]] || exit 1; done
run_check native-dependency-probes 60 node --input-type=module -e 'import {createRequire} from "node:module";const r=createRequire(process.cwd()+"/package.json");r("node:sqlite");r("esbuild").transformSync("const a=1");await import(r.resolve("rastermill"));await import(r.resolve("@openclaw/fs-safe"));console.log("NATIVE_DEPENDENCIES_READY");'
run_check new-regressions 300 node scripts/run-vitest.mjs run "${tests[0]}" --maxWorkers=1 --passWithNoTests=false
run_check companion-regressions 600 node scripts/run-vitest.mjs run "${tests[@]:1}" --maxWorkers=1 --passWithNoTests=false
run_check types-core 240 node scripts/run-tsgo.mjs -p tsconfig.core.json --noEmit --incremental false
run_check types-extensions 240 node scripts/run-tsgo.mjs -p tsconfig.extensions.json --noEmit --incremental false
run_check types-extension-tests 240 node scripts/run-tsgo.mjs -p test/tsconfig/tsconfig.extensions.test.json --noEmit --incremental false
run_check lint 240 node --import ./scripts/tsx.mjs scripts/run-lint.mts
# Invoke the actual installed package bin without relying on a projected .bin directory.
run_check format-check 90 node --input-type=module -e 'import fs from "node:fs";import path from "node:path";import {spawnSync} from "node:child_process";const root=fs.realpathSync("node_modules/oxfmt");const p=JSON.parse(fs.readFileSync(path.join(root,"package.json")));const bin=typeof p.bin==="string"?p.bin:p.bin.oxfmt;const r=spawnSync(path.join(root,bin),["--check"],{stdio:"inherit"});if(r.error)throw r.error;process.exit(r.status??1);'
run_check frozen-lock 90 bash -c 'before=$(sha256sum pnpm-lock.yaml); pnpm install --lockfile-only --offline --frozen-lockfile --ignore-scripts --ignore-pnpmfile && test "$before" = "$(sha256sum pnpm-lock.yaml)"'
printf 'PROJECT=%s FINAL_EXIT=%s\n' "$PROJECT" "$status"
exit "$status"
