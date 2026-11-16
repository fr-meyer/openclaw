#!/usr/bin/env bash
set -Eeuo pipefail
: "${GITHUB_WORKSPACE:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GITHUB_SHA:?}" "${PROJECT:?}"
[[ $GITHUB_RUN_ATTEMPT == 1 && ${GITHUB_REPOSITORY} == fr-meyer/openclaw ]]
[[ ${GITHUB_REF} == refs/heads/ci/offline-provider-regressions-20261116 ]]
[[ $PROJECT == bfl || $PROJECT == embeddings ]]
[[ $(realpath -e "$GITHUB_WORKSPACE") == "$GITHUB_WORKSPACE" ]]
artifacts=$GITHUB_WORKSPACE/inventory-artifacts/$PROJECT
[[ ! -e $artifacts ]]
mkdir -p "$artifacts"
export ARTIFACT_DIR=$artifacts
stage=source-identity
finish() {
  local rc=$?
  trap - EXIT
  python3 - "$artifacts" "$stage" "$rc" <<'FINAL'
import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1]); row={'diagnosticOnly':True,'productQualified':False,'stage':sys.argv[2],'exit':int(sys.argv[3])}
(r/'driver-exit.json').write_text(json.dumps(row,indent=2))
files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(r.iterdir()) if p.is_file() and p.name!='filesSHA256.json'}
(r/'filesSHA256.json').write_text(json.dumps(files,indent=2))
FINAL
  exit "$rc"
}
trap finish EXIT
cd "$GITHUB_WORKSPACE"
tools=$GITHUB_WORKSPACE/tooling/.github/offline-provider-regressions
export GIT_NO_LAZY_FETCH=1 GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gc.auto GIT_CONFIG_VALUE_0=0
python3 - "$tools/sources.json" "$PROJECT" <<'PY'
import gzip,hashlib,json,pathlib,subprocess,sys
x=json.load(open(sys.argv[1]))[sys.argv[2]]
def git(root,*args): return subprocess.check_output(['git','-C',root,*args],text=True).strip()
for rel in ['inventory-driver.sh','inventory-collector.mjs','run.sh','hydration-inventory.mjs','openclaw-image-dependency-projector.mjs','Dockerfile','sources.json']:
 f=pathlib.Path(sys.argv[1]).parent/rel
 assert f.is_file() and not f.is_symlink() and f.resolve()==f.absolute(), 'noncanonical tooling path'
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
receipt={k:x[k] for k in ['carrierSha','base','patchSha256','expectedCandidateTree']}
receipt['toolingSha']=__import__('os').environ['GITHUB_SHA']
(pathlib.Path(__import__('os').environ['ARTIFACT_DIR'])/'source-identity.json').write_text(json.dumps(receipt,indent=2))
PY
# Only dependency manifests, inert configuration and patches enter networked setup.
context=$(mktemp -d "$RUNNER_TEMP/offline-provider-deps.XXXXXX")
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
sha256sum package.json pnpm-lock.yaml pnpm-workspace.yaml >"$artifacts/input-manifests.SHA256"
cd "$GITHUB_WORKSPACE"
stage=dependency-image-build
build_argv=(docker build --no-cache --progress plain --iidfile "$RUNNER_TEMP/offline-provider-image.id" -f "$tools/Dockerfile" "$context")
printf '%q ' "${build_argv[@]}" >"$artifacts/docker-build-argv.txt"
"${build_argv[@]}" >"$artifacts/docker-build.log" 2>&1
image=$(cat "$RUNNER_TEMP/offline-provider-image.id")
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]]
printf 'IMMUTABLE_IMAGE=%s\n' "$image"

stage=image-provenance
cp "$RUNNER_TEMP/offline-provider-image.id" "$artifacts/image.id"
docker image inspect "$image" >"$artifacts/image-inspect.json"
sha256sum "$artifacts/docker-build.log" >"$artifacts/docker-build-log.SHA256"
stage=inventory-container
argv=(docker run --rm --pull never --network none --read-only
  --tmpfs /tmp:rw,nosuid,nodev,exec,size=2g
  --security-opt no-new-privileges --cap-drop ALL --pids-limit 512
  --user "$(id -u):$(id -g)"
  --label openclaw.purpose=inventory-only-preflight
  --env HOME=/tmp/home --env CI=true --env COREPACK_ENABLE_NETWORK=0
  --env COREPACK_DEFAULT_TO_LATEST=0
  --mount "type=bind,src=$GITHUB_WORKSPACE/candidate,dst=/candidate,readonly"
  --mount "type=bind,src=$tools,dst=/tooling,readonly"
  --mount "type=bind,src=$artifacts,dst=/inventory"
  --workdir /candidate --entrypoint /usr/bin/timeout "$image"
  --signal=TERM --kill-after=15 1500
  /usr/local/bin/node /tooling/inventory-collector.mjs /candidate /app/node_modules /inventory /tooling)
printf '%q ' "${argv[@]}" >"$artifacts/docker-argv.txt"
"${argv[@]}" >"$artifacts/container.stdout" 2>"$artifacts/container.stderr"
stage=inventory-receipt
python3 - "$artifacts/RESULT.json" <<'CHECK'
import json,sys
x=json.load(open(sys.argv[1])); assert x['diagnosticOnly'] and not x['productQualified']
assert x['planComplete'] and x['noProjectionWrites'] and x['exit']==0
print('INVENTORY_DIAGNOSTIC',x['status'],'BYTES',x['actualTotalBytes'],'CAP',x['capBytes'])
CHECK
stage=complete
