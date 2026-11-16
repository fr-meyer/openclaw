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
for rel in ['run.sh','hydration-inventory.mjs','openclaw-image-dependency-projector.mjs','Dockerfile','sources.json']:
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
# Direct readonly measurement route, never the hydrating test wrapper.
# Exact independently reviewed R2 projector, pinned again inside measurement.
sha256sum "$tools/openclaw-image-dependency-projector.mjs" "$tools/hydration-inventory.mjs" "$tools/Dockerfile" "$tools/sources.json"
set +e
docker run --rm --pull never --network none --read-only \
 --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
 --security-opt no-new-privileges --cap-drop ALL --pids-limit 512 --memory 2g --cpus 2 \
 --mount "type=bind,src=$GITHUB_WORKSPACE/candidate,dst=/candidate,readonly" \
 --mount "type=bind,src=$tools,dst=/trusted,readonly" \
 --env HOME=/tmp --env COREPACK_ENABLE_NETWORK=0 \
 --entrypoint /usr/bin/timeout "$image" --signal=TERM --kill-after=15 900 \
 /usr/local/bin/node /trusted/hydration-inventory.mjs /candidate /app/node_modules /trusted/openclaw-image-dependency-projector.mjs \
 > "$RUNNER_TEMP/hydration-inventory.json" 2> "$RUNNER_TEMP/hydration-inventory.stderr"
rc=$?
set -e
printf 'MEASUREMENT_CONTAINER_EXIT=%s\n' "$rc"
[[ $(wc -c < "$RUNNER_TEMP/hydration-inventory.stderr") -le 16384 ]] || exit 1
cat "$RUNNER_TEMP/hydration-inventory.stderr"
[[ $(wc -c < "$RUNNER_TEMP/hydration-inventory.json") -le 524288 ]] || exit 1
cat "$RUNNER_TEMP/hydration-inventory.json"
[[ $rc == 0 ]] || exit 1
printf 'PROJECT=%s MEASUREMENT_COMPLETE=1 TARGET_VALIDATION=UNRUN\n' "$PROJECT"
