#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 4 && "$1" == --image-id && "$2" =~ ^sha256:[0-9a-f]{64}$ && "$3" == --manifest-sha && "$4" =~ ^[0-9a-f]{64}$ ]]
manifest_sha=$4
image_id=$2
export CI=true OPENCLAW_BUILD_ALL_NO_PNPM=1 COREPACK_ENABLE_NETWORK=0
test "$(node -p process.versions.node 9<&-)" = 24.16.0
test "$(pnpm --version 9<&-)" = 12.9.0
export B_EXPECTED_TESTS='["ui/src/pages/chat/chat-composer-queue.test.ts","ui/src/pages/chat/chat-thread-input-order.test.ts","ui/src/pages/chat/chat-pending-inputs.test.ts","ui/src/pages/chat/user-message-content.test.ts"]'
export B_INVENTORY_DIR=/tmp/b-inventory
export OPENCLAW_VITEST_FS_MODULE_CACHE_ROOT=/tmp/b-vitest-fs-module-cache

test ! -e "$B_INVENTORY_DIR"
mkdir "$B_INVENTORY_DIR" 9<&-
export GIT_COMMIT=$(cat .github/qualification/input-source-sha 9<&-)
[[ "$GIT_COMMIT" =~ ^[0-9a-f]{40}$ ]]
manifest_path="$PWD/.github/qualification/b-full-source.json"
python3 .github/qualification/b-tree-guard.py verify . "$manifest_path" "$manifest_sha" 9<&-
cp .github/qualification/b-tree-guard.py /tmp/b-sealed-tree-guard.py 9<&-
sealed_sha=$(sha256sum /tmp/b-sealed-tree-guard.py 9<&- | cut -d' ' -f1 9<&-)
trap 'status=$?; trap - EXIT; if echo "$sealed_sha  /tmp/b-sealed-tree-guard.py" | sha256sum -c - 9<&-; then python3 /tmp/b-sealed-tree-guard.py verify "$PWD" "$manifest_path" "$manifest_sha" 9<&- || status=1; else status=1; fi; exit "$status"' EXIT
python3 -B .github/qualification/b-capacity-admit.py --image-id "$image_id" --manifest-sha "$manifest_sha" 9<&-
node .github/qualification/b-project-ui.mjs 9<&-
python3 -I -B .github/qualification/b-physical-dependencies.py --manifest-sha256 "$manifest_sha" --image-id "$image_id" --capacity-receipt-sha256 "$(sha256sum /tmp/b-capacity-admission 9<&- | cut -d ' ' -f1 9<&-)" --contract /tmp/b-host-runtime/b-physical-allocation.py --contract-sha256 06b8f7539c24ca31a7819883747e264d419419733d0801059e6d1faf0085d1cf
exec 9<&-
python3 .github/qualification/b-expect-probe.py --image-id "$image_id"
python3 .github/qualification/b-source-check.py .
files=(ui/src/i18n/locales/en.ts ui/src/pages/chat/chat-composer-queue.test.ts ui/src/pages/chat/chat-thread-inputs.ts ui/src/pages/chat/chat-thread-items.ts ui/src/pages/chat/components/chat-composer-queue.ts ui/src/pages/chat/user-message-content.ts)
pnpm exec oxfmt --check "${files[@]}"
pnpm exec oxlint --tsconfig ui/tsconfig.json "${files[@]}"
pnpm test ui/src/pages/chat/chat-composer-queue.test.ts ui/src/pages/chat/chat-thread-input-order.test.ts ui/src/pages/chat/chat-pending-inputs.test.ts ui/src/pages/chat/user-message-content.test.ts --maxWorkers=1 -- --expect.requireAssertions --reporter=default --reporter="$PWD/.github/qualification/b-inventory-reporter.mjs"
node .github/qualification/b-inventory-check.mjs
pnpm tsgo:ui
pnpm tsgo:test:ui
pnpm ui:build
python3 .github/qualification/b-source-check.py .
