#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 4 && "$1" == --image-id && "$2" =~ ^sha256:[0-9a-f]{64}$ && "$3" == --manifest-sha && "$4" =~ ^[0-9a-f]{64}$ ]]
manifest_sha=$4
image_id=$2
export CI=true OPENCLAW_BUILD_ALL_NO_PNPM=1 COREPACK_ENABLE_NETWORK=0
test "$(node -p process.versions.node)" = 24.16.0
test "$(pnpm --version)" = 12.9.0
export B_EXPECTED_TESTS='["ui/src/pages/chat/chat-composer-queue.test.ts","ui/src/pages/chat/chat-thread-input-order.test.ts","ui/src/pages/chat/chat-pending-inputs.test.ts","ui/src/pages/chat/user-message-content.test.ts"]'
export B_INVENTORY_DIR=/tmp/b-inventory

test ! -e "$B_INVENTORY_DIR"
mkdir "$B_INVENTORY_DIR"
export GIT_COMMIT=$(cat .github/qualification/input-source-sha)
[[ "$GIT_COMMIT" =~ ^[0-9a-f]{40}$ ]]
manifest_path="$PWD/.github/qualification/b-full-source.json"
python3 .github/qualification/b-tree-guard.py verify . "$manifest_path" "$manifest_sha"
cp .github/qualification/b-tree-guard.py /tmp/b-sealed-tree-guard.py
sealed_sha=$(sha256sum /tmp/b-sealed-tree-guard.py | cut -d' ' -f1)
trap 'status=$?; trap - EXIT; if echo "$sealed_sha  /tmp/b-sealed-tree-guard.py" | sha256sum -c -; then python3 /tmp/b-sealed-tree-guard.py verify "$PWD" "$manifest_path" "$manifest_sha" || status=1; else status=1; fi; exit "$status"' EXIT
python3 -B .github/qualification/b-capacity-admit.py --image-id "$image_id" --manifest-sha "$manifest_sha"
node .github/qualification/b-project-ui.mjs
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
