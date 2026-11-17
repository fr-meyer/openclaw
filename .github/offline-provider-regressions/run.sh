#!/usr/bin/env bash
set -Eeuo pipefail
: "${OPENCLAW_NO_COPY_CONFIG:?Exact independently approved config required}" "${OPENCLAW_NO_COPY_RECEIPT:?Sealed image receipt required}"
tools=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# Candidate assembly/network acquisition is separate. No install/build/hydration fallback.
exec node "$tools/full-validation.mjs" full "$OPENCLAW_NO_COPY_CONFIG" "$OPENCLAW_NO_COPY_RECEIPT"
