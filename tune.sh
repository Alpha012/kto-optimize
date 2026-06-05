#!/usr/bin/env bash
# Backward-compatible entrypoint. Main script moved to kto.sh.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KTO_SCRIPT="${SCRIPT_DIR}/kto.sh"
KTO_RAW_URL="${KTO_RAW_URL:-https://raw.githubusercontent.com/Alpha012/kto-optimize/main/kto.sh}"

if [[ -f "$KTO_SCRIPT" ]]; then
    exec bash "$KTO_SCRIPT" "$@"
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "[ERROR] curl not found. Use kto.sh directly or install curl." >&2
    exit 1
fi

exec bash <(curl -fsSL "$KTO_RAW_URL") "$@"
