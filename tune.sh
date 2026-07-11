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

if [[ ! "$KTO_RAW_URL" =~ ^https:// ]] && [[ "${KTO_ALLOW_INSECURE_UPDATE_URL:-0}" != "1" ]]; then
    echo "[ERROR] Refusing insecure KTO_RAW_URL: $KTO_RAW_URL" >&2
    exit 1
fi

tmp="$(mktemp)"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT
curl -fsSL "$KTO_RAW_URL" -o "$tmp"
size="$(wc -c < "$tmp")"
if [[ ! "$size" =~ ^[0-9]+$ ]] || (( size < 10000 || size > 2097152 )); then
    echo "[ERROR] Downloaded kto.sh has invalid size: $size" >&2
    exit 1
fi
if [[ "$(head -n 1 "$tmp")" != "#!/usr/bin/env bash" ]] || ! bash -n "$tmp"; then
    echo "[ERROR] Downloaded kto.sh failed validation" >&2
    exit 1
fi

bash "$tmp" "$@"
