#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

bash -n tune.sh
bash -n kto.sh
bash -n scripts/kto-stats-push.sh

PYTHON_CMD=()
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' >/dev/null 2>&1; then
    PYTHON_CMD=(python3)
elif command -v py >/dev/null 2>&1 && py -3 -c 'import sys' >/dev/null 2>&1; then
    PYTHON_CMD=(py -3)
elif command -v python >/dev/null 2>&1 && python -c 'import sys' >/dev/null 2>&1; then
    PYTHON_CMD=(python)
else
    echo "working python3/python not found" >&2
    exit 1
fi

PYTHONDONTWRITEBYTECODE=1 "${PYTHON_CMD[@]}" - <<'PY'
from pathlib import Path

path = Path("scripts/kto-stats-collector.py")
compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY

PYTHONDONTWRITEBYTECODE=1 "${PYTHON_CMD[@]}" -m unittest discover -s tests -p 'test_*.py'

echo "checks ok"
