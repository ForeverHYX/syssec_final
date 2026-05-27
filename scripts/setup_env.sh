#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${1:-"$ROOT_DIR/.venv"}"

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -e "$ROOT_DIR[all]"

cat <<EOF
HardenInspector environment is ready.

Activate:
  source "$VENV_DIR/bin/activate"

Verify:
  "$VENV_DIR/bin/python" -m pytest -q
  "$VENV_DIR/bin/python" -m hardeninspector --help
EOF

