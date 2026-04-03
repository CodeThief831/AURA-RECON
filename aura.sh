#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN=""

# Check if Python is installed
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  echo "[!] python3 or python was not found in PATH. Please install Python 3.9+." >&2
  exit 1
fi

# Automatically install requirements if requests module is missing
if ! "${PYTHON_BIN}" -c "import requests" >/dev/null 2>&1; then
    echo "[*] First time setup: Installing required Python packages..."
    "${PYTHON_BIN}" -m pip install -r "${SCRIPT_DIR}/requirements.txt"
fi

# Execute the orchestrator
exec "${PYTHON_BIN}" "${SCRIPT_DIR}/bounty_bot.py" "$@"
