#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="${ROOT_DIR}/demo_runtime/pids"

if [[ ! -d "${PID_DIR}" ]]; then
  echo "No PID directory found."
  exit 0
fi

for pidfile in "${PID_DIR}"/*.pid; do
  [[ -e "${pidfile}" ]] || continue
  pid="$(cat "${pidfile}")"
  if kill -0 "${pid}" 2>/dev/null; then
    echo "Stopping PID ${pid}"
    kill "${pid}" || true
  fi
  rm -f "${pidfile}"
done
