#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AAA_USERS_FILE="${ROOT_DIR}/services/aaa_service/data/users.json"
AAA_STATE_FILE="${ROOT_DIR}/services/aaa_service/data/aaa_state.json"
CA_STATE_FILE="${ROOT_DIR}/services/ca_service/data/ca_state.json"
CM_STATE_FILE="${ROOT_DIR}/services/cm_service/data/cm_state.json"
KM_STATE_FILE="${ROOT_DIR}/services/km_service/data/km_state.json"
RM_STATE_FILE="${ROOT_DIR}/services/rm_service/data/rm_state.json"
RM_RESOURCE_DIR="${ROOT_DIR}/services/rm_service/data/resources"
PKI_DIR="${ROOT_DIR}/artifacts/pki"
RUNTIME_DIR="${ROOT_DIR}/demo_runtime"
VENV_DIR="${ROOT_DIR}/.venv"

if [[ -x "${ROOT_DIR}/scripts/stop_all.sh" ]]; then
  "${ROOT_DIR}/scripts/stop_all.sh" || true
fi

for pidfile in "${RUNTIME_DIR}/pids"/*.pid; do
  [[ -e "${pidfile}" ]] || continue
  pid="$(cat "${pidfile}")"
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" || true
  fi
  rm -f "${pidfile}"
done

rm -rf "${RUNTIME_DIR}"
rm -rf "${PKI_DIR}"
rm -rf "${VENV_DIR}"

find "${ROOT_DIR}" -type d \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.mypy_cache' -o -name '.ruff_cache' \) -prune -exec rm -rf {} +
find "${ROOT_DIR}" -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '.coverage' -o -name '*.log' -o -name '.DS_Store' \) -delete
rm -rf "${ROOT_DIR}/htmlcov"

rm -f "${AAA_STATE_FILE}" "${CA_STATE_FILE}" "${CM_STATE_FILE}" "${KM_STATE_FILE}" "${RM_STATE_FILE}"
rm -rf "${RM_RESOURCE_DIR}"
mkdir -p "${ROOT_DIR}/services/aaa_service/data" \
         "${ROOT_DIR}/services/ca_service/data" \
         "${ROOT_DIR}/services/cm_service/data" \
         "${ROOT_DIR}/services/km_service/data" \
         "${ROOT_DIR}/services/rm_service/data/resources"

if [[ ! -f "${AAA_USERS_FILE}" ]]; then
  python3 - <<'PY' "${ROOT_DIR}"
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from common.config import DEMO_USERS, DEMO_USERS_FILE
DEMO_USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
DEMO_USERS_FILE.write_text(json.dumps({"users": DEMO_USERS}, indent=2, sort_keys=True), encoding="utf-8")
PY
fi

echo "Cleanup complete. Generated runtime state, PKI artifacts, resources, logs, caches and virtual environment were removed."

