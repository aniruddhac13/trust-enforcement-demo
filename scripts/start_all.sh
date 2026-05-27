#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${ROOT_DIR}/demo_runtime/logs"
PID_DIR="${ROOT_DIR}/demo_runtime/pids"
mkdir -p "${LOG_DIR}" "${PID_DIR}"

if [[ -d "${ROOT_DIR}/.venv" ]]; then
  source "${ROOT_DIR}/.venv/bin/activate"
fi

VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"
if [[ ! -x "${VENV_PYTHON}" ]]; then
  VENV_PYTHON="$(command -v python3)"
fi

export PYTHONPATH="${ROOT_DIR}:${PYTHONPATH:-}"

AAA_PORT="${AAA_PORT:-8401}"
CA_PORT="${CA_PORT:-8402}"
CM_PORT="${CM_PORT:-8403}"
KM_PORT="${KM_PORT:-8404}"
RM_PORT="${RM_PORT:-8405}"
FRONTEND_PORT="${FRONTEND_PORT:-8080}"

"${VENV_PYTHON}" "${ROOT_DIR}/scripts/bootstrap_demo.py"

start_service() {
  local name="$1"
  local cmd="$2"
  local logfile="${LOG_DIR}/${name}.log"
  local pidfile="${PID_DIR}/${name}.pid"
  if [[ -f "${pidfile}" ]] && kill -0 "$(cat "${pidfile}")" 2>/dev/null; then
    echo "${name} is already running with PID $(cat "${pidfile}")"
    return
  fi
  echo "Starting ${name} ..."
  nohup bash -lc "${cmd}" </dev/null >"${logfile}" 2>&1 &
  echo $! > "${pidfile}"
}

COMMON_ENV="AAA_PORT='${AAA_PORT}' CA_PORT='${CA_PORT}' CM_PORT='${CM_PORT}' KM_PORT='${KM_PORT}' RM_PORT='${RM_PORT}' FRONTEND_PORT='${FRONTEND_PORT}'"

start_service "aaa" "cd '${ROOT_DIR}' && ${COMMON_ENV} '${VENV_PYTHON}' -m uvicorn services.aaa_service.app:app --host 0.0.0.0 --port ${AAA_PORT}"
start_service "ca" "cd '${ROOT_DIR}' && ${COMMON_ENV} '${VENV_PYTHON}' -m uvicorn services.ca_service.app:app --host 0.0.0.0 --port ${CA_PORT}"
start_service "cm" "cd '${ROOT_DIR}' && ${COMMON_ENV} '${VENV_PYTHON}' -m uvicorn services.cm_service.app:app --host 0.0.0.0 --port ${CM_PORT}"
start_service "km" "cd '${ROOT_DIR}' && ${COMMON_ENV} '${VENV_PYTHON}' -m uvicorn services.km_service.app:app --host 0.0.0.0 --port ${KM_PORT}"
start_service "rm" "cd '${ROOT_DIR}' && ${COMMON_ENV} '${VENV_PYTHON}' -m uvicorn services.rm_service.app:app --host 0.0.0.0 --port ${RM_PORT}"
start_service "frontend" "cd '${ROOT_DIR}' && ${COMMON_ENV} '${VENV_PYTHON}' frontend/app.py"

echo
echo "Services starting."
echo
echo "Frontend: http://127.0.0.1:${FRONTEND_PORT}"
echo "Logs: ${LOG_DIR}"
echo "PIDs: ${PID_DIR}"
