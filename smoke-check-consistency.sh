#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER_SCRIPT="${SCRIPT_DIR}/script.sh"
MATRIX_FILE="${SCRIPT_DIR}/smoke-check-consistency-matrix.yaml"

if [[ ! -f "${RUNNER_SCRIPT}" ]]; then
  echo "[ERROR] Missing source script: ${RUNNER_SCRIPT}" >&2
  exit 1
fi

if [[ ! -f "${MATRIX_FILE}" ]]; then
  echo "[ERROR] Missing matrix file: ${MATRIX_FILE}" >&2
  exit 1
fi

INVENTORY_API_MATRIX_FILE="${MATRIX_FILE}" "${RUNNER_SCRIPT}" "$@"
