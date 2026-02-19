#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SUPPORTED_ENDPOINTS=""
DEFAULT_ENDPOINTS=""

log_info() {
  printf "%b[INFO]%b %s\n" "${GREEN}" "${NC}" "$1"
}

log_warn() {
  printf "%b[WARN]%b %s\n" "${YELLOW}" "${NC}" "$1"
}

log_error() {
  printf "%b[ERROR]%b %s\n" "${RED}" "${NC}" "$1"
}

usage() {
  cat <<'EOF'
Usage:
  ./script.sh -f <enabled|disabled> [options]

Required:
  -f  Feature flag state for Check default behavior:
      enabled  => omitted consistency for Check resolves to at_least_as_acknowledged
      disabled => omitted consistency for Check resolves to minimize_latency

Options:
  -e  gRPC endpoint (default: ${INVENTORY_API_ENDPOINT:-${INVENTORY_API_IP:-localhost}:9081})
  -u  HTTP base URL for CheckSelf via curl (default: ${INVENTORY_API_HTTP_ENDPOINT:-http://localhost:8081})
  -m  Matrix YAML file (default: ./smoke-check-consistency-matrix.yaml)
  -c  Docker container name for debug-log verification (recommended)
  -H  Additional grpcurl header (repeatable), e.g. -H "x-rh-identity: <base64>"
  -r  Comma-separated endpoint ids to run
      (default: check,checkself,checkbulk,checkbulkself,streamedlistobjects,checkforupdate)
  -t  at_least_as_fresh token (default: GgYKBENJQVg=)
  -o  output directory (default: /tmp/check-consistency-smoke-<timestamp>)
  -h  show help

Endpoint ids:
  Derived from matrix YAML file.

Examples:
  ./script.sh -f enabled -e localhost:9081 -c development-inventory-api-1
  ./script.sh -f disabled -r check,checkself -c development-inventory-api-1
  ./script.sh -f enabled -r checkself -u http://localhost:8081 -H "x-rh-identity: <base64>"
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    log_error "Missing dependency: ${cmd}"
    exit 1
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if ! grep -Fq "${needle}" <<<"${haystack}"; then
    log_error "${message}"
    log_error "Expected to find: ${needle}"
    return 1
  fi
}

method_for_endpoint() {
  yq -r ".endpoints.${1}.grpc_method // \"\"" "${MATRIX_FILE}"
}

transport_for_endpoint() {
  yq -r ".endpoints.${1}.transport // \"grpc\"" "${MATRIX_FILE}"
}

http_path_for_endpoint() {
  yq -r ".endpoints.${1}.http_path // \"\"" "${MATRIX_FILE}"
}

consistency_json_for() {
  case "$1" in
    default) printf "null" ;;
    minimize) printf '{"minimizeLatency":true}' ;;
    fresh) jq -nc --arg token "${FRESH_TOKEN}" '{atLeastAsFresh:{token:$token}}' ;;
    acknowledged) printf '{"atLeastAsAcknowledged":true}' ;;
    *) return 1 ;;
  esac
}

expected_mode_for() {
  local endpoint="$1"
  local scenario="$2"
  local keyed plain
  keyed="$(yq -r ".endpoints.${endpoint}.scenarios.${scenario}.expected_mode.${FLAG_STATE}" "${MATRIX_FILE}")"
  if [[ "${keyed}" != "null" && -n "${keyed}" ]]; then
    printf "%s" "${keyed}"
    return 0
  fi
  plain="$(yq -r ".endpoints.${endpoint}.scenarios.${scenario}.expected_mode" "${MATRIX_FILE}")"
  if [[ "${plain}" == "null" || -z "${plain}" ]]; then
    printf "not_applicable"
  else
    printf "%s" "${plain}"
  fi
}

expected_debug_log_for() {
  local endpoint="$1"
  local scenario="$2"
  local keyed plain
  keyed="$(yq -r ".endpoints.${endpoint}.scenarios.${scenario}.expected_log.${FLAG_STATE}" "${MATRIX_FILE}")"
  if [[ "${keyed}" != "null" && -n "${keyed}" ]]; then
    printf "%s" "${keyed}"
    return 0
  fi
  plain="$(yq -r ".endpoints.${endpoint}.scenarios.${scenario}.expected_log" "${MATRIX_FILE}")"
  if [[ "${plain}" == "null" || -z "${plain}" ]]; then
    printf ""
  else
    printf "%s" "${plain}"
  fi
}

build_payload() {
  local endpoint="$1"
  local consistency_json="$2"

  case "${endpoint}" in
    check|checkforupdate)
      jq -nc \
        --arg resource_type "${RESOURCE_TYPE}" \
        --arg resource_id "${RESOURCE_ID}" \
        --arg reporter_type "${REPORTER_TYPE}" \
        --arg reporter_instance_id "${REPORTER_INSTANCE_ID}" \
        --arg relation "${RELATION}" \
        --arg subject_resource_type "${SUBJECT_RESOURCE_TYPE}" \
        --arg subject_resource_id "${SUBJECT_RESOURCE_ID}" \
        --arg subject_reporter_type "${SUBJECT_REPORTER_TYPE}" \
        --argjson consistency "${consistency_json}" \
        '{
          object: {
            resourceType: $resource_type,
            resourceId: $resource_id,
            reporter: {
              type: $reporter_type,
              instanceId: $reporter_instance_id
            }
          },
          relation: $relation,
          subject: {
            resource: {
              resourceType: $subject_resource_type,
              resourceId: $subject_resource_id,
              reporter: { type: $subject_reporter_type }
            }
          }
        } + (if $consistency == null or "'"${endpoint}"'" == "checkforupdate" then {} else {consistency: $consistency} end)'
      ;;
    checkself)
      jq -nc \
        --arg resource_type "${RESOURCE_TYPE}" \
        --arg resource_id "${RESOURCE_ID}" \
        --arg reporter_type "${REPORTER_TYPE}" \
        --arg reporter_instance_id "${REPORTER_INSTANCE_ID}" \
        --arg relation "${RELATION}" \
        --argjson consistency "${consistency_json}" \
        '{
          object: {
            resourceType: $resource_type,
            resourceId: $resource_id,
            reporter: {
              type: $reporter_type,
              instanceId: $reporter_instance_id
            }
          },
          relation: $relation
        } + (if $consistency == null then {} else {consistency: $consistency} end)'
      ;;
    checkbulk)
      jq -nc \
        --arg resource_type "${RESOURCE_TYPE}" \
        --arg resource_id "${RESOURCE_ID}" \
        --arg reporter_type "${REPORTER_TYPE}" \
        --arg reporter_instance_id "${REPORTER_INSTANCE_ID}" \
        --arg relation "${RELATION}" \
        --arg subject_resource_type "${SUBJECT_RESOURCE_TYPE}" \
        --arg subject_resource_id "${SUBJECT_RESOURCE_ID}" \
        --arg subject_reporter_type "${SUBJECT_REPORTER_TYPE}" \
        --argjson consistency "${consistency_json}" \
        '{
          items: [
            {
              object: {
                resourceType: $resource_type,
                resourceId: $resource_id,
                reporter: {
                  type: $reporter_type,
                  instanceId: $reporter_instance_id
                }
              },
              relation: $relation,
              subject: {
                resource: {
                  resourceType: $subject_resource_type,
                  resourceId: $subject_resource_id,
                  reporter: { type: $subject_reporter_type }
                }
              }
            }
          ]
        } + (if $consistency == null then {} else {consistency: $consistency} end)'
      ;;
    checkbulkself)
      jq -nc \
        --arg resource_type "${RESOURCE_TYPE}" \
        --arg resource_id "${RESOURCE_ID}" \
        --arg reporter_type "${REPORTER_TYPE}" \
        --arg reporter_instance_id "${REPORTER_INSTANCE_ID}" \
        --arg relation "${RELATION}" \
        --argjson consistency "${consistency_json}" \
        '{
          items: [
            {
              object: {
                resourceType: $resource_type,
                resourceId: $resource_id,
                reporter: {
                  type: $reporter_type,
                  instanceId: $reporter_instance_id
                }
              },
              relation: $relation
            }
          ]
        } + (if $consistency == null then {} else {consistency: $consistency} end)'
      ;;
    streamedlistobjects)
      jq -nc \
        --arg resource_type "${RESOURCE_TYPE}" \
        --arg reporter_type "${REPORTER_TYPE}" \
        --arg relation "${RELATION}" \
        --arg subject_resource_type "${SUBJECT_RESOURCE_TYPE}" \
        --arg subject_resource_id "${SUBJECT_RESOURCE_ID}" \
        --arg subject_reporter_type "${SUBJECT_REPORTER_TYPE}" \
        --argjson consistency "${consistency_json}" \
        '{
          objectType: {
            resourceType: $resource_type,
            reporterType: $reporter_type
          },
          relation: $relation,
          subject: {
            resource: {
              resourceType: $subject_resource_type,
              resourceId: $subject_resource_id,
              reporter: { type: $subject_reporter_type }
            }
          }
        } + (if $consistency == null then {} else {consistency: $consistency} end)'
      ;;
    *)
      return 1
      ;;
  esac
}

validate_success_response() {
  local endpoint="$1"
  local response="$2"
  local scenario_name="$3"

  case "${endpoint}" in
    check|checkself|checkforupdate)
      if ! jq -e '.allowed' >/dev/null 2>&1 <<<"${response}"; then
        log_error "${scenario_name}: expected allowed field in response"
        return 1
      fi
      ;;
    checkbulk|checkbulkself)
      if ! jq -e '.pairs | length >= 1' >/dev/null 2>&1 <<<"${response}"; then
        log_error "${scenario_name}: expected at least one pair in response"
        return 1
      fi
      ;;
    streamedlistobjects)
      # Stream may be empty; grpc success is enough for smoke.
      ;;
    *)
      return 1
      ;;
  esac

  return 0
}

run_scenario() {
  local endpoint="$1"
  local scenario="$2"
  local method="$3"
  local expected_mode="$4"
  local output_file="$5"
  local expected_log_line="$6"
  local scenario_name="${endpoint}:${scenario}"

  local consistency_json
  consistency_json="$(consistency_json_for "${scenario}")"
  local payload
  payload="$(build_payload "${endpoint}" "${consistency_json}")"

  local start_ts=""
  if [[ -n "${DOCKER_CONTAINER}" ]]; then
    start_ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  fi

  local response=""
  local grpc_status=0
  local http_status=""

  local transport
  transport="$(transport_for_endpoint "${endpoint}")"
  if [[ "${transport}" == "http" ]]; then
    local http_path
    http_path="$(http_path_for_endpoint "${endpoint}")"
    if [[ -z "${http_path}" ]]; then
      log_error "${scenario_name}: missing http_path for endpoint ${endpoint} in matrix"
      return 1
    fi

    local curl_out curl_status
    curl_out="$(curl -sS -X POST "${HTTP_BASE_URL}${http_path}" \
      -H "content-type: application/json" \
      "${COMMON_HEADER_ARGS[@]}" \
      -d "${payload}" \
      -w $'\n__HTTP_STATUS__:%{http_code}' 2>&1)" || curl_status=$?
    curl_status="${curl_status:-0}"
    if [[ ${curl_status} -ne 0 ]]; then
      grpc_status=${curl_status}
      response="${curl_out}"
    else
      http_status="$(awk -F: '/^__HTTP_STATUS__:/ {print $2}' <<<"${curl_out}" | tail -n1)"
      response="$(awk '!/^__HTTP_STATUS__:/ {print}' <<<"${curl_out}")"
      if [[ -z "${http_status}" || "${http_status}" -ge 400 ]]; then
        grpc_status=1
      fi
    fi
  else
    if [[ -z "${method}" ]]; then
      log_error "${scenario_name}: missing grpc_method for endpoint ${endpoint} in matrix"
      return 1
    fi
    response="$(grpcurl -plaintext "${COMMON_HEADER_ARGS[@]}" -d "${payload}" "${ENDPOINT}" "${method}" 2>&1)" || grpc_status=$?
  fi

  printf "%s\n" "${payload}" > "${output_file}.request.json"
  printf "%s\n" "${response}" > "${output_file}.response.txt"
  if [[ -n "${http_status}" ]]; then
    printf "%s\n" "${http_status}" > "${output_file}.http-status.txt"
  fi
  {
    printf "endpoint=%s\n" "${endpoint}"
    printf "scenario=%s\n" "${scenario}"
    printf "expected_mode=%s\n" "${expected_mode}"
    printf "expected_log=%s\n" "${expected_log_line}"
  } > "${output_file}.expected.txt"

  if [[ "${expected_mode}" == "unsupported_ack" ]]; then
    if [[ ${grpc_status} -eq 0 ]]; then
      log_error "${scenario_name}: expected InvalidArgument for acknowledged but call succeeded"
      return 1
    fi
    assert_contains "${response}" "inventory managed zookies aren't available" \
      "${scenario_name}: missing unsupported zookies error" || return 1
    log_info "${scenario_name}: expected InvalidArgument observed"
    return 0
  fi

  if [[ ${grpc_status} -ne 0 ]]; then
    log_error "${scenario_name}: request failed unexpectedly"
    log_error "Saved output: ${output_file}.response.txt"
    return 1
  fi

  validate_success_response "${endpoint}" "${response}" "${scenario_name}" || return 1

  local allowed token
  allowed="$(jq -r '.allowed // empty' <<<"${response}" 2>/dev/null || true)"
  token="$(jq -r '.consistencyToken.token // .consistency_token.token // empty' <<<"${response}" 2>/dev/null || true)"
  log_info "${scenario_name}: expected_mode=${expected_mode}, allowed='${allowed}', token='${token}'"

  if [[ -n "${DOCKER_CONTAINER}" && -n "${expected_log_line}" ]]; then
    local log_chunk
    log_chunk="$(docker logs --since "${start_ts}" "${DOCKER_CONTAINER}" 2>&1 || true)"
    printf "%s\n" "${log_chunk}" > "${output_file}.log-chunk.txt"
    assert_contains "${log_chunk}" "${expected_log_line}" \
      "${scenario_name}: missing expected debug log" || return 1
    log_info "${scenario_name}: observed_expected_log='${expected_log_line}'"
  fi

  return 0
}

is_supported_endpoint() {
  local endpoint="$1"
  case ",${SUPPORTED_ENDPOINTS}," in
    *",${endpoint},"*) return 0 ;;
    *) return 1 ;;
  esac
}

scenarios_for_endpoint() {
  yq -r ".endpoints.${1}.scenarios | keys | join(\",\")" "${MATRIX_FILE}"
}

ENDPOINT="${INVENTORY_API_ENDPOINT:-${INVENTORY_API_IP:-localhost}:9081}"
HTTP_BASE_URL="${INVENTORY_API_HTTP_ENDPOINT:-http://localhost:8081}"
MATRIX_FILE="${INVENTORY_API_MATRIX_FILE:-${SCRIPT_DIR}/smoke-check-consistency-matrix.yaml}"
FLAG_STATE=""
FRESH_TOKEN="GgYKBENJQVg="
OUTPUT_DIR="/tmp/check-consistency-smoke-$(date +%Y%m%d%H%M%S)"
DOCKER_CONTAINER="${INVENTORY_API_CONTAINER:-}"
RUN_ENDPOINTS="${DEFAULT_ENDPOINTS}"
COMMON_HEADER_ARGS=()

while getopts ":e:u:m:f:t:o:c:r:H:h" opt; do
  case "${opt}" in
    e) ENDPOINT="${OPTARG}" ;;
    u) HTTP_BASE_URL="${OPTARG}" ;;
    m) MATRIX_FILE="${OPTARG}" ;;
    f) FLAG_STATE="${OPTARG}" ;;
    t) FRESH_TOKEN="${OPTARG}" ;;
    o) OUTPUT_DIR="${OPTARG}" ;;
    c) DOCKER_CONTAINER="${OPTARG}" ;;
    r) RUN_ENDPOINTS="${OPTARG}" ;;
    H)
      COMMON_HEADER_ARGS+=("-H" "${OPTARG}")
      ;;
    h)
      usage
      exit 0
      ;;
    :)
      log_error "Option -${OPTARG} requires an argument"
      usage
      exit 1
      ;;
    \?)
      log_error "Unknown option: -${OPTARG}"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${FLAG_STATE}" ]]; then
  log_error "-f is required (enabled|disabled)"
  usage
  exit 1
fi

if [[ "${FLAG_STATE}" != "enabled" && "${FLAG_STATE}" != "disabled" ]]; then
  log_error "-f must be either enabled or disabled"
  exit 1
fi

RESOURCE_TYPE="${CHECK_RESOURCE_TYPE:-host}"
RESOURCE_ID="${CHECK_RESOURCE_ID:-dd1b73b9-3e33-4264-968c-e3ce55b9afec}"
REPORTER_TYPE="${CHECK_REPORTER_TYPE:-hbi}"
REPORTER_INSTANCE_ID="${CHECK_REPORTER_INSTANCE_ID:-3088be62-1c60-4884-b133-9200542d0b3f}"
RELATION="${CHECK_RELATION:-view}"
SUBJECT_RESOURCE_TYPE="${CHECK_SUBJECT_RESOURCE_TYPE:-principal}"
SUBJECT_RESOURCE_ID="${CHECK_SUBJECT_RESOURCE_ID:-sarah}"
SUBJECT_REPORTER_TYPE="${CHECK_SUBJECT_REPORTER_TYPE:-rbac}"

require_cmd grpcurl
require_cmd curl
require_cmd jq
require_cmd yq
if [[ -n "${DOCKER_CONTAINER}" ]]; then
  require_cmd docker
fi

if [[ ! -f "${MATRIX_FILE}" ]]; then
  log_error "Matrix file not found: ${MATRIX_FILE}"
  exit 1
fi

SUPPORTED_ENDPOINTS="$(yq -r '.endpoints | keys | join(",")' "${MATRIX_FILE}")"
DEFAULT_ENDPOINTS="${SUPPORTED_ENDPOINTS}"
if [[ -z "${RUN_ENDPOINTS}" ]]; then
  RUN_ENDPOINTS="${DEFAULT_ENDPOINTS}"
fi

mkdir -p "${OUTPUT_DIR}"

log_info "Endpoint: ${ENDPOINT}"
log_info "HTTP base URL (for checkself): ${HTTP_BASE_URL}"
log_info "Feature flag state for Check default: ${FLAG_STATE}"
log_info "Matrix file: ${MATRIX_FILE}"
log_info "Output directory: ${OUTPUT_DIR}"
log_info "Run endpoints: ${RUN_ENDPOINTS}"
if [[ ${#COMMON_HEADER_ARGS[@]} -gt 0 ]]; then
  log_info "custom headers: ${#COMMON_HEADER_ARGS[@]} args"
else
  log_warn "No grpcurl headers set; self/meta-auth endpoints may fail with PermissionDenied in some environments."
fi
if [[ -n "${DOCKER_CONTAINER}" ]]; then
  log_info "Docker log verification container: ${DOCKER_CONTAINER}"
else
  log_warn "Docker log verification disabled; unsupported/success checks rely on gRPC results."
fi

pass_count=0
fail_count=0

IFS=',' read -r -a endpoint_list <<<"${RUN_ENDPOINTS}"
for endpoint in "${endpoint_list[@]}"; do
  endpoint="${endpoint//[[:space:]]/}"
  if [[ -z "${endpoint}" ]]; then
    continue
  fi
  if ! is_supported_endpoint "${endpoint}"; then
    log_error "Unsupported endpoint id: ${endpoint}"
    fail_count=$((fail_count + 1))
    continue
  fi

  method="$(method_for_endpoint "${endpoint}")"
  endpoint_output_dir="${OUTPUT_DIR}/${endpoint}"
  mkdir -p "${endpoint_output_dir}"

  IFS=',' read -r -a scenario_list <<<"$(scenarios_for_endpoint "${endpoint}")"
  for scenario in "${scenario_list[@]}"; do
    expected_mode="$(expected_mode_for "${endpoint}" "${scenario}")"
    if [[ "${expected_mode}" == "not_applicable" ]]; then
      log_info "${endpoint}:${scenario}: skipped (not applicable)"
      continue
    fi

    expected_log_line="$(expected_debug_log_for "${endpoint}" "${scenario}")"
    scenario_output_file="${endpoint_output_dir}/${scenario}"
    if run_scenario \
      "${endpoint}" \
      "${scenario}" \
      "${method}" \
      "${expected_mode}" \
      "${scenario_output_file}" \
      "${expected_log_line}"; then
      pass_count=$((pass_count + 1))
    else
      fail_count=$((fail_count + 1))
    fi
  done
done

printf "\n"
log_info "Completed consistency smoke test suite"
log_info "Passed: ${pass_count}"
if [[ ${fail_count} -gt 0 ]]; then
  log_error "Failed: ${fail_count}"
  log_error "Inspect artifacts under: ${OUTPUT_DIR}"
  exit 1
fi
log_info "Failed: ${fail_count}"
log_info "All scenarios passed."
