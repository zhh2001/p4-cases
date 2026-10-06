#!/usr/bin/env bash
# Case 07: meter-based policing (indirect meter variant).
#
#   sudo ./run.sh        # blast test, expect non-metered > metered
#   sudo ./run.sh cli    # drop into mininet CLI after bring-up

set -euo pipefail

CASE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${CASE_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${REPO_ROOT}/common/run_helpers.sh"
require_root
trap_cleanup

compile_p4 "${CASE_DIR}/indirect_meter.p4"

BIN_DIR="${CASE_DIR}/bin"
mkdir -p "${BIN_DIR}"
log "Building Go controller"
( cd "${REPO_ROOT}" && go build -o "${BIN_DIR}/controller" ./07_meter/controller )

MODE="${1:-test}"
EXTRA=()
if [[ "${MODE}" == "test" ]]; then
    EXTRA+=(--run-test)
fi

log "Starting mininet + controller + (optional) blast test"
start_topology "${CASE_DIR}/topology.py" \
    --p4info "${BUILD_DIR}/indirect_meter.p4info.txt" \
    --config "${BUILD_DIR}/indirect_meter.json" \
    --controller "${BIN_DIR}/controller" \
    "${EXTRA[@]}"
