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
trap_cleanup
require_root

log "Compiling indirect_meter.p4"
mkdir -p "${BUILD_DIR}"
p4c -b bmv2 --target bmv2 --arch v1model --std p4-16 \
    --p4runtime-files "${BUILD_DIR}/main.p4info.txt" \
    -o "${BUILD_DIR}" \
    "${CASE_DIR}/indirect_meter.p4"
# Normalise the JSON filename.
if [[ -f "${BUILD_DIR}/indirect_meter.json" && ! -f "${BUILD_DIR}/main.json" ]]; then
    mv "${BUILD_DIR}/indirect_meter.json" "${BUILD_DIR}/main.json"
fi

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
python3 "${CASE_DIR}/topology.py" \
    --p4info "${BUILD_DIR}/main.p4info.txt" \
    --config "${BUILD_DIR}/main.json" \
    --controller "${BIN_DIR}/controller" \
    "${EXTRA[@]}"
