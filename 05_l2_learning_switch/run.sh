#!/usr/bin/env bash
# Case 05: L2 learning switch (digest variant).
#
#   sudo ./run.sh        # pingAll twice, expect 100% on both
#   sudo ./run.sh cli    # drop into mininet CLI after bring-up

set -euo pipefail

CASE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${CASE_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${REPO_ROOT}/common/run_helpers.sh"
trap_cleanup
require_root

# Compile main_digest.p4. p4c writes main_digest.{json,p4i}; we
# reference those filenames directly.
log "Compiling main_digest.p4"
mkdir -p "${BUILD_DIR}"
rm -rf "${BUILD_DIR}/main.json"  # clear leftover from earlier run.sh revisions
p4c -b bmv2 --target bmv2 --arch v1model \
    --std p4-16 \
    --p4runtime-files "${BUILD_DIR}/main_digest.p4info.txt" \
    -o "${BUILD_DIR}" \
    "${CASE_DIR}/main_digest.p4"

BIN_DIR="${CASE_DIR}/bin"
mkdir -p "${BIN_DIR}"
log "Building Go controller"
( cd "${REPO_ROOT}" && go build -o "${BIN_DIR}/controller" ./05_l2_learning_switch/controller )

MODE="${1:-test}"
EXTRA=()
if [[ "${MODE}" == "test" ]]; then
    EXTRA+=(--run-test)
fi

log "Starting mininet + controller + (optional) pingAll"
python3 "${CASE_DIR}/topology.py" \
    --p4info "${BUILD_DIR}/main_digest.p4info.txt" \
    --config "${BUILD_DIR}/main_digest.json" \
    --controller "${BIN_DIR}/controller" \
    "${EXTRA[@]}"
