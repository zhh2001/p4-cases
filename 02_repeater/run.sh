#!/usr/bin/env bash
# Compile the P4 program, boot mininet with 2 hosts, let the Go
# controller push the pipeline, run a send/sniff verification across
# h1 <-> h2, and tear everything down.
#
#   sudo ./run.sh        # automated test
#   sudo ./run.sh cli    # drop into mininet CLI after bring-up

set -euo pipefail

CASE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${CASE_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${REPO_ROOT}/common/run_helpers.sh"
trap_cleanup
require_root

compile_p4 "${CASE_DIR}/main.p4"

BIN_DIR="${CASE_DIR}/bin"
mkdir -p "${BIN_DIR}"
log "Building Go controller"
( cd "${REPO_ROOT}" && go build -o "${BIN_DIR}/controller" ./02_repeater/controller )

MODE="${1:-test}"
EXTRA=()
if [[ "${MODE}" == "test" ]]; then
    EXTRA+=(--run-test)
fi

log "Starting mininet + controller + (optional) test"
python3 "${CASE_DIR}/topology.py" \
    --p4info "${BUILD_DIR}/main.p4info.txt" \
    --config "${BUILD_DIR}/main.json" \
    --controller "${BIN_DIR}/controller" \
    "${EXTRA[@]}"
