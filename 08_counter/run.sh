#!/usr/bin/env bash
# Case 08: per-port packet counter.
#
#   sudo ./run.sh                # indirect counter test
#   sudo ./run.sh test direct    # direct counter test
#   sudo ./run.sh cli indirect   # mininet CLI

set -euo pipefail

CASE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${CASE_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${REPO_ROOT}/common/run_helpers.sh"
require_root
trap_cleanup

MODE="${1:-test}"
VARIANT="${2:-indirect}"
case "${MODE}" in
    test|cli) ;;
    *) die "Usage: $0 [test|cli] [indirect|direct]" ;;
esac
case "${VARIANT}" in
    indirect|direct) ;;
    *) die "Counter variant must be indirect or direct" ;;
esac
compile_p4 "${CASE_DIR}/${VARIANT}_counter.p4"

BIN_DIR="${CASE_DIR}/bin"
mkdir -p "${BIN_DIR}"
log "Building Go controller"
( cd "${REPO_ROOT}" && go build -o "${BIN_DIR}/controller" ./08_counter/controller )

EXTRA=()
if [[ "${MODE}" == "test" ]]; then
    EXTRA+=(--run-test)
fi

log "Starting mininet + ${VARIANT} counter controller + (optional) frame test"
start_topology "${CASE_DIR}/topology.py" \
    --p4info "${BUILD_DIR}/${VARIANT}_counter.p4info.txt" \
    --config "${BUILD_DIR}/${VARIANT}_counter.json" \
    --controller "${BIN_DIR}/controller" \
    "${EXTRA[@]}"
