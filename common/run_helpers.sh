#!/usr/bin/env bash
# Shared helpers for per-case run.sh scripts.
# Source this file, not execute it.

set -euo pipefail

# Prefer the modern Go toolchain under /usr/local/go when both it and the
# older apt-installed Go co-exist on PATH. The p4-cases go.mod declares
# `go 1.25` which the 1.22 apt build misunderstands as a request to
# download an exact "1.25" toolchain.
if [[ -x /usr/local/go/bin/go ]]; then
    export PATH="/usr/local/go/bin:$PATH"
fi

CASE_DIR="${CASE_DIR:-$(pwd)}"
BUILD_DIR="${BUILD_DIR:-${CASE_DIR}/build}"
TOPOLOGY_PID=""

log() { printf '\033[1;34m[%s]\033[0m %s\n' "$(basename "${CASE_DIR}")" "$*" >&2; }
die() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "This script must run under sudo (mininet needs root)."
}

# compile_p4 <main.p4> → ${BUILD_DIR}/{main.json, main.p4info.txt}
compile_p4() {
    local src="$1"
    local base
    base="$(basename "${src}" .p4)"
    mkdir -p "${BUILD_DIR}"
    log "Compiling ${src} -> ${BUILD_DIR}/${base}.{json,p4info.txt}"
    p4c -b bmv2 --target bmv2 --arch v1model \
        --std p4-16 \
        --p4runtime-files "${BUILD_DIR}/${base}.p4info.txt" \
        -o "${BUILD_DIR}" \
        "${src}"
}

# start_topology <topology.py> [extra args...]
# Wait for this topology and preserve its exit status.
start_topology() {
    local topo="$1"
    shift
    log "Launching mininet topology: ${topo}"
    python3 "${topo}" "$@" <&0 &
    TOPOLOGY_PID=$!
    local status=0
    wait "${TOPOLOGY_PID}" || status=$?
    TOPOLOGY_PID=""
    return "${status}"
}

# Stop only the topology started by this script. Python owns network cleanup.
kill_topology() {
    if [[ -n "${TOPOLOGY_PID}" ]]; then
        kill -TERM "${TOPOLOGY_PID}" 2>/dev/null || true
        wait "${TOPOLOGY_PID}" 2>/dev/null || true
        TOPOLOGY_PID=""
    fi
}

trap_cleanup() {
    trap kill_topology EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}
