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
LOG_DIR="${LOG_DIR:-/tmp/p4-cases}"
mkdir -p "${BUILD_DIR}" "${LOG_DIR}"

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
    log "Compiling ${src} -> ${BUILD_DIR}/${base}.{json,p4info.txt}"
    p4c -b bmv2 --target bmv2 --arch v1model \
        --std p4-16 \
        --p4runtime-files "${BUILD_DIR}/${base}.p4info.txt" \
        -o "${BUILD_DIR}" \
        "${src}"
}

# start_topology <topology.py> [extra args...]
# Boots mininet in the background, leaves it running. Use with kill_topology.
start_topology() {
    local topo="$1"
    shift
    log "Launching mininet topology: ${topo}"
    python3 "${topo}" "$@"
}

# kill_topology — tear down any leftover simple_switch_grpc and mn/ovs state.
kill_topology() {
    log "Cleaning up mininet residue"
    pkill -TERM -f simple_switch_grpc 2>/dev/null || true
    mn -c >/dev/null 2>&1 || true
}

trap_cleanup() {
    trap kill_topology EXIT INT TERM
}
