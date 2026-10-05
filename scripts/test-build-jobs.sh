#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
JOBS_HELPER="$SCRIPT_DIR/build-jobs.sh"

assert_jobs() {
    local cpus=$1
    local available_kib=$2
    local expected=$3
    local actual

    actual=$("$JOBS_HELPER" "$cpus" "$available_kib")
    if [[ "$actual" != "$expected" ]]; then
        printf 'expected %s jobs for %s CPUs and %s KiB available, got %s\n' \
            "$expected" "$cpus" "$available_kib" "$actual" >&2
        exit 1
    fi
}

assert_jobs 1 8388608 2
assert_jobs 48 15728640 7
assert_jobs 48 262144000 49
assert_jobs 1 524288 1
printf 'build job selection: PASS\n'
