#!/usr/bin/env bash
set -euo pipefail

if (( $# > 2 )); then
    echo "usage: $0 [cpu-count [available-memory-kib]]" >&2
    exit 2
fi

cpu_count=${1:-$(nproc)}
available_kib=${2:-$(awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo)}
if [[ ! "$cpu_count" =~ ^[1-9][0-9]*$ || ! "$available_kib" =~ ^[0-9]+$ ]]; then
    echo "error: CPU count and available memory must be non-negative integers" >&2
    exit 2
fi

cpu_jobs=$((cpu_count + 1))
# Keep 2 GiB per compile job available for the LTO linker and the host.
memory_jobs=$((available_kib / 2097152))
if (( memory_jobs < 1 )); then
    memory_jobs=1
fi

if (( cpu_jobs < memory_jobs )); then
    printf '%s\n' "$cpu_jobs"
else
    printf '%s\n' "$memory_jobs"
fi
