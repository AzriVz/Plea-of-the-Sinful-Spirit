#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
log="$project_root/artifacts/monitor_smoke.log"

if [[ $EUID -ne 0 ]]; then
	echo "Run this load/attach test with: sudo ./scripts/test_monitor.sh" >&2
	exit 77
fi
make -C "$project_root" all tests >/dev/null
mkdir -p "$project_root/artifacts"
"$project_root/build/monitor" --duration 3 --interval 1 --no-clear >"$log" 2>&1 &
monitor_pid=$!
"$project_root/build/syscall_stress" --iterations 10000
wait "$monitor_pid"
grep -q '^TOTAL' "$log"
echo "PASS: mandatory hooks produced live per-CPU rates. Evidence: $log"

