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
for _ in $(seq 1 100); do
	grep -q 'Hooks attached:' "$log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "FAIL: monitor exited before attach; inspect $log" >&2
		wait "$monitor_pid" 2>/dev/null || true
		exit 1
	fi
	sleep 0.05
done
if ! grep -q 'Hooks attached:' "$log"; then
	echo "FAIL: monitor attach synchronization timed out; inspect $log" >&2
	kill -INT "$monitor_pid" 2>/dev/null || true
	wait "$monitor_pid" 2>/dev/null || true
	exit 1
fi
"$project_root/build/syscall_stress" --iterations 10000
set +e
wait "$monitor_pid"
monitor_status=$?
set -e
if [[ $monitor_status -ne 0 ]]; then
	echo "FAIL: monitor returned $monitor_status; inspect $log" >&2
	exit 1
fi
grep -q '^TOTAL' "$log"
echo "PASS: mandatory hooks produced live per-CPU rates. Evidence: $log"
