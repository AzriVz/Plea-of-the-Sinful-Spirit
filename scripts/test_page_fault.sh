#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
log="$project_root/artifacts/page_fault_monitor.log"

if [[ $EUID -ne 0 ]]; then
	echo "Run this hook test with: sudo ./scripts/test_page_fault.sh" >&2
	exit 77
fi
make -C "$project_root" all tests >/dev/null
mkdir -p "$project_root/artifacts"
"$project_root/build/monitor" --page-faults --no-clear --interval 0.5 --duration 3 \
	>"$log" 2>&1 &
monitor_pid=$!
for _ in $(seq 1 100); do
	grep -q 'handle_mm_fault' "$log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "FAIL: page-fault monitor exited before attach; inspect $log" >&2
		wait "$monitor_pid" 2>/dev/null || true
		exit 1
	fi
	sleep 0.05
done
if ! grep -q 'handle_mm_fault' "$log"; then
	echo "FAIL: page-fault attach synchronization timed out; inspect $log" >&2
	kill -INT "$monitor_pid" 2>/dev/null || true
	wait "$monitor_pid" 2>/dev/null || true
	exit 1
fi
"$project_root/build/page_fault_test" 32768
set +e
wait "$monitor_pid"
monitor_status=$?
set -e
if [[ $monitor_status -ne 0 ]]; then
	echo "FAIL: page-fault monitor returned $monitor_status; inspect $log" >&2
	exit 1
fi
grep -q 'PAGEFAULT/s' "$log"
echo "PASS: page-fault hook attached and reported activity. Evidence: $log"
