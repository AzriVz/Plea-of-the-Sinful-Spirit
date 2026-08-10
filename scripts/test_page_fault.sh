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
	if ! kill -0 "$monitor_pid" 2>/dev/null; then break; fi
	sleep 0.05
done
"$project_root/build/page_fault_test" 32768
wait "$monitor_pid"
grep -q 'PAGEFAULT/s' "$log"
echo "PASS: page-fault hook attached and reported activity. Evidence: $log"

