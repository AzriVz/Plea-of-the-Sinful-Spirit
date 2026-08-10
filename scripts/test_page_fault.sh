#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
monitor_log="$artifact_dir/page_fault_demo.log"
workload_log="$artifact_dir/page_fault_workload.log"
workload_pid=""
monitor_pid=""
target_tgid=""

cleanup() {
	if [[ -n $workload_pid ]]; then kill -CONT "$workload_pid" 2>/dev/null || true; fi
	if [[ -n $monitor_pid ]]; then kill -INT "$monitor_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
	echo "Run this hook test with: sudo ./scripts/test_page_fault.sh" >&2
	exit 77
fi
make -C "$project_root" all tests >/dev/null
mkdir -p "$artifact_dir"

"$project_root/build/page_fault_test" --pause 32768 >"$workload_log" 2>&1 &
workload_pid=$!
target_tgid=$workload_pid
for _ in $(seq 1 200); do
	state=$(awk '/^State:/ {print $2}' "/proc/$workload_pid/status" 2>/dev/null || true)
	[[ $state == T ]] && break
	sleep 0.05
done
if [[ ${state:-} != T ]]; then
	echo "FAIL: page-fault workload did not reach its SIGSTOP point" >&2
	exit 1
fi

"$project_root/build/monitor" --page-fault-demo --sample 64 --no-clear \
	--target-pid "$workload_pid" --interval 0.5 --duration 3 \
	>"$monitor_log" 2>&1 &
monitor_pid=$!
for _ in $(seq 1 200); do
	grep -q 'handle_mm_fault' "$monitor_log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "FAIL: page-fault monitor exited before attach; inspect $monitor_log" >&2
		wait "$monitor_pid" 2>/dev/null || true
		exit 1
	fi
	sleep 0.05
done
if ! grep -q 'handle_mm_fault' "$monitor_log"; then
	echo "FAIL: page-fault attach synchronization timed out; inspect $monitor_log" >&2
	exit 1
fi

kill -CONT "$workload_pid"
wait "$workload_pid"
workload_pid=""
set +e
wait "$monitor_pid"
monitor_status=$?
set -e
monitor_pid=""
if [[ $monitor_status -ne 0 ]]; then
	echo "FAIL: page-fault monitor returned $monitor_status; inspect $monitor_log" >&2
	exit 1
fi
if ! grep -Eq "^EVENT ts=[0-9]+ cpu=[0-9]+ pid=[0-9]+ tgid=$target_tgid " \
	"$monitor_log" ||
	! grep -Eq ' comm=page_fault_test page_fault address=0x[0-9a-f]+' \
	"$monitor_log"; then
	echo "FAIL: no detailed page-fault record was captured; inspect $monitor_log" >&2
	exit 1
fi
grep -q 'PAGEFAULT/s' "$monitor_log"
cat "$workload_log"
echo "PASS: page-fault metadata and per-CPU rates captured. Evidence: $monitor_log"
