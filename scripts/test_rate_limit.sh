#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
target="$artifact_dir/rate_limit_target"
workload_log="$artifact_dir/rate_limit_workload.log"
monitor_log="$artifact_dir/rate_limit_monitor.log"
threshold=10
workload_pid=""
monitor_pid=""

cleanup() {
	if [[ -n $workload_pid ]]; then kill -CONT "$workload_pid" 2>/dev/null || true; fi
	if [[ -n $monitor_pid ]]; then kill -INT "$monitor_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
	echo "Run this enforcement test with: sudo ./scripts/test_rate_limit.sh" >&2
	exit 77
fi
if ! tr ',' '\n' </sys/kernel/security/lsm | grep -qx bpf; then
	echo "SKIP: BPF LSM is not active in /sys/kernel/security/lsm; real rejection cannot be tested."
	exit 77
fi
mkdir -p "$artifact_dir"
: >"$target"
make -C "$project_root" all tests >/dev/null

"$project_root/build/rate_limit_test" "$target" "$threshold" >"$workload_log" 2>&1 &
workload_pid=$!
for _ in $(seq 1 200); do
	state=$(awk '/^State:/ {print $2}' "/proc/$workload_pid/status" 2>/dev/null || true)
	[[ $state == T ]] && break
	sleep 0.05
done
if [[ ${state:-} != T ]]; then
	echo "Rate workload did not reach synchronization point" >&2
	exit 1
fi

"$project_root/build/monitor" --no-clear --rate-limit "$target" \
	--limit "$threshold" --target-pid "$workload_pid" >"$monitor_log" 2>&1 &
monitor_pid=$!
for _ in $(seq 1 200); do
	grep -q 'LSM file_open' "$monitor_log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "Rate limiter failed to attach; inspect $monitor_log" >&2
		exit 1
	fi
	sleep 0.05
done
if ! grep -q 'LSM file_open' "$monitor_log"; then
	echo "Rate limiter attach synchronization timed out; inspect $monitor_log" >&2
	exit 1
fi
kill -CONT "$workload_pid"
wait "$workload_pid"
workload_pid=""
kill -INT "$monitor_pid"
wait "$monitor_pid"
monitor_pid=""
grep -q '^PASS$' "$workload_log"
cat "$workload_log"
