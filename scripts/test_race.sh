#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
stress_log="$artifact_dir/race_workload.log"
monitor_log="$artifact_dir/race_test.log"
workload_pid=""
monitor_pid=""

cleanup() {
	if [[ -n $workload_pid ]]; then kill -CONT "$workload_pid" 2>/dev/null || true; fi
	if [[ -n $monitor_pid ]]; then kill -INT "$monitor_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
	echo "Run the deterministic map test with: sudo ./scripts/test_race.sh" >&2
	exit 77
fi
mkdir -p "$artifact_dir"
make -C "$project_root" all tests >/dev/null

"$project_root/build/syscall_stress" --pause --iterations 100000 >"$stress_log" 2>&1 &
workload_pid=$!
for _ in $(seq 1 200); do
	state=$(awk '/^State:/ {print $2}' "/proc/$workload_pid/status" 2>/dev/null || true)
	[[ $state == T ]] && break
	sleep 0.05
done
if [[ ${state:-} != T ]]; then
	echo "Workload did not reach its SIGSTOP synchronization point" >&2
	exit 1
fi
ready=$(grep '^READY ' "$stress_log")
expected=$(sed -n 's/.* expected=\([0-9][0-9]*\).*/\1/p' <<<"$ready")
syscall_nr=$(sed -n 's/.* syscall=\([0-9][0-9]*\).*/\1/p' <<<"$ready")

"$project_root/build/monitor" --no-clear --interval 1 \
	--test-pid "$workload_pid" --test-syscall "$syscall_nr" --expect "$expected" \
	>"$monitor_log" 2>&1 &
monitor_pid=$!
for _ in $(seq 1 200); do
	grep -q 'Hooks attached:' "$monitor_log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "Monitor exited before attach; inspect $monitor_log" >&2
		exit 1
	fi
	sleep 0.05
done
if ! grep -q 'Hooks attached:' "$monitor_log"; then
	echo "Monitor attach synchronization timed out" >&2
	exit 1
fi

kill -CONT "$workload_pid"
wait "$workload_pid"
workload_pid=""
kill -INT "$monitor_pid"
set +e
wait "$monitor_pid"
monitor_status=$?
set -e
monitor_pid=""
if [[ $monitor_status -ne 0 ]] || ! grep -q ' PASS$' "$monitor_log"; then
	echo "FAIL: deterministic counter mismatch; inspect $monitor_log" >&2
	exit 1
fi
grep 'VERIFICATION ' "$monitor_log"
echo "PASS: one worker per allowed CPU updated exact per-CPU counts."

