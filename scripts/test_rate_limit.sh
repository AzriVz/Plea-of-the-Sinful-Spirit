#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
target=""
workload_log="$artifact_dir/rate_limit_workload.log"
monitor_log="$artifact_dir/rate_limit_monitor.log"
demo_log="$artifact_dir/rate_limit_demo.log"
program_log="$artifact_dir/rate_limit_bpftool_prog_list.log"
map_log="$artifact_dir/rate_limit_bpftool_map_list.log"
map_dump_log="$artifact_dir/rate_limit_bpftool_map_dump.log"
threshold=10
workload_pid=""
monitor_pid=""

cleanup() {
	if [[ -n $workload_pid ]]; then kill -CONT "$workload_pid" 2>/dev/null || true; fi
	if [[ -n $monitor_pid ]]; then kill -INT "$monitor_pid" 2>/dev/null || true; fi
	if [[ -n $target ]]; then rm -f "$target"; fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
	echo "Run this enforcement test with: sudo ./scripts/test_rate_limit.sh" >&2
	exit 77
fi
mkdir -p "$artifact_dir"
lsm_available=false
override_available=false
override_status="target-absent"
lsm_file=/sys/kernel/security/lsm
if [[ -r $lsm_file ]] && tr ',' '\n' <"$lsm_file" | grep -qx bpf; then
	lsm_available=true
fi
error_injection_list=""
for candidate in /sys/kernel/debug/error_injection/list \
	/sys/kernel/debug/tracing/error_injection/list; do
	if [[ -e $candidate ]]; then
		error_injection_list=$candidate
		break
	fi
done
if [[ -z $error_injection_list ]]; then
	override_status="list-absent"
elif [[ ! -r $error_injection_list ]]; then
	override_status="list-unreadable"
elif grep -qw '__x64_sys_openat' "$error_injection_list"; then
	override_available=true
	override_status="target-present"
fi
if [[ $lsm_available == false && $override_available == false ]]; then
	{
		echo "SKIP: no supported kernel enforcement hook is available."
		printf 'Active LSMs: '
		if [[ -r $lsm_file ]]; then
			cat "$lsm_file"
			echo
		else
			echo "unavailable ($lsm_file is absent or unreadable)"
		fi
		printf 'BPF LSM active: %s\n' "$lsm_available"
		printf '__x64_sys_openat error-injectable: %s\n' "$override_available"
		printf 'Error-injection capability: %s\n' "$override_status"
		printf 'Error-injection list: %s\n' "${error_injection_list:-not-found}"
		echo "Neither an authoritative LSM return nor a whitelisted bpf_override_return target can be used."
	} | tee "$demo_log"
	exit 77
fi
target=$(mktemp /tmp/plea_rate_limit_target.XXXXXX)
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
	grep -Eq 'LSM file_open|override __x64_sys_openat' "$monitor_log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "Rate limiter failed to attach; inspect $monitor_log" >&2
		exit 1
	fi
	sleep 0.05
done
if ! grep -Eq 'LSM file_open|override __x64_sys_openat' "$monitor_log"; then
	echo "Rate limiter attach synchronization timed out; inspect $monitor_log" >&2
	exit 1
fi
bpftool prog list >"$program_log" 2>&1
bpftool map list >"$map_log" 2>&1
kill -CONT "$workload_pid"
wait "$workload_pid"
workload_pid=""
bpftool map dump name rate_state >"$map_dump_log" 2>&1
kill -INT "$monitor_pid"
wait "$monitor_pid"
monitor_pid=""
grep -q '^PASS$' "$workload_log"
cat "$workload_log"
{
	echo "Rate-limit workload:"
	cat "$workload_log"
	echo
	echo "Monitor:"
	cat "$monitor_log"
	echo
	echo "Loaded programs while enforcement was attached:"
	cat "$program_log"
	echo
	echo "Loaded maps while enforcement was attached:"
	cat "$map_log"
	echo
	echo "Per-CPU rate-state map after the workload:"
	cat "$map_dump_log"
} >"$demo_log"
echo "Evidence: $demo_log"
