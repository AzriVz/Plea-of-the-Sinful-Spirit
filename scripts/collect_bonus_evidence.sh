#!/usr/bin/env bash
set -uo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
capability_log="$artifact_dir/bonus_capabilities.log"
summary_log="$artifact_dir/bonus_test_summary.log"
overall_status=0
inventory_pid=""

cleanup() {
	if [[ -n $inventory_pid ]]; then
		kill -INT "$inventory_pid" 2>/dev/null || true
	fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
	echo "Run full bonus evidence collection with: sudo ./scripts/collect_bonus_evidence.sh" >&2
	exit 77
fi
mkdir -p "$artifact_dir"
make -C "$project_root" all tests >/dev/null || exit 1

{
	date --iso-8601=seconds
	uname -a
	bpftool version
	bpftool feature probe
	clang --version
	ls -lh /sys/kernel/btf/vmlinux
	printf 'Active LSMs: '
	if [[ -r /sys/kernel/security/lsm ]]; then
		cat /sys/kernel/security/lsm
		echo
	else
		echo "unavailable (securityfs is absent or unreadable)"
	fi
	echo "BTF targets:"
	bpftool btf dump file /sys/kernel/btf/vmlinux format raw |
		grep -E "FUNC '(handle_mm_fault|__x64_sys_openat)'"
	echo "Error-injectable functions (informational):"
	error_injection_list=""
	for candidate in /sys/kernel/debug/error_injection/list \
		/sys/kernel/debug/tracing/error_injection/list; do
		if [[ -e $candidate ]]; then
			error_injection_list=$candidate
			break
		fi
	done
	if [[ -z $error_injection_list ]]; then
		echo "list absent"
	elif [[ ! -r $error_injection_list ]]; then
		echo "list unreadable"
	else
		echo "list: $error_injection_list"
		if grep -w '__x64_sys_openat' "$error_injection_list"; then
			true
		else
			echo "__x64_sys_openat: absent"
		fi
	fi
} >"$capability_log" 2>&1

: >"$summary_log"
run_test() {
	local label=$1
	local script=$2
	local status

	echo "[$label]" | tee -a "$summary_log"
	"$script" 2>&1 | tee -a "$summary_log"
	status=${PIPESTATUS[0]}
	echo "status=$status" | tee -a "$summary_log"
	echo | tee -a "$summary_log"
	if [[ $status -ne 0 && $status -ne 77 ]]; then
		overall_status=1
	fi
}

run_test page_fault "$project_root/scripts/test_page_fault.sh"
run_test race "$project_root/scripts/test_race.sh"
run_test fentry "$project_root/scripts/test_fentry.sh"
run_test rate_limit "$project_root/scripts/test_rate_limit.sh"

"$project_root/build/monitor" --page-faults --fentry --duration 5 --no-clear \
	>"$artifact_dir/bonus_inventory_monitor.log" 2>&1 &
inventory_pid=$!
for _ in $(seq 1 200); do
	grep -q 'Hooks attached:' "$artifact_dir/bonus_inventory_monitor.log" 2>/dev/null && break
	if ! kill -0 "$inventory_pid" 2>/dev/null; then break; fi
	sleep 0.05
done
if grep -q 'Hooks attached:' "$artifact_dir/bonus_inventory_monitor.log"; then
	bpftool prog list >"$artifact_dir/bpftool_prog_list.log" 2>&1
	bpftool map list >"$artifact_dir/bpftool_map_list.log" 2>&1
	bpftool map dump name stats >"$artifact_dir/bpftool_map_dump_stats.log" 2>&1
	bpftool map dump name cfg_map >"$artifact_dir/bpftool_map_dump_config.log" 2>&1
	kill -INT "$inventory_pid" 2>/dev/null || true
	wait "$inventory_pid" 2>/dev/null || true
	inventory_pid=""
else
	echo "Combined bonus inventory monitor failed to attach." | tee -a "$summary_log"
	wait "$inventory_pid" 2>/dev/null || true
	inventory_pid=""
	overall_status=1
fi

echo "Bonus evidence saved under $artifact_dir"
exit "$overall_status"
