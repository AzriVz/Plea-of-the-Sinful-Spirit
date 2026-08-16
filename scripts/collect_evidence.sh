#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
monitor_log="$artifact_dir/evidence_monitor.log"
monitor_pid=""

cleanup() {
	if [[ -n $monitor_pid ]]; then
		kill -INT "$monitor_pid" 2>/dev/null || true
		wait "$monitor_pid" 2>/dev/null || true
	fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
	echo "Full feature/prog/map evidence requires root. Run: sudo ./scripts/collect_evidence.sh" >&2
	exit 77
fi
mkdir -p "$artifact_dir"
make -C "$project_root" all tests >/dev/null

"$project_root/build/monitor" --duration 15 --no-clear >"$monitor_log" 2>&1 &
monitor_pid=$!
for _ in $(seq 1 200); do
	grep -q 'Hooks attached:' "$monitor_log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "Monitor failed; inspect $monitor_log" >&2
		exit 1
	fi
	sleep 0.05
done
if ! grep -q 'Hooks attached:' "$monitor_log"; then
	echo "Monitor attach synchronization timed out" >&2
	exit 1
fi

uname -a >"$artifact_dir/uname.txt"
ls -lh /sys/kernel/btf/vmlinux >"$artifact_dir/btf_vmlinux.txt"
bpftool version >"$artifact_dir/bpftool_version.txt"
clang --version >"$artifact_dir/clang_version.txt"
bpftool feature probe >"$artifact_dir/bpftool_feature_probe.txt" 2>&1
bpftool prog list >"$artifact_dir/bpftool_prog_list.txt" 2>&1
bpftool map list >"$artifact_dir/bpftool_map_list.txt" 2>&1
bpftool map show >"$artifact_dir/bpftool_map_show.txt" 2>&1
bpftool map dump name stats >"$artifact_dir/bpftool_map_dump_stats.txt" 2>&1
bpftool map dump name cfg_map >"$artifact_dir/bpftool_map_dump_config.txt" 2>&1
kill -INT "$monitor_pid"
wait "$monitor_pid"
monitor_pid=""
printf 'Evidence collected at %s\n' "$artifact_dir"
