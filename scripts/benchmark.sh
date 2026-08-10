#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
monitor_log="$artifact_dir/benchmark_monitor.log"

if ! command -v perf >/dev/null 2>&1; then
	echo "perf is missing. On Ubuntu install the matching linux-tools package." >&2
	exit 77
fi
if [[ $EUID -ne 0 ]]; then
	echo "Run both comparable modes with: sudo ./scripts/benchmark.sh" >&2
	exit 77
fi
mkdir -p "$artifact_dir"
make -C "$project_root" all tests >/dev/null

echo "Benchmarking baseline..."
perf stat -o "$artifact_dir/benchmark_baseline.txt" \
	-- "$project_root/build/syscall_stress" --iterations 1000000 \
	>"$artifact_dir/benchmark_baseline_workload.txt"

echo "Benchmarking with mandatory BPF monitor loaded..."
"$project_root/build/monitor" --no-clear --duration 60 >"$monitor_log" 2>&1 &
monitor_pid=$!
trap 'kill -INT "$monitor_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 200); do
	grep -q 'Hooks attached:' "$monitor_log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "Monitor failed; inspect $monitor_log" >&2
		exit 1
	fi
	sleep 0.05
done
perf stat -o "$artifact_dir/benchmark_monitor_loaded.txt" \
	-- "$project_root/build/syscall_stress" --iterations 1000000 \
	>"$artifact_dir/benchmark_monitor_workload.txt"
kill -INT "$monitor_pid"
wait "$monitor_pid"
trap - EXIT
echo "Actual measurements saved under $artifact_dir (no values were synthesized)."

