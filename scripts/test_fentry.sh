#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
monitor_log="$artifact_dir/fentry_demo.log"
workload_log="$artifact_dir/fentry_workload.log"
target=""
iterations=100
workload_pid=""
monitor_pid=""

cleanup() {
	if [[ -n $workload_pid ]]; then kill -CONT "$workload_pid" 2>/dev/null || true; fi
	if [[ -n $monitor_pid ]]; then kill -INT "$monitor_pid" 2>/dev/null || true; fi
	if [[ -n $target ]]; then rm -f "$target"; fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
	echo "Run this BTF tracing test with: sudo ./scripts/test_fentry.sh" >&2
	exit 77
fi
mkdir -p "$artifact_dir"
target=$(mktemp /tmp/plea_fentry_target.XXXXXX)
make -C "$project_root" all tests >/dev/null

"$project_root/build/fentry_test" --pause --iterations "$iterations" "$target" \
	>"$workload_log" 2>&1 &
workload_pid=$!
for _ in $(seq 1 200); do
	state=$(awk '/^State:/ {print $2}' "/proc/$workload_pid/status" 2>/dev/null || true)
	[[ $state == T ]] && break
	sleep 0.05
done
if [[ ${state:-} != T ]]; then
	echo "FAIL: fentry workload did not reach its SIGSTOP point" >&2
	exit 1
fi

"$project_root/build/monitor" --fentry-demo --sample 1 --no-clear \
	--target-pid "$workload_pid" >"$monitor_log" 2>&1 &
monitor_pid=$!
for _ in $(seq 1 200); do
	grep -q 'fentry/fexit openat' "$monitor_log" 2>/dev/null && break
	if ! kill -0 "$monitor_pid" 2>/dev/null; then
		echo "FAIL: fentry/fexit monitor exited before attach; inspect $monitor_log" >&2
		wait "$monitor_pid" 2>/dev/null || true
		exit 1
	fi
	sleep 0.05
done
if ! grep -q 'fentry/fexit openat' "$monitor_log"; then
	echo "FAIL: fentry/fexit attach synchronization timed out" >&2
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
if [[ $monitor_status -ne 0 ]]; then
	echo "FAIL: fentry monitor returned $monitor_status; inspect $monitor_log" >&2
	exit 1
fi

enter_count=$(grep -c ' fentry openat ' "$monitor_log" || true)
exit_count=$(grep -c ' fexit openat ' "$monitor_log" || true)
path_count=$(grep -Fc "path=$target" "$monitor_log" || true)
if [[ $enter_count -ne $iterations || $exit_count -ne $iterations ||
	$path_count -ne $iterations ]]; then
	echo "FAIL: expected $iterations enter/exit/path records, got " \
		"enter=$enter_count exit=$exit_count path=$path_count" >&2
	exit 1
fi
if ! grep -Eq '^EVENT ts=[0-9]+ cpu=[0-9]+ pid=[0-9]+ tgid=[0-9]+ comm=fentry_test fentry openat dfd=-?[0-9]+ flags=(0|0x[0-9a-f]+) path=' \
	"$monitor_log" ||
	! grep -Eq '^EVENT ts=[0-9]+ cpu=[0-9]+ pid=[0-9]+ tgid=[0-9]+ comm=fentry_test fexit openat ret=-?[0-9]+' \
	"$monitor_log"; then
	echo "FAIL: fentry/fexit metadata, arguments, or return value is incomplete" >&2
	exit 1
fi
grep -q ' PASS$' "$workload_log"
cat "$workload_log"
echo "FENTRY expected=$iterations observed=$enter_count"
echo "FEXIT expected=$iterations observed=$exit_count"
echo "PASS: typed arguments, user pathname, and return values captured."
