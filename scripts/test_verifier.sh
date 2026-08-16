#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"
invalid_log="$artifact_dir/verifier_reject.log"
accept_log="$artifact_dir/verifier_accept.log"
pin_path="/tmp/plea_invalid_$$"

if [[ $EUID -ne 0 ]]; then
	echo "Verifier loading requires privilege. Run: sudo make verifier-test" >&2
	exit 77
fi
if mountpoint -q /sys/fs/bpf; then
	pin_path="/sys/fs/bpf/plea_invalid_$$"
fi

mkdir -p "$artifact_dir"
make -C "$project_root" all build/invalid_memory.bpf.o >/dev/null
trap 'rm -f "$pin_path"' EXIT

echo "Attempting intentionally unsafe program load..."
set +e
bpftool -d prog load "$project_root/build/invalid_memory.bpf.o" "$pin_path" \
	type tracepoint >"$invalid_log" 2>&1
invalid_status=$?
set -e
if [[ $invalid_status -eq 0 ]]; then
	echo "FAIL: the intentionally invalid program was accepted" >&2
	exit 1
fi
if ! grep -Eqi 'invalid mem access|scalar.*(pointer|mem)|R[0-9]+.*scalar' "$invalid_log"; then
	echo "FAIL: load failed, but the log does not prove the intended memory-safety rejection" >&2
	echo "Inspect $invalid_log" >&2
	exit 1
fi
echo "PASS: unsafe scalar-derived pointer was rejected ($invalid_log)"

echo "Loading and attaching the valid baseline monitor..."
if ! "$project_root/build/monitor" --duration 2 --interval 0.5 --no-clear \
	>"$accept_log" 2>&1; then
	echo "FAIL: valid monitor did not load; inspect $accept_log" >&2
	exit 1
fi
if ! grep -q 'Hooks attached: sys_enter, sys_exit, sched_switch' "$accept_log"; then
	echo "FAIL: valid-load evidence is incomplete" >&2
	exit 1
fi
echo "PASS: valid monitor loaded, attached, sampled, and detached ($accept_log)"
