#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$project_root/artifacts"

if [[ $EUID -ne 0 ]]; then
	echo "Full feature/prog/map evidence requires root. Run: sudo ./scripts/collect_evidence.sh" >&2
	exit 77
fi
mkdir -p "$artifact_dir"
uname -a >"$artifact_dir/uname.txt"
ls -lh /sys/kernel/btf/vmlinux >"$artifact_dir/btf_vmlinux.txt"
bpftool version >"$artifact_dir/bpftool_version.txt"
clang --version >"$artifact_dir/clang_version.txt"
bpftool feature probe >"$artifact_dir/bpftool_feature_probe.txt" 2>&1
bpftool prog list >"$artifact_dir/bpftool_prog_list.txt" 2>&1
bpftool map list >"$artifact_dir/bpftool_map_list.txt" 2>&1
bpftool map show >"$artifact_dir/bpftool_map_show.txt" 2>&1
printf 'Evidence collected at %s\n' "$artifact_dir"

