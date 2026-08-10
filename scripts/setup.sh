#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
packages=(clang llvm gcc make libbpf-dev libelf-dev zlib1g-dev pkg-config bpftool linux-tools-common)
missing=()

for command in clang gcc make pkg-config bpftool; do
	if ! command -v "$command" >/dev/null 2>&1; then
		missing+=("$command")
	fi
done
if ! pkg-config --exists libbpf 2>/dev/null; then
	missing+=("libbpf-dev")
fi

echo "Project: $project_root"
echo "Kernel: $(uname -r)"
if [[ -r /sys/kernel/btf/vmlinux ]]; then
	echo "Kernel BTF: available at /sys/kernel/btf/vmlinux"
else
	echo "Kernel BTF: MISSING"
fi

if ((${#missing[@]} == 0)); then
	echo "Core build dependencies are already available."
else
	echo "Missing commands/packages: ${missing[*]}"
fi

if [[ ${1:-} == --install ]]; then
	echo "Installing Ubuntu/Debian dependencies with apt..."
	sudo apt-get update
	sudo apt-get install -y "${packages[@]}"
elif [[ $# -gt 0 ]]; then
	echo "Usage: $0 [--install]" >&2
	exit 2
else
	echo "No packages changed. Run '$0 --install' to install the full dependency set."
fi

