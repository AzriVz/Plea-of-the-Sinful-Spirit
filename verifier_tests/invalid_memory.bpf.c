#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Compiles to bytecode, but the verifier must reject scalar-as-pointer access. */
SEC("tracepoint/raw_syscalls/sys_enter")
int invalid_memory(void *ctx)
{
	volatile __u64 *unsafe = (volatile __u64 *)0xdeadbeefULL;

	(void)ctx;
	return *unsafe;
}

char LICENSE[] SEC("license") = "GPL";

