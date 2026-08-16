#ifndef PLEA_MONITOR_H
#define PLEA_MONITOR_H

/* vmlinux.h already provides kernel integer types for the BPF translation unit. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define MONITOR_COMM_LEN 16
#define MONITOR_PATH_LEN 64
#define MONITOR_MAX_SYSCALL_ARGS 6

enum monitor_event_type {
	MONITOR_EVENT_SYSCALL_ENTER = 1,
	MONITOR_EVENT_SYSCALL_EXIT = 2,
	MONITOR_EVENT_SCHED_SWITCH = 3,
	MONITOR_EVENT_PAGE_FAULT = 4,
	MONITOR_EVENT_FENTRY = 5,
	MONITOR_EVENT_FEXIT = 6,
	MONITOR_EVENT_RATE_LIMIT = 7,
};

struct cpu_stats {
	__u64 syscall_enter_count;
	__u64 syscall_exit_count;
	__u64 context_switch_count;
	__u64 page_fault_count;
	__u64 rate_limited_count;
	__u64 ringbuf_dropped_count;
	__u64 fentry_count;
	__u64 fexit_count;
	__u64 sample_sequence;
};

struct verification_stats {
	__u64 count;
};

struct monitor_config {
	__u32 emit_events;
	__u32 sample_rate;
	__u32 verification_tgid;
	__u32 verification_syscall;
	__u32 rate_limit_enabled;
	__u32 rate_limit_threshold;
	__u32 rate_limit_tgid;
	__u32 reserved;
	__u64 rate_limit_inode;
	__u64 event_mask;
	__u64 pidns_dev;
	__u64 pidns_ino;
	__u32 bonus_target_tgid;
	__u32 reserved2;
	char rate_limit_path[MONITOR_PATH_LEN];
};

struct monitor_event_header {
	__u64 timestamp_ns;
	__u32 pid;  /* thread ID */
	__u32 tgid; /* process ID */
	__u32 cpu;
	__u32 event_type;
	char comm[MONITOR_COMM_LEN];
};

struct syscall_event_data {
	__s64 id;
	__u64 args[MONITOR_MAX_SYSCALL_ARGS];
	__s64 ret;
};

/* Temporary entry-side state used to enrich the matching syscall-exit event. */
struct syscall_snapshot {
	__s64 id;
	__u64 args[MONITOR_MAX_SYSCALL_ARGS];
};

struct sched_event_data {
	__s32 prev_pid;
	__s32 next_pid;
	__s64 prev_state;
	char prev_comm[MONITOR_COMM_LEN];
	char next_comm[MONITOR_COMM_LEN];
};

struct page_fault_event_data {
	__u64 address;
};

struct tracing_event_data {
	__s64 arg0;
	__s64 arg1;
	__s64 ret;
	char path[MONITOR_PATH_LEN];
};

struct rate_limit_event_data {
	__u32 threshold;
	__u32 count;
	__s32 error;
	__u32 reserved;
};

struct monitor_event {
	struct monitor_event_header header;
	union {
		struct syscall_event_data syscall;
		struct sched_event_data sched;
		struct page_fault_event_data page_fault;
		struct tracing_event_data tracing;
		struct rate_limit_event_data rate_limit;
	} data;
};

struct rate_key {
	__u32 tgid;
	__u32 operation;
};

struct rate_state {
	__u64 window_start_ns;
	__u32 count;
	__u32 reserved;
};

#define MONITOR_RATE_OPERATION_FILE_OPEN 1U
#define MONITOR_RATE_WINDOW_NS 1000000000ULL
#define MONITOR_EVENT_BIT(type) (1ULL << (type))
#define MONITOR_EVENT_MASK_ALL (~0ULL)

#endif /* PLEA_MONITOR_H */
