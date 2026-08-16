#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "monitor.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cpu_stats);
} stats SEC(".maps");

/* Isolated from system statistics so deterministic tests cannot be polluted. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct verification_stats);
} verification SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct monitor_config);
} cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* One independent rate window for each (process, operation, logical CPU). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct rate_key);
	__type(value, struct rate_state);
} rate_state SEC(".maps");

/*
 * Correlation only, not aggregation. A normal LRU hash is required because a
 * task can enter on one CPU and exit after migrating to another CPU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, __u32); /* kernel thread ID */
	__type(value, struct syscall_snapshot);
} active_syscalls SEC(".maps");

static __always_inline struct cpu_stats *get_stats(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline const struct monitor_config *get_config(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&cfg_map, &key);
}

static __always_inline __u32 current_tgid_in_configured_ns(
	const struct monitor_config *cfg)
{
	struct bpf_pidns_info ns = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (cfg && cfg->pidns_ino &&
	    bpf_get_ns_current_pid_tgid(cfg->pidns_dev, cfg->pidns_ino, &ns,
					sizeof(ns)) == 0 && ns.tgid)
		return ns.tgid;
	return pid_tgid >> 32;
}

static __always_inline bool should_emit(struct cpu_stats *cpu_stats,
					const struct monitor_config *cfg, __u32 type)
{
	__u32 rate;

	if (!cfg || !cfg->emit_events)
		return false;
	if (!(cfg->event_mask & MONITOR_EVENT_BIT(type)))
		return false;
	rate = cfg->sample_rate;
	if (rate <= 1)
		return true;
	cpu_stats->sample_sequence++;
	return cpu_stats->sample_sequence % rate == 0;
}

static __always_inline void fill_header(struct monitor_event_header *header,
					const struct monitor_config *cfg, __u32 type)
{
	struct bpf_pidns_info ns = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	header->timestamp_ns = bpf_ktime_get_ns();
	header->pid = (__u32)pid_tgid;
	header->tgid = pid_tgid >> 32;
	header->cpu = bpf_get_smp_processor_id();
	header->event_type = type;
	if (cfg && cfg->pidns_ino &&
	    bpf_get_ns_current_pid_tgid(cfg->pidns_dev, cfg->pidns_ino, &ns,
					sizeof(ns)) == 0 && ns.tgid) {
		header->pid = ns.pid;
		header->tgid = ns.tgid;
	}
	bpf_get_current_comm(header->comm, sizeof(header->comm));
}

static __always_inline struct monitor_event *reserve_event(struct cpu_stats *cpu_stats,
							    const struct monitor_config *cfg,
							    __u32 type)
{
	struct monitor_event *event;

	if (!should_emit(cpu_stats, cfg, type))
		return NULL;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		cpu_stats->ringbuf_dropped_count++;
		return NULL;
	}
	__builtin_memset(event, 0, sizeof(*event));
	fill_header(&event->header, cfg, type);
	return event;
}

static __always_inline bool rate_should_reject(const struct monitor_config *cfg,
					       __u32 tgid, __u32 *current_count)
{
	struct rate_state initial = {};
	struct rate_state *state;
	struct rate_key key = {
		.tgid = tgid,
		.operation = MONITOR_RATE_OPERATION_FILE_OPEN,
	};
	__u64 now = bpf_ktime_get_ns();

	state = bpf_map_lookup_elem(&rate_state, &key);
	if (!state) {
		initial.window_start_ns = now;
		initial.count = 1;
		bpf_map_update_elem(&rate_state, &key, &initial, BPF_NOEXIST);
		return false;
	}
	if (now - state->window_start_ns >= MONITOR_RATE_WINDOW_NS) {
		state->window_start_ns = now;
		state->count = 1;
		return false;
	}
	if (state->count < cfg->rate_limit_threshold) {
		state->count++;
		return false;
	}
	*current_count = state->count;
	return true;
}

static __always_inline void record_rate_rejection(const struct monitor_config *cfg,
						    __u32 current_count)
{
	struct rate_limit_event_data *rate_data;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;

	cpu_stats = get_stats();
	if (!cpu_stats)
		return;
	cpu_stats->rate_limited_count++;
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_RATE_LIMIT);
	if (!event)
		return;
	rate_data = &event->data.rate_limit;
	rate_data->threshold = cfg->rate_limit_threshold;
	rate_data->count = current_count;
	rate_data->error = -11;
	bpf_ringbuf_submit(event, 0);
}

static __always_inline bool paths_equal(const char left[MONITOR_PATH_LEN],
					const char right[MONITOR_PATH_LEN])
{
	int i;

#pragma unroll
	for (i = 0; i < MONITOR_PATH_LEN; i++) {
		if (left[i] != right[i])
			return false;
		if (left[i] == '\0')
			return true;
	}
	return false;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	const struct monitor_config *cfg;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;
	struct verification_stats *verify;
	struct syscall_snapshot snapshot = {};
	__u64 pid_tgid;
	__u32 tid;
	__u32 key = 0;

	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->syscall_enter_count++;

	cfg = get_config();
	pid_tgid = bpf_get_current_pid_tgid();
	tid = (__u32)pid_tgid;
	if (cfg && cfg->verification_tgid &&
	    cfg->verification_tgid == current_tgid_in_configured_ns(cfg) &&
	    cfg->verification_syscall == (__u32)ctx->id) {
		verify = bpf_map_lookup_elem(&verification, &key);
		if (verify)
			verify->count++;
	}

	if (cfg && cfg->emit_events &&
	    (cfg->event_mask &
	     (MONITOR_EVENT_BIT(MONITOR_EVENT_SYSCALL_ENTER) |
	      MONITOR_EVENT_BIT(MONITOR_EVENT_SYSCALL_EXIT)))) {
		snapshot.id = ctx->id;
		/* Keep tracepoint-context accesses at verifier-known constant offsets. */
		snapshot.args[0] = ctx->args[0];
		snapshot.args[1] = ctx->args[1];
		snapshot.args[2] = ctx->args[2];
		snapshot.args[3] = ctx->args[3];
		snapshot.args[4] = ctx->args[4];
		snapshot.args[5] = ctx->args[5];
		if (cfg->event_mask & MONITOR_EVENT_BIT(MONITOR_EVENT_SYSCALL_EXIT))
			bpf_map_update_elem(&active_syscalls, &tid, &snapshot, BPF_ANY);
	}

	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_SYSCALL_ENTER);
	if (!event)
		return 0;
	event->data.syscall.id = snapshot.id;
	event->data.syscall.args[0] = snapshot.args[0];
	event->data.syscall.args[1] = snapshot.args[1];
	event->data.syscall.args[2] = snapshot.args[2];
	event->data.syscall.args[3] = snapshot.args[3];
	event->data.syscall.args[4] = snapshot.args[4];
	event->data.syscall.args[5] = snapshot.args[5];
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	const struct monitor_config *cfg;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;
	struct syscall_snapshot *snapshot;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->syscall_exit_count++;
	cfg = get_config();
	snapshot = bpf_map_lookup_elem(&active_syscalls, &tid);
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_SYSCALL_EXIT);
	if (!event) {
		if (snapshot)
			bpf_map_delete_elem(&active_syscalls, &tid);
		return 0;
	}
	/* This kernel's BTF tracepoint context exposes id directly, so no stale map. */
	event->data.syscall.id = ctx->id;
	event->data.syscall.ret = ctx->ret;
	if (snapshot && snapshot->id == ctx->id) {
		event->data.syscall.args[0] = snapshot->args[0];
		event->data.syscall.args[1] = snapshot->args[1];
		event->data.syscall.args[2] = snapshot->args[2];
		event->data.syscall.args[3] = snapshot->args[3];
		event->data.syscall.args[4] = snapshot->args[4];
		event->data.syscall.args[5] = snapshot->args[5];
	}
	if (snapshot)
		bpf_map_delete_elem(&active_syscalls, &tid);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	const struct monitor_config *cfg;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;

	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->context_switch_count++;
	cfg = get_config();
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_SCHED_SWITCH);
	if (!event)
		return 0;
	event->data.sched.prev_pid = ctx->prev_pid;
	event->data.sched.next_pid = ctx->next_pid;
	event->data.sched.prev_state = ctx->prev_state;
	/* Use a helper so LLVM cannot synthesize a directly-dereferenced ctx copy. */
	bpf_probe_read_kernel(event->data.sched.prev_comm,
			      sizeof(event->data.sched.prev_comm), ctx->prev_comm);
	bpf_probe_read_kernel(event->data.sched.next_comm,
			      sizeof(event->data.sched.next_comm), ctx->next_comm);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* The BTF signature of handle_mm_fault exposes the fault address as arg #2. */
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(page_fault, struct vm_area_struct *vma, unsigned long address,
	       unsigned int flags, struct pt_regs *regs)
{
	const struct monitor_config *cfg;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;

	(void)ctx;
	(void)vma;
	(void)flags;
	(void)regs;
	cfg = get_config();
	if (cfg && cfg->bonus_target_tgid &&
	    cfg->bonus_target_tgid != current_tgid_in_configured_ns(cfg))
		return 0;
	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->page_fault_count++;
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_PAGE_FAULT);
	if (!event)
		return 0;
	event->data.page_fault.address = address;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* Optional, read-only, BTF-typed tracing demonstration. */
SEC("fentry/__x64_sys_openat")
int BPF_PROG(openat_enter, const struct pt_regs *regs)
{
	const struct monitor_config *cfg;
	const char *filename;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;
	long dfd;
	long flags;

	(void)ctx;
	cfg = get_config();
	if (cfg && cfg->bonus_target_tgid &&
	    cfg->bonus_target_tgid != current_tgid_in_configured_ns(cfg))
		return 0;
	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->fentry_count++;
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_FENTRY);
	if (!event)
		return 0;
	/* openat(2) defines dfd as int; sign-extend AT_FDCWD (-100). */
	dfd = (__s32)BPF_CORE_READ(regs, di);
	filename = (const char *)BPF_CORE_READ(regs, si);
	flags = BPF_CORE_READ(regs, dx);
	event->data.tracing.arg0 = dfd;
	event->data.tracing.arg1 = flags;
	bpf_probe_read_user_str(event->data.tracing.path,
				sizeof(event->data.tracing.path), filename);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("fexit/__x64_sys_openat")
int BPF_PROG(openat_exit, const struct pt_regs *regs, long ret)
{
	const struct monitor_config *cfg;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;

	(void)ctx;
	(void)regs;
	cfg = get_config();
	if (cfg && cfg->bonus_target_tgid &&
	    cfg->bonus_target_tgid != current_tgid_in_configured_ns(cfg))
		return 0;
	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->fexit_count++;
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_FEXIT);
	if (!event)
		return 0;
	event->data.tracing.ret = ret;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/*
 * Optional enforcement. file_open is an LSM hook whose return value is
 * authoritative; unlike a tracepoint return, -EAGAIN really reaches openat(2).
 */
SEC("lsm/file_open")
int BPF_PROG(limit_file_open, struct file *file, int ret)
{
	const struct monitor_config *cfg;
	__u64 inode;
	__u32 current_count = 0;
	__u32 current_tgid;

	(void)ctx;
	if (ret)
		return ret;
	cfg = get_config();
	if (!cfg || !cfg->rate_limit_enabled || !cfg->rate_limit_threshold)
		return 0;
	current_tgid = current_tgid_in_configured_ns(cfg);
	if (current_tgid != cfg->rate_limit_tgid)
		return 0;
	inode = BPF_CORE_READ(file, f_inode, i_ino);
	if (inode != cfg->rate_limit_inode)
		return 0;

	if (!rate_should_reject(cfg, current_tgid, &current_count))
		return 0;
	record_rate_rejection(cfg, current_count);
	return -11;
}

/*
 * Fallback for kernels without active BPF LSM. The loader enables this only
 * after /sys/kernel/debug/error_injection/list explicitly confirms
 * __x64_sys_openat is error-injectable.
 */
SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(limit_openat, const struct pt_regs *regs)
{
	char path[MONITOR_PATH_LEN] = {};
	const struct monitor_config *cfg;
	const char *filename;
	__u32 current_count = 0;
	__u32 current_tgid;
	long length;

	cfg = get_config();
	if (!cfg || !cfg->rate_limit_enabled || !cfg->rate_limit_threshold)
		return 0;
	current_tgid = current_tgid_in_configured_ns(cfg);
	if (current_tgid != cfg->rate_limit_tgid)
		return 0;
	filename = (const char *)BPF_CORE_READ(regs, si);
	length = bpf_probe_read_user_str(path, sizeof(path), filename);
	if (length <= 0 || length > MONITOR_PATH_LEN)
		return 0;
	if (!paths_equal(path, cfg->rate_limit_path))
		return 0;
	if (!rate_should_reject(cfg, current_tgid, &current_count))
		return 0;
	record_rate_rejection(cfg, current_count);
	bpf_override_return(ctx, -11); /* EAGAIN, only on the whitelisted target. */
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
