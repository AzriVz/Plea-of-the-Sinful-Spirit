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

static __always_inline bool should_emit(struct cpu_stats *cpu_stats,
					const struct monitor_config *cfg)
{
	__u32 rate;

	if (!cfg || !cfg->emit_events)
		return false;
	rate = cfg->sample_rate;
	if (rate <= 1)
		return true;
	cpu_stats->sample_sequence++;
	return cpu_stats->sample_sequence % rate == 0;
}

static __always_inline void fill_header(struct monitor_event_header *header, __u32 type)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	header->timestamp_ns = bpf_ktime_get_ns();
	header->pid = (__u32)pid_tgid;
	header->tgid = pid_tgid >> 32;
	header->cpu = bpf_get_smp_processor_id();
	header->event_type = type;
	bpf_get_current_comm(header->comm, sizeof(header->comm));
}

static __always_inline struct monitor_event *reserve_event(struct cpu_stats *cpu_stats,
							    const struct monitor_config *cfg,
							    __u32 type)
{
	struct monitor_event *event;

	if (!should_emit(cpu_stats, cfg))
		return NULL;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		cpu_stats->ringbuf_dropped_count++;
		return NULL;
	}
	__builtin_memset(event, 0, sizeof(*event));
	fill_header(&event->header, type);
	return event;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	const struct monitor_config *cfg;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;
	__u64 pid_tgid;
	int i;

	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->syscall_enter_count++;

	cfg = get_config();
	pid_tgid = bpf_get_current_pid_tgid();
	if (cfg && cfg->verification_tgid &&
	    cfg->verification_tgid == (__u32)(pid_tgid >> 32) &&
	    cfg->verification_syscall == (__u32)ctx->id)
		cpu_stats->verification_count++;

	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_SYSCALL_ENTER);
	if (!event)
		return 0;
	event->data.syscall.id = ctx->id;
#pragma unroll
	for (i = 0; i < MONITOR_MAX_SYSCALL_ARGS; i++)
		event->data.syscall.args[i] = ctx->args[i];
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	const struct monitor_config *cfg;
	struct monitor_event *event;
	struct cpu_stats *cpu_stats;

	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->syscall_exit_count++;
	cfg = get_config();
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_SYSCALL_EXIT);
	if (!event)
		return 0;
	/* This kernel's BTF tracepoint context exposes id directly, so no stale map. */
	event->data.syscall.id = ctx->id;
	event->data.syscall.ret = ctx->ret;
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
	__builtin_memcpy(event->data.sched.prev_comm, ctx->prev_comm,
			 sizeof(event->data.sched.prev_comm));
	__builtin_memcpy(event->data.sched.next_comm, ctx->next_comm,
			 sizeof(event->data.sched.next_comm));
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* BTF ID 121855 on the inspected kernel: the address is the second argument. */
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
	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->page_fault_count++;
	cfg = get_config();
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
	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->fentry_count++;
	cfg = get_config();
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_FENTRY);
	if (!event)
		return 0;
	dfd = BPF_CORE_READ(regs, di);
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
	cpu_stats = get_stats();
	if (!cpu_stats)
		return 0;
	cpu_stats->fexit_count++;
	cfg = get_config();
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
	struct rate_state initial = {};
	struct rate_limit_event_data *rate_data;
	struct monitor_event *event;
	struct rate_state *state;
	struct cpu_stats *cpu_stats;
	struct rate_key key = {};
	__u64 pid_tgid;
	__u64 now;
	__u64 inode;

	(void)ctx;
	if (ret)
		return ret;
	cfg = get_config();
	if (!cfg || !cfg->rate_limit_enabled || !cfg->rate_limit_threshold)
		return 0;
	pid_tgid = bpf_get_current_pid_tgid();
	if ((__u32)(pid_tgid >> 32) != cfg->rate_limit_tgid)
		return 0;
	inode = BPF_CORE_READ(file, f_inode, i_ino);
	if (inode != cfg->rate_limit_inode)
		return 0;

	key.tgid = pid_tgid >> 32;
	key.operation = MONITOR_RATE_OPERATION_FILE_OPEN;
	now = bpf_ktime_get_ns();
	state = bpf_map_lookup_elem(&rate_state, &key);
	if (!state) {
		initial.window_start_ns = now;
		initial.count = 1;
		bpf_map_update_elem(&rate_state, &key, &initial, BPF_NOEXIST);
		return 0;
	}
	if (now - state->window_start_ns >= MONITOR_RATE_WINDOW_NS) {
		state->window_start_ns = now;
		state->count = 1;
		return 0;
	}
	if (state->count < cfg->rate_limit_threshold) {
		state->count++;
		return 0;
	}

	cpu_stats = get_stats();
	if (!cpu_stats)
		return -11; /* EAGAIN */
	cpu_stats->rate_limited_count++;
	event = reserve_event(cpu_stats, cfg, MONITOR_EVENT_RATE_LIMIT);
	if (event) {
		rate_data = &event->data.rate_limit;
		rate_data->threshold = cfg->rate_limit_threshold;
		rate_data->count = state->count;
		rate_data->error = -11;
		bpf_ringbuf_submit(event, 0);
	}
	return -11;
}

char LICENSE[] SEC("license") = "GPL";
