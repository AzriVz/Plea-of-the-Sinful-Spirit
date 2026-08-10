#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "monitor.h"
#include "monitor.skel.h"

struct options {
	double interval_sec;
	unsigned int sample_rate;
	unsigned int duration_sec;
	bool events;
	bool no_clear;
	bool page_faults;
	bool fentry;
	__u64 event_mask;
	const char *rate_limit_path;
	__u32 rate_limit_threshold;
	__u32 target_pid;
	__u32 verification_pid;
	__u32 verification_syscall;
	__u64 expected;
	bool expected_set;
};

static volatile sig_atomic_t exiting;

enum rate_enforcement_mode {
	RATE_ENFORCEMENT_NONE,
	RATE_ENFORCEMENT_LSM,
	RATE_ENFORCEMENT_OVERRIDE,
};

static void handle_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

static int libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"Usage: %s [OPTIONS]\n"
		"\n"
		"Live eBPF CPU activity monitor. Root/CAP_BPF privileges are required.\n"
		"\n"
		"  -i, --interval SEC       refresh interval (default: 1.0)\n"
		"  -v, --events             print sampled event metadata\n"
		"      --sample N           emit one of every N events (default: 1000)\n"
		"      --no-clear           do not clear the terminal between tables\n"
		"      --page-faults        attach kprobe/handle_mm_fault\n"
		"      --page-fault-demo    page-fault hook plus filtered detail events\n"
		"      --fentry             attach fentry/fexit to __x64_sys_openat\n"
		"      --fentry-demo        fentry/fexit plus filtered detail events\n"
		"      --rate-limit FILE    enforce per-CPU file-open rate on FILE\n"
		"      --limit N            successful opens/CPU/second (default: 100)\n"
		"      --target-pid PID     scope limiter or optional bonus demo TGID\n"
		"      --test-pid PID       count one syscall for this TGID\n"
		"      --test-syscall NR    syscall number for --test-pid\n"
		"      --expect N           compare filtered count at shutdown\n"
		"      --duration SEC       stop automatically after SEC\n"
		"  -h, --help               show this help\n",
		program);
}

static int parse_u32(const char *text, __u32 *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 0);
	if (errno || !end || *end != '\0' || parsed > UINT32_MAX)
		return -EINVAL;
	*value = (__u32)parsed;
	return 0;
}

static int parse_u64(const char *text, __u64 *value)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || !end || *end != '\0')
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int parse_interval(const char *text, double *value)
{
	char *end = NULL;
	double parsed;

	errno = 0;
	parsed = strtod(text, &end);
	if (errno || !end || *end != '\0' || parsed < 0.05 || parsed > 3600.0)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int parse_options(int argc, char **argv, struct options *opts)
{
	enum {
		OPT_SAMPLE = 1000,
		OPT_NO_CLEAR,
		OPT_PAGE_FAULTS,
		OPT_PAGE_FAULT_DEMO,
		OPT_FENTRY,
		OPT_FENTRY_DEMO,
		OPT_RATE_LIMIT,
		OPT_LIMIT,
		OPT_TARGET_PID,
		OPT_TEST_PID,
		OPT_TEST_SYSCALL,
		OPT_EXPECT,
		OPT_DURATION,
	};
	static const struct option long_options[] = {
		{ "interval", required_argument, NULL, 'i' },
		{ "events", no_argument, NULL, 'v' },
		{ "sample", required_argument, NULL, OPT_SAMPLE },
		{ "no-clear", no_argument, NULL, OPT_NO_CLEAR },
		{ "page-faults", no_argument, NULL, OPT_PAGE_FAULTS },
		{ "page-fault-demo", no_argument, NULL, OPT_PAGE_FAULT_DEMO },
		{ "fentry", no_argument, NULL, OPT_FENTRY },
		{ "fentry-demo", no_argument, NULL, OPT_FENTRY_DEMO },
		{ "rate-limit", required_argument, NULL, OPT_RATE_LIMIT },
		{ "limit", required_argument, NULL, OPT_LIMIT },
		{ "target-pid", required_argument, NULL, OPT_TARGET_PID },
		{ "test-pid", required_argument, NULL, OPT_TEST_PID },
		{ "test-syscall", required_argument, NULL, OPT_TEST_SYSCALL },
		{ "expect", required_argument, NULL, OPT_EXPECT },
		{ "duration", required_argument, NULL, OPT_DURATION },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "i:vh", long_options, NULL)) != -1) {
		switch (option) {
		case 'i':
			if (parse_interval(optarg, &opts->interval_sec))
				goto invalid;
			break;
		case 'v':
			opts->events = true;
			opts->event_mask = MONITOR_EVENT_MASK_ALL;
			break;
		case 'h':
			usage(stdout, argv[0]);
			return 1;
		case OPT_SAMPLE:
			if (parse_u32(optarg, &opts->sample_rate) || !opts->sample_rate)
				goto invalid;
			break;
		case OPT_NO_CLEAR:
			opts->no_clear = true;
			break;
		case OPT_PAGE_FAULTS:
			opts->page_faults = true;
			break;
		case OPT_PAGE_FAULT_DEMO:
			opts->page_faults = true;
			opts->events = true;
			opts->event_mask |= MONITOR_EVENT_BIT(MONITOR_EVENT_PAGE_FAULT);
			break;
		case OPT_FENTRY:
			opts->fentry = true;
			break;
		case OPT_FENTRY_DEMO:
			opts->fentry = true;
			opts->events = true;
			opts->event_mask |= MONITOR_EVENT_BIT(MONITOR_EVENT_FENTRY) |
					    MONITOR_EVENT_BIT(MONITOR_EVENT_FEXIT);
			break;
		case OPT_RATE_LIMIT:
			opts->rate_limit_path = optarg;
			break;
		case OPT_LIMIT:
			if (parse_u32(optarg, &opts->rate_limit_threshold) ||
			    !opts->rate_limit_threshold)
				goto invalid;
			break;
		case OPT_TARGET_PID:
			if (parse_u32(optarg, &opts->target_pid) || !opts->target_pid)
				goto invalid;
			break;
		case OPT_TEST_PID:
			if (parse_u32(optarg, &opts->verification_pid) ||
			    !opts->verification_pid)
				goto invalid;
			break;
		case OPT_TEST_SYSCALL:
			if (parse_u32(optarg, &opts->verification_syscall))
				goto invalid;
			break;
		case OPT_EXPECT:
			if (parse_u64(optarg, &opts->expected))
				goto invalid;
			opts->expected_set = true;
			break;
		case OPT_DURATION:
			if (parse_u32(optarg, &opts->duration_sec) || !opts->duration_sec)
				goto invalid;
			break;
		default:
			return -EINVAL;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected positional argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	if (opts->rate_limit_path && !opts->target_pid) {
		fprintf(stderr, "--rate-limit requires --target-pid for safe scoping\n");
		return -EINVAL;
	}
	if (opts->expected_set && !opts->verification_pid) {
		fprintf(stderr, "--expect requires --test-pid\n");
		return -EINVAL;
	}
	if (opts->events)
		opts->no_clear = true;
	return 0;

invalid:
	fprintf(stderr, "Invalid numeric option\n");
	return -EINVAL;
}

static bool kernel_has_bpf_lsm(void)
{
	char buffer[512];
	char *save = NULL;
	char *token;
	FILE *file;

	file = fopen("/sys/kernel/security/lsm", "re");
	if (!file)
		return false;
	if (!fgets(buffer, sizeof(buffer), file)) {
		fclose(file);
		return false;
	}
	fclose(file);
	for (token = strtok_r(buffer, ",\n", &save); token;
	     token = strtok_r(NULL, ",\n", &save)) {
		if (strcmp(token, "bpf") == 0)
			return true;
	}
	return false;
}

static bool error_injection_target_available(const char *target)
{
	static const char *const list_paths[] = {
		"/sys/kernel/debug/error_injection/list",
		/* Compatibility with kernels that expose it below tracefs. */
		"/sys/kernel/debug/tracing/error_injection/list",
	};
	char line[512];
	size_t target_len = strlen(target);
	size_t path_index;

	for (path_index = 0; path_index < sizeof(list_paths) / sizeof(list_paths[0]);
	     path_index++) {
		FILE *file = fopen(list_paths[path_index], "re");

		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			char *match = strstr(line, target);

			if (!match)
				continue;
			if (match != line && !isspace((unsigned char)match[-1]))
				continue;
			if (match[target_len] != '\0' &&
			    !isspace((unsigned char)match[target_len]))
				continue;
			fclose(file);
			return true;
		}
		fclose(file);
	}
	return false;
}

static double monotonic_seconds(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec + now.tv_nsec / 1000000000.0;
}

static __u64 counter_delta(__u64 current, __u64 previous)
{
	return current >= previous ? current - previous : current;
}

static int print_table(int map_fd, int cpu_count, struct cpu_stats *previous,
		       const struct options *opts, double elapsed)
{
	struct cpu_stats *current;
	__u64 total_syscalls = 0;
	__u64 total_switches = 0;
	__u64 total_faults = 0;
	__u64 total_limited = 0;
	__u32 key = 0;
	int cpu;
	int err;

	current = calloc((size_t)cpu_count, sizeof(*current));
	if (!current)
		return -ENOMEM;
	err = bpf_map_lookup_elem(map_fd, &key, current);
	if (err) {
		err = -errno;
		free(current);
		return err;
	}
	if (!opts->no_clear)
		printf("\033[2J\033[H");
	printf("CPU    SYSCALL/s    CTX-SW/s");
	if (opts->page_faults)
		printf("    PAGEFAULT/s");
	if (opts->rate_limit_path)
		printf("    LIMITED");
	printf("\n");
	printf("---------------------------------------------------------------\n");
	for (cpu = 0; cpu < cpu_count; cpu++) {
		__u64 syscalls = counter_delta(current[cpu].syscall_enter_count,
					       previous[cpu].syscall_enter_count);
		__u64 switches = counter_delta(current[cpu].context_switch_count,
					       previous[cpu].context_switch_count);
		__u64 faults = counter_delta(current[cpu].page_fault_count,
					     previous[cpu].page_fault_count);
		__u64 limited = counter_delta(current[cpu].rate_limited_count,
					      previous[cpu].rate_limited_count);

		printf("%-6d %-12.0f %-12.0f", cpu, syscalls / elapsed,
		       switches / elapsed);
		if (opts->page_faults)
			printf(" %-13.0f", faults / elapsed);
		if (opts->rate_limit_path)
			printf(" %-10" PRIu64, (uint64_t)limited);
		printf("\n");
		total_syscalls += syscalls;
		total_switches += switches;
		total_faults += faults;
		total_limited += limited;
	}
	printf("---------------------------------------------------------------\n");
	printf("%-6s %-12.0f %-12.0f", "TOTAL", total_syscalls / elapsed,
	       total_switches / elapsed);
	if (opts->page_faults)
		printf(" %-13.0f", total_faults / elapsed);
	if (opts->rate_limit_path)
		printf(" %-10" PRIu64, (uint64_t)total_limited);
	printf("\n\nCtrl+C to stop\n");
	fflush(stdout);
	memcpy(previous, current, (size_t)cpu_count * sizeof(*current));
	free(current);
	return 0;
}

static int print_event(void *ctx, void *data, size_t size)
{
	const struct monitor_event *event = data;

	(void)ctx;
	if (size < sizeof(*event)) {
		fprintf(stderr, "Short ring-buffer record: %zu bytes\n", size);
		return 0;
	}
	printf("EVENT ts=%" PRIu64 " cpu=%u pid=%u tgid=%u comm=%.*s ",
	       (uint64_t)event->header.timestamp_ns, event->header.cpu, event->header.pid,
	       event->header.tgid, MONITOR_COMM_LEN, event->header.comm);
	switch (event->header.event_type) {
	case MONITOR_EVENT_SYSCALL_ENTER:
		printf("sys_enter id=%" PRId64
		       " args=[%#" PRIx64 ",%#" PRIx64 ",%#" PRIx64
		       ",%#" PRIx64 ",%#" PRIx64 ",%#" PRIx64 "]",
		       (int64_t)event->data.syscall.id,
		       (uint64_t)event->data.syscall.args[0],
		       (uint64_t)event->data.syscall.args[1],
		       (uint64_t)event->data.syscall.args[2],
		       (uint64_t)event->data.syscall.args[3],
		       (uint64_t)event->data.syscall.args[4],
		       (uint64_t)event->data.syscall.args[5]);
		break;
	case MONITOR_EVENT_SYSCALL_EXIT:
		printf("sys_exit id=%" PRId64 " ret=%" PRId64,
		       (int64_t)event->data.syscall.id,
		       (int64_t)event->data.syscall.ret);
		break;
	case MONITOR_EVENT_SCHED_SWITCH:
		printf("sched_switch prev=%.*s/%d state=%" PRId64
		       " next=%.*s/%d",
		       MONITOR_COMM_LEN, event->data.sched.prev_comm,
		       event->data.sched.prev_pid,
		       (int64_t)event->data.sched.prev_state,
		       MONITOR_COMM_LEN, event->data.sched.next_comm,
		       event->data.sched.next_pid);
		break;
	case MONITOR_EVENT_PAGE_FAULT:
		printf("page_fault address=%#" PRIx64,
		       (uint64_t)event->data.page_fault.address);
		break;
	case MONITOR_EVENT_FENTRY:
		printf("fentry openat dfd=%" PRId64 " flags=%#" PRIx64 " path=%.*s",
		       (int64_t)event->data.tracing.arg0,
		       (uint64_t)event->data.tracing.arg1,
		       MONITOR_PATH_LEN, event->data.tracing.path);
		break;
	case MONITOR_EVENT_FEXIT:
		printf("fexit openat ret=%" PRId64,
		       (int64_t)event->data.tracing.ret);
		break;
	case MONITOR_EVENT_RATE_LIMIT:
		printf("rate_limit count=%u threshold=%u error=%d",
		       event->data.rate_limit.count,
		       event->data.rate_limit.threshold,
		       event->data.rate_limit.error);
		break;
	default:
		printf("unknown type=%u", event->header.event_type);
	}
	printf("\n");
	return 0;
}

static int read_verification_total(int map_fd, int cpu_count, __u64 *total)
{
	struct verification_stats *values;
	__u32 key = 0;
	int cpu;

	values = calloc((size_t)cpu_count, sizeof(*values));
	if (!values)
		return -ENOMEM;
	if (bpf_map_lookup_elem(map_fd, &key, values)) {
		int err = -errno;

		free(values);
		return err;
	}
	*total = 0;
	for (cpu = 0; cpu < cpu_count; cpu++)
		*total += values[cpu].count;
	free(values);
	return 0;
}

int main(int argc, char **argv)
{
	struct options opts = {
		.interval_sec = 1.0,
		.sample_rate = 1000,
		.rate_limit_threshold = 100,
		.event_mask = 0,
	};
	struct monitor_bpf *skeleton = NULL;
	struct ring_buffer *ring = NULL;
	struct cpu_stats *previous = NULL;
	struct monitor_config cfg = {};
	struct sigaction action = {};
	struct utsname uts = {};
	struct rlimit memlock = { RLIM_INFINITY, RLIM_INFINITY };
	struct stat rate_target = {};
	enum rate_enforcement_mode rate_mode = RATE_ENFORCEMENT_NONE;
	double started;
	double last_sample;
	__u32 key = 0;
	int stats_fd = -1;
	int verification_fd = -1;
	int cpu_count;
	int err;
	int exit_code = 1;

	err = parse_options(argc, argv, &opts);
	if (err > 0)
		return 0;
	if (err) {
		usage(stderr, argv[0]);
		return 2;
	}
	if (opts.rate_limit_path) {
		if (stat(opts.rate_limit_path, &rate_target)) {
			fprintf(stderr, "Cannot stat rate-limit target %s: %s\n",
				opts.rate_limit_path, strerror(errno));
			return 2;
		}
		if (kernel_has_bpf_lsm()) {
			rate_mode = RATE_ENFORCEMENT_LSM;
		} else if (error_injection_target_available("__x64_sys_openat")) {
			rate_mode = RATE_ENFORCEMENT_OVERRIDE;
		} else {
			fprintf(stderr,
				"Rate limiting unavailable: BPF LSM is inactive and "
				"__x64_sys_openat is not listed as error-injectable (or "
				"debugfs is unreadable). No observational hook was used "
				"for fake enforcement.\n");
			return 3;
		}
		if (rate_mode == RATE_ENFORCEMENT_OVERRIDE &&
		    strlen(opts.rate_limit_path) >= MONITOR_PATH_LEN) {
			fprintf(stderr,
				"Rate-limit path is too long for the kprobe fallback "
				"(maximum %d bytes including NUL)\n",
				MONITOR_PATH_LEN);
			return 2;
		}
	}

	libbpf_set_print(libbpf_log);
	if (setrlimit(RLIMIT_MEMLOCK, &memlock) && errno != EPERM)
		fprintf(stderr, "Warning: cannot raise memlock limit: %s\n", strerror(errno));

	skeleton = monitor_bpf__open();
	if (!skeleton) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto cleanup;
	}
	bpf_program__set_autoload(skeleton->progs.page_fault, opts.page_faults);
	bpf_program__set_autoload(skeleton->progs.openat_enter, opts.fentry);
	bpf_program__set_autoload(skeleton->progs.openat_exit, opts.fentry);
	bpf_program__set_autoload(skeleton->progs.limit_file_open,
				  rate_mode == RATE_ENFORCEMENT_LSM);
	bpf_program__set_autoload(skeleton->progs.limit_openat,
				  rate_mode == RATE_ENFORCEMENT_OVERRIDE);

	err = monitor_bpf__load(skeleton);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %s (%d)\n",
			strerror(-err), err);
		goto cleanup;
	}

	cfg.emit_events = opts.events;
	cfg.sample_rate = opts.sample_rate;
	cfg.verification_tgid = opts.verification_pid;
	cfg.verification_syscall = opts.verification_syscall;
	cfg.rate_limit_enabled = opts.rate_limit_path != NULL;
	cfg.rate_limit_threshold = opts.rate_limit_threshold;
	cfg.rate_limit_tgid = opts.target_pid;
	cfg.rate_limit_inode = rate_target.st_ino;
	cfg.event_mask = opts.event_mask;
	cfg.bonus_target_tgid = opts.target_pid;
	if (opts.rate_limit_path)
		snprintf(cfg.rate_limit_path, sizeof(cfg.rate_limit_path), "%s",
			 opts.rate_limit_path);
	if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.cfg_map), &key, &cfg,
				BPF_ANY)) {
		err = -errno;
		fprintf(stderr, "Failed to configure BPF maps: %s\n", strerror(errno));
		goto cleanup;
	}

	if (opts.events) {
		ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
					print_event, NULL, NULL);
		if (!ring) {
			err = -errno;
			fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
			goto cleanup;
		}
	}
	err = monitor_bpf__attach(skeleton);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %s (%d)\n",
			strerror(-err), err);
		goto cleanup;
	}

	stats_fd = bpf_map__fd(skeleton->maps.stats);
	verification_fd = bpf_map__fd(skeleton->maps.verification);
	cpu_count = libbpf_num_possible_cpus();
	if (cpu_count <= 0) {
		fprintf(stderr, "Failed to determine possible CPU count: %d\n", cpu_count);
		goto cleanup;
	}
	previous = calloc((size_t)cpu_count, sizeof(*previous));
	if (!previous) {
		fprintf(stderr, "Out of memory for %d per-CPU values\n", cpu_count);
		goto cleanup;
	}
	if (bpf_map_lookup_elem(stats_fd, &key, previous)) {
		fprintf(stderr, "Initial per-CPU map read failed: %s\n", strerror(errno));
		goto cleanup;
	}

	action.sa_handler = handle_signal;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) {
		fprintf(stderr, "Failed to install signal handlers: %s\n", strerror(errno));
		goto cleanup;
	}
	uname(&uts);
	printf("Plea of the Sinful Spirit - eBPF CPU Monitor\n\n");
	printf("Kernel: %s\nInterval: %.2f sec\nCPUs possible: %d\n",
	       uts.release, opts.interval_sec, cpu_count);
	printf("Hooks attached: sys_enter, sys_exit, sched_switch%s%s%s%s\n",
	       opts.page_faults ? ", handle_mm_fault" : "",
	       opts.fentry ? ", fentry/fexit openat" : "",
	       rate_mode == RATE_ENFORCEMENT_LSM ? ", LSM file_open" : "",
	       rate_mode == RATE_ENFORCEMENT_OVERRIDE ?
			", override __x64_sys_openat" : "");
	if (opts.events)
		printf("Detailed events: one sample per %u matching hook events\n",
		       opts.sample_rate);
	printf("\n");
	fflush(stdout);

	started = monotonic_seconds();
	last_sample = started;
	while (!exiting) {
		double now;

		if (ring) {
			err = ring_buffer__poll(ring, 100);
			if (err < 0 && err != -EINTR) {
				fprintf(stderr, "Ring-buffer poll failed: %s\n", strerror(-err));
				goto cleanup;
			}
		} else {
			poll(NULL, 0, 100);
		}
		now = monotonic_seconds();
		if (now - last_sample >= opts.interval_sec) {
			err = print_table(stats_fd, cpu_count, previous, &opts,
					  now - last_sample);
			if (err) {
				fprintf(stderr, "Per-CPU map read failed: %s\n", strerror(-err));
				goto cleanup;
			}
			last_sample = now;
		}
		if (opts.duration_sec && now - started >= opts.duration_sec)
			break;
	}

	exit_code = 0;
	if (opts.verification_pid) {
		__u64 observed = 0;

		err = read_verification_total(verification_fd, cpu_count, &observed);
		if (err) {
			fprintf(stderr, "Failed to read verification counter: %s\n",
				strerror(-err));
			exit_code = 1;
		} else if (opts.expected_set) {
			__s64 difference = (__s64)observed - (__s64)opts.expected;
			bool pass = observed == opts.expected;

			printf("VERIFICATION expected=%" PRIu64 " observed=%" PRIu64
			       " difference=%" PRId64 " %s\n",
			       (uint64_t)opts.expected, (uint64_t)observed,
			       (int64_t)difference, pass ? "PASS" : "FAIL");
			if (!pass)
				exit_code = 4;
		} else {
			printf("VERIFICATION observed=%" PRIu64 "\n", (uint64_t)observed);
		}
	}

cleanup:
	free(previous);
	ring_buffer__free(ring);
	monitor_bpf__destroy(skeleton);
	return exit_code;
}
