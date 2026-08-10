#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct burst_result {
	unsigned int success;
	unsigned int limited;
	unsigned int unexpected;
};

static int pin_first_available_cpu(void)
{
	cpu_set_t allowed;
	cpu_set_t selected;
	int cpu;

	if (sched_getaffinity(0, sizeof(allowed), &allowed))
		return -1;
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &allowed))
			continue;
		CPU_ZERO(&selected);
		CPU_SET(cpu, &selected);
		return sched_setaffinity(0, sizeof(selected), &selected);
	}
	errno = ENODEV;
	return -1;
}

static struct burst_result run_burst(const char *path, unsigned int attempts)
{
	struct burst_result result = {};
	unsigned int i;

	for (i = 0; i < attempts; i++) {
		int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);

		if (fd >= 0) {
			result.success++;
			(void)syscall(SYS_close, fd);
		} else if (errno == EAGAIN) {
			result.limited++;
		} else {
			result.unexpected++;
		}
	}
	return result;
}

int main(int argc, char **argv)
{
	struct timespec next_window = { .tv_sec = 1, .tv_nsec = 100000000 };
	struct burst_result first;
	struct burst_result second;
	char *end = NULL;
	unsigned long threshold;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s TARGET_FILE THRESHOLD\n", argv[0]);
		return 2;
	}
	errno = 0;
	threshold = strtoul(argv[2], &end, 10);
	if (errno || !end || *end || !threshold || threshold > 1000000) {
		fprintf(stderr, "Invalid threshold\n");
		return 2;
	}
	if (pin_first_available_cpu()) {
		perror("sched_setaffinity");
		return 1;
	}
	printf("READY pid=%d path=%s threshold=%lu\n", getpid(), argv[1], threshold);
	fflush(stdout);
	raise(SIGSTOP);

	first = run_burst(argv[1], (unsigned int)threshold + 3);
	printf("WINDOW1 success=%u limited=%u unexpected=%u\n",
	       first.success, first.limited, first.unexpected);
	clock_nanosleep(CLOCK_MONOTONIC, 0, &next_window, NULL);
	second = run_burst(argv[1], (unsigned int)threshold);
	printf("WINDOW2 success=%u limited=%u unexpected=%u\n",
	       second.success, second.limited, second.unexpected);
	if (first.success == threshold && first.limited == 3 &&
	    !first.unexpected && second.success == threshold &&
	    !second.limited && !second.unexpected) {
		printf("PASS\n");
		return 0;
	}
	printf("FAIL\n");
	return 1;
}

