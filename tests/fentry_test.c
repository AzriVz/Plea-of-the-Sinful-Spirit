#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int parse_iterations(const char *text, unsigned int *iterations)
{
	char *end = NULL;
	unsigned long value;

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno || !end || *end || !value || value > 1000000)
		return -1;
	*iterations = (unsigned int)value;
	return 0;
}

int main(int argc, char **argv)
{
	unsigned int iterations = 100;
	unsigned int success = 0;
	unsigned int failures = 0;
	bool pause_before_run = false;
	const char *path = NULL;
	unsigned int i;
	int arg;

	for (arg = 1; arg < argc; arg++) {
		if (strcmp(argv[arg], "--pause") == 0) {
			pause_before_run = true;
		} else if (strcmp(argv[arg], "--iterations") == 0 && arg + 1 < argc) {
			if (parse_iterations(argv[++arg], &iterations)) {
				fprintf(stderr, "Invalid iteration count\n");
				return 2;
			}
		} else if (!path) {
			path = argv[arg];
		} else {
			fprintf(stderr,
				"Usage: %s [--pause] [--iterations N] TARGET_FILE\n",
				argv[0]);
			return 2;
		}
	}
	if (!path) {
		fprintf(stderr, "Usage: %s [--pause] [--iterations N] TARGET_FILE\n",
			argv[0]);
		return 2;
	}
	/* Validate the file before the monitor attaches; it is not part of N. */
	{
		int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);

		if (fd < 0) {
			fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
			return 1;
		}
		(void)syscall(SYS_close, fd);
	}

	printf("READY pid=%d target=__x64_sys_openat iterations=%u path=%s\n",
	       getpid(), iterations, path);
	fflush(stdout);
	if (pause_before_run)
		raise(SIGSTOP);

	for (i = 0; i < iterations; i++) {
		int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);

		if (fd < 0) {
			failures++;
			continue;
		}
		success++;
		(void)syscall(SYS_close, fd);
	}
	printf("DONE expected=%u success=%u failures=%u %s\n", iterations,
	       success, failures,
	       success == iterations && failures == 0 ? "PASS" : "FAIL");
	return success == iterations && failures == 0 ? 0 : 1;
}
