#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

struct worker {
	pthread_t thread;
	pthread_barrier_t *barrier;
	uint64_t iterations;
	int cpu;
	int affinity_error;
};

static void *run_worker(void *opaque)
{
	struct worker *worker = opaque;
	cpu_set_t affinity;
	uint64_t i;

	CPU_ZERO(&affinity);
	CPU_SET(worker->cpu, &affinity);
	worker->affinity_error = pthread_setaffinity_np(pthread_self(), sizeof(affinity),
							  &affinity);
	pthread_barrier_wait(worker->barrier);
	for (i = 0; i < worker->iterations; i++)
		(void)syscall(SYS_getpid);
	return NULL;
}

static int parse_iterations(const char *text, uint64_t *iterations)
{
	char *end = NULL;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno || !end || *end || !value)
		return -1;
	*iterations = value;
	return 0;
}

int main(int argc, char **argv)
{
	uint64_t iterations = 100000;
	bool pause_before_run = false;
	pthread_barrier_t barrier;
	cpu_set_t allowed;
	struct worker *workers;
	int worker_count;
	int created = 0;
	int cpu;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--pause") == 0) {
			pause_before_run = true;
		} else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
			if (parse_iterations(argv[++i], &iterations)) {
				fprintf(stderr, "Invalid iteration count\n");
				return 2;
			}
		} else {
			fprintf(stderr, "Usage: %s [--pause] [--iterations N]\n", argv[0]);
			return 2;
		}
	}
	if (sched_getaffinity(0, sizeof(allowed), &allowed)) {
		perror("sched_getaffinity");
		return 1;
	}
	worker_count = CPU_COUNT(&allowed);
	if (worker_count <= 0) {
		fprintf(stderr, "No CPUs are available in this affinity mask\n");
		return 1;
	}
	workers = calloc((size_t)worker_count, sizeof(*workers));
	if (!workers) {
		perror("calloc");
		return 1;
	}
	if (pthread_barrier_init(&barrier, NULL, (unsigned int)worker_count)) {
		fprintf(stderr, "pthread_barrier_init failed\n");
		free(workers);
		return 1;
	}
	printf("READY pid=%d cpus=%d workers=%d iterations=%llu expected=%llu syscall=%d\n",
	       getpid(), worker_count, worker_count, (unsigned long long)iterations,
	       (unsigned long long)(iterations * (uint64_t)worker_count), SYS_getpid);
	fflush(stdout);
	if (pause_before_run)
		raise(SIGSTOP);

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		int rc;

		if (!CPU_ISSET(cpu, &allowed))
			continue;
		workers[created].barrier = &barrier;
		workers[created].iterations = iterations;
		workers[created].cpu = cpu;
		rc = pthread_create(&workers[created].thread, NULL, run_worker,
				    &workers[created]);
		if (rc) {
			fprintf(stderr, "pthread_create: %s\n", strerror(rc));
			return 1;
		}
		created++;
	}
	for (i = 0; i < created; i++) {
		pthread_join(workers[i].thread, NULL);
		if (workers[i].affinity_error)
			fprintf(stderr, "Warning: CPU %d affinity failed: %s\n",
				workers[i].cpu, strerror(workers[i].affinity_error));
	}
	printf("DONE expected=%llu\n",
	       (unsigned long long)(iterations * (uint64_t)worker_count));
	pthread_barrier_destroy(&barrier);
	free(workers);
	return 0;
}
