#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	size_t page_count = 32768;
	bool pause_before_run = false;
	size_t page_size;
	size_t length;
	volatile unsigned char *area;
	unsigned long checksum = 0;
	size_t i;
	int arg = 1;

	if (arg < argc && strcmp(argv[arg], "--pause") == 0) {
		pause_before_run = true;
		arg++;
	}
	if (arg < argc) {
		char *end = NULL;
		unsigned long parsed;

		errno = 0;
		parsed = strtoul(argv[arg++], &end, 10);
		if (errno || !end || *end || !parsed) {
			fprintf(stderr, "Usage: %s [--pause] [PAGE_COUNT]\n", argv[0]);
			return 2;
		}
		page_count = parsed;
	}
	if (arg != argc) {
		fprintf(stderr, "Usage: %s [--pause] [PAGE_COUNT]\n", argv[0]);
		return 2;
	}
	printf("READY pid=%d pages=%zu\n", getpid(), page_count);
	fflush(stdout);
	if (pause_before_run)
		raise(SIGSTOP);
	page_size = (size_t)sysconf(_SC_PAGESIZE);
	if (page_count > SIZE_MAX / page_size) {
		fprintf(stderr, "Requested mapping is too large\n");
		return 2;
	}
	length = page_count * page_size;
	area = mmap(NULL, length, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	for (i = 0; i < page_count; i++) {
		area[i * page_size] = (unsigned char)i;
		checksum += area[i * page_size];
	}
	printf("Touched %zu anonymous pages (%zu bytes), checksum=%lu\n",
	       page_count, length, checksum);
	munmap((void *)area, length);
	return 0;
}
