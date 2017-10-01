#include <stdio.h>
#include <stdlib.h>
#include "libptrace_do.h"

#define BUFF_SIZE 256

int main(int argc, char *argv[]) {
	// Validate given args
	if (argc < 3) {
		printf("Usage: "
			"%s <PID> <string>\n"
			"Inject a string to a running process stdout\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	struct ptrace_do *target;
	int pid = atoi(argv[1]);

	// Hook the remote process
	target = ptrace_do_init(pid);

	// Allocate a block of memory inside the remote process
	char *buffer = ptrace_do_malloc(target, BUFF_SIZE);

	// Fill the memory with a constant byte
	memset(buffer, 0, BUFF_SIZE);

	// Populate the allocated buffer
	snprintf(buffer, BUFF_SIZE, "%s", argv[2]);

	// Push the data to the remote process address space
	unsigned long remote_addr = (unsigned long)ptrace_do_push_mem(target, buffer);

	// Invoke the system call in the remote process
	ptrace_do_syscall(target, __NR_write, 1, remote_addr, strnlen(buffer, BUFF_SIZE), 0, 0, 0);

	// Cleanup remote process memory allocation
	ptrace_do_cleanup(target);

	exit(EXIT_SUCCESS);
}