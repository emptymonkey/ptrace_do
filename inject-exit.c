#include <stdio.h>
#include <stdlib.h>
#include "libptrace_do.h"

int main(int argc, char *argv[]) {
	struct ptrace_do *target;      
	if (argc < 2) {
		printf("Usage: %s <PID>\n", argv[0]);
		exit(1);
	}
	int pid = atoi(argv[1]);

	printf("PID: %s\n", argv[1]);
	target = ptrace_do_init(pid);
	ptrace_do_syscall(target, __NR_exit, 42, 0, 0, 0, 0, 0);
	ptrace_do_cleanup(target);
	return 0;
}