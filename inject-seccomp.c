#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include "libptrace_do.h"

static int
inject_seccomp(int pid, int syscall_nr)
{
	struct ptrace_do *target;
	target = ptrace_do_init(pid);

	// Allocate a block of memory for the bpf filters
	struct sock_filter *filters = ptrace_do_malloc(target, 4*sizeof(struct sock_filter));

	// Fill the memory with a constant byte
	memset(filters, 0, 4*sizeof(struct sock_filter));

	struct sock_filter _filters[] = {
		// [0] Load architecture from 'seccomp_data' buffer into accumulator
	    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

	    // [1] Jump forward 1 instructions if the system call does not match syscall_nr
	    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, syscall_nr, 0, 1),

	    // [2] Destination of system call match: kill task
	    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),

	    // [3] Destination of system call mismatch: allow task
	    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
  	};
  	// Copy the generated filters to the allocated memory
	memcpy(filters, _filters, 4 * sizeof(struct sock_filter));

	// Push filters to the remote process memory address
	unsigned long filters_addr =  (unsigned long) ptrace_do_push_mem(target, filters);

	// Allocate a block of memory for the filtered program
	struct sock_fprog *prog = ptrace_do_malloc(target, sizeof(struct sock_fprog));
	// Fill the memory with a constant byte
	memset(prog, 0, sizeof(struct sock_fprog));
	// Populate sock_fprog with the required information
	prog->len = 4;
	prog->filter = filters_addr;
	// Push prog to the remote process memory address
	unsigned long prog_addr =  (unsigned long) ptrace_do_push_mem(target, prog);

	// Execute prctl with PR_SET_NO_NEW_PRIVS because the requirement to use the SECCOMP_SET_MODE_FILTER operation,
	// either the caller must have the CAP_SYS_ADMIN capability in its user namespace, or the thread must already 
	// have the no_new_privs bit set
	// This requirement ensures that an unprivileged process cannot apply a malicious filter and then invoke a
	// set-user-ID or other privileged program using execve, thus potentially compromising that program. 
	if (ptrace_do_syscall(target, __NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)) {
		perror("prctl no new privs");
	    exit(EXIT_FAILURE);
	}

	// Execute seccomp syscall with the generated bpf filters
	if (ptrace_do_syscall(target, __NR_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog_addr, 0, 0, 0)) {
		perror("prctl seccomp");
		exit(EXIT_FAILURE);
	}

	// Clean the remote process memory 
	ptrace_do_cleanup(target);

	return 0;
}

int
main(int argc, char *argv[])
{
	// Validate given args
	if (argc < 3) {
		fprintf(stderr, "Usage: "
		       "%s <PID> <syscall_nr>\n"
		       "Inject a seccomp profile to a process\n", argv[0]);
		exit(EXIT_FAILURE);
   	}

   	// Inject the seccomp profile
	if (inject_seccomp(atoi(argv[1]), atoi(argv[2]))) exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

