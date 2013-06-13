
/*******************************************************************************
 *
 * This snippet is just some test code as a demo. Nothing special to see here.
 * Add or change code as needed for your own learning / testing.
 *
 ******************************************************************************/

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "libptrace_do.h"

#define BUFF_LEN	50


int main(int argc, char **argv){
	int retval;
	int pid;

	char *string1, *string2, *string3;
	void *tmp_addr;

	struct ptrace_do *target;


	if(argc != 2){
		fprintf(stderr, "usage: %s PID\n", program_invocation_short_name);
		exit(-1);
	}

	// grab the pid of a target process.
	retval = strtol(argv[1], NULL, 10);
	if(errno || !retval){
		fprintf(stderr, "usage: %s PID\n", program_invocation_short_name);
		exit(-1);
	}
	pid = retval;

	// Hook the target.
	target = ptrace_do_init(pid);

	// Demonstrating memory allocation in the target process.
	string1 = (char *) ptrace_do_malloc(target, BUFF_LEN);
	memset(string1, 0, BUFF_LEN);
	// Treat the local string as you would normally.
	snprintf(string1, BUFF_LEN, "foo\n");
	// Then, when its all set, push it into the remote processes memory. It will know the right spot automatically.
	tmp_addr = ptrace_do_push_mem(target, string1);
	// Now that it's in the remote memory we can remotely call the write() syscall, and point it at the remote address.
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(string1, BUFF_LEN), 0, 0, 0);

	// Lets do it a couple more times with different buffer sizes. 
	string2 = (char *) ptrace_do_malloc(target, BUFF_LEN - 3);
	memset(string2, 0, BUFF_LEN - 3);
	snprintf(string2, BUFF_LEN - 3, "bar\n");
	tmp_addr = ptrace_do_push_mem(target, string2);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(string2, BUFF_LEN - 3), 0, 0, 0);

	// One more time...
	string3 = (char *) ptrace_do_malloc(target, BUFF_LEN - 5);
	memset(string3, 0, BUFF_LEN - 5);
	snprintf(string3, BUFF_LEN - 5, "baz\n");
	tmp_addr = ptrace_do_push_mem(target, string3);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(string3, BUFF_LEN - 5), 0, 0, 0);

	// Throw in a sleep(60); in here if you want to pause and go examine the targets /proc/PID/maps file.

	// Let's clear the memory in the local buffers...
	memset(string2, 0, BUFF_LEN - 3);
	memset(string3, 0, BUFF_LEN - 5);

	// and now demonstrate that we can pull the data from the remote memory locations.
	tmp_addr = ptrace_do_pull_mem(target, string3);
	// Here you'll see the address in the remote memory being known and printed locally.
	printf("DEBUG: tmp_addr: %p\n", tmp_addr);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(string3, BUFF_LEN - 5), 0, 0, 0);

	tmp_addr = ptrace_do_pull_mem(target, string2);
	printf("DEBUG: tmp_addr: %p\n", tmp_addr);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(string2, BUFF_LEN - 3), 0, 0, 0);

	// Unhook and clean up.
	ptrace_do_cleanup(target);

	return(0);
}
