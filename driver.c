
/*******************************************************************************
 *
 * This code snippet is a test driver only. Nothing special to see here.
 * Add or change code as needed for your own learning / testing.
 *
 ******************************************************************************/

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include "libptrace_do.h"

#define BUFF_LEN	50


int main(int argc, char **argv){
	int retval;
	int pid;

	char *cat, *scratch, *fever;
	void *tmp_addr;

	struct ptrace_do *target;


	if(argc != 2){
		fprintf(stderr, "usage:...\n");
		exit(-1);
	}

	retval = strtol(argv[1], NULL, 10);
	if(errno || !retval){
		fprintf(stderr, "usage:...\n");
		exit(-1);
	}
	pid = retval;

	target = ptrace_do_init(pid);

	cat = (char *) ptrace_do_malloc(target, BUFF_LEN);
	memset(cat, 0, BUFF_LEN);
	snprintf(cat, BUFF_LEN, "cat\n");
	tmp_addr = ptrace_do_push_mem(target, cat);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(cat, BUFF_LEN), 0, 0, 0);

	scratch = (char *) ptrace_do_malloc(target, BUFF_LEN - 3);
	memset(scratch, 0, BUFF_LEN - 3);
	snprintf(scratch, BUFF_LEN - 3, "scratch\n");
	tmp_addr = ptrace_do_push_mem(target, scratch);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(scratch, BUFF_LEN - 3), 0, 0, 0);

	fever = (char *) ptrace_do_malloc(target, BUFF_LEN - 5);
	memset(fever, 0, BUFF_LEN - 5);
	snprintf(fever, BUFF_LEN - 5, "fever\n");
	tmp_addr = ptrace_do_push_mem(target, fever);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(fever, BUFF_LEN - 5), 0, 0, 0);

	memset(scratch, 0, BUFF_LEN);
	memset(fever, 0, BUFF_LEN - 5);

	tmp_addr = ptrace_do_pull_mem(target, fever);
	printf("DEBUG: tmp_addr: %p\n", tmp_addr);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(fever, BUFF_LEN), 0, 0, 0);

	tmp_addr = ptrace_do_pull_mem(target, scratch);
	printf("DEBUG: tmp_addr: %p\n", tmp_addr);
	ptrace_do_syscall(target, __NR_write, 1, (unsigned long) tmp_addr, strnlen(scratch, BUFF_LEN), 0, 0, 0);

	ptrace_do_cleanup(target);

	return(0);
}
