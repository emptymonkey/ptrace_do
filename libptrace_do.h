
#define _GNU_SOURCE


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>


#define SIZEOF_SYSENTER 2


/* Basic object for keeping state. */
struct ptrace_do{
	int pid;
	unsigned long sig_ignore;
	struct user_regs_struct saved_regs;
	struct mem_node *mem_head;
};


/* As needed, nodes of memory both local and remote. */
struct mem_node{
	void *local_address;
	unsigned long remote_address;
	size_t word_count;

	struct mem_node *next;
};



struct ptrace_do *ptrace_do_init(int pid);
void *ptrace_do_malloc(struct ptrace_do *target, size_t size);
void *ptrace_do_push_mem(struct ptrace_do *target, void *local_address);
void *ptrace_do_pull_mem(struct ptrace_do *target, void *local_address);
#define ptrace_do_sig_ignore(TARGET, SIGNAL)	TARGET->sig_ignore |= 1<<SIGNAL
unsigned long ptrace_do_syscall(struct ptrace_do *target, unsigned long rax, \
		unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long r10, unsigned long r8, unsigned long r9);
void ptrace_do_cleanup(struct ptrace_do *target);
