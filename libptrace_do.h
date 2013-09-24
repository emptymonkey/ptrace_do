
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


/* ptrace_do_init() hooks the target and prepares it to run our commands. */
struct ptrace_do *ptrace_do_init(int pid);

/* ptrace_do_malloc() allocates memory in the remote process for our use, without worry of upsetting the remote memory state. */
void *ptrace_do_malloc(struct ptrace_do *target, size_t size);

/* ptrace_do_push_mem() and ptrace_do_pull_mem() synchronize the memory states between local and remote buffers. */ 
void *ptrace_do_push_mem(struct ptrace_do *target, void *local_address);
void *ptrace_do_pull_mem(struct ptrace_do *target, void *local_address);

/* Short helper function to translate your local address to the remote one. */
void *ptrace_do_get_remote_addr(struct ptrace_do *target, void *local_addr);

/* ptrace_do_sig_ignore() sets the signal mask for the remote process. */
/* This is simple enough, we only need a macro. */
/* Note, this is for *our* handling of remote signals. This won't persist once we detatch. */
#define ptrace_do_sig_ignore(TARGET, SIGNAL)	TARGET->sig_ignore |= 1<<SIGNAL

/* ptrace_do_syscall() will execute the given syscall inside the remote process. */
unsigned long ptrace_do_syscall(struct ptrace_do *target, unsigned long rax, \
		unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long r10, unsigned long r8, unsigned long r9);

/* ptrace_do_cleanup() will detatch and do it's best to clean up the data structures. */
void ptrace_do_cleanup(struct ptrace_do *target);
