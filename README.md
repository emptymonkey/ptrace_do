# ptrace_do #

<i>ptrace_do</i> is a [ptrace](http://en.wikipedia.org/wiki/Ptrace) library designed to simplify [syscall](http://en.wikipedia.org/wiki/Syscall) injection in Linux.

**What is ptrace?**

[ptrace](http://linux.die.net/man/2/ptrace) is the debugging interface provided by the [Linux](http://en.wikipedia.org/wiki/Linux) kernel. It allows you to connect to a running process, examine and alter its memory, and change it's runtime state. Unfortunately, it's quite complex and requires a solid understanding of the underlying architecture and OS. <i>ptrace_do</i> was written to allow pentesters access to a simplified interface for injecting syscalls into a target process.

The best introduction to ptrace that I've seen comes in the form of two articles by Pradeep Padala dating back to 2002:

* [Playing with ptrace, Part I](http://www.linuxjournal.com/article/6100)
* [Playing with ptrace, Part II](http://www.linuxjournal.com/article/6210)

**That's awesome! [1337 h4X0rZ rUL3!!](http://hackertyper.com/)**

Sorry, no. This isn't an ["exploit"](http://en.wikipedia.org/wiki/Sploit). This code only uses standard, though not commonly understood, interfaces for process interaction and control. In order to affect a process you don't already own, you will need to have the [CAP_SYS_PTRACE](http://lxr.linux.no/#linux+v3.9.4/include/uapi/linux/capability.h#L218) [capability](http://linux.die.net/man/7/capabilities) (i.e. root).

**Can I use this on any Linux host?**

Currently, <i>ptrace_do</i> will only work on x86_64 Linux. Because it uses the Linux ptrace interface to inject assembly language [syscalls](http://en.wikipedia.org/wiki/Syscall) into a target process, nothing here is portable. I did try to keep it as modular as possible, and I would consider porting it to another architecture if it became popular enough. 

## Usage ##

**Example: Injecting "exit(42);"**

	struct ptrace_do *target;      

	target = ptrace_do_init(TARGET_PID);
	ptrace_do_syscall(target, _NR_exit, 42, 0, 0, 0, 0, 0);

**Example: Injecting open / dup2 / close calls to hijack stdin / stdout / stderr.**

	char *buffer;
	struct ptrace_do *target;
	void *remote_addr;
	int fd;

	target = ptrace_do_init(TARGET_PID);
	buffer = (char *) ptrace_do_malloc(target, BUFF_SIZE);
	memset(buffer, 0, BUFF_SIZE);
	snprintf(buffer, BUFF_SIZE, "/dev/pts/4");
	remote_addr = ptrace_do_push_mem(target, buffer);
	fd = ptrace_do_syscall(target, __NR_open, remote_addr, O_RDWR, 0, 0, 0, 0);
	ptrace_do_syscall(target, __NR_dup2, fd, 0, 0, 0, 0, 0);
	ptrace_do_syscall(target, __NR_dup2, fd, 1, 0, 0, 0, 0);
	ptrace_do_syscall(target, __NR_dup2, fd, 2, 0, 0, 0, 0);
	ptrace_do_syscall(target, __NR_close, fd, 0, 0, 0, 0, 0);
	ptrace_do_cleanup(target);

For a more advanced usage, please examine my [shelljack](https://github.com/emptymonkey/shelljack) code, for which this library was written to accomidate.

## Documentation ##

Here is the brief list of function interfaces. These functions are documented in greater detail within the source.

	/* ptrace_do_init() hooks the target and prepares it to run our commands. */
	struct ptrace_do *ptrace_do_init(int pid);
	
	/* ptrace_do_malloc() allocates memory in the remote process for our use, without worry of upsetting the remote memory state. */
	void *ptrace_do_malloc(struct ptrace_do *target, size_t size);
	
	/* ptrace_do_free() frees a joint memory object. "operation" refers to the FREE_* modes above. */
	void ptrace_do_free(struct ptrace_do *target, void *local_address, int operation);
	
	/* ptrace_do_push_mem() and ptrace_do_pull_mem() synchronize the memory states between local and remote buffers. */
	void *ptrace_do_push_mem(struct ptrace_do *target, void *local_address);
	void *ptrace_do_pull_mem(struct ptrace_do *target, void *local_address);
	
	/* Short helper function to translate your local address to the remote one. */
	void *ptrace_do_get_remote_addr(struct ptrace_do *target, void *local_addr);
	
	/* ptrace_do_sig_ignore() sets the signal mask for the remote process. */
	/* This is simple enough, we only need a macro. */
	/* Note, this is for *our* handling of remote signals. This won't persist once we detatch. */
	#define ptrace_do_sig_ignore(TARGET, SIGNAL)  TARGET->sig_ignore |= 1<<SIGNAL
	
	/* ptrace_do_syscall() will execute the given syscall inside the remote process. */
	unsigned long ptrace_do_syscall(struct ptrace_do *target, unsigned long rax, \
	unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long r10, unsigned long r8, unsigned long r9);
	
	/* ptrace_do_cleanup() will detatch and do it's best to clean up the data structures. */
	void ptrace_do_cleanup(struct ptrace_do *target);
	
	/* get_proc_pid_maps() processes the maps file and returns the created object.*/
	struct parse_maps *get_proc_pid_maps(pid_t target);
	
	/* free_parse_maps_list() destroys a parse_maps object chain. */
	void free_parse_maps_list(struct parse_maps *head);
	
	/* Mostly for debugging, but in case it comes in handy, this function prints the parse_maps object members. */
	void dump_parse_maps_list(struct parse_maps *head);

## Installation ##

	git clone https://github.com/emptymonkey/ptrace_do.git
	cd ptrace_do
	make
