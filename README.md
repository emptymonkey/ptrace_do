# ptrace_do #

_ptrace_do_ is a [ptrace](http://en.wikipedia.org/wiki/Ptrace) library to simplify [syscall](http://en.wikipedia.org/wiki/Syscall) injection in Linux.

**What?**

[ptrace](http://linux.die.net/man/2/ptrace) is a powerful debugging tool native to Linux. It allows you to connect to a running process, examine and alter its memory, and change it's runtime state. Unfortunately, it's quite complex and requires a solid understanding of the underlying architecture and OS. _ptrace_do_ was written to allow pentesters access to a simplified interface for injecting syscalls into a target process.

**That's awesome! [1337 h4X0rZ rUL3!!](http://hackertyper.com/)**

Sorry, no. This isn't an exploit. This code only uses standard, though not commonly known, interfaces for process interaction and control. In order to affect a process you don't already own, you will need to have the CAP_SYS_PTRACE [capability](http://linux.die.net/man/7/capabilities) (i.e. root).

**What OS / Arch combo will this work on?**

Right now, only Linux x86_64. Given that we are using ptrace() for injecting syscalls in their assembly language form, this code is not portable. I did try to keep it as modular as possible, so extending it to a different Linux architecture shouldn't be too difficult.

## Usage ##

**Example: Injecting "exit(42);"**

```
	struct ptrace_do *target;      

	target = ptrace_do_init(TARGET_PID);
	ptrace_do_syscall(target, _NR_exit, 42, 0, 0, 0, 0, 0);
```

**Example: Injecting open / dup2 / close calls to hijack stdin / stdout / stderr.**

```
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
```

## Installation ##

```
git clone git@github.com:emptymonkey/ptrace_do.git
cd ptrace_do
make
```
## Documentation ##

The functions are documented inside the source.
