/**********************************************************************
 *
 *	libptrace_do : 2012-12-24
 *		emptymonkey's ptrace library for easy syscall injection.
 *
 *
 *	Example use, injecting open / dup2 / close calls to hijack stdin / stdout / stderr:
 *
 *		char *buffer;
 *		struct ptrace_do *target;
 *		void *remote_addr;
 *		int fd;
 *     
 *		target = ptrace_do_init(PID);
 *		buffer = (char *) ptrace_do_malloc(target, BUFF_SIZE);
 *		memset(buffer, 0, BUFF_SIZE);
 *		snprintf(buffer, BUFF_SIZE, "/dev/pts/4");
 *		remote_addr = ptrace_do_push_mem(target, buffer);
 *		fd = ptrace_do_syscall(target, __NR_open, remote_addr, O_RDWR, 0, 0, 0, 0);
 *		ptrace_do_syscall(target, __NR_dup2, fd, 0, 0, 0, 0, 0);
 *		ptrace_do_syscall(target, __NR_dup2, fd, 1, 0, 0, 0, 0);
 *		ptrace_do_syscall(target, __NR_dup2, fd, 2, 0, 0, 0, 0);
 *		ptrace_do_syscall(target, __NR_close, fd, 0, 0, 0, 0, 0);
 *		ptrace_do_cleanup(target);
 *
 **********************************************************************/

#include "libptrace_do.h"


/**********************************************************************
 *
 *	struct ptrace_do *ptrace_do_init(int pid)
 *
 *		Input:
 *			The process id of the target.
 *
 *		Output:
 *			Pointer to a struct ptrace_do object. NULL on error.
 *
 *		Purpose:
 *			Initialize the session. Attach to the process and save its
 *			register state (for later restoration).
 *	
 **********************************************************************/
struct ptrace_do *ptrace_do_init(int pid){
	int retval, status;
	unsigned long peekdata;
	unsigned long i;
	struct ptrace_do *target;
	siginfo_t siginfo;

	struct parse_maps *map_current;


	if((target = (struct ptrace_do *) malloc(sizeof(struct ptrace_do))) == NULL){
		fprintf(stderr, "%s: malloc(%d): %s\n", program_invocation_short_name, \
				(int) sizeof(struct ptrace_do), strerror(errno));
		return(NULL);
	}
	memset(target, 0, sizeof(struct ptrace_do));
	target->pid = pid;


	// Here we test to see if the child is already attached. This may be the case if the child
	// is a willing accomplice, aka PTRACE_TRACEME.
	// We are testing if it is already traced by trying to read data, specifically its last 
	// signal received. If PTRACE_GETSIGINFO is succesfull *and* the last signal recieved was 
	// SIGTRAP, then it's prolly safe to assume this is the PTRACE_TRACEME case.

	memset(&siginfo, 0, sizeof(siginfo));
	if(ptrace(PTRACE_GETSIGINFO, target->pid, NULL, &siginfo)){

		if((retval = ptrace(PTRACE_ATTACH, target->pid, NULL, NULL)) == -1){
			fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
					(int) PTRACE_ATTACH, (int) target->pid, (long unsigned int) NULL, \
					(long unsigned int) NULL, strerror(errno));
			free(target);
			return(NULL);
		}

		if((retval = waitpid(target->pid, &status, 0)) < 1){
			fprintf(stderr, "%s: waitpid(%d, %lx, 0): %s\n", program_invocation_short_name, \
					(int) target->pid, (unsigned long) &status, strerror(errno));
			free(target);
			return(NULL);
		}

		if(!WIFSTOPPED(status)){
			free(target);
			return(NULL);
		}
	}else{
		if(siginfo.si_signo != SIGTRAP){
			fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): Success, but not recently trapped. Aborting!\n", program_invocation_short_name, \
					(int) PTRACE_GETSIGINFO, (int) target->pid, (long unsigned int) NULL, \
					(long unsigned int) &siginfo);
			free(target);
			return(NULL);
		}
	}

	if((retval = ptrace(PTRACE_GETREGS, target->pid, NULL, &(target->saved_regs))) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_GETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &(target->saved_regs), strerror(errno));
		free(target);
		return(NULL);
	}

	// The tactic for performing syscall injection is to fill the registers to the appropriate values for your syscall,
	// then point $rip at a piece of executable memory that contains the SYSCALL instruction.

	// If we came in from a PTRACE_ATTACH call, then it's likely we are on a syscall edge, and can save time by just
	// using the one SIZEOF_SYSCALL addresses behind where we are right now.
	errno = 0;
	peekdata = ptrace(PTRACE_PEEKTEXT, target->pid, (target->saved_regs).rip - SIZEOF_SYSCALL, NULL);

	if(!errno && ((SYSCALL_MASK & peekdata) == SYSCALL)){
		target->syscall_address = (target->saved_regs).rip - SIZEOF_SYSCALL;

	// Otherwise, we will need to start stepping through the various regions of executable memory looking for 
	// a SYSCALL instruction.
	}else{
		if((target->map_head = get_proc_pid_maps(target->pid)) == NULL){
			fprintf(stderr, "%s: get_proc_pid_maps(%d): %s\n", program_invocation_short_name, \
					(int) target->pid, strerror(errno));
			free(target);
			return(NULL);
		}

		map_current = target->map_head;
		while(map_current){

			if(target->syscall_address){
				break;
			}

			if((map_current->perms & MAPS_EXECUTE)){

				for(i = map_current->start_address; i < (map_current->end_address - sizeof(i)); i++){
					errno = 0;
					peekdata = ptrace(PTRACE_PEEKTEXT, target->pid, i, NULL);
					if(errno){
						fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
								(int) PTRACE_PEEKTEXT, (int) target->pid, i, \
								(long unsigned int) NULL, strerror(errno));
						free_parse_maps_list(target->map_head);
						free(target);
						return(NULL);
					}

					if((SYSCALL_MASK & peekdata) == SYSCALL){
						target->syscall_address = i;
						break;
					}
				}
			}

			map_current = map_current->next;
		}
	}
	return(target);
}


/**********************************************************************
 *
 *	void *ptrace_do_malloc(struct ptrace_do *target, size_t size)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *			The desired size for the users local buffer.
 *
 *		Output:
 *			A pointer to the local storage space. NULL on error.
 *
 *		Purpose:
 *			Reserve a chunk of memory of the given 'size' in both the local
 *			and remote processes, and link them together inside of this 
 *			sessions ptrace_do object. This gives the local code a place
 *			in the remote process to save data for various purposes.
 *			(e.g. the file path needed for an open() syscall).
 *
 *		Note: 
 *			Multiple calls to ptrace_do_malloc will make multiple calls to
 *			mmap in the remote context. This should be fine and will
 *			usually be arranged as page aligned sequential chunks by the
 *			OS.
 *
 **********************************************************************/
void *ptrace_do_malloc(struct ptrace_do *target, size_t size){

	struct mem_node *new_mem_node, *last_mem_node;


	if(!size){
		return(NULL);
	}

	last_mem_node = target->mem_head;
	if(last_mem_node){
		while(last_mem_node->next){
			last_mem_node = last_mem_node->next;
		}
	}

	while(size % sizeof(long)){
		size++;
	}

	if((new_mem_node = (struct mem_node *) malloc(sizeof(struct mem_node))) == NULL){
		fprintf(stderr, "%s: malloc(%d): %s\n", program_invocation_short_name, \
				(int) sizeof(struct mem_node), strerror(errno));
		return(NULL);
	}
	memset(new_mem_node, 0, sizeof(struct mem_node));

	if((new_mem_node->local_address = malloc(size)) == NULL){
		fprintf(stderr, "%s: malloc(%d): %s\n", program_invocation_short_name, \
				(int) size, strerror(errno));
		free(new_mem_node);
		return(NULL);
	}
	new_mem_node->word_count = (size / sizeof(long));

	if((long) (new_mem_node->remote_address = ptrace_do_syscall(target, \
					__NR_mmap, (unsigned long) NULL, size, \
					PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)) < 0){
		fprintf(stderr, "%s: ptrace_do_syscall(%lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx): %s\n", \
				program_invocation_short_name, (unsigned long) target, \
				(unsigned long) __NR_mmap, (unsigned long) NULL, (unsigned long) size, \
				(unsigned long) (PROT_READ|PROT_WRITE), (unsigned long) (MAP_PRIVATE|MAP_ANONYMOUS), \
				(unsigned long) -1, (unsigned long) 0, strerror(-new_mem_node->remote_address));
		free(new_mem_node->local_address);
		free(new_mem_node);
		return(NULL);
	}	

	if(last_mem_node){
		last_mem_node->next = new_mem_node;
	}else{
		target->mem_head = new_mem_node;
	}

	return(new_mem_node->local_address);
}


/**********************************************************************
 *
 *	void *ptrace_do_push_mem(struct ptrace_do *target, void *local_address)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *			A reference to a local buffer that was created with ptrace_do_malloc().
 *
 *		Output:
 *			A pointer to the buffer in the remote process. (Presumably for
 *			use in a later syscall). NULL on error.
 *
 *		Purpose:
 *			Copies the data in the local_address buffer to the buffer in
 *			the remote process to which it is linked. Upon return you 
 *			have an address to hand a remote syscall. 
 *
 **********************************************************************/
void *ptrace_do_push_mem(struct ptrace_do *target, void *local_address){

	int retval, i; 
	unsigned long ptrace_data;
	struct mem_node *node;


	node = target->mem_head;
	if(node){
		while(node->next && node->local_address != local_address){
			node = node->next;
		}
	}

	if(!(node && (node->local_address == local_address))){
		fprintf(stderr, "%s: ptrace_do_pull_mem(%lx, %lx): No matching address location\n", 
				program_invocation_short_name, (unsigned long) target, (unsigned long) local_address);
		return(NULL);
	}

	memset(&ptrace_data, 0, sizeof(ptrace_data));
	for(i = 0; i < (int) node->word_count; i++){
		memcpy(&ptrace_data, &(((char *) local_address)[i * sizeof(long)]), sizeof(long));

		if((retval = ptrace(PTRACE_POKETEXT, target->pid, \
						(void *) (node->remote_address + (i * sizeof(long))), (void *) ptrace_data)) == -1){
			fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
					(int) PTRACE_POKETEXT, (int) target->pid, \
					(long unsigned int) (node->remote_address + (i * sizeof(long))), \
					(long unsigned int) ptrace_data, strerror(errno));
			return(NULL);
		}
	}

	return((void *) node->remote_address);
}


/**********************************************************************
 *
 *	void *ptrace_do_pull_mem(struct ptrace_do *target, void *local_address)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *			A reference to a local buffer that was created with ptrace_do_malloc().
 *
 *		Output:
 *			A pointer to the buffer in the remote process. (Presumably for
 *			use in a later syscall). NULL on error.
 *
 *		Purpose:
 *			Copies the data in the remote process buffer to the buffer in
 *			local_address to which it is linked.
 *
 **********************************************************************/
void *ptrace_do_pull_mem(struct ptrace_do *target, void *local_address){

	int i; 

	unsigned long ptrace_data;
	struct mem_node *node;

	node = target->mem_head;
	if(node){
		while(node->next && node->local_address != local_address){
			node = node->next;
		}
	}

	if(!(node && (node->local_address == local_address))){
		fprintf(stderr, "%s: ptrace_do_pull_mem(%lx, %lx): No matching address location\n", 
				program_invocation_short_name, (unsigned long) target, (unsigned long) local_address);
		return(NULL);
	}

	memset(&ptrace_data, 0, sizeof(ptrace_data));
	for(i = 0; i < (int) node->word_count; i++){

		errno = 0;
		ptrace_data = ptrace(PTRACE_PEEKTEXT, target->pid, \
				(void *) (node->remote_address + (i * sizeof(long))), NULL);
		if(errno){
			fprintf(stderr, "%s: ptrace(%d, %d, %lx, NULL): %s\n", program_invocation_short_name, \
					(int) PTRACE_PEEKTEXT, (int) target->pid, \
					(long unsigned int) (node->remote_address + (i * sizeof(long))), strerror(errno)); 
			return(NULL);
		}
		memcpy(&(((char *) local_address)[i * sizeof(long)]), &ptrace_data, sizeof(long));
	}

	return((void *) node->remote_address);
}

/**********************************************************************
 *	 
 * void *ptrace_do_get_remote_addr(struct ptrace_do *target, void *local_address) 
 *	 
 *	Input:  
 *		This sessions ptrace_do object. 
 *		A local memory address as returned by ptrace_do_malloc().
 *	 
 *	Output:
 *		The remote memory address associated with the local address.
 *		NULL will be returned on error (i.e. no matching address).
 * 
 **********************************************************************/
void *ptrace_do_get_remote_addr(struct ptrace_do *target, void *local_address){
	struct mem_node *node;

	node = target->mem_head;
	if(node){
		while(node->next && node->local_address != local_address){
			node = node->next;
		}
	}

	if(!(node && (node->local_address == local_address))){
		fprintf(stderr, "%s: ptrace_do_pull_mem(%lx, %lx): No matching address location\n",
				program_invocation_short_name, (unsigned long) target, (unsigned long) local_address);
		return(NULL);
	}

	return((void *) node->remote_address);
}


/**********************************************************************
 *	 
 *	unsigned long ptrace_do_syscall(struct ptrace_do *target, \
 *		unsigned long rax, unsigned long rdi, unsigned long rsi, \
 *		unsigned long rdx, unsigned long r10, unsigned long r8, unsigned long r9)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *			The registers as you would want to set them for a syscall.
 *				(Registers that are not needed should be set to 0.)
 *
 *		Output:
 *			The results of the syscall will be returned (as we recieved it 
 *			back from rax.)
 *			On error, errno will be set appropriately.
 * 
 *		Purpose:
 *			Set up and execute a syscall within the remote process.
 *
 *		Example code for running "exit(42);" in the remote process:
 *
 *			#include <syscall.h>
 *				...
 *			struct ptrace_do *my_target;			
 *			unsigned long my_rax;
 *				...
 *			my_rax = ptrace_do_syscall(my_target, _NR_exit, 42, 0, 0, 0, 0, 0);
 *
 **********************************************************************/
unsigned long ptrace_do_syscall(struct ptrace_do *target, unsigned long rax, \
		unsigned long rdi, unsigned long rsi, unsigned long rdx, \
		unsigned long r10, unsigned long r8, unsigned long r9){

	int retval, status, sig_remember = 0;
	struct user_regs_struct attack_regs;


	/*
	 * There are two possible failure modes when calling ptrace_do_syscall():
	 *	
	 * 	1) ptrace_do_syscall() fails. In this case we should return -1 
	 *		and leave errno untouched (as it should be properly set when
	 *		the error occurs).
	 *	
	 *	or	
	 *	
	 * 	2) ptrace_do_syscall() is fine, but the remote syscall fails. 
	 *		In this case, we can't analyze the error without being intrusive,
	 *		so we will leave that job to the calling code. We should return the 
	 *		syscall results as it was passed to us in rax, but that may 
	 * 		legitimately be less than 0. As such we should zero out errno to ensure
	 *		the failure mode we are in is clear.
	 */
	errno = 0;

	memcpy(&attack_regs, &(target->saved_regs), sizeof(attack_regs));

	attack_regs.rax = rax;
	attack_regs.rdi = rdi;
	attack_regs.rsi = rsi;
	attack_regs.rdx = rdx;
	attack_regs.r10 = r10;
	attack_regs.r8 = r8;
	attack_regs.r9 = r9;

	attack_regs.rip = target->syscall_address;

	if((retval = ptrace(PTRACE_SETREGS, target->pid, NULL, &attack_regs)) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_SETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &attack_regs, strerror(errno));
		return(-1);
	}

RETRY:
	status = 0;
	if((retval = ptrace(PTRACE_SINGLESTEP, target->pid, NULL, NULL)) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_SINGLESTEP, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) NULL, strerror(errno));
		return(-1);
	}

	if((retval = waitpid(target->pid, &status, 0)) < 1){
		fprintf(stderr, "%s: waitpid(%d, %lx, 0): %s\n", program_invocation_short_name, \
				(int) target->pid, (unsigned long) &status, strerror(errno));
		return(-1);
	}

	if(status){
		if(WIFEXITED(status)){
			errno = ECHILD;
			fprintf(stderr, "%s: waitpid(%d, %lx, 0): WIFEXITED(%d)\n", program_invocation_short_name, \
					target->pid, (unsigned long) &status, status);
			return(-1);
		}
		if(WIFSIGNALED(status)){
			errno = ECHILD;
			fprintf(stderr, "%s: waitpid(%d, %lx, 0): WIFSIGNALED(%d): WTERMSIG(%d): %d\n", \
					program_invocation_short_name, target->pid, (unsigned long) &status, \
					status, status, WTERMSIG(status));
			return(-1);
		}
		if(WIFSTOPPED(status)){

			if(target->sig_ignore & 1<<WSTOPSIG(status)){
				goto RETRY;
			}else if(WSTOPSIG(status) != SIGTRAP){
				sig_remember = status;
				goto RETRY;
			}
		}
		if(WIFCONTINUED(status)){
			errno = EINTR;
			fprintf(stderr, "%s: waitpid(%d, %lx, 0): WIFCONTINUED(%d)\n", program_invocation_short_name, \
					target->pid, (unsigned long) &status, status);
			return(-1);
		}
	}

	if((retval = ptrace(PTRACE_GETREGS, target->pid, NULL, &attack_regs)) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_GETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &attack_regs, strerror(errno));
		return(-1);
	}

	// Re-deliver any signals we caught and ignored.
	if(sig_remember){
		// Not checking for errors here. This is a best effort to deliver the previous signal state.
		kill(target->pid, sig_remember);
	}

	// Let's reset this to what it was upon entry.
	if((retval = ptrace(PTRACE_SETREGS, target->pid, NULL, &(target->saved_regs))) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_SETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &(target->saved_regs), strerror(errno));
		return(-1);
	}

	// Made it this far. Sounds like the ptrace_do_syscall() was fine. :)
	errno = 0;
	return(attack_regs.rax);
}


/**********************************************************************
 *
 *	void ptrace_do_cleanup(struct ptrace_do *target)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *
 *		Output:
 *			None.
 *
 *		Purpose:
 *			Restore the registers of the target process. Free remote 
 *			memory buffers. Destroy and free the local objects.
 *			Detach from the process and let it resume.
 *
 *			Note: It is intended that this function is safe to call when 
 *			attempting to gracefully disengage the target process after
 *			encountering errors.
 *
 **********************************************************************/
void ptrace_do_cleanup(struct ptrace_do *target){

	int retval;
	struct mem_node *this_node, *previous_node;


	this_node = target->mem_head;
	while(this_node){

		if((retval = (int) ptrace_do_syscall(target, \
						__NR_munmap, this_node->remote_address, this_node->word_count * sizeof(long), \
						0, 0, 0, 0)) < 0){
			fprintf(stderr, "%s: ptrace_do_syscall(%lx, %d, %lx, %d, %d, %d, %d, %d): %s\n", \
					program_invocation_short_name, \
					(unsigned long) target, __NR_munmap, this_node->remote_address, \
					(int) (this_node->word_count * sizeof(long)), 0, 0, 0, 0, strerror(-retval));
		}	

		free(this_node->local_address);

		previous_node = this_node;
		this_node = this_node->next;
		free(previous_node);
	}

	if((retval = ptrace(PTRACE_SETREGS, target->pid, NULL, &(target->saved_regs))) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_SETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &(target->saved_regs), strerror(errno));
	}

	if((retval = ptrace(PTRACE_DETACH, target->pid, NULL, NULL)) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_DETACH, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) NULL, strerror(errno));
	}

	free(target);
}


/**********************************************************************
 *
 *	void ptrace_do_free(struct ptrace_do *target, void *local_address, int operation)
 *
 *		Input:
 *			This sessions ptrace_do object, the local_address of the joint memory node,
 *			and the way you would like it freed.
 *
 *		Output:
 *			None.
 *
 *		Purpose:
 *			To dispose of unused objects, both local and / or remote. 
 *
 *		Operations:
 *			FREE_LOCAL   - Destroy the local data, but leave the remote data intact.
 *			FREE_REMOTE  - Destroy the remote data, but leave the local data intact.
 *			FREE_BOTH    - Destroy both the local and remote data.
 *
 *		Notes:
 *			Regardless of the operation chosen, the node associated with the local_address
 *			will be destroyed. 
 *
 *			This function is useful for using FREE_LOCAL to disassociate the remote 
 *			data with the controler process, while leaving it intact for use after a 
 *			PTRACE_DETACH call. Also, when you call ptrace_do_cleanup(), all 
 *			nodes that have not been manually delt with will be destroyed and the memory
 *			will be freed, both remote and local. 
 *
 **********************************************************************/
void ptrace_do_free(struct ptrace_do *target, void *local_address, int operation){
	int retval;
	struct mem_node *this_node, *previous_node;

	previous_node = NULL;
	this_node = target->mem_head;

	while(this_node){
		if(this_node->local_address == local_address){
			break;
		}	
		previous_node = this_node;
		this_node = this_node->next;
	}

	if(operation & FREE_REMOTE){
		if((retval = (int) ptrace_do_syscall(target, \
						__NR_munmap, this_node->remote_address, this_node->word_count * sizeof(long), \
						0, 0, 0, 0)) < 0){
			fprintf(stderr, "%s: ptrace_do_syscall(%lx, %d, %lx, %d, %d, %d, %d, %d): %s\n", \
					program_invocation_short_name, \
					(unsigned long) target, __NR_munmap, this_node->remote_address, \
					(int) (this_node->word_count * sizeof(long)), 0, 0, 0, 0, strerror(-retval));
		}	
	}

	if(operation & FREE_LOCAL){
		free(this_node->local_address);
	}

	if(previous_node){
		previous_node->next = this_node->next;
	}else{
		target->mem_head = this_node->next;
	}

	free(this_node);
}
