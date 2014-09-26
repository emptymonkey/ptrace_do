
#include "libptrace_do.h"


#define PROC_STRING "/proc/"
#define MAPS_STRING "/maps"


// Internal helper functions don't need to make it into the main .h file.*/
struct parse_maps *parse_next_line(char *line);


/***********************************************************************************************************************
 *
 *	get_proc_pid_maps()
 *
 *		Input:
 *			The process id of the target.
 *
 *		Output:
 *			Pointer to a struct parse_maps object. NULL on error.
 *
 *		Purpose:
 *			The parse_maps object pointer will be a pointer to the head of a linked list. This list represents the 
 *			different regions of memory allocated by the kernel. This will be a reflection of the entries in the 
 *			/proc/PID/maps file.
 *
 **********************************************************************************************************************/
struct parse_maps *get_proc_pid_maps(pid_t target){

	struct parse_maps *map_head = NULL, *map_tail = NULL, *map_tmp;

	int fd, buffer_len;
	int ret_int;

	char *buffer;
	char *tmp_ptr;


	// I'm afraid that this function just parses a file and turns it into a linked list. Not very exciting.

	buffer_len = getpagesize();

	if((buffer = (char *) calloc(buffer_len, sizeof(char))) == NULL){
		fprintf(stderr, "calloc(%d, %d): %s\n", buffer_len, (int) sizeof(char), strerror(errno));
		goto CLEAN_UP;
	}


	tmp_ptr = buffer;
	memcpy(tmp_ptr, PROC_STRING, strlen(PROC_STRING));

	tmp_ptr = strchr(buffer, '\0');
	snprintf(tmp_ptr, (PATH_MAX - 1) - (strlen(PROC_STRING) + strlen(MAPS_STRING)), "%d", target);

	tmp_ptr = strchr(buffer, '\0');
	memcpy(tmp_ptr, MAPS_STRING, strlen(MAPS_STRING));

	if((fd = open(buffer, O_RDONLY)) == -1){
		fprintf(stderr, "open(%s, O_RDONLY): %s\n", buffer, strerror(errno));
		goto CLEAN_UP;
	}


	memset(buffer, 0, buffer_len);
	tmp_ptr = buffer;

	while((ret_int = read(fd, tmp_ptr, 1)) > 0){
		if(*tmp_ptr	== '\n'){
			*tmp_ptr = '\0';

			if((map_tmp = parse_next_line(buffer)) == NULL){
				fprintf(stderr, "parse_next_line(%s): %s\n", buffer, strerror(errno));
				goto CLEAN_UP;
			}

			if(!map_head){
				map_head = map_tmp;
				map_tail = map_tmp;
			}else{
				map_tail->next = map_tmp;
				map_tmp->previous = map_tail;
				map_tail = map_tmp;
			}

			memset(buffer, 0, buffer_len);
			tmp_ptr = buffer;

		}else{
			tmp_ptr++;
		}
	}

	if(ret_int == -1){
		fprintf(stderr, "read(%d, %lx, 1): %s\n", fd, (unsigned long) tmp_ptr, strerror(errno));
		goto CLEAN_UP;
	}


	free(buffer);
	close(fd);
	return(map_head);


CLEAN_UP:

	free(buffer);
	close(fd);
	free_parse_maps_list(map_head);
	return(NULL);
}


/***********************************************************************************************************************
 *
 *	parse_next_line()
 *
 *		Input:
 *			A pointer to the string that represents the next line of the file.
 *
 *		Output:
 *			A pointer to the next node, as created from this line.
 *
 *		Purpose:
 *			This is a helper function, not exposed externally. It parses a line and returns a node. Enough said. :)
 *
 **********************************************************************************************************************/
struct parse_maps *parse_next_line(char *line){

	struct parse_maps *node = NULL;
	char *token_head, *token_tail;

	// The comments mentioning data types are just trying to demonstrate
	// the type of data we will be parsing in that area.

	if((node = (struct parse_maps *) calloc(1, sizeof(struct parse_maps))) == NULL){
		fprintf(stderr, "calloc(1, %d): %s\n", (int) sizeof(struct parse_maps), strerror(errno));
		goto CLEAN_UP;
	}

	// unsigned long start_address;
	token_head = line;
	if((token_tail = strchr(token_head, '-')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, '-', strerror(errno));
		goto CLEAN_UP;
	}

	*token_tail = '\0';
	node->start_address = strtoul(token_head, NULL, 16);

	// unsigned long end_address;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->end_address = strtoul(token_head, NULL, 16);

	// unsigned int perms;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	if(*(token_head++) == 'r'){
		node->perms |= MAPS_READ;
	}
	if(*(token_head++) == 'w'){
		node->perms |= MAPS_WRITE;
	}
	if(*(token_head++) == 'x'){
		node->perms |= MAPS_EXECUTE;
	}
	if(*token_head == 'p'){
		node->perms |= MAPS_PRIVATE;
	}else if(*token_head == 's'){
		node->perms |= MAPS_SHARED;
	}

	// unsigned long offset;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->offset = strtoul(token_head, NULL, 16);

	// unsigned int dev_major;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ':')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ':', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->dev_major = strtol(token_head, NULL, 16);

	// unsigned int dev_minor;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->dev_minor = strtol(token_head, NULL, 16);

	// unsigned long inode;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->inode = strtol(token_head, NULL, 10);

	// char pathname[PATH_MAX];
	token_head = token_tail + 1;
	if(*token_head){
		if((token_head = strrchr(token_head, ' ')) == NULL){
			fprintf(stderr, "strrchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
			goto CLEAN_UP;
		}
		token_head++;
		memcpy(node->pathname, token_head, strlen(token_head));
	}

	return(node);

CLEAN_UP:
	free(node);
	return(NULL);
}


/***********************************************************************************************************************
 *
 *	free_parse_maps_list()
 *
 *		Input:
 *			A pointer to the head of the list.
 *
 *		Output:
 *			Nothing.
 *
 *		Purpose:
 *			Free the members of the linked list.
 *
 **********************************************************************************************************************/
void free_parse_maps_list(struct parse_maps *head){
	struct parse_maps *tmp;

	while(head){
		tmp = head->next;
		free(head);
		head = tmp;
	}
}


/***********************************************************************************************************************
 *
 *	dump_parse_maps_list()
 *
 *		Input:
 *			A pointer to the head of the list.
 *
 *		Output:
 *			Nothing, but it will print representations of the internal data to stdout.
 *
 *		Purpose:
 *			Show us what the linked list looks like. Mostly intended for debugging.
 *
 **********************************************************************************************************************/
void dump_parse_maps_list(struct parse_maps *head){

	while(head){
		printf("--------------------------------------------------------------------------------\n");	
		printf("node: %lx\n", (unsigned long) head);
		printf("--------------------------------------------------------------------------------\n");	
		printf("start_address:\t\t%lx\n", head->start_address);
		printf("end_address:\t\t%lx\n", head->end_address);
		printf("perms:\t\t\t%05x\n", head->perms);
		printf("offset:\t\t\t%lx\n", head->offset);
		printf("dev_major:\t\t%x\n", head->dev_major);
		printf("dev_minor:\t\t%x\n", head->dev_minor);
		printf("inode:\t\t\t%lx\n", head->inode);
		printf("pathname:\t\t%s\n", head->pathname);

		printf("parse_maps *next:\t%lx\n", (unsigned long) head->next);
		printf("parse_maps *previous:\t%lx\n", (unsigned long) head->previous);
		printf("\n");

		head = head->next;
	}
}
