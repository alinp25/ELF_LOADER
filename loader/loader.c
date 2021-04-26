#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "exec_parser.h"
#include "debug.h"
#include "utils.h"

typedef struct mapped_pages {
	char *is_mapped;
} mapped_pages;

int file;
so_exec_t *exec;
struct sigaction old_action;

void handler(int signum, siginfo_t *info, void *context);

void set_signal(int should_restore)
{
	struct sigaction action;

	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	if (should_restore == 0) {
		action.sa_sigaction = handler;

		sigaction(SIGSEGV, &action, &old_action);
	} else {
		action.sa_sigaction = old_action.sa_sigaction;

		sigaction(SIGSEGV, &action, NULL);
	}
}

int check_segment_fault_address(int fault_address, so_seg_t segment) {
	int lower_bound = segment.vaddr;
	int upper_bound = segment.vaddr + segment.mem_size;

	if (fault_address >= lower_bound && fault_address <= upper_bound)
		return 1;

	return 0;
}

void load_page(so_seg_t* segment, int fault_address) {
	mapped_pages *data;

	int size = (fault_address - (int)segment->vaddr) / getpagesize();

	void *res = mmap(
		(void *)(segment->vaddr + size * getpagesize()),
		getpagesize(),
		PROT_WRITE,
		MAP_FIXED | MAP_PRIVATE,
		file,
		size * getpagesize() + segment->offset
	);
	
	if (getpagesize() * (size + 1) >= segment->file_size) {
		void * ptr = (void*)(segment->file_size + segment->vaddr);
		int value = 0;
		size_t num = -segment->file_size;

		if (getpagesize() * (size + 1) <= segment->mem_size) {
			num += getpagesize() * (size + 1);
		} else {
			num += segment->mem_size;
		}

		memset(ptr, value, num);
	}

	mprotect(res, getpagesize(), segment->perm);

	data = (mapped_pages*)(segment->data);
	data->is_mapped[(fault_address - segment->vaddr) / getpagesize()] = 1;
}

void handler(int signum, siginfo_t *info, void *context)
{
	mapped_pages *data;

	int i;
	int fault_address;
	int found_faults = 0;

	if (signum != SIGSEGV) {
		set_signal(1);
		return;
	}

	fault_address = (int)info->si_addr;

	for (i = 0; i < exec->segments_no; i++) {
		if (check_segment_fault_address(fault_address, exec->segments[i])) {
			data = (mapped_pages*)exec->segments[i].data;

			if (data->is_mapped[(fault_address - exec->segments[i].vaddr) /
						getpagesize()]) {
				break;
			}

			load_page(&exec->segments[i], (int)fault_address);
			found_faults = 1;
			break;
		}
	}

	if (found_faults == 0) {
		set_signal(1);
		return;
	}
}

int so_init_loader(void) {
	set_signal(0);

	return 0;
}

void init_mapped_pages() {
	int i;

	for (i = 0; i < exec->segments_no; i++) {
		exec->segments[i].data = (mapped_pages*)malloc(sizeof(mapped_pages));

		int number_of_pages = exec->segments[i].mem_size / getpagesize() + 1;

		((mapped_pages*)exec->segments[i].data)->is_mapped
			= (char *)calloc(number_of_pages, sizeof(char));
	}
}

int so_execute(char *path, char *argv[])
{

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	file = open(path, O_RDONLY);

	init_mapped_pages();

	so_start_exec(exec, argv);

	return 0;
}
