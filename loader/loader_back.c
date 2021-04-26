/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include "exec_parser.h"

#include "utils.h"

#define PAGE_SIZE 0x1000

static so_exec_t *exec;

static struct sigaction old_action;
static int file;

void handler(int signum, siginfo_t *info, void *context);

typedef struct mapped_pages {
	char *is_mapped;
	int size;
} mapped_pages;

/**
* Sets the signal
* int should_restore -> 0 -> registers the handler
* 					 -> 1 -> uses the handler from the old action
*/
static void set_signal(int should_restore)
{
	struct sigaction action;
	int rc;

    if (should_restore == 1) {
        action.sa_sigaction = old_action.sa_sigaction;
    } else {
        action.sa_sigaction = handler;
    }
    
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

    if (should_restore == 1) {
	    rc = sigaction(SIGSEGV, &action, NULL);
    } else {
        rc = sigaction(SIGSEGV, &action, &old_action);
    }

	DIE(rc == 0, "sigaction");
}

static int check_segment_address(uintptr_t address, so_seg_t segment) {
	uintptr_t lower_bound = segment.vaddr;
	uintptr_t upper_bound = segment.vaddr + segment.mem_size;

	if (address >= lower_bound && address <= upper_bound)
		return 1;

	return 0;
}

void load_page(so_seg_t* segment, uintptr_t address) {
	mapped_pages *data;

	// int total_size = (address - (int)segment->vaddr) / PAGE_SIZE;
	// int offset = (address - segment->vaddr) / PAGE_SIZE;

	void *res;

	// int should_map = total_size * PAGE_SIZE < segment->file_size ? 1 : 0;

	// if (should_map == 1) {
	// 	res = mmap(
	// 		(void *)(segment->vaddr + total_size * PAGE_SIZE),
	// 		PAGE_SIZE,
	// 		PROT_WRITE,
	// 		MAP_FIXED | MAP_PRIVATE,
	// 		file,
	// 		// offset);
	// 		total_size * PAGE_SIZE + segment->offset);

		// if (PAGE_SIZE * (total_size + 1) >= segment->file_size) {
		// 	if (PAGE_SIZE * (total_size + 1) <= segment->mem_size) {
		// 		memset(
		// 			(void*)(segment->file_size + segment->vaddr),
		// 			0,
		// 			PAGE_SIZE * (total_size + 1) - segment->file_size);
		// 	} else {
		// 		memset(
		// 			(void*)(segment->file_size + segment->vaddr),
		// 			0,
		// 			segment->mem_size - segment->file_size);
		// 	}
		// }
	// } else {
	// 	res = mmap(
	// 		(void *)(segment->vaddr + total_size * PAGE_SIZE),
	// 		PAGE_SIZE,
	// 		PROT_WRITE,
	// 		MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
	// 		-1,
	// 		0);
	// }

	// if (should_map == 1 && (total_size + 1) * PAGE_SIZE >= segment->file_size) {
	// 	if ((total_size + 1) * PAGE_SIZE < segment->mem_size) {
	// 		memset(
	// 			(void*)(segment->vaddr + segment->file_size),
	// 			0,
	// 			PAGE_SIZE * (total_size + 1) - segment->file_size
	// 		);
	// 	} else {
	// 		memset(
	// 			(void*)(segment->vaddr + segment->file_size),
	// 			0,
	// 			(((int)address - segment->vaddr) / PAGE_SIZE + 1) * PAGE_SIZE - segment->mem_size - segment->file_size
	// 		);
	// 	}
	// }
	
	// mprotect(res, PAGE_SIZE, segment->perm);

	// data = (mapped_pages*)(segment->data);
	// data->is_mapped[offset] = 1;

	int permissions, zeroiseStartPosition;

	void *alignedAddr = (void*)ALIGN_DOWN(address, PAGE_SIZE);

	if (segment->vaddr + segment->file_size > (int)alignedAddr) {
		if (segment->file_size != segment->mem_size &&
		    ALIGN_DOWN(segment->vaddr + segment->file_size,
			       PAGE_SIZE) == (int)alignedAddr) {
			// hole is in current page
			zeroiseStartPosition = segment->file_size % PAGE_SIZE;
		} else {
			// no hole
			zeroiseStartPosition = -1;
		}
	} else {
		// over hole; current page is empty
		zeroiseStartPosition = 0;
	}

	permissions = segment->perm;
	if (zeroiseStartPosition >= 0) {
		// add write permissions so that we can zeroise the hole
		permissions |= PROT_WRITE;
	}	

	if (zeroiseStartPosition != -1) {
		res = mmap(alignedAddr, PAGE_SIZE, permissions,
			  MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
		DIE(res == MAP_FAILED, "mmap");
	}

	if (zeroiseStartPosition != 0) {
		res = mmap(alignedAddr,
			  zeroiseStartPosition == -1 ? PAGE_SIZE :
						       zeroiseStartPosition,
			  permissions, MAP_PRIVATE | MAP_FIXED, file,
			  segment->offset + (int)alignedAddr - segment->vaddr);
		DIE(res == MAP_FAILED, "mmap");
	}

	if (zeroiseStartPosition >= 0) {
		memset(alignedAddr + zeroiseStartPosition, 0,
		       PAGE_SIZE - zeroiseStartPosition);
	}

	if (zeroiseStartPosition >= 0) {
		// set correct permissions
		mprotect(alignedAddr, PAGE_SIZE, segment->perm);
	}

	data = (mapped_pages*)segment->data;
	data->is_mapped[((int)address - segment->vaddr) / PAGE_SIZE] = 1;

	return 0;
}

void handler(int signum, siginfo_t *info, void *context) {
	int found_fault = 0;
	so_seg_t *segment;
	mapped_pages *data;

	if (signum != SIGSEGV) {
		set_signal(1);

		return;
	}

	// char *address = (char *)info->si_addr;

	// for (int i = 0; i < exec->segments_no; i++) {
	// 	segment = &exec->segments[i];

	// 	if ((int)address >= )
	// 	// if (check_segment_address((uintptr_t)address, segment) == 1) {
	// 		mapped_pages* data = (mapped_pages*)((&(exec->segments[i]))->data);
			
	// 		int page_offset = ((int)address - exec->segments[i].vaddr) / PAGE_SIZE;

	// 		if (data->is_mapped[page_offset] == 1)
	// 			break;

	// 		load_page(&(exec->segments[i]), (int)address);
	// 		found_fault = 1;

	// 		break;
	// 	}
	// }
	int i;
	uintptr_t address = (uintptr_t)info->si_addr;
	for (i = 0; i < exec->segments_no; i++) {
		segment = &exec->segments[i];

		if (address >= segment->vaddr &&
		    address < segment->vaddr + segment->mem_size) {
			data = (mapped_pages *)segment->data;

			if (data->is_mapped[(address - segment->vaddr) /
						PAGE_SIZE]) {
				break;
			}

			load_page(segment, address);
			found_fault = 1;
			break;
		}
	}

	if (found_fault == 0) {
		set_signal(1);
		return;
	}
}

/**
* Initialize on-demand loader
*/
int so_init_loader(void)
{
	set_signal(0);
	
	return 0;
}

/**
* Executes the given process with the arguments
* char *path -> path to the executable
* char *argv[] -> parameters
*/
int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	file = open(path, O_RDONLY);

	for (int i = 0; i < exec->segments_no; i++) {
		so_seg_t *segment = &exec->segments[i];

		int number_of_pages = segment->mem_size / PAGE_SIZE + 1;

		segment->data = malloc(sizeof(mapped_pages));
		((mapped_pages*)segment->data)->size = number_of_pages;
		((mapped_pages*)segment->data)->is_mapped = (char *)calloc(number_of_pages, sizeof(char));

		DIE(((mapped_pages*)segment->data)->is_mapped, "calloc");
	}

	so_start_exec(exec, argv);

	return -1;
}
