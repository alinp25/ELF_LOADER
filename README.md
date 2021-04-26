# ELF Loader

Pisica Alin-Georgian

334CC


## Introduction
The project sums up an on-demand loader in the [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) format. 

Each file is made up of one ELF header, followed by file date. This way of structuring the file involves the segmentation part of the loader, where the executable tries accessing addresses that have not been loaded into memory at the given point in time. On the signal propagation, the loader will treat the loading of a new page into the memory.

## Implementation

The executable parser is presented and written in in `exec_parser.c` (with its header `exec_parser.h`).

For setting and restorin the signal, the function `set_signal` will execute the following steps:
- The mask and the flags are being built the same way for both situations
- On a signal set the handler is attributted to the `sa_sigaction` field, while on restoring a signal the previous sigaction is brought back

To load a new page (`load_page`) we need to find the address of the fault action. For each segment, I used a new struct defined as `mapped_pages` (presented down below) that contains a flag array defining if the page indexed at a given position has been mapped or not. In this way, after finding the file, we can be in two scenarios: either the page has already been mapped (which would involve permissions problem) or we calculate the offset of the current page, followed by a new opperation of mapping.

```
typedef struct mapped_pages {
	char *is_mapped; // array of flags containing the status of each page
} mapped_pages;
```

## Usage Build the loader:
```
make
```

This should generate the `libso_loader.so` library. Next, build the example:

```
make -f Makefile.example
```

This should generate the `so_exec` and `so_test_prog` used for the test:

```
LD_LIBRARY_PATH=. ./so_exec so_test_prog
```

## Repository

Will become public after grading the homework
[https://github.com/alinp25/ELF_LOADER

## References
Labs + Courses ACS UPB SO 
https://dtrugman.medium.com/elf-loaders-libraries-and-executables-on-linux-e5cfce318f94
https://community.mellanox.com/s/article/understanding-on-demand-paging--odp-x