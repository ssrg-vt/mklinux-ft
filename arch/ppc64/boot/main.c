/*
 * Copyright (C) Paul Mackerras 1997.
 *
 * Updates for PPC64 by Todd Inglett, Dave Engebretsen & Peter Bergner.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <stdarg.h>
#include <stddef.h>
#include "elf.h"
#include "page.h"
#include "string.h"
#include "stdio.h"
#include "prom.h"
#include "zlib.h"

static void gunzip(void *, int, unsigned char *, int *);
extern void flush_cache(void *, unsigned long);


/* Value picked to match that used by yaboot */
#define PROG_START	0x01400000
#define RAM_END		(512<<20) // Fixme: use OF */
#define	ONE_MB		0x100000

extern char _start[];
extern char _end[];
extern char _vmlinux_start[];
extern char _vmlinux_end[];
extern char _initrd_start[];
extern char _initrd_end[];
extern unsigned long vmlinux_filesize;
extern unsigned long vmlinux_memsize;

struct addr_range {
	unsigned long addr;
	unsigned long size;
	unsigned long memsize;
};
static struct addr_range vmlinux = {0, 0, 0};
static struct addr_range vmlinuz = {0, 0, 0};
static struct addr_range initrd  = {0, 0, 0};

static char scratch[46912];	/* scratch space for gunzip, from zlib_inflate_workspacesize() */


typedef void (*kernel_entry_t)( unsigned long,
                                unsigned long,
                                void *,
				void *);


#undef DEBUG

static unsigned long claim_base;

static unsigned long try_claim(unsigned long size)
{
	unsigned long addr = 0;

	for(; claim_base < RAM_END; claim_base += ONE_MB) {
#ifdef DEBUG
		printf("    trying: 0x%08lx\n\r", claim_base);
#endif
		addr = (unsigned long)claim(claim_base, size, 0);
		if ((void *)addr != (void *)-1)
			break;
	}
	if (addr == 0)
		return 0;
	claim_base = PAGE_ALIGN(claim_base + size);
	return addr;
}

void start(unsigned long a1, unsigned long a2, void *promptr)
{
	unsigned long i;
	kernel_entry_t kernel_entry;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *elf64ph;

	prom = (int (*)(void *)) promptr;
	chosen_handle = finddevice("/chosen");
	if (chosen_handle == (void *) -1)
		exit();
	if (getprop(chosen_handle, "stdout", &stdout, sizeof(stdout)) != 4)
		exit();
	stderr = stdout;
	if (getprop(chosen_handle, "stdin", &stdin, sizeof(stdin)) != 4)
		exit();

	printf("\n\rzImage starting: loaded at 0x%lx\n\r", (unsigned long) _start);

	/*
	 * The first available claim_base must be above the end of the
	 * the loaded kernel wrapper file (_start to _end includes the
	 * initrd image if it is present) and rounded up to a nice
	 * 1 MB boundary for good measure.
	 */

	claim_base = _ALIGN_UP((unsigned long)_end, ONE_MB);

#if defined(PROG_START)
	/*
	 * Maintain a "magic" minimum address. This keeps some older
	 * firmware platforms running.
	 */

	if (claim_base < PROG_START)
		claim_base = PROG_START;
#endif

	/*
	 * Now we try to claim some memory for the kernel itself
	 * our "vmlinux_memsize" is the memory footprint in RAM, _HOWEVER_, what
	 * our Makefile stuffs in is an image containing all sort of junk including
	 * an ELF header. We need to do some calculations here to find the right
	 * size... In practice we add 1Mb, that is enough, but we should really
	 * consider fixing the Makefile to put a _raw_ kernel in there !
	 */
	vmlinux_memsize += ONE_MB;
	printf("Allocating 0x%lx bytes for kernel ...\n\r", vmlinux_memsize);
	vmlinux.addr = try_claim(vmlinux_memsize);
	if (vmlinux.addr == 0) {
		printf("Can't allocate memory for kernel image !\n\r");
		exit();
	}
	vmlinuz.addr = (unsigned long)_vmlinux_start;
	vmlinuz.size = (unsigned long)(_vmlinux_end - _vmlinux_start);
	vmlinux.size = PAGE_ALIGN(vmlinux_filesize);
	vmlinux.memsize = vmlinux_memsize;

	/*
	 * Now we try to claim memory for the initrd (and copy it there)
	 */
	initrd.size = (unsigned long)(_initrd_end - _initrd_start);
	initrd.memsize = initrd.size;
	if ( initrd.size > 0 ) {
		printf("Allocating 0x%lx bytes for initrd ...\n\r", initrd.size);
		initrd.addr = try_claim(initrd.size);
		if (initrd.addr == 0) {
			printf("Can't allocate memory for initial ramdisk !\n\r");
			exit();
		}
		a1 = initrd.addr;
		a2 = initrd.size;
		printf("initial ramdisk moving 0x%lx <- 0x%lx (0x%lx bytes)\n\r",
		       initrd.addr, (unsigned long)_initrd_start, initrd.size);
		memmove((void *)initrd.addr, (void *)_initrd_start, initrd.size);
		printf("initrd head: 0x%lx\n\r", *((unsigned long *)initrd.addr));
	}

	/* Eventually gunzip the kernel */
	if (*(unsigned short *)vmlinuz.addr == 0x1f8b) {
		int len;
		printf("gunzipping (0x%lx <- 0x%lx:0x%0lx)...",
		       vmlinux.addr, vmlinuz.addr, vmlinuz.addr+vmlinuz.size);
		len = vmlinuz.size;
		gunzip((void *)vmlinux.addr, vmlinux.size,
			(unsigned char *)vmlinuz.addr, &len);
		printf("done 0x%lx bytes\n\r", len);
	} else {
		memmove((void *)vmlinux.addr,(void *)vmlinuz.addr,vmlinuz.size);
	}

	/* Skip over the ELF header */
	elf64 = (Elf64_Ehdr *)vmlinux.addr;
	if ( elf64->e_ident[EI_MAG0]  != ELFMAG0	||
	     elf64->e_ident[EI_MAG1]  != ELFMAG1	||
	     elf64->e_ident[EI_MAG2]  != ELFMAG2	||
	     elf64->e_ident[EI_MAG3]  != ELFMAG3	||
	     elf64->e_ident[EI_CLASS] != ELFCLASS64	||
	     elf64->e_ident[EI_DATA]  != ELFDATA2MSB	||
	     elf64->e_type            != ET_EXEC	||
	     elf64->e_machine         != EM_PPC64 )
	{
		printf("Error: not a valid PPC64 ELF file!\n\r");
		exit();
	}

	elf64ph = (Elf64_Phdr *)((unsigned long)elf64 +
				(unsigned long)elf64->e_phoff);
	for(i=0; i < (unsigned int)elf64->e_phnum ;i++,elf64ph++) {
		if (elf64ph->p_type == PT_LOAD && elf64ph->p_offset != 0)
			break;
	}
#ifdef DEBUG
	printf("... skipping 0x%lx bytes of ELF header\n\r",
			(unsigned long)elf64ph->p_offset);
#endif
	vmlinux.addr += (unsigned long)elf64ph->p_offset;
	vmlinux.size -= (unsigned long)elf64ph->p_offset;

	flush_cache((void *)vmlinux.addr, vmlinux.size);

	kernel_entry = (kernel_entry_t)vmlinux.addr;
#ifdef DEBUG
	printf( "kernel:\n\r"
		"        entry addr = 0x%lx\n\r"
		"        a1         = 0x%lx,\n\r"
		"        a2         = 0x%lx,\n\r"
		"        prom       = 0x%lx,\n\r"
		"        bi_recs    = 0x%lx,\n\r",
		(unsigned long)kernel_entry, a1, a2,
		(unsigned long)prom, NULL);
#endif

	kernel_entry( a1, a2, prom, NULL );

	printf("Error: Linux kernel returned to zImage bootloader!\n\r");

	exit();
}

#define HEAD_CRC	2
#define EXTRA_FIELD	4
#define ORIG_NAME	8
#define COMMENT		0x10
#define RESERVED	0xe0

static void gunzip(void *dst, int dstlen, unsigned char *src, int *lenp)
{
	z_stream s;
	int r, i, flags;

	/* skip header */
	i = 10;
	flags = src[3];
	if (src[2] != Z_DEFLATED || (flags & RESERVED) != 0) {
		printf("bad gzipped data\n\r");
		exit();
	}
	if ((flags & EXTRA_FIELD) != 0)
		i = 12 + src[10] + (src[11] << 8);
	if ((flags & ORIG_NAME) != 0)
		while (src[i++] != 0)
			;
	if ((flags & COMMENT) != 0)
		while (src[i++] != 0)
			;
	if ((flags & HEAD_CRC) != 0)
		i += 2;
	if (i >= *lenp) {
		printf("gunzip: ran out of data in header\n\r");
		exit();
	}

	if (zlib_inflate_workspacesize() > sizeof(scratch)) {
		printf("gunzip needs more mem\n");
		exit();
	}
	memset(&s, 0, sizeof(s));
	s.workspace = scratch;
	r = zlib_inflateInit2(&s, -MAX_WBITS);
	if (r != Z_OK) {
		printf("inflateInit2 returned %d\n\r", r);
		exit();
	}
	s.next_in = src + i;
	s.avail_in = *lenp - i;
	s.next_out = dst;
	s.avail_out = dstlen;
	r = zlib_inflate(&s, Z_FINISH);
	if (r != Z_OK && r != Z_STREAM_END) {
		printf("inflate returned %d msg: %s\n\r", r, s.msg);
		exit();
	}
	*lenp = s.next_out - (unsigned char *) dst;
	zlib_inflateEnd(&s);
}

