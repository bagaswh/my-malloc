#define _GNU_SOURCE

#ifndef MEMLIB_H
#define MEMLIB_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef int64_t i64;
typedef uintptr_t uptr;
typedef intptr_t iptr;

#define HEAP_SIZE_DEFAULT (iptr)(1 * 1024 * 1024)
#define BRK_FAILED (void *)-1

/* Block header and footer size in bytes */
#define BLOCK_HEADER_SIZE 4
#define BLOCK_FOOTER_SIZE BLOCK_HEADER_SIZE

#define INLINE __attribute__((always_inline))
#define NOINLINE __attribute__((noinline))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define FLAG1_INITIALIZED 0x1

/* Static variables, will be put into .data segment in the process */

static bool flag1 = 0;
static char *mem_heap;      /* Points to the first byte of heap */
static char *mem_brk;       /* Points to the last byte of heap plus 1 */
static char *mem_max_addr;  /* Max legal heap address plus 1 */
static char *last_fit_addr; /* The address of last fit block */

#ifdef MYMALLOC_DEBUG
#include <stdio.h>
#define mym_debug_prefix "[mym_debug - %s] "
#define mym_debug0(source, fmt) printf(mym_debug_prefix fmt, source)
#define mym_debug1(source, fmt, v1) printf(mym_debug_prefix "%s %x\n", source, fmt, v1)
#define mym_debug_mem_heap(source) mym_debug1("mem_heap: %d\n", source, mem_heap)
#define mym_debug_mem_brk(source) mym_debug1("mem_brk: %d\n", source, mem_brk)
#define mym_debug_last_fit_adddr(source) mym_debug1("last_fit_addr: %d\n", source, last_fit_addr)
#else
#define mym_debug_prefix
#define mym_debug0(fmt, source)
#define mym_debug1(fmt, source, v1)
#define mym_debug_mem_brk(source)
#define mym_debug_mem_heap(source)
#define mym_debug_last_fit_adddr(source)
#endif

static bool INLINE is_initialized() {
	return (flag1 & FLAG1_INITIALIZED) != 0;
}

static uptr INLINE align_8(uptr addr) {
	return (((addr) + 7) & (~7));
}

static bool INLINE is_allocated(u32 hdr) {
	return (hdr & 0x1) == 0x1;
}

static bool INLINE is_free(u32 hdr) {
	return (hdr & 0x1) == 0x0;
}

static size_t INLINE get_block_size(u32 hdr) {
	return hdr & 0xFFFFFFF8;  // turn off lowest bit
}

static u32 INLINE set_hdr_as_free(u32 hdr) {
	return hdr & 0xFFFFFFF8;  // turn off lowest bit
}

static u32 INLINE set_hdr_as_allocated(u32 hdr) {
	return hdr | 0x1;  // turn on lowest bit
}

void *mem_sbrk(iptr increment) {
	if (increment < 0) {
		return NULL; /* deny deallocate */
	}

	return sbrk(increment);
}

static void INLINE zero_fill_footer(u32 size, void *hdrptr) {
	uptr footaddr = ((uptr)hdrptr) + size - BLOCK_FOOTER_SIZE;
	memset((void *)footaddr, 0, BLOCK_FOOTER_SIZE);
}

static void INLINE write_block_hdr(u32 size, void *hdrptr, bool with_footer, bool allocated) {
	if (allocated) {
		size = set_hdr_as_allocated(size);
	} else {
		size = set_hdr_as_free(size);
	}
	memcpy(hdrptr, &size, sizeof(size));
	if (with_footer) {
		uptr footaddr = ((uptr)hdrptr) + size - BLOCK_FOOTER_SIZE;
		memcpy((void *)footaddr, &size, sizeof(size));
	}
}

static int INLINE mm_init() {
	if (!is_initialized()) {
		mem_heap = mem_sbrk(HEAP_SIZE_DEFAULT);
		if (mem_heap == BRK_FAILED) {
			errno = ENOMEM;
			return -1;
		}
		mem_brk = mem_heap + HEAP_SIZE_DEFAULT;
		mym_debug_mem_brk("mm_init");
		mym_debug_mem_heap("mm_init");
		last_fit_addr = mem_heap;

		// setup very first block
		write_block_hdr(align_8(HEAP_SIZE_DEFAULT), mem_heap, true, false);

		flag1 |= FLAG1_INITIALIZED;
	}
	return 0;
}

static void INLINE split(void *block_start_ptr, u32 orig_block_size, u32 alloc_block_size) {
	/* Go to the next block after alloc_block_size, and put a header in there */
	u32 new_block_size = orig_block_size - alloc_block_size;
	write_block_hdr(
	    new_block_size,
	    block_start_ptr + alloc_block_size, /* Go the the next block */
	    true, false);
}

void *mm_malloc(size_t size) {
	if (unlikely(!is_initialized()) && (mm_init() == -1)) {
		errno = ENOMEM;
		return NULL;
	}

	/* Traverse from the start of the heap until program break,
	    finding block with next fit policy */
	char *ptr = last_fit_addr;
	const size_t asize = align_8(size);
	for (; ptr < mem_brk;) {
		/* At the very start of the heap, we will always see a block header */
		u32 hdr;
		memcpy(&hdr, ptr, sizeof(u32));
		u32 block_size = get_block_size(hdr);
		if (is_free(hdr) && (block_size >= asize)) {
			hdr = set_hdr_as_allocated(hdr);
			memcpy(ptr, &hdr, sizeof(hdr));
			last_fit_addr = ptr;
			zero_fill_footer(block_size, ptr); /* Remove footer */
			split(ptr, block_size, asize);
			return ptr + BLOCK_HEADER_SIZE;
		}
		ptr += block_size;
	}

	/* We haven't found free block, need to grow the heap */
}

static void INLINE coalesce() {}

#endif /* MEMLIB_H */