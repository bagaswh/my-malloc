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
static char *mem_heap;     /* Points to the first byte of heap */
static char *mem_brk;      /* Points to the last byte of heap plus 1 */
static char *mem_max_addr; /* Max legal heap address plus 1 */

static bool INLINE is_initialized() {
	return flag1 & FLAG1_INITIALIZED != 0;
}

static void INLINE write_block_size(size_t size, void *ptr, bool with_footer) {
	memcpy(ptr, &size, sizeof(size));
	if (with_footer) {
		uptr footeraddr = ((uptr)ptr) + size - BLOCK_FOOTER_SIZE;
		memcpy((void *)footeraddr, &size, 1);
	}
}

static uptr INLINE align_8(uptr addr) {
	return (((addr) + 7) & (~7));
}

void *mem_sbrk(iptr increment) {
	if (increment < 0) {
		return NULL; /* deny deallocate */
	}

	return sbrk(increment);
}

static int INLINE mm_init() {
	if (!is_initialized()) {
		mem_heap = mem_sbrk(HEAP_SIZE_DEFAULT);
		if (mem_heap == BRK_FAILED) {
			errno = ENOMEM;
			return -1;
		}
		mem_brk = mem_heap + HEAP_SIZE_DEFAULT;

		// setup very first block
		write_block_size(HEAP_SIZE_DEFAULT, mem_heap, true);

		flag1 |= FLAG1_INITIALIZED;
	}
	return 0;
}

static bool INLINE is_allocated(u32 hdr) {
	return (hdr & 0x1) == 0x1;
}

static bool INLINE is_free(u32 hdr) {
	return (hdr & 0x1) == 0x0;
}

void *mm_malloc(size_t size) {
	if (unlikely(!is_initialized()) && (mm_init() == -1)) {
		errno = ENOMEM;
		return NULL;
	}

	/* Traverse from the start of the heap until program break,
	    finding block with first fit policy */
	for (char *ptr = mem_heap; ptr < mem_brk; ptr++) {
		/* At the very start of the heap, we will always see a block header */
		u32 hdr_bs;
		memcpy(&hdr_bs, ptr, sizeof(u32));
		ptr += hdr_bs;
		if (is_free(hdr_bs)) {
		}
	}
}

#endif /* MEMLIB_H */