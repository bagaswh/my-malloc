#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef int64_t i64;
typedef uintptr_t uptr;
typedef intptr_t iptr;

#define HEAP_SIZE_DEFAULT (iptr)(100 * 1024 * 1024)
#define BRK_FAILED (void *)-1

/* Block header and footer size in bytes */
#define BLOCK_HEADER_SIZE 4
#define BLOCK_FOOTER_SIZE BLOCK_HEADER_SIZE

#define INLINE __attribute__((always_inline))
#define NOINLINE __attribute__((noinline))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define FLAG1_INITIALIZED 0x1

/* Forward declarations */
static u32 INLINE get_block_size(u32 hdr);
static bool INLINE is_free(u32 hdr);
static bool INLINE is_allocated(u32 hdr);
static bool INLINE is_prev_block_allocated(u32 hdr);
static u32 INLINE set_hdr_as_prev_allocated(u32 hdr);

/* Static variables, will be put into .data segment in the process addr space */

static u8 flag1 = 0;
static char *mem_heap;      /* Points to the first byte of heap */
static char *mem_brk;       /* Points to the last byte of heap plus 1 */
static char *mem_max_addr;  /* Max legal heap address plus 1 */
static char *last_fit_addr; /* The address of last fit block */

#define HEAP_SIZE() (size_t)(mem_brk - mem_heap)

/* Debugging constants toggles */
static const bool config_debug =
#ifdef MYMALLOC_DEBUG
    true
#else
    false
#endif
    ;

static const bool debug_list_all_blocks =
#ifdef MYMALLOC_DEBUG
    true
#else
    false
#endif
    ;

/* Debugging */
#define mym_debug_prefix "[mym_debug : %s] "

#define mym_debug0(source, fmt)                   \
	do {                                          \
		if (unlikely(config_debug)) {             \
			printf(mym_debug_prefix fmt, source); \
		}                                         \
	} while (0)

#define mym_debug1(source, fmt, v1)                   \
	do {                                              \
		if (unlikely(config_debug)) {                 \
			printf(mym_debug_prefix fmt, source, v1); \
		}                                             \
	} while (0)

#define mym_debug2(source, fmt, v1, v2)                   \
	do {                                                  \
		if (unlikely(config_debug)) {                     \
			printf(mym_debug_prefix fmt, source, v1, v2); \
		}                                                 \
	} while (0)

#define mym_debug_heap_size(source) mym_debug1(source, "heap_size: %u\n", HEAP_SIZE())
#define mym_debug_mem_heap(source) mym_debug1(source, "mem_heap: %u\n", mem_heap)
#define mym_debug_mem_brk(source) mym_debug1(source, "mem_brk: %u\n", mem_brk)
#define mym_debug_last_fit_addr(source) mym_debug1("last_fit_addr: %u\n", source, last_fit_addr)

/* Assertions */
#define mym_assert(e)                                            \
	do {                                                         \
		if (unlikely(config_debug && !(e))) {                    \
			printf(                                              \
			    "<mymalloc>: %s:%d: Failed assertion: \"%s\"\n", \
			    __FILE__, __LINE__, #e);                         \
			abort();                                             \
		}                                                        \
	} while (0)

static void INLINE mym_debug_list_all_blocks() {
	if (unlikely(config_debug)) {
		u32 block_n = 0;
		mym_debug_heap_size("mym_debug_list_all_blocks");
		printf("## All blocks list\n");
		for (char *ptr = mem_heap; ptr < mem_brk;) {
			u32 hdr;
			memcpy(&hdr, ptr, sizeof(u32));
			u32 block_size = get_block_size(hdr);
			bool _is_free = is_free(hdr);
			printf("\n");
			printf("## %s Block %d ##\n", _is_free ? "[FREE]" : "[ALLOCATED]", block_n);
			if (is_prev_block_allocated(hdr)) {
				printf("- Prev block is allocated\n");
			}
			printf("- Size: %u\n", block_size);
			printf("- Start addr: %u\n", ptr);
			printf("- End addr: %u\n", ptr + block_size);
			if (_is_free) {
				printf("- Free\n");
			} else {
				printf("- Allocated\n");
				printf("- Payload size: %u\n", block_size - BLOCK_HEADER_SIZE);
			}
			void *footaddr = ptr + block_size - BLOCK_FOOTER_SIZE;
			/* Debug if there's a footer where it shouldn't be */
			u32 ftr;
			memcpy(&ftr, footaddr, sizeof(u32));
			if (ftr == hdr) { /* There might be footer in here */
				printf("- Footer: %u\n", ftr);
				if (is_allocated(hdr)) {
					printf("- Footer should not in allocated block. This is a problem!");
				}
			}
			block_n++;
			if (block_n > 2) {
				return;
			}
			ptr += block_size;
		}
	}
}

static bool INLINE is_initialized() {
	return (flag1 & FLAG1_INITIALIZED) != 0;
}

static uptr INLINE align_8(uptr addr) {
	return (((addr) + 7) & (~7));
}

static bool INLINE is_allocated(u32 hdr) {
	return (hdr & 0x1) == 0x1;
}

static bool INLINE is_prev_block_allocated(u32 hdr) {
	return (hdr & 0x2) == 0x2;
}

static bool INLINE is_free(u32 hdr) {
	return (hdr & 0x1) == 0x0;
}

static u32 INLINE get_block_size(u32 hdr) {
	return hdr & 0xFFFFFFF8;  // turn off lowest bit
}

static u32 INLINE set_hdr_as_free(u32 hdr) {
	return hdr & 0xFFFFFFFE;  // turn off lowest bit
}

static u32 INLINE set_hdr_as_allocated(u32 hdr) {
	return hdr | 0x1;  // turn on lowest bit
}

static u32 INLINE set_hdr_as_prev_allocated(u32 hdr) {
	return hdr | 0x2;  // turn on 2nd from lowest bit
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

static void INLINE write_block_hdr(void *hdrptr, u32 size, bool with_footer, bool allocated) {
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
		mym_assert(((mem_brk - mem_heap) == HEAP_SIZE_DEFAULT));
		mym_debug_heap_size("mm_init");
		last_fit_addr = mem_heap;

		// setup very first block
		write_block_hdr(mem_heap, align_8(HEAP_SIZE_DEFAULT), true, false);

		flag1 |= FLAG1_INITIALIZED;
	}
	return 0;
}

static void INLINE split(char *block_start_ptr, u32 orig_block_size, u32 alloc_block_size) {
	/* Write current block header to change size */
	u32 curr_block_new_size = alloc_block_size;
	write_block_hdr(
	    block_start_ptr,
	    curr_block_new_size,
	    false, /* No footer since it's now allocated */
	    true);

	/* The new free block */
	/* Go to the next block after alloc_block_size, and put a header in there */
	char *next_block_hdr_ptr = (void *)((uptr)block_start_ptr + (uptr)alloc_block_size);
	u32 new_block_size = orig_block_size - alloc_block_size;
	write_block_hdr(
	    next_block_hdr_ptr,                        /* Go the the next block */
	    set_hdr_as_prev_allocated(new_block_size), /* Encode the information that the previous block is allocated in the header of the next block */
	    true, false);

#ifdef MYMALLOC_DEBUG
	u32 nb_hdr;
	memcpy(&nb_hdr, next_block_hdr_ptr, BLOCK_HEADER_SIZE);
	mym_debug2("split", "next block header: %u, next block header prev block is allocated bit: %u\n", nb_hdr, nb_hdr & 0x2);

	u32 cb_hdr;
	memcpy(&cb_hdr, block_start_ptr, BLOCK_HEADER_SIZE);
	mym_debug1("split", "curr block header after split: %u\n", cb_hdr);
#endif
}

void *mm_malloc(size_t size) {
	if (unlikely(!is_initialized()) && (mm_init() == -1)) {
		errno = ENOMEM;
		return NULL;
	}

	/* Traverse from the start of the heap until program break,
	finding block with next fit policy */

	char *ptr = last_fit_addr;
	const size_t asize = align_8(BLOCK_HEADER_SIZE + size);
	// for (;;) {
	for (; ptr < mem_brk;) {
		/* At the very start of the heap, we will always see a block header */
		u32 hdr;
		memcpy(&hdr, ptr, sizeof(u32));
		u32 block_size = get_block_size(hdr);
		if (is_free(hdr) && (block_size >= asize)) {
			hdr = set_hdr_as_allocated(hdr);
			memcpy(ptr, &hdr, sizeof(hdr));
			last_fit_addr = ptr;
			split(ptr, block_size, asize);
			mym_debug_list_all_blocks();
			return ptr + BLOCK_HEADER_SIZE;
		}
		ptr += block_size;
	}

	/* We haven't found free block, need to grow the heap */
	// mem_brk = mem_sbrk(asize);
	// }
}

static void INLINE coalesce() {}
