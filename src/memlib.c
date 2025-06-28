#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <execinfo.h>  // Needed for backtrace
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;
typedef uintptr_t uptr;
typedef intptr_t iptr;

#define KiB 1024
#define MiB 1024 * KiB

#define HEAP_SIZE_DEFAULT (iptr)(4 * KiB)
#define BRK_FAILED (void *)-1
#define GROW_HEAP_FAILED (void *)-1
/*
    We grow heap size by 2x when the current heap size is less than this value.
*/
#define GROW_HEAP_DOUBLE_MAX_HEAP_SIZE 16 * KiB

/*
    Reserved 8 bytes put at the very last of the heap, to indicate whether the last block
    is allocated or free. This is used when growing the heap.
    When growing the heap, we want to coalesce newly free block with the previous adjacent free block.

    This header size has to be 8-byte aligned. Otherwise, block
    at the end of the heap with size align_8(block_size-HEAP_EPILOGUE_HEADER_SIZE)
    could overwrite this epilogue header.
*/
#define HEAP_EPILOGUE_HEADER_SIZE 8

/* Block header and footer size in bytes */

#define BLOCK_HEADER_SIZE 4
#define BLOCK_FOOTER_SIZE BLOCK_HEADER_SIZE

/*
    High bound for valid block address.
*/
#define VALID_BLOCK_ADDR_HI_BOUND mem_brk - HEAP_EPILOGUE_HEADER_SIZE

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
static void INLINE *grow_heap(size_t needs, char *last_block_ptr);
static u64 determine_heap_incr();

/* Static variables, will be put into .data segment in the process addr space */

static u8 flag1 = 0;
static char *mem_heap = 0;      /* Points to the first byte of heap */
static char *mem_brk = 0;       /* Points to the last byte of heap plus 1 */
static char *mem_max_addr;      /* Max legal heap address plus 1 */
static char *last_fit_addr = 0; /* The address of last fit block */

#define get_heap_size() (size_t)(mem_brk - mem_heap)

#define max(a, b) a > b ? a : b
#define min(a, b) a < b ? a : b

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
#define mym_debug_prefix "[mym_debug : %s:%d:%s] "

#define mym_debug0(source, fmt)                                       \
	do {                                                              \
		if (unlikely(config_debug)) {                                 \
			printf(mym_debug_prefix fmt, __FILE__, __LINE__, source); \
		}                                                             \
	} while (0)

#define mym_debug1(source, fmt, v1)                                       \
	do {                                                                  \
		if (unlikely(config_debug)) {                                     \
			printf(mym_debug_prefix fmt, __FILE__, __LINE__, source, v1); \
		}                                                                 \
	} while (0)

#define mym_debug2(source, fmt, v1, v2)                                       \
	do {                                                                      \
		if (unlikely(config_debug)) {                                         \
			printf(mym_debug_prefix fmt, __FILE__, __LINE__, source, v1, v2); \
		}                                                                     \
	} while (0)

#define mym_debug_heap_size(source) mym_debug1(source, "heap_size: %u\n", get_heap_size())
#define mym_debug_mem_heap(source) mym_debug1(source, "mem_heap: %p\n", mem_heap)
#define mym_debug_mem_brk(source) mym_debug1(source, "mem_brk: %p\n", mem_brk)
#define mym_debug_last_fit_addr(source) mym_debug1("last_fit_addr: %p\n", source, last_fit_addr)

/* Assertions */
#define print_backtrace()                                              \
	do {                                                               \
		void *bt[32];                                                  \
		int bt_size = backtrace(bt, 32);                               \
		char **bt_syms = backtrace_symbols(bt, bt_size);               \
		if (bt_syms) {                                                 \
			printf("<mymalloc>: Stack trace:\n");                      \
			for (int i = 0; i < bt_size; ++i) {                        \
				printf("  [%d] %s\n", i, bt_syms[i]);                  \
			}                                                          \
			free(bt_syms);                                             \
		} else {                                                       \
			printf("<mymalloc>: Failed to get stack trace symbols\n"); \
		}                                                              \
	} while (0)

#define mym_assert(e)                                            \
	do {                                                         \
		if (unlikely(config_debug && !(e))) {                    \
			printf(                                              \
			    "<mymalloc>: %s:%d: Failed assertion: \"%s\"\n", \
			    __FILE__, __LINE__, #e);                         \
			print_backtrace();                                   \
			abort();                                             \
		}                                                        \
	} while (0)

#define mym_assert_addr_within_bound(addr) mym_assert((addr >= mem_heap) && (addr < mem_brk))

static void INLINE print_block_info(void *hdrptr) {
	u32 hdr;
	memcpy(&hdr, hdrptr, sizeof(hdr));
	u32 block_size = get_block_size(hdr);

	bool _is_free = is_free(hdr);

	if (is_prev_block_allocated(hdr)) {
		printf("- Prev block is allocated\n");
	}

	if (_is_free) {
		printf("- Free\n");
	} else {
		printf("- Allocated\n");
		printf("- Payload size: %u\n", block_size - BLOCK_HEADER_SIZE);
	}

	printf("- Size: %u\n", block_size);
	printf("- Start addr: %u\n", hdrptr);
	printf("- End addr: %u\n", hdrptr + block_size);
}

static void INLINE mym_debug_list_all_blocks() {
	if (unlikely(config_debug)) {
		u32 block_n = 0;
		mym_debug_heap_size("mym_debug_list_all_blocks");
		printf("\n# All blocks list\n");
		char *ptr = mem_heap;
		for (; ptr < VALID_BLOCK_ADDR_HI_BOUND;) {
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
			printf("- Start addr: %p\n", ptr);
			printf("- End addr: %p\n", ptr + block_size);
			if (_is_free) {
				printf("- Free\n");
			} else {
				printf("- Allocated\n");
				printf("- Payload size: %u\n", block_size - BLOCK_HEADER_SIZE);
			}
			block_n++;
			ptr += block_size;
		}
		printf("\n## Epilogue Header\n");
		u64 epilogue;
		memcpy(&epilogue, ptr, sizeof(epilogue));
		printf("- Value: %u\n\n", epilogue);
	}
}

static bool INLINE is_initialized() {
	return (flag1 & FLAG1_INITIALIZED) == FLAG1_INITIALIZED;
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
	u32 asize;
	if (allocated) {
		asize = set_hdr_as_allocated(size);
	} else {
		asize = set_hdr_as_free(size);
	}
	// mym_assert_addr_within_bound(hdrptr + sizeof(asize));
	memcpy(hdrptr, &asize, sizeof(asize));
	if (with_footer) {
		uptr footaddr = ((uptr)hdrptr) + size - BLOCK_FOOTER_SIZE;
		// mym_assert_addr_within_bound(footaddr + sizeof(asize));
		mym_debug1("write_block_hdr", "footaddr: %p\n", footaddr);
		memcpy((void *)footaddr, &asize, sizeof(asize));
	}
}

static int INLINE mm_init() {
	if (unlikely(!is_initialized())) {
		u32 const heap_size = align_8(HEAP_SIZE_DEFAULT);
		void *new_heap = grow_heap(heap_size, 0);
		if (new_heap == GROW_HEAP_FAILED) {
			return -1;
		}
		mym_assert(get_heap_size() == heap_size);
		last_fit_addr = mem_heap;

		flag1 |= FLAG1_INITIALIZED;
	}
	return 0;
}

static u64 determine_heap_incr() {
	if (get_heap_size() < GROW_HEAP_DOUBLE_MAX_HEAP_SIZE) {
		return get_heap_size() * 2;
	}
	return (3 * GROW_HEAP_DOUBLE_MAX_HEAP_SIZE) >> 2;
}

static void INLINE *grow_heap(size_t needs, char *last_block_hdr_ptr) {
	mym_debug1("grow_heap", "needs to grow heap to serve %d bytes allocation request\n", needs);

	const char *old_brk = mem_brk;
	u32 sbrk_incr = max(needs, determine_heap_incr());
	mym_debug1("grow_heap", "sbrk_incr: %d\n", sbrk_incr);

	/* When growing heap, it needs to coalesce with the preceeding free block */
	u64 epilogue_hdr = 0x0;
	u32 last_block_size;
	if (likely(get_heap_size() > 0 && last_block_hdr_ptr > 0)) {
		u32 last_block_hdr;
		memcpy(&last_block_hdr, last_block_hdr_ptr, sizeof(last_block_hdr));
		/* We'll rely that the caller will provide us with a valid last block footer, so no need to check anything */
		if (is_allocated(last_block_hdr)) {
			epilogue_hdr = 0x1;
		} else {
			last_block_size = get_block_size(last_block_hdr);
			last_block_size += sbrk_incr;
			mym_debug1("grow_heap", "last_block_size after sbrk_incr: %d\n", last_block_size);
		}
	}

	const void *prev_brk = mem_sbrk(sbrk_incr);
	if (prev_brk == BRK_FAILED) {
		errno = ENOMEM;
		return GROW_HEAP_FAILED;
	}

	mym_debug2("grow_heap", "prev_brk: %p; mem_brk before increment: %p\n", prev_brk, mem_brk);

	if (mem_heap == 0) {
		mem_heap = prev_brk;
	}
	mem_brk = prev_brk + sbrk_incr;

	if (last_block_hdr_ptr > 0 && epilogue_hdr == 0x0) {
		/* Coalesce prev free block to the newly expanded heap */
		write_block_hdr(last_block_hdr_ptr, last_block_size, true, false);
		mym_debug0("grow_heap", "\n\nnew block:\n");
		print_block_info(last_block_hdr_ptr);
	} else {
		/* Otherwise create new block */
		write_block_hdr(prev_brk, align_8(sbrk_incr - HEAP_EPILOGUE_HEADER_SIZE), true, false);
		mym_debug0("grow_heap", "\n\nnew block:\n");
		print_block_info(prev_brk);
	}
	printf("\n");

	// mym_debug_list_all_blocks();

	/* Write epilogue header at the end of the heap */
	memcpy((void *)mem_brk - HEAP_EPILOGUE_HEADER_SIZE, &epilogue_hdr, sizeof(epilogue_hdr));

	mym_debug_mem_heap("grow_heap");
	mym_debug_mem_brk("grow_heap");
	mym_debug_heap_size("grow_heap");

	return prev_brk;
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
	mym_debug1("split", "allock_block_size: %d\n", alloc_block_size);
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

static char INLINE *place(char *ptr, u32 hdr, u32 block_size, size_t asize) {
	if (block_size >= asize) {
		hdr = set_hdr_as_allocated(hdr);
		memcpy(ptr, &hdr, sizeof(hdr));
		last_fit_addr = ptr;
		split(ptr, block_size, asize);
		return ptr + BLOCK_HEADER_SIZE;
	}
	return 0;
}

void *mm_malloc(size_t size) {
	if (unlikely(!is_initialized()) && (mm_init() == -1)) {
		errno = ENOMEM;
		return NULL;
	}

	/* Traverse from the start of the heap until program break,
	finding block with next fit policy */

	char *ptr = last_fit_addr;
	char *prev_hdr_ptr;
	bool prev_block_is_free = false;
	const size_t asize = align_8(BLOCK_HEADER_SIZE + size);
	for (;;) {
		for (; ptr < VALID_BLOCK_ADDR_HI_BOUND;) {
			u32 hdr;
			memcpy(&hdr, ptr, sizeof(u32));
			u32 block_size = get_block_size(hdr);
			if (is_free(hdr)) {
				prev_block_is_free = true;
				char *block_ptr = place(ptr, hdr, block_size, asize);
				if (block_ptr) {
					mym_debug_list_all_blocks();
					return (void *)block_ptr;
				}
			} else {
				prev_block_is_free = false;
			}
			prev_hdr_ptr = ptr;
			ptr += block_size;
		}

		/* We haven't found free block, need to grow the heap */
		if (grow_heap(asize, prev_hdr_ptr) == GROW_HEAP_FAILED) {
			errno = ENOMEM;
			return NULL;
		}
		if (prev_block_is_free) {
			/* Backtrack to the previously free block */
			ptr = prev_hdr_ptr;
		}
	}
}

static void INLINE coalesce() {}
