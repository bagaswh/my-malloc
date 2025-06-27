#include <unistd.h>

extern void *mm_malloc(size_t size);

int main() {
	mm_malloc(1);
	mm_malloc(17);
}