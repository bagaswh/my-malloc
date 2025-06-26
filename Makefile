# Makefile for Custom Malloc Implementation
# Supports both test executable and LD_PRELOAD shared library builds

# Compiler and tools
CC = clang
AR = ar
RM = rm -f

# Directories
SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build
DEBUG_DIR = $(BUILD_DIR)/debug
RELEASE_DIR = $(BUILD_DIR)/release

# Source files
MALLOC_SRCS = $(SRC_DIR)/mymalloc.c $(SRC_DIR)/memlib.c
TEST_SRCS = $(TEST_DIR)/mymalloc_test.c
MALLOC_HEADERS = $(SRC_DIR)/mymalloc.h

# Target names
TEST_TARGET = mymalloc_test
SHARED_TARGET = libmymalloc.so
STATIC_TARGET = libmymalloc.a

# Build mode (default to debug)
MODE ?= debug

# Set directories based on mode
ifeq ($(MODE),release)
    TARGET_DIR = $(RELEASE_DIR)
    CFLAGS_MODE = -O3 -DNDEBUG -flto
    LDFLAGS_MODE = -O3 -flto
else
    TARGET_DIR = $(DEBUG_DIR)
    # CFLAGS_MODE = -O0 -g3 -ggdb3 -DDEBUG -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common
    CFLAGS_MODE = -O0 -g3 -ggdb3 -DDEBUG -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common
    # LDFLAGS_MODE = -fsanitize=address -fsanitize=undefined -rdynamic
    LDFLAGS_MODE = -rdynamic
endif

# Common compiler flags
CFLAGS_COMMON = -Wall -Wextra -std=c17 -fPIC -I$(SRC_DIR)

# Final flags
CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_MODE)
LDFLAGS = $(LDFLAGS_MODE)

# Object files
MALLOC_OBJS = $(MALLOC_SRCS:$(SRC_DIR)/%.c=$(TARGET_DIR)/%.o)
TEST_OBJS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(TARGET_DIR)/%.o)

# Targets
.PHONY: all clean debug release test shared static install help

# Default target
all: $(TARGET_DIR)/$(TEST_TARGET) $(TARGET_DIR)/$(SHARED_TARGET)

# Help target
help:
	@echo "Available targets:"
	@echo "  all       - Build test executable and shared library (default: debug mode)"
	@echo "  test      - Build and run test executable"
	@echo "  shared    - Build shared library for LD_PRELOAD"
	@echo "  static    - Build static library"
	@echo "  debug     - Build in debug mode (with ASAN, UBSAN, debug symbols)"
	@echo "  release   - Build in release mode (optimized, no debug info)"
	@echo "  clean     - Remove all build artifacts"
	@echo "  install   - Install shared library to system (requires sudo)"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                    # Build debug version"
	@echo "  make MODE=release       # Build release version"
	@echo "  make test               # Build and run tests"
	@echo "  make shared MODE=release # Build optimized shared library"

# Build modes
debug:
	$(MAKE) MODE=debug all

release:
	$(MAKE) MODE=release all

# Test executable (links with malloc implementation directly)
$(TARGET_DIR)/$(TEST_TARGET): $(TEST_OBJS) $(MALLOC_OBJS) | $(TARGET_DIR)
	$(CC) $(LDFLAGS) -o $@ $^

# Shared library for LD_PRELOAD
$(TARGET_DIR)/$(SHARED_TARGET): $(MALLOC_OBJS) | $(TARGET_DIR)
	$(CC) $(LDFLAGS) -shared -o $@ $^

# Static library
$(TARGET_DIR)/$(STATIC_TARGET): $(MALLOC_OBJS) | $(TARGET_DIR)
	$(AR) rcs $@ $^

# Convenience targets
shared: $(TARGET_DIR)/$(SHARED_TARGET)
static: $(TARGET_DIR)/$(STATIC_TARGET)

# Object files from src directory
$(TARGET_DIR)/%.o: $(SRC_DIR)/%.c $(MALLOC_HEADERS) | $(TARGET_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Object files from test directory
$(TARGET_DIR)/%.o: $(TEST_DIR)/%.c $(MALLOC_HEADERS) | $(TARGET_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create build directories
$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

$(DEBUG_DIR):
	mkdir -p $(DEBUG_DIR)

$(RELEASE_DIR):
	mkdir -p $(RELEASE_DIR)

# Test target - build and run tests with better ASAN output
test: $(TARGET_DIR)/$(TEST_TARGET)
	@echo "Running tests with enhanced ASAN reporting..."
	ASAN_OPTIONS="symbolize=1:print_stacktrace=1:check_initialization_order=1:strict_init_order=1:abort_on_error=1" \
	MSAN_OPTIONS="print_stats=1" \
	UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
	./$(TARGET_DIR)/$(TEST_TARGET)

# Install shared library (useful for system-wide LD_PRELOAD)
install: $(RELEASE_DIR)/$(SHARED_TARGET)
	@echo "Installing $(SHARED_TARGET) to /usr/local/lib..."
	sudo cp $(RELEASE_DIR)/$(SHARED_TARGET) /usr/local/lib/
	sudo ldconfig

# Example usage targets
example-test: $(TARGET_DIR)/$(TEST_TARGET)
	@echo "Running isolated malloc tests..."
	./$(TARGET_DIR)/$(TEST_TARGET)

example-preload: $(TARGET_DIR)/$(SHARED_TARGET)
	@echo "Example: Using LD_PRELOAD with ls command"
	@echo "LD_PRELOAD=./$(TARGET_DIR)/$(SHARED_TARGET) ls -la"
	@echo "Run the above command to test your malloc with any program"

# Clean build artifacts
clean:
	$(RM) -r $(BUILD_DIR)
	$(RM) $(SRC_DIR)/*.o  # Clean any leftover object files in src

# Development helpers with better debugging
valgrind-test: $(RELEASE_DIR)/$(TEST_TARGET)
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(RELEASE_DIR)/$(TEST_TARGET)

gdb-test: $(DEBUG_DIR)/$(TEST_TARGET)
	gdb -ex "set environment ASAN_OPTIONS=abort_on_error=1:symbolize=1" ./$(DEBUG_DIR)/$(TEST_TARGET)

# Run with addr2line for manual symbol resolution
addr2line-test: $(DEBUG_DIR)/$(TEST_TARGET)
	@echo "Run your test, then use: addr2line -e ./$(DEBUG_DIR)/$(TEST_TARGET) <address>"
	@echo "Or install llvm-symbolizer for automatic symbolization"
	./$(DEBUG_DIR)/$(TEST_TARGET)

# Show build configuration
info:
	@echo "Build Configuration:"
	@echo "  Mode: $(MODE)"
	@echo "  Target Directory: $(TARGET_DIR)"
	@echo "  CC: $(CC)"
	@echo "  CFLAGS: $(CFLAGS)"
	@echo "  LDFLAGS: $(LDFLAGS)"
	@echo "  Sources: $(MALLOC_SRCS)"

# Dependencies (simple dependency tracking)
$(TARGET_DIR)/mymalloc.o: $(SRC_DIR)/mymalloc.c $(SRC_DIR)/mymalloc.h
$(TARGET_DIR)/memlib.o: $(SRC_DIR)/memlib.c
$(TARGET_DIR)/mymalloc_test.o: $(TEST_DIR)/mymalloc_test.c $(SRC_DIR)/mymalloc.h