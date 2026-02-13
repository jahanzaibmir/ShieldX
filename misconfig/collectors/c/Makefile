# ShieldX Enhanced Collectors Makefile
# Simplified for current structure

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_WIN32_WINNT=0x0601
LDFLAGS = -lws2_32 -liphlpapi

# Target
TARGET = shieldx-collector.exe

# Source files (only the ones that exist)
SRCS = main.c \
       core/config.c \
       core/logger.c \
       network/scanner.c

# Object files
OBJS = main.o \
       core/config.o \
       core/logger.o \
       network/scanner.o

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJS)
	@echo [LINK] Building $(TARGET)...
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo [SUCCESS] Build complete: $(TARGET)

# Compile
%.o: %.c
	@echo [CC] Compiling $<...
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	@echo [CLEAN] Removing build artifacts...
	@if exist main.o del main.o
	@if exist core\config.o del core\config.o
	@if exist core\logger.o del core\logger.o
	@if exist network\scanner.o del network\scanner.o
	@if exist $(TARGET) del $(TARGET)
	@echo [CLEAN] Done!

# Rebuild
rebuild: clean all

# Test
test: all
	@echo [TEST] Running network scan...
	$(TARGET) -m network -o test_output.json -v

# Help
help:
	@echo ShieldX C Collector Makefile
	@echo.
	@echo Available targets:
	@echo   make          - Build the collector
	@echo   make clean    - Remove build artifacts  
	@echo   make rebuild  - Clean and rebuild
	@echo   make test     - Build and run test scan
	@echo   make help     - Show this help

.PHONY: all clean rebuild test help
