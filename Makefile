# Linux BOF SDK
#
# Usage:
#   make            Build all available architectures
#   make x64        Build for Linux x86_64
#   make x86        Build for Linux x86 (32-bit)
#   make arm64      Build for Linux ARM64
#   make arm        Build for Linux ARM
#   make clean      Remove build artifacts
#
# Dependencies:
#   sudo apt install gcc-i686-linux-gnu gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf

CFLAGS = -O2 -Wall -Wextra -Wno-unused-parameter -fPIC -Iinclude
SRCS   = src/elf_bof.c src/bof_async.c src/bof_api.c src/nax_bof_sdk.c

.PHONY: all x64 arm64 clean

all: clean x64 arm64 clean-o

x64:
	@mkdir -p build/x64 lib
	@for f in $(SRCS); do \
		gcc $(CFLAGS) -c -o build/x64/$$(basename $$f .c).o $$f || exit 1; \
	done
	@ar rcs lib/libelf_bof_x64.a build/x64/*.o
	@echo "[+] lib/libelf_bof_x64.a"

arm64:
	@if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then \
		echo "[!] arm64: compiler not found. Install: sudo apt install gcc-aarch64-linux-gnu"; \
		exit 1; \
	fi
	@mkdir -p build/arm64 lib
	@for f in $(SRCS); do \
		aarch64-linux-gnu-gcc $(CFLAGS) -c -o build/arm64/$$(basename $$f .c).o $$f || exit 1; \
	done
	@aarch64-linux-gnu-ar rcs lib/libelf_bof_arm64.a build/arm64/*.o
	@echo "[+] lib/libelf_bof_arm64.a"

clean:
	@(rm -rf build lib) && echo '[+] cleaning'
clean-o:
	@(find . -type f -name '*.o' |xargs rm) && echo '[+] Temporary files deleted'
