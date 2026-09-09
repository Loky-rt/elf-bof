CC = gcc
CC_ARM64 = aarch64-linux-gnu-gcc

CFLAGS = -O2 -Wall

INCLUDE = -I ../include
SRC = ../src/bof_api.c ../src/bof_async.c ../src/elf_bof.c ../src/nax_bof_sdk.c
LDFLAGS = -lpthread

TARGET = bof_loader
TARGET_ARM64 = bof_loader_arm64

all: clean $(TARGET) $(TARGET_ARM64)

$(TARGET): bof_loader.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $(TARGET) bof_loader.c $(SRC) $(LDFLAGS)

$(TARGET_ARM64): bof_loader.c
	$(CC_ARM64) $(CFLAGS) $(INCLUDE) -o $(TARGET_ARM64) bof_loader.c $(SRC) $(LDFLAGS)
clean:
	rm -f $(TARGET) $(TARGET_ARM64)

.PHONY: all clean
