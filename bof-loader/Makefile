CC = gcc
CFLAGS = -O2 -Wall
INCLUDE = -I ../include
SRC = ../src/bof_api.c ../src/bof_async.c ../src/elf_bof.c ../src/nax_bof_sdk.c
LDFLAGS = -lpthread

TARGET = bof_loader

all: clean $(TARGET)

$(TARGET): bof_loader.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $(TARGET) bof_loader.c $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
