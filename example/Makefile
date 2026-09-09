CC      = gcc
CFLAGS  = -c -fno-builtin -fno-stack-protector -fPIC -Wall -Wextra -I ../include

BOFS    = uptime.o bof_custom.o bof_fail.o DLR.o

all: clean $(BOFS)

DLR.o: DLR.c
	$(CC) $(CFLAGS) -o $@ $<

uptime.o: uptime.c
	$(CC) $(CFLAGS) -o $@ $<

bof_custom.o: bof_custom.c
	$(CC) $(CFLAGS) -o $@ $<

bof_fail.o: bof_fail.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o
