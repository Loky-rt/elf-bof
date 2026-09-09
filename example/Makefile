CC      = gcc
CCAMR64 = aarch64-linux-gnu-gcc

CFLAGS      = -c -fno-builtin -fno-stack-protector -fPIC -Wall -Wextra -Wno-address -I ../include
CFLAGSAMR64 = -c  -Os -fPIC -fno-builtin -Iinclude -I ../include

BOFS       = uptime.o bof_custom.o bof_fail.o DLR.o multi_probe.o
BOFS_ARM64 = uptime_arm64.o bof_custom_arm64.o bof_fail_arm64.o DLR_arm64.o multi_probe_arm64.o

all: clean $(BOFS) arm64

arm64: $(BOFS_ARM64)

DLR.o: DLR.c
	$(CC) $(CFLAGS) -o $@ $<

uptime.o: uptime.c
	$(CC) $(CFLAGS) -o $@ $<

bof_custom.o: bof_custom.c
	$(CC) $(CFLAGS) -o $@ $<

bof_fail.o: bof_fail.c
	$(CC) $(CFLAGS) -o $@ $<

multi_probe.o: multi_probe.c
	$(CC) $(CFLAGS) -o $@ $<

DLR_arm64.o: DLR.c
	$(CCAMR64) $(CFLAGSAMR64) -o $@ $<

uptime_arm64.o: uptime.c
	$(CCAMR64) $(CFLAGSAMR64) -o $@ $<

bof_custom_arm64.o: bof_custom.c
	$(CCAMR64) $(CFLAGSAMR64) -o $@ $<

bof_fail_arm64.o: bof_fail.c
	$(CCAMR64) $(CFLAGSAMR64) -o $@ $<

multi_probe_arm64.o: multi_probe.c
	$(CCAMR64) $(CFLAGSAMR64) -o $@ $<

clean:
	rm -f *.o
