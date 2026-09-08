# ELF BOF SDK

A static library for loading and executing **ELF Beacon Object Files** (BOFs) in-memory on Linux. BOFs are position-independent `.o` files compiled from C that run inside the host process without touching disk.

This SDK is a **standalone, agent-agnostic library**. It has no dependency on any specific C2 framework or agent implementation. Any Linux C2 agent written in C can integrate it by linking the static library and including the headers.

The [NaxDarks Linux Agent](https://github.com/Loky-rt/NaxDarks) is one consumer of this SDK, but the SDK is developed and versioned independently.

The included **BOF Loader** (`bof-loader/`) is a standalone interactive shell that allows BOF developers to ** compile, and test BOFs without deploying a C2 server or agent**. This makes the development cycle fast: edit → compile → test → iterate, all from a terminal.

---

## Features

- **In-memory ELF loading** — mmap → relocate → execute → zero → munmap
- **Multi-architecture** — x86_64 and ARM64 ELF relocation support (BOF execution)
- **Cross-compilation** — SDK library builds for x64 and ARM64 (agent linking)
- **Async execution** — run BOFs in background threads (up to 8 concurrent)
- **Cooperative cancellation** — stop pipe for graceful `jobkill`
- **Custom symbol registration** — expose agent-internal functions to BOFs
- **Thread-safe output** — `__thread` buffers prevent interference between concurrent BOFs
- **OPSEC cleanup** — zero memory and deep-copy sensitive data before freeing

---

## Requirements

### Build dependencies

| Architecture | Package | Compiler |
|---|---|---|
| x64 | `gcc` (default) | `gcc` |
| ARM64 | `gcc-aarch64-linux-gnu` | `aarch64-linux-gnu-gcc` |

Install all cross-compilers:

```bash
sudo apt install gcc-aarch64-linux-gnu
```

---

## Building

```bash
make            # Build all architectures
make x64        # Build only x86_64
make arm64      # Build only ARM64
make clean      # Remove build artifacts
```

Output:

```
lib/
├── libelf_bof_x64.a
├── libelf_bof_arm64.a
```

If a cross-compiler is not installed, the target fails with the exact package name to install.

---

## Repository Structure

```
elf-bof/
├── include/
│   ├── nax_bof_sdk.h      ← Umbrella header (include this)
│   ├── bof_api.h           ← Beacon* and Ax* API declarations
│   ├── elf_bof.h           ← ELF loader interface
│   └── bof_async.h         ← Async job system interface
├── src/
│   ├── nax_bof_sdk.c       ← SDK init + custom symbol registration
│   ├── bof_api.c           ← API implementations + symbol resolution table
│   ├── elf_bof.c           ← In-memory ELF relocatable loader
│   └── bof_async.c         ← Background thread job manager
├── bof-loader/
│   ├── bof_loader.c        ← Standalone test loader (interactive shell)
│   └── Makefile
├── example/
│   ├── uptime.c            ← Example BOF: system uptime
│   ├── bof_custom.c        ← Example BOF: uses custom agent symbols
│   ├── bof_fail.c          ← Example BOF: intentional failure (dlopen)
│   └── Makefile
├── lib/                    ← Built static libraries (after make)
├── Makefile
└── README.md
```

---

## Supported Architectures

### BOF execution (ELF loader)

The in-memory ELF loader supports relocations for **two architectures**:

| Architecture | Relocations | BOF execution |
|---|---|---|
| **x86_64** | `R_X86_64_64`, `R_X86_64_PC32`, `R_X86_64_PLT32`, `R_X86_64_32`, `R_X86_64_32S` | ✅ Supported |
| **ARM64** | `R_AARCH64_ABS64`, `R_AARCH64_CALL26`, `R_AARCH64_JUMP26`, `R_AARCH64_ADR_PREL_PG_HI21`, `R_AARCH64_ADD_ABS_LO12_NC`, `R_AARCH64_LDST*` | ✅ Supported |

### SDK library compilation

The static libraries build for both architectures.

| Library | Target | BOF execution |
|---|---|---|
| `libelf_bof_x64.a` | x86_64 agents | ✅ Full BOF support |
| `libelf_bof_arm64.a` | ARM64 agents | ✅ Full BOF support |

---

## ELF Loader Internals

The loader (`elf_bof.c`) performs these steps for each BOF execution:

```
┌─ Step 1: Validate ELF header
│    Check: magic bytes, ELFCLASS64, ET_REL, EM_X86_64 or EM_AARCH64
│
├─ Step 2: Allocate arena
│    mmap(RW) a contiguous block for all loadable sections + trampolines
│
├─ Step 3: Load sections
│    Copy .text, .data, .rodata, .bss into the arena
│    Track section bases for relocation
│
├─ Step 4: Resolve symbols
│    For each symbol in .symtab:
│      - Local/defined: compute address from section base
│      - Undefined (Ax*/Beacon*): look up in bof_resolve_symbol()
│        → First checks custom symbol table (nax_bof_resolve_custom)
│        → Then checks base API table (bof_api_table)
│      - Unresolved: abort with "Unresolved: <name>" error
│
├─ Step 5: Apply relocations
│    x86_64: R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_32/32S
│    ARM64:  R_AARCH64_ABS64, R_AARCH64_CALL26, R_AARCH64_JUMP26,
│            R_AARCH64_ADR_PREL_PG_HI21, R_AARCH64_ADD_ABS_LO12_NC,
│            R_AARCH64_LDST{8,16,32,64,128}_ABS_LO12_NC
│    Trampolines: for calls beyond ±128MB on ARM64
│
├─ Step 6: Set memory permissions
│    .text sections: mprotect(RX) — executable, not writable
│    .data/.bss:     remain RW
│
├─ Step 7: Execute
│    bof_output_init() → entry("go") → bof_output_get()
│
└─ Step 8: OPSEC cleanup
     Zero arena memory → munmap → free symbol values
```

### Why BOFs fail

A BOF fails at load time if it uses symbols not in the API table. The loader reports the exact symbol name:

```
BOF error: Unresolved: dlopen
```

**Common failure causes:**

| Symptom | Cause | Fix |
|---|---|---|
| `Unresolved: dlopen` | BOF uses `dlopen()` directly | Not supported — use Ax* wrappers only |
| `Unresolved: printf` | BOF calls libc directly | Use `BeaconPrintf()` instead |
| `Unresolved: malloc` | BOF calls libc directly | Use `AxMalloc()` instead |
| `Unresolved: MyFunc` | BOF calls a custom function | Register with `nax_bof_register_symbol()` |
| `relocation failed` | Unsupported relocation type | Check compiler flags: `-fPIC -c` required |

The example `bof_fail.c` demonstrates this intentionally — it calls `dlopen()` which is not in the API table, producing a clear error message.

---

## API Reference

### Beacon Core

| Function | Description |
|----------|-------------|
| `BeaconDataParse(datap *p, char *buf, int sz)` | Initialize argument parser |
| `BeaconDataInt(datap *p)` | Extract 4-byte int (little-endian) |
| `BeaconDataShort(datap *p)` | Extract 2-byte short |
| `BeaconDataLength(datap *p)` | Remaining unparsed bytes |
| `BeaconDataExtract(datap *p, int *sz)` | Extract length-prefixed string |
| `BeaconOutput(int type, char *data, int len)` | Emit raw output bytes |
| `BeaconPrintf(int type, char *fmt, ...)` | Emit formatted output |
| `BeaconFormatAlloc(formatp *f, int maxsz)` | Allocate format buffer |
| `BeaconFormatReset/Append/Printf/ToString/Free/Int` | Format buffer operations |
| `BeaconIsAdmin()` | Returns 1 if `euid == 0` |
| `BeaconGetStopJobEvent()` | Returns poll fd for async stop (-1 if sync) |

Output types: `CALLBACK_OUTPUT` (0x00), `CALLBACK_ERROR` (0x0D).

### Inter-BOF Shared Globals

| Function | Description |
|----------|-------------|
| `AxSetGlobal(key, ptr)` | Store a pointer by name (max 16, key must be a string literal) |
| `AxGetGlobal(key)` | Retrieve a pointer by name (NULL if missing) |

Pointers persist in the host process heap across BOF executions. Used for producer/consumer patterns (e.g., keylogger).

### File System

| Wrapper | Underlying call |
|---------|----------------|
| `AxOpenFile(path, flags, mode)` | `open()` |
| `AxCloseFile(fd)` | `close()` |
| `AxReadFile(fd, buf, count)` | `read()` |
| `AxWriteFile(fd, buf, count)` | `write()` |
| `AxReadFileToBuffer(path, &buf, max)` | `open` + `read` + `malloc` |
| `AxFileStat(path, &mode, &size, &uid, &gid)` | `stat()` |
| `AxOpenDir(path)` | `open(O_DIRECTORY)` |
| `AxReadDir(fd, buf, size)` | `getdents64` |
| `AxFileTime(path, &atime, &mtime)` | `stat()` (timestamps) |
| `AxSetFileTime(path, atime, mtime)` | `utimensat()` |
| `AxRealpath(path, resolved)` | `realpath()` |

### Memory & Strings

| Wrapper | Description |
|---------|-------------|
| `AxMalloc(size)` / `AxFree(ptr)` | Heap allocation |
| `AxMemset` / `AxMemcpy` | Memory operations |
| `AxStrlen` / `AxStrcmp` / `AxStrncmp` | String comparison |
| `AxStrcpy` / `AxStrncpy` / `AxStrcat` | String copy/concat |
| `AxStrstr` / `AxStrchr` | String search |
| `AxSnprintf(buf, size, fmt, ...)` | Formatted string |

### Process Info

| Wrapper | Description |
|---------|-------------|
| `AxGetPid()` / `AxGetUid()` / `AxGetEuid()` | PID and UID |
| `AxGetCwd(buf, size)` | Current working directory |
| `AxGetEnv(name, buf, size)` | Read from `/proc/self/environ` |

### Process Control

| Wrapper | Underlying call |
|---------|----------------|
| `AxFork()` | `fork()` |
| `AxExecve(path, argv, envp)` | `execve()` |
| `AxWaitpid(pid, &status, opts)` | `waitpid()` |
| `AxKill(pid, sig)` | `kill()` |
| `AxPtrace(req, pid, addr, data)` | `ptrace()` |
| `AxProcessVmReadv` / `AxProcessVmWritev` | Cross-process memory R/W |
| `AxPidfdOpen(pid, flags)` | `pidfd_open()` |
| `AxPidfdGetfd(pidfd, targetfd, flags)` | `pidfd_getfd()` |

### Networking

| Wrapper | Description |
|---------|-------------|
| `AxSocket` / `AxConnect` / `AxBind` / `AxListen` / `AxAccept` | Socket lifecycle |
| `AxSend` / `AxRecv` | TCP send/receive |
| `AxSendto` / `AxRecvfrom` | UDP send/receive |
| `AxClose(fd)` | Close socket |
| `AxSetsockopt` / `AxGetsockopt` | Socket options |
| `AxInetPton` / `AxInetNtop` / `AxInetNtoa` | Address conversion |
| `AxHtons` / `AxNtohs` | Byte order |

### Advanced Filesystem

| Wrapper | Underlying call |
|---------|----------------|
| `AxChdir` / `AxFchdir` | Change directory |
| `AxChmod` / `AxFchmod` | Change permissions |
| `AxChown` / `AxFchown` | Change ownership |
| `AxSymlink` / `AxReadlink` | Symbolic links |
| `AxDup` / `AxDup2` | Duplicate file descriptors |
| `AxIoctl(fd, request, ...)` | Device control |

### System

| Wrapper | Description |
|---------|-------------|
| `AxGetErrno()` | Current `errno` value |
| `AxFcntl(fd, cmd, arg)` | File descriptor control |
| `AxPoll(fds, nfds, timeout_ms)` | Poll file descriptors |
| `AxSysinfo(&info)` | System info (uptime, RAM, load) |
| `AxUname(&buf)` | Kernel version and hostname |

### io_uring

| Wrapper | Underlying call |
|---------|----------------|
| `AxIoUringSetup(entries, &params)` | `io_uring_setup()` |
| `AxIoUringEnter(fd, submit, complete, flags)` | `io_uring_enter()` |
| `AxIoUringRegister(fd, opcode, arg, nr)` | `io_uring_register()` |

---

## Async Job System

The async system (`bof_async.c`) manages background BOF execution:

```
Main Thread                              Worker Thread (job #N)
───────────                              ──────────────────────
nax_async_start(bof, args)
  ├─ deep-copy bof_data + args
  ├─ create stop_pipe
  └─ pthread_create ──────────────────→  nax_bof_execute()
                                           └─ go(args, len)
nax_async_drain(callback)                      └─ BeaconPrintf(...)
  └─ if completed:                             └─ check should_stop()
       callback(output)                        └─ return
       free + cleanup                    job.state = COMPLETED

nax_async_kill(job_idx)
  └─ write(stop_pipe[1]) ─────────────→  BOF detects via poll(stop_pipe[0])
```

### Key characteristics

| Property | Value |
|---|---|
| Max concurrent jobs | 8 |
| Output isolation | `__thread` buffer per thread |
| Stop mechanism | Cooperative — BOF must poll `BeaconGetStopJobEvent()` |
| Memory safety | Deep copies of BOF data; zero before free |
| Result delivery | Via callback in `nax_async_drain()` |
| Thread model | `pthread_create` + `pthread_detach` |

---

## Custom Symbol Registration

The SDK allows agents to expose internal functions to BOFs via `nax_bof_register_symbol()`. This enables BOFs to call agent-specific functionality without modifying the SDK.

### Practical Example: ZIP Compression BOF

A common use case is implementing a ZIP compression BOF. A BOF cannot link against -lz at compile time because it's compiled as a relocatable object (.o). However, the agent can link against zlib. The solution is to link the agent with -lz and expose the necessary zlib functions to the BOF.

#### 1. Agent: Expose zlib Functions

**`exported.h`**
```c
#ifndef NAX_EXPORTED_H
#define NAX_EXPORTED_H

#include <zlib.h>

uLong AgentCrc32(uLong crc, const Bytef *buf, uInt len);
int AgentDeflateInit2(z_streamp strm, int level, int method,
                       int windowBits, int memLevel, int strategy,
                       const char *version, int stream_size);
int AgentDeflate(z_streamp strm, int flush);
int AgentDeflateEnd(z_streamp strm);
uLong AgentCompressBound(uLong sourceLen);

#endif
```

**`exported.c`**
```c
#include "exported.h"
#include <zlib.h>

/* ── Funciones zlib expuestas ── */
uLong AgentCrc32(uLong crc, const Bytef *buf, uInt len)
{
    return crc32(crc, buf, len);
}

int AgentDeflateInit2(z_streamp strm, int level, int method,
                       int windowBits, int memLevel, int strategy,
                       const char *version, int stream_size)
{
    return deflateInit2_(strm, level, method, windowBits, memLevel,
                         strategy, version, stream_size);
}

int AgentDeflate(z_streamp strm, int flush)
{
    return deflate(strm, flush);
}

int AgentDeflateEnd(z_streamp strm)
{
    return deflateEnd(strm);
}

uLong AgentCompressBound(uLong sourceLen)
{
    return compressBound(sourceLen);
}
```

#### 2. Register Symbols in Agent Transport

**`https.c`** (or any transport)
```c
#include "exported.h"

void nax_https_main(NaxAgent *a)
     signal(SIGPIPE, SIG_IGN);
     gen_session_id(a->session_id);
     nax_bof_sdk_init();

     nax_bof_register_symbol("AgentCrc32", AgentCrc32);
     nax_bof_register_symbol("AgentDeflateInit2", AgentDeflateInit2);
     nax_bof_register_symbol("AgentDeflate", AgentDeflate);
     nax_bof_register_symbol("AgentDeflateEnd", AgentDeflateEnd);
     nax_bof_register_symbol("AgentCompressBound", AgentCompressBound);
     NaxSysInfo info;
    /*...*/
```

#### 3. BOF: Use Exposed Functions

**`bof_zip.c`**
```c
#include "bof_api.h"
#include <stdint.h>
#include <fcntl.h>
#include <zlib.h>

/* ── zlib functions exposed by the agent ── */
extern uLong AgentCrc32(uLong crc, const Bytef *buf, uInt len);
extern int AgentDeflateInit2(z_streamp strm, int level, int method,
                              int windowBits, int memLevel, int strategy,
                              const char *version, int stream_size);
extern int AgentDeflate(z_streamp strm, int flush);
extern int AgentDeflateEnd(z_streamp strm);
extern uLong AgentCompressBound(uLong sourceLen);

/* ── BOF implementation using exposed functions ── */
void go(char *args, int args_len) {
    /* ... uses AgentCrc32, AgentDeflate, etc. ... */
}
```

### How Symbol Resolution Works

The BOF can now access zlib functions because the agent exposes them via the symbol table.

```text
BOF calls AgentCrc32()
  └─ bof_resolve_symbol("AgentCrc32")
       ├─ 1. nax_bof_resolve_custom() → checks custom table → FOUND ✓
       └─ 2. bof_api_table[] → checks base Ax*/Beacon* table (fallback)
```

### Benefits of This Approach

| **Aspect** | **Benefit** |
|--------|---------|
| `Security` | The agent controls exactly what functions are exposed (whitelist) |
| `No dlopen` | No need to expose dlopen or load libraries at runtime |
| `No external dependencies` | The BOF doesn't depend on libz.so being present on the target |
| `Small BOF size` | The BOF contains only orchestration logic, not the entire compression library |
| `Portability` | Works on any system where the agent runs |

### Key Points

- Maximum 64 custom symbols. Register before spawning any BOF threads.
- The agent must be linked with -lz to provide the underlying zlib implementation (for this example)

---

## BOF Loader (Test Tool)

The `bof-loader/` is a **standalone development tool** for testing BOFs. It requires **no C2 server, no agent deployment, and no network setup**. The entire development cycle happens locally:

```
Edit BOF → gcc -c -o mybof.o mybof.c → ./bof_loader mybof.o → see output → repeat
```

This eliminates the overhead of deploying an agent just to test a BOF. The loader uses the exact same SDK runtime (ELF loader, API table, async system) that a real agent would use, so BOFs that work in the loader will work in any agent that integrates the SDK.

### Building

```bash
cd bof-loader
make
```

### Usage

```bash
# Interactive mode
./bof_loader

# Direct execution
./bof_loader uptime.o

# With arguments
./bof_loader mybof.o str:hello int:42

# Async execution
./bof_loader --async keylog_start.o
```

### Interactive commands

| Command | Description |
|---|---|
| `<bof.o> [args...]` | Execute BOF synchronously |
| `--async <bof.o> [args...]` | Execute BOF in background |
| `jobs` | List running background BOFs |
| `kill <id>` | Stop a background BOF |
| `help` | Show commands |
| `exit` | Quit (kills all running jobs) |

### Argument types

| Type | Syntax | Example |
|---|---|---|
| String | `str:value` | `str:hello` |
| Integer (32-bit) | `int:value` | `int:42` |
| Short (16-bit) | `short:value` | `short:80` |
| Wide string | `wstr:value` | `wstr:hello` |

### Testing examples

```bash
# Build example BOFs
cd example && make && cd ..
cd bof-loader && make && cd ..

# Test: uptime (uses AxSysinfo)
./bof-loader/bof_loader example/uptime.o

# Test: custom symbols (calls agent-registered functions)
./bof-loader/bof_loader example/bof_custom.o

# Test: intentional failure (dlopen not in API table)
./bof-loader/bof_loader example/bof_fail.o
```

Expected outputs:

```
# uptime.o — SUCCESS
[OK] BOF completed
====================[Uptime]====================
[+] System Uptime: 3 days, 14 hours, 22 minutes, 8 seconds
[+] Total RAM: 16384 MB
[+] Processes: 342

# bof_custom.o — SUCCESS (uses registered custom_add / custom_get_info)
[OK] BOF completed
[*] Custom BOF initiated
[+] 10 + 32 = 42
[+] System info:: PID: 12345, UID: 1000
[*] Custom BOF completed

# bof_fail.o — FAILURE (dlopen not in API table)
[ERR] BOF failed
BOF error: Unresolved: dlopen
```

---

## Real-World Integration Example

The [NaxDarks](https://github.com/Loky-rt/NaxDarks) Linux Agent is one consumer of this SDK. Its integration serves as a reference for how any agent can adopt the SDK:

---

# Disclaimer

For authorized security research, penetration testing, red team operations, and security tooling development only. Use only on systems where you have explicit authorization.

