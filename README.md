# ELF BOF SDK

A static library for loading and executing **ELF Beacon Object Files** (BOFs) in-memory on Linux. BOFs are position-independent `.o` files compiled from C that run inside the host process without touching disk.

This SDK is a **standalone, agent-agnostic library**. It has no dependency on any specific C2 framework or agent implementation. Any Linux C2 agent written in C can integrate it by linking the static library and including the headers.

The [NaxDarks Linux Agent](https://github.com/Loky-rt/NaxDarks) is one consumer of this SDK, but the SDK is developed and versioned independently.

The included **BOF Loader** (`bof-loader/`) is a standalone interactive shell that allows BOF developers to compile and test BOFs without deploying a C2 server or agent. This makes the development cycle fast: edit → compile → test → iterate, all from a terminal.

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
- **Dynamic libc resolution** — BOFs can call any function from any loaded DSO via `LIBC$`, `RTLD$`, or `LIBXXX$` prefixes without dlsym
- **Explicit library resolution** — BOFs can resolve symbols from a specific shared library via `LIBXXX$` prefix (e.g., `LIBZ$zlibVersion`)
- **Automatic BOF dependency management** — pre-validates and optionally loads required DSOs before BOF execution (`bof_deps.c`)
- **Configurable dlopen policy** — strict mode (no new DSO loads) or flexible mode (auto-load missing dependencies)

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

The SDK also requires `libdl` at link time (`-ldl`) for the dependency manager when `BOF_DEPS_ALLOW_DLOPEN=1` (default).

---

## Building

```bash
make            # Build all architectures
make x64        # Build only x86_64
make arm64      # Build only ARM64
make clean      # Remove build artifacts
```

### Build options

| Option | Default | Description |
|---|---|---|
| `BOF_DEPS_ALLOW_DLOPEN=1` | **1** | Flexible mode — missing DSOs are found and loaded via `dlopen()` before BOF execution |
| `BOF_DEPS_ALLOW_DLOPEN=0` | — | Strict mode — BOF is rejected if any required DSO is not already loaded |

```bash
make x64 BOF_DEPS_ALLOW_DLOPEN=0   # Strict mode build
```

Output:

```
lib/
├── libelf_bof_x64.a
├── libelf_bof_arm64.a
```

If a cross-compiler is not installed, the target fails with the exact package name to install.

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
├─ Step 4: Discover dependencies (bof_deps_prepare)
│    Scan .symtab for undefined symbols with LIBXXX$ prefix
│    For each library hint:
│      - Check if DSO is already in runtime cache → skip
│      - If missing and BOF_DEPS_ALLOW_DLOPEN=1 → locate on disk + dlopen()
│      - If missing and BOF_DEPS_ALLOW_DLOPEN=0 → abort with dependency error
│
├─ Step 5: Resolve symbols
│    For each symbol in .symtab:
│      - Local/defined: compute address from section base
│      - Undefined (Ax*/Beacon*/LIBC$/RTLD$/LIBXXX$): look up in bof_resolve_symbol()
│        → Layer 1: custom symbol table (nax_bof_resolve_custom)
│        → Layer 2: base API table (bof_api_table)
│        → Layer 3: runtime DSO resolution (in-memory DSO cache walk)
│             - LIBC$foo   → strip prefix → resolve "foo" from loaded DSOs
│             - RTLD$foo   → strip prefix → global search across all loaded DSOs
│             - LIBXXX$foo → strip prefix, match DSO "xxx" → resolve "foo" from it
│      - Unresolved: abort with "Unresolved: <name>" error
│
├─ Step 6: Apply relocations
│    x86_64: R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_32/32S
│    ARM64:  R_AARCH64_ABS64, R_AARCH64_CALL26, R_AARCH64_JUMP26,
│            R_AARCH64_ADR_PREL_PG_HI21, R_AARCH64_ADD_ABS_LO12_NC,
│            R_AARCH64_LDST{8,16,32,64,128}_ABS_LO12_NC
│    Trampolines: for calls beyond ±128MB on ARM64
│
├─ Step 7: Set memory permissions
│    .text sections: mprotect(RX) — executable, not writable
│    .data/.bss:     remain RW
│
├─ Step 8: Execute
│    bof_output_init() → entry("go") → bof_output_get()
│
└─ Step 9: OPSEC cleanup
     Zero arena memory → munmap → free symbol values
```

### Why BOFs fail

A BOF fails at load time if it uses symbols not in the API table and not resolvable at runtime. The loader reports the exact symbol name:

```
BOF error: Unresolved: dlopen
```

**Common failure causes:**

| Symptom | Cause | Fix |
|---|---|---|
| `Unresolved: dlopen` | BOF calls `dlopen()` directly (as an unregistered symbol) | Use `RTLD$dlopen` or `LIBC$dlopen` for runtime resolution |
| `Unresolved: printf` | BOF calls libc directly | Use `BeaconPrintf()` or `LIBC$printf` |
| `Unresolved: malloc` | BOF calls libc directly | Use `AxMalloc()` or `LIBC$malloc` |
| `Unresolved: MyFunc` | BOF calls a custom function | Register with `nax_bof_register_symbol()` |
| `Unresolved: LIBZ$zlibVersion` | libz not loaded and dlopen disabled | Set `BOF_DEPS_ALLOW_DLOPEN=1` or preload libz |
| `relocation failed` | Unsupported relocation type | Check compiler flags: `-fPIC -c` required |
| `dependency error: libxyz` | Required DSO not found on disk | Install the library package |

The example `bof_fail.c` demonstrates this intentionally — it calls `dlopen()` directly as an undefined symbol (not via `LIBC$` or `RTLD$`), producing a clear error message.

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
| `AxStatvfs(path, &buf)` | `statvfs()` — filesystem space and mount info |
| `AxFstatvfs(fd, &buf)` | `fstatvfs()` — same, via open file descriptor |
| `AxOpenDir(path)` | `open(O_DIRECTORY)` |
| `AxReadDir(fd, buf, size)` | `getdents64` |
| `AxFileTime(path, &atime, &mtime)` | `stat()` (timestamps) |
| `AxSetFileTime(path, atime, mtime)` | `utimensat()` |
| `AxRealpath(path, resolved)` | `realpath()` |

### Memory & Strings

| Wrapper | Description |
|---------|-------------|
| `AxMalloc(size)` / `AxFree(ptr)` | Heap allocation |
| `AxMemset` / `AxMemcpy` / `AxMemmove` | Memory operations |
| `AxMemcmp(a, b, n)` | Memory comparison |
| `AxMemfdCreate(name, flags)` | Create anonymous memory-backed file descriptor |
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
| `AxExecveat(dirfd, path, argv, envp, flags)` | `execveat()` — execute relative to directory fd |
| `AxFexecve(fd, argv, envp)` | `fexecve()` — execute from open file descriptor |
| `AxWaitpid(pid, &status, opts)` | `waitpid()` |
| `AxKill(pid, sig)` | `kill()` |
| `AxExit(status)` | `exit()` — terminate current process |
| `AxPipe(fd[2])` | `pipe()` — create anonymous pipe |
| `AxSocketpair(domain, type, protocol, sv[2])` | `socketpair()` — create connected socket pair |
| `AxPtrace(req, pid, addr, data)` | `ptrace()` |
| `AxProcessVmReadv` / `AxProcessVmWritev` | Cross-process memory R/W |
| `AxPidfdOpen(pid, flags)` | `pidfd_open()` |
| `AxPidfdGetfd(pidfd, targetfd, flags)` | `pidfd_getfd()` |

> **Note:** `AxClone` has been removed. The previous implementation executed `SYS_clone` raw without running `fn(arg)` in the child, which did not match `clone(2)` semantics. Use `AxFork()` for standard process creation, or `LIBC$clone` for full `clone()` semantics.

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

### Time

| Wrapper | Description |
|---------|-------------|
| `AxLocaltime(timer)` | Convert `time_t` to local `struct tm` |

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
  ├─ bof_deps_prepare() (dependency check)
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

## SDK Agent Integration

This section covers the API surface the agent uses to drive the SDK: initialization, synchronous execution, and the full async lifecycle (start → drain → list → kill).

The single umbrella header covers everything:

```c
#include "nax_bof_sdk.h"
```

---

### Initialization

```c
void nax_bof_sdk_init(void);
```

Call once at agent startup, before any BOF execution or symbol registration. Initializes the async job system and the extended symbol table. Not thread-safe — call from the main thread before spawning worker threads.

```c
void nax_https_main(NaxAgent *a) {
    nax_bof_sdk_init();
    /* ... register custom symbols, start transport loop ... */
}
```

---

### Synchronous execution

```c
int nax_bof_execute(const uint8_t *elf_data, uint32_t elf_size,
                    const uint8_t *args,     uint32_t args_size,
                    const char    *entry_name,
                    char         **output,   uint32_t *output_len);
```

Loads and runs a BOF in the calling thread. Blocks until `go()` returns.

| Parameter | Description |
|-----------|-------------|
| `elf_data` / `elf_size` | Raw `.o` file bytes |
| `args` / `args_size` | Packed argument buffer (CS format); pass `NULL`/`0` if the BOF takes no arguments |
| `entry_name` | Entry function name — always `"go"` for standard BOFs |
| `output` | Receives a `malloc`'d string with all `BeaconPrintf`/`BeaconOutput` output; caller must `free()` |
| `output_len` | Receives the output length in bytes |

Returns `0` on success, `-1` on error. On error, `*output` contains the error message (e.g., `"Unresolved: dlopen"`).

```c
char    *output     = NULL;
uint32_t output_len = 0;

int rc = nax_bof_execute(bof_data, bof_size,
                          args, args_size,
                          "go",
                          &output, &output_len);

if (rc == 0) {
    /* send output to C2 */
    send_result(output, output_len);
} else {
    send_error(output, output_len);
}
free(output);
```

---

### Asynchronous execution

#### Start a background BOF

```c
int nax_async_start(uint32_t        task_id,
                    const uint8_t  *bof_data, uint32_t bof_size,
                    const uint8_t  *args_data, uint32_t args_size);
```

Launches the BOF in a background `pthread`. `bof_data` and `args_data` are deep-copied internally — the caller can free them immediately after the call returns.

| Parameter | Description |
|-----------|-------------|
| `task_id` | Caller-assigned identifier used to correlate results in the drain callback |
| `bof_data` / `bof_size` | Raw `.o` file bytes |
| `args_data` / `args_size` | Packed argument buffer; pass `NULL`/`0` if none |

Returns the job index (0–7) on success, or `-1` if all slots are occupied (`MAX_ASYNC_JOBS = 8`).

```c
int job_idx = nax_async_start(task->id,
                               bof_data, bof_size,
                               args_data, args_size);
if (job_idx < 0) {
    /* all 8 slots busy */
    send_error_to_c2("async slots full");
}
```

#### Drain completed jobs

```c
typedef void (*async_result_cb)(uint32_t task_id, uint8_t status,
                                 const char *output, uint32_t output_len,
                                 void *user_data);

void nax_async_drain(async_result_cb cb, void *user_data);
```

Checks all job slots for completed BOFs and invokes `cb` for each one found. The slot is freed after the callback returns. Call this periodically from the agent's heartbeat loop.

| Callback parameter | Description |
|--------------------|-------------|
| `task_id` | The `task_id` passed to `nax_async_start` |
| `status` | `NAX_STATUS_OK` (0x00) or `NAX_STATUS_ERR` (0x01) |
| `output` / `output_len` | BOF output; valid only for the duration of the callback |
| `user_data` | Opaque pointer forwarded from `nax_async_drain` |

```c
static void on_bof_complete(uint32_t task_id, uint8_t status,
                             const char *output, uint32_t output_len,
                             void *user_data) {
    NaxAgent *agent = (NaxAgent *)user_data;
    send_result_to_c2(agent, task_id, status, output, output_len);
}

/* In the heartbeat loop: */
nax_async_drain(on_bof_complete, agent);
```

#### List running jobs

```c
int nax_async_list(char *buf, int cap);
```

Writes a formatted list of currently running async BOFs to `buf`. Returns the number of bytes written. Pass the result to `BeaconPrintf` or send it directly to the C2.

```c
char     list[1024];
uint32_t list_len = (uint32_t)nax_async_list(list, sizeof(list));

send_result_to_c2(agent, task_id, NAX_STATUS_OK, list, list_len);
```

Example output:

```
job 0  task=1001  state=RUNNING
job 2  task=1003  state=RUNNING
```

#### Kill a running job

```c
int nax_async_kill(int job_idx);
```

Signals the BOF in slot `job_idx` to stop by writing to its stop pipe. The BOF must be checking `BeaconGetStopJobEvent()` cooperatively; if it does not poll the stop event, the signal has no immediate effect. Returns `0` on success, `-1` if the slot is not active.

```c
int rc = nax_async_kill(job_idx);
if (rc != 0) {
    send_error_to_c2("invalid or inactive job index");
}
```

> **Note:** A killed job's output is discarded — `nax_async_drain` will not deliver a result for it. The slot is freed by the worker thread once it detects the stop signal.

---

### Full agent integration example

```c
#include "nax_bof_sdk.h"

/* ── Startup ── */
void agent_init(NaxAgent *a) {
    nax_bof_sdk_init();
    nax_bof_register_symbol("AgentSendFile", agent_send_file);
}

/* ── Heartbeat loop (called every ~1 s) ── */
void agent_heartbeat(NaxAgent *a) {
    nax_async_drain(on_bof_complete, a);
}

/* ── Dispatch incoming C2 task ── */
void agent_dispatch(NaxAgent *a, NaxTask *t) {
    switch (t->type) {

    case TASK_BOF_SYNC: {
        char    *out = NULL;
        uint32_t len = 0;
        int rc = nax_bof_execute(t->bof_data, t->bof_size,
                                  t->args, t->args_size,
                                  "go", &out, &len);
        send_result_to_c2(a, t->id, rc == 0 ? NAX_STATUS_OK : NAX_STATUS_ERR, out, len);
        free(out);
        break;
    }

    case TASK_BOF_ASYNC: {
        int job = nax_async_start(t->id,
                                   t->bof_data, t->bof_size,
                                   t->args, t->args_size);
        if (job < 0)
            send_error_to_c2(a, t->id, "async slots full");
        break;
    }

    case TASK_BOF_LIST: {
        char     buf[1024];
        uint32_t len = (uint32_t)nax_async_list(buf, sizeof(buf));
        send_result_to_c2(a, t->id, NAX_STATUS_OK, buf, len);
        break;
    }

    case TASK_BOF_KILL: {
        int job_idx = *(int *)t->args;
        int rc = nax_async_kill(job_idx);
        if (rc != 0)
            send_error_to_c2(a, t->id, "invalid job index");
        break;
    }
    }
}
```

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

/* Declare agent wrappers using primitive C types — no <zlib.h> needed.
 * The BOF must not link against libz; it calls the agent's wrappers instead. */
extern unsigned long AgentCrc32(unsigned long crc, const unsigned char *buf, unsigned int len);
extern int           AgentDeflateInit2(void *strm, int level, int method,
                                        int windowBits, int memLevel, int strategy,
                                        const char *version, int stream_size);
extern int           AgentDeflate(void *strm, int flush);
extern int           AgentDeflateEnd(void *strm);
extern unsigned long AgentCompressBound(unsigned long sourceLen);

void go(char *args, int args_len) {
    /* ... uses AgentCrc32, AgentDeflate, etc. ... */
}
```

### How Symbol Resolution Works

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

## Runtime Symbol Resolution (`LIBC$`, `RTLD$`, `LIBXXX$`)

BOFs can resolve symbols from the host process's loaded shared libraries at runtime without `dlsym` or `-ldl` dependencies. Three prefixes are supported, each with different search semantics.

---

### `LIBC$` — libc-first DSO resolution

BOFs can call **any exported function** from the host's loaded DSOs using the `LIBC$` prefix. The SDK resolves these by walking the in-memory DSO cache (populated from `/proc/self/maps`) — no `dlsym`, no `-ldl` dependency.

```
BOF calls LIBC$opendir("/etc")
  └─ bof_resolve_symbol("LIBC$opendir")
       ├─ Layer 1: custom table → miss
       ├─ Layer 2: Ax* table → miss
       └─ Layer 3: strip "LIBC$" → "opendir"
            ├─ Walk runtime DSO cache (all loaded shared libraries)
            │    → locate DSO exporting "opendir" (typically libc.so)
            │    → resolve via .gnu_hash / SysV hash walk
            └─ Return resolved address
```

After the first call, the DSO cache is populated. Subsequent resolutions only perform the hash walk (~nanoseconds).

#### Usage in a BOF

Declare external functions with the `LIBC$` prefix. For opaque types (`FILE *`, `DIR *`, etc.), see [BOF type declarations](#bof-type-declarations) below.

```c
#include "bof_api.h"

extern int    LIBC$getpid(void);
extern int    LIBC$getuid(void);
extern char  *LIBC$getenv(const char *);
extern char  *LIBC$getcwd(char *, int);
extern int    LIBC$uname(void *);
extern int    LIBC$access(const char *, int);
extern void  *LIBC$opendir(const char *);
extern void  *LIBC$readdir(void *);
extern int    LIBC$closedir(void *);
extern void  *LIBC$fopen(const char *, const char *);
extern char  *LIBC$fgets(char *, int, void *);
extern int    LIBC$fclose(void *);
extern long   LIBC$sysconf(int);
extern double LIBC$strtod(const char *, char **);
extern long   LIBC$time(long *);

void go(char *args, int args_len) {
    BeaconPrintf(CALLBACK_OUTPUT, "PID=%d UID=%d\n", LIBC$getpid(), LIBC$getuid());

    char *home = LIBC$getenv("HOME");
    BeaconPrintf(CALLBACK_OUTPUT, "HOME=%s\n", home ? home : "(null)");

    void *dir = LIBC$opendir("/tmp");
    if (dir) {
        void *ent = LIBC$readdir(dir);
        if (ent) {
            char *name = (char *)ent + 19; /* d_name offset in dirent64 */
            BeaconPrintf(CALLBACK_OUTPUT, "first: %s\n", name);
        }
        LIBC$closedir(dir);
    }
}
```

---

### `RTLD$` — Global DSO search (no dlopen)

The `RTLD$` prefix performs a **global** symbol lookup across all shared libraries already loaded in the process. Unlike `LIBC$`, it does not prioritize any specific library — it finds the first DSO that exports the requested symbol.

```
BOF calls RTLD$dlopen(...)
  └─ bof_resolve_symbol("RTLD$dlopen")
       └─ Layer 3: strip "RTLD$" → "dlopen"
            → global search across all loaded DSOs
            → found in libdl.so → return address
```

**Important:** `RTLD$` does **not** trigger dynamic loading and does **not** participate in dependency pre-validation. If the symbol is not found in any currently-loaded DSO, the BOF is rejected before `go()` runs:

```
BOF error: Unresolved: RTLD$some_function
```

Use `RTLD$` when the target library is reliably present in the host process. For symbols that may need to be loaded on demand, use `LIBXXX$` instead.

---

### `LIBXXX$` — Explicit library-qualified resolution

The `LIBXXX$` prefix lets a BOF resolve a symbol from a **specific** shared library. The general format is:

```
LIB<library>$<symbol>
```

Examples:

| Symbol | Target library |
|--------|----------------|
| `LIBZ$zlibVersion` | `libz.so` |
| `LIBSQLITE3$sqlite3_libversion` | `libsqlite3.so` |
| `LIBPIXMAN$pixman_version` | `libpixman-1.so` |
| `LIBHARFBUZZ$hb_version_string` | `libharfbuzz.so` |
| `LIBPNG16$png_access_version_number` | `libpng16.so` |
| `LIBCAIRO$cairo_version` | `libcairo.so` |

`LIBXXX$` symbols **participate in dependency pre-validation** via `bof_deps_prepare()`. Before `go()` runs, the dependency manager checks whether the required DSO is loaded. In flexible mode (`BOF_DEPS_ALLOW_DLOPEN=1`), it will locate and `dlopen()` missing libraries automatically. In strict mode (`BOF_DEPS_ALLOW_DLOPEN=0`), the BOF is rejected if any required DSO is absent.

```c
#include "bof_api.h"

extern const char  *LIBZ$zlibVersion(void);
extern const char  *LIBSQLITE3$sqlite3_libversion(void);

void go(char *args, int args_len) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] zlib    = %s\n", LIBZ$zlibVersion());
    BeaconPrintf(CALLBACK_OUTPUT, "[+] sqlite3 = %s\n", LIBSQLITE3$sqlite3_libversion());
}
```

---

### BOF type declarations

Since BOFs don't have access to libc headers, opaque types must be declared as `void *`:

| libc type | BOF declaration |
|---|---|
| `FILE *` | `void *` |
| `DIR *` | `void *` |
| `struct dirent *` | `void *` (access fields by byte offset) |
| `struct utsname *` | `void *` or `char[512]` buffer |

### OPSEC considerations

| Aspect | Ax\* Wrappers | LIBC$ / RTLD$ | LIBXXX$ |
|---|---|---|---|
| **Resolve method** | Compile-time table lookup | Runtime DSO cache walk | Runtime DSO cache walk + dep check |
| **dlsym usage** | None | None | None (hash walk) |
| **Underlying calls** | Mostly libc (open, read, malloc…); a few use `syscall()` directly (getdents64, io_uring, pidfd, process_vm, memfd_create, execveat) | The resolved function from the DSO — may be hooked | Depends on target DSO |
| **String exposure** | Function names in SDK's `.rodata` only | Function name briefly on stack during hash comparison | Same as LIBC$/RTLD$ |
| **/proc access** | None | Reads `/proc/self/maps` once (cached) | Same + dep check |
| **dlopen triggered** | Never | Never | Only if missing + flexible mode |

The Ax\* wrappers resolve at compile time (via the SDK's symbol table) — the BOF itself contains no name strings for them. The LIBC$/RTLD$/LIBXXX$ prefixes require a runtime name comparison. Both mechanisms call the same underlying libc functions for the majority of operations, so neither offers a systematic advantage over the other in terms of EDR hook avoidance. Choose based on coverage: use Ax\* when the needed function is in the table, use runtime prefixes for everything else.

---

## BOF Dependency Manager

The dependency manager (`bof_deps.c` / `bof_deps.h`) pre-validates and optionally pre-loads shared library dependencies declared by a BOF through `LIBXXX$` symbols.

### How it works

```
BOF references LIBZ$zlibVersion
  └─ bof_deps_prepare() scans .symtab for LIBXXX$ patterns
       └─ extracts hint: "libz"
            ├─ Check runtime DSO cache → found? → OK, proceed
            └─ Not found:
                 ├─ BOF_DEPS_ALLOW_DLOPEN=0 → FAIL (dependency error)
                 └─ BOF_DEPS_ALLOW_DLOPEN=1 → search system lib dirs
                      ├─ /usr/lib/x86_64-linux-gnu/libz.so.1 → dlopen()
                      ├─ Rescan /proc/self/maps → update DSO cache
                      └─ OK, symbol is now resolvable
```

### Strict vs. Flexible mode

| Mode | Build flag | Behavior |
|---|---|---|
| **Flexible** (default) | `BOF_DEPS_ALLOW_DLOPEN=1` | Missing DSOs are located in system library paths and loaded via `dlopen()` |
| **Strict** | `BOF_DEPS_ALLOW_DLOPEN=0` | BOF is rejected if any required DSO is not already loaded in the process |

### Library path restrictions

The dependency manager restricts candidate library paths to standard system locations. The following paths are **rejected** as potential DSO sources:

| Rejected path | Reason |
|---|---|
| `/tmp/` | User-writable, potential injection vector |
| `/var/tmp/` | Same as above |
| `/dev/shm/` | Memory-backed, user-writable |
| `/home/` | User-controlled |
| `/root/` | User-controlled |

Only libraries found under standard system library directories (e.g., `/usr/lib`, `/usr/lib64`, `/usr/lib/x86_64-linux-gnu`, `/lib`, `/usr/local/lib`) are accepted.

### Global policy switch

```c
extern int g_bof_deps_allow_dlopen;  /* 0 = strict, 1 = flexible (default) */
```

Set once at agent startup. Not thread-safe to modify at runtime.

---

## BOF Loader (Test Tool)

The `bof-loader/` is a **standalone development tool** for testing BOFs. It requires **no C2 server, no agent deployment, and no network setup**. The entire development cycle happens locally:

```
Edit BOF → gcc -c -o mybof.o mybof.c → ./bof_loader mybof.o → see output → repeat
```

This eliminates the overhead of deploying an agent just to test a BOF. The loader uses the exact same SDK runtime (ELF loader, API table, async system, dependency manager) that a real agent would use, so BOFs that work in the loader will work in any agent that integrates the SDK.

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

# Test: DLR — dynamic library resolution via LIBC$
./bof-loader/bof_loader example/DLR.o

# Test: multi_probe — multi-library resolution via LIBXXX$
./bof-loader/bof_loader example/multi_probe.o

# Test: custom symbols (calls agent-registered functions)
./bof-loader/bof_loader example/bof_custom.o

# Test: intentional failure (dlopen() called directly, not via LIBC$)
./bof-loader/bof_loader example/bof_fail.o
```

Expected outputs:

```
# uptime.o — SUCCESS
[OK] BOF completed
====================[Uptime]====================
[+] System Uptime: 3 days, 14 hours, 22 minutes, 8 seconds
[+] Load averages: 0.12 0.08 0.05
[+] Total RAM: 16384 MB
[+] Free RAM: 8192 MB
[+] Total swap: 2048 MB
[+] Processes: 342

# DLR.o — SUCCESS (resolves 19 LIBC$ symbols)
[OK] BOF completed
PID=12345 PPID=12300 UID=1000 EUID=1000 GID=1000
HOME=/home/user
CWD=/home/user
Kernel: Linux 6.x.y x86_64
CPUs=8
access=0
readdir OK
hostname: myhost
strtod=3.14159
time=1753123456

=== 19 LIBC$ OK ===

# multi_probe.o — SUCCESS (resolves LIBXXX$ symbols, output depends on installed libs)
[OK] BOF completed
[*] multi-probe
[+] LIBZ        = 1.2.11
[+] LIBSQLITE3  = 3.39.2
[+] LIBPIXMAN   = 0.40.0
[+] LIBHARFBUZZ = 5.1.0
[+] LIBPNG16    = 10640
[+] LIBCAIRO    = 11512
[*] done

# bof_custom.o — SUCCESS (uses registered custom_add / custom_get_info)
[OK] BOF completed
[*] Custom BOF initiated
[+] 10 + 32 = 42
[+] System info:: PID: 12345, UID: 1000
[*] Custom BOF completed

# bof_fail.o — FAILURE (dlopen not in API table — use LIBC$dlopen or RTLD$dlopen instead)
[ERR] BOF failed
BOF error: Unresolved: dlopen
```

---

## Real-World Integration Example

The [NaxDarks](https://github.com/Loky-rt/NaxDarks) Linux Agent is one consumer of this SDK. Its integration serves as a reference for how any agent can adopt the SDK:

---

# Disclaimer

For authorized security research, penetration testing, red team operations, and security tooling development only. Use only on systems where you have explicit authorization.
