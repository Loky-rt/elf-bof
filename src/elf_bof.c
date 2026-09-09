/* elf_bof.c — ELF BOF Loader for Linux Agent
 * In-memory loader for ELF relocatable objects (.o files compiled with gcc -c)
 * Supports x86_64 and ARM64 relocations.
 * OPSEC: mmap(RW) → mprotect per-section → execute → zero → munmap
 *
 * Ported from external agent: replaced nostdlib/syscall with libc,
 * removed msgpack, simplified to single output string interface.
 */

#include "elf_bof.h"
#include "bof_deps.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

extern int bof_deps_prepare(const uint8_t *elf_data, uint32_t elf_size,
                            char *err_buf, int err_sz);

/* ── Extern from bof_api.c ── */
extern void        bof_output_init(void);
extern void        bof_output_cleanup(void);
extern const char *bof_output_get(uint32_t *out_len);
extern int         bof_output_get_error(void);
extern void       *bof_resolve_symbol(const char *name);

/* ── Internal structures ── */

typedef struct {
    void     *base;
    size_t    size;
    size_t    raw_size;
    uint32_t  flags;
    int       shndx;
} loaded_section_t;

typedef struct {
    void   *base;
    size_t  total_size;
    void   *trampoline;
    int     tramp_count;
} bof_arena_t;

typedef struct {
    uint64_t value;
    int      section;
    int      resolved;
} sym_value_t;

typedef void (*bof_entry_t)(char *args, int args_len);

/* ── Trampoline sizes ── */
#if defined(__x86_64__) || defined(_M_X64)
#  define TRAMPOLINE_SIZE 14   /* jmp [rip+0]; .quad addr */
#elif defined(__aarch64__)
#  define TRAMPOLINE_SIZE 16   /* ldr x16, [pc+8]; br x16; .quad addr */
#else
#  define TRAMPOLINE_SIZE 14
#endif

/* ── Helpers ── */

static inline size_t page_align(size_t s) { return (s + 4095) & ~(size_t)4095; }

/* ── Validate ELF header ── */

static int validate_elf(const Elf64_Ehdr *e, uint32_t sz) {
    if (e->e_ident[0] != ELFMAG0 || e->e_ident[1] != ELFMAG1 ||
        e->e_ident[2] != ELFMAG2 || e->e_ident[3] != ELFMAG3)  return -1;
    if (e->e_ident[4] != ELFCLASS64 || e->e_ident[5] != ELFDATA2LSB) return -1;
    if (e->e_type != ET_REL) return -1;
#if defined(__x86_64__) || defined(_M_X64)
    if (e->e_machine != EM_X86_64) return -1;
#elif defined(__aarch64__)
    if (e->e_machine != EM_AARCH64) return -1;
#endif
    if (e->e_shoff == 0 || e->e_shnum == 0) return -1;
    if (e->e_shentsize != sizeof(Elf64_Shdr)) return -1;
    if (e->e_shoff + (uint64_t)e->e_shnum * e->e_shentsize > sz) return -1;
    return 0;
}

/* ── Validación de nombres en .strtab ──
 *
 * Devuelve la longitud del nombre en `strtab + off`, o 0 si el
 * offset está fuera del strtab o no encuentra NUL antes del final.
 *
 * CRÍTICO: llamar a strcmp/strlen directamente sobre un puntero
 * calculado como strtab + st_name sin validar el rango hace que
 * la implementación SIMD de libc (AVX2/AVX512) lea 32-64 bytes
 * fuera del buffer → SIGSEGV. Esta función garantiza que el nombre
 * está completo dentro del strtab antes de permitir cualquier
 * comparación. */
static size_t _strtab_name_len(const char *strtab, size_t strtab_size,
                               uint32_t off) {
    if (!strtab || off >= strtab_size) return 0;
    for (size_t i = off; i < strtab_size; i++) {
        if (strtab[i] == '\0') return i - off;
    }
    return 0;   /* sin NUL → corrupto */
}

/* ── Allocate all sections in a single contiguous mmap ── */

static int allocate_sections(const uint8_t *elf, uint32_t elf_size,
                             const Elf64_Ehdr *ehdr,
                             const Elf64_Shdr *shdrs,
                             loaded_section_t *secs, int *nsecs,
                             bof_arena_t *arena) {
    *nsecs = 0;
    memset(arena, 0, sizeof(*arena));

    /* Pass 1: total size */
    size_t total = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (!(shdrs[i].sh_flags & SHF_ALLOC)) continue;
        total = page_align(total);
        total += shdrs[i].sh_size > 0 ? shdrs[i].sh_size : 16;
    }
    total = page_align(total);
    size_t tramp_off = total;
    total += page_align(BOF_MAX_TRAMPOLINES * TRAMPOLINE_SIZE);

    /* Single mmap */
    size_t mmap_sz = page_align(total);
    void *base = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return -1;
    memset(base, 0, mmap_sz);

    arena->base       = base;
    arena->total_size  = mmap_sz;
    arena->trampoline  = (uint8_t *)base + tramp_off;
    arena->tramp_count = 0;

    /* Pass 2: lay out sections */
    size_t off = 0;
    for (int i = 0; i < ehdr->e_shnum && *nsecs < BOF_MAX_SECTIONS; i++) {
        const Elf64_Shdr *sh = &shdrs[i];
        if (!(sh->sh_flags & SHF_ALLOC)) continue;
        off = page_align(off);
        size_t sec_sz = sh->sh_size > 0 ? sh->sh_size : 16;
        void *sec_base = (uint8_t *)base + off;
        if (sh->sh_type != SHT_NOBITS && sh->sh_size > 0) {
            /* Bounds check: prevent out-of-bounds read from malformed .o */
            if (sh->sh_offset > elf_size ||
                sh->sh_size > (uint64_t)elf_size - sh->sh_offset) {
                munmap(base, mmap_sz);
                return -1;
            }
            memcpy(sec_base, elf + sh->sh_offset, sh->sh_size);
        }
        loaded_section_t *ls = &secs[*nsecs];
        ls->base     = sec_base;
        ls->size     = sec_sz;
        ls->raw_size = sh->sh_size;
        ls->flags    = (uint32_t)sh->sh_flags;
        ls->shndx    = i;
        (*nsecs)++;
        off += sec_sz;
    }
    return 0;
}

/* ── Write trampoline stub ── */

static void *write_trampoline(bof_arena_t *a, uint64_t target) {
    if (a->tramp_count >= BOF_MAX_TRAMPOLINES) return NULL;
    uint8_t *stub = (uint8_t *)a->trampoline + (a->tramp_count * TRAMPOLINE_SIZE);
    a->tramp_count++;

#if defined(__x86_64__) || defined(_M_X64)
    /* jmp [rip+0]; .quad target */
    stub[0] = 0xFF; stub[1] = 0x25;
    stub[2] = stub[3] = stub[4] = stub[5] = 0x00;
    memcpy(stub + 6, &target, 8);
#elif defined(__aarch64__)
    uint32_t ldr = 0x58000050; /* ldr x16, pc+8 */
    uint32_t br  = 0xD61F0200; /* br x16 */
    memcpy(stub + 0, &ldr, 4);
    memcpy(stub + 4, &br, 4);
    memcpy(stub + 8, &target, 8);
#endif
    return stub;
}

/* ── Find loaded section by ELF index ── */

static loaded_section_t *find_section(loaded_section_t *s, int n, int shndx) {
    for (int i = 0; i < n; i++)
        if (s[i].shndx == shndx) return &s[i];
    return NULL;
}

/* ── Resolve symbols ──
 *
 * FIX: recibe el tamaño del strtab para validar cada st_name antes
 * de leerlo o pasarlo al resolver. Sin esto, un .o malformado o
 * trimeado puede hacer que strcmp/strlen de libc lean fuera del
 * mmap del BOF y maten el proceso. */
static int resolve_symbols(const Elf64_Sym *sym, int nsym,
                           const char *str, size_t str_size,
                           loaded_section_t *secs, int nsecs,
                           sym_value_t *vals, bof_arena_t *arena,
                           char *err_sym, int err_sz) {
    for (int i = 0; i < nsym; i++) {
        vals[i].resolved = 0; vals[i].value = 0; vals[i].section = -1;

        /* STT_SECTION → section base */
        if (ELF64_ST_TYPE(sym[i].st_info) == 3) {
            loaded_section_t *ls = find_section(secs, nsecs, sym[i].st_shndx);
            if (ls) {
                vals[i].value = (uint64_t)(uintptr_t)ls->base;
                vals[i].section = sym[i].st_shndx;
                vals[i].resolved = 1;
            }
            continue;
        }
        /* Defined symbol */
        if (sym[i].st_shndx != SHN_UNDEF) {
            loaded_section_t *ls = find_section(secs, nsecs, sym[i].st_shndx);
            if (ls) {
                vals[i].value = (uint64_t)(uintptr_t)ls->base + sym[i].st_value;
                vals[i].section = sym[i].st_shndx;
                vals[i].resolved = 1;
            }
            continue;
        }
        /* Undefined — resolver desde el SDK */
        if (sym[i].st_name == 0) {
            vals[i].resolved = 1;
            continue;
        }

        /* FIX: validar st_name contra el tamaño del strtab antes de
         * tocar `str + st_name`. Si el nombre no tiene NUL dentro
         * del strtab, el .o está corrupto → abortar limpiamente. */
        if (_strtab_name_len(str, str_size, sym[i].st_name) == 0) {
            snprintf(err_sym, err_sz, "Corrupt symbol name at index %d", i);
            return -1;
        }

        const char *name = str + sym[i].st_name;
        if (name[0] == '\0') {
            vals[i].resolved = 1;
            continue;
        }

        void *func = bof_resolve_symbol(name);
        if (func) {
            /* Every resolved symbol is reached through a trampoline in
             * the BOF's own arena. This keeps R_X86_64_PLT32 /
             * R_X86_64_PC32 displacements inside 32 bits even when the
             * target DSO is mapped more than 2 GB away. If the
             * trampoline pool is exhausted we must NOT fall back to
             * the raw target address: a PLT32 relocation against a
             * far-away address silently truncates and the BOF jumps to
             * garbage. Fail cleanly instead. */
            void *tramp = write_trampoline(arena, (uint64_t)(uintptr_t)func);
            if (!tramp) {
                snprintf(err_sym, err_sz,
                         "Trampoline pool exhausted (%d slots) resolving '%s'",
                         BOF_MAX_TRAMPOLINES, name);
                return -1;
            }
            vals[i].value = (uint64_t)(uintptr_t)tramp;
            vals[i].section = -1;
            vals[i].resolved = 1;
        } else if (ELF64_ST_BIND(sym[i].st_info) == STB_WEAK) {
            vals[i].value = 0; vals[i].resolved = 1;
        } else {
            snprintf(err_sym, err_sz, "Unresolved: %s", name);
            return -1;
        }
    }
    return 0;
}

/* ── Apply relocations — x86_64 ── */

#if defined(__x86_64__) || defined(_M_X64)
static int apply_relocs_x64(const Elf64_Rela *r, int n,
                             sym_value_t *v, loaded_section_t *t) {
    for (int i = 0; i < n; i++) {
        uint32_t si = (uint32_t)ELF64_R_SYM(r[i].r_info);
        uint32_t ty = (uint32_t)ELF64_R_TYPE(r[i].r_info);
        if (!v[si].resolved) return -1;
        uint64_t S = v[si].value;
        int64_t  A = r[i].r_addend;
        uint8_t *P = (uint8_t *)t->base + r[i].r_offset;
        switch (ty) {
        case R_X86_64_64:   *(uint64_t *)P = S + A; break;
        case R_X86_64_PC32:
        case R_X86_64_PLT32:*(int32_t *)P = (int32_t)((int64_t)S + A - (int64_t)(uintptr_t)P); break;
        case R_X86_64_32:   *(uint32_t *)P = (uint32_t)(S + A); break;
        case R_X86_64_32S:  *(int32_t *)P = (int32_t)(S + A); break;
        default: break;
        }
    }
    return 0;
}
#endif

/* ── Apply relocations — ARM64 ── */

#if defined(__aarch64__)
static int apply_relocs_arm64(const Elf64_Rela *r, int n,
                               sym_value_t *v, loaded_section_t *t) {
    for (int i = 0; i < n; i++) {
        uint32_t si = (uint32_t)ELF64_R_SYM(r[i].r_info);
        uint32_t ty = (uint32_t)ELF64_R_TYPE(r[i].r_info);
        if (!v[si].resolved) return -1;
        uint64_t S = v[si].value;
        int64_t  A = r[i].r_addend;
        uint8_t *P = (uint8_t *)t->base + r[i].r_offset;
        switch (ty) {
        case R_AARCH64_ABS64: *(uint64_t *)P = S + A; break;
        case R_AARCH64_CALL26:
        case R_AARCH64_JUMP26: {
            int64_t off = ((int64_t)S + A - (int64_t)(uintptr_t)P) >> 2;
            *(uint32_t *)P = (*(uint32_t *)P & 0xFC000000) | (off & 0x3FFFFFF);
            break;
        }
        case R_AARCH64_ADR_PREL_PG_HI21: {
            int64_t ps = ((int64_t)S + A) & ~0xFFFLL;
            int64_t pp = (int64_t)(uintptr_t)P & ~0xFFFLL;
            int64_t off = ps - pp;
            uint32_t lo = ((off >> 12) & 0x3) << 29;
            uint32_t hi = ((off >> 14) & 0x7FFFF) << 5;
            *(uint32_t *)P = (*(uint32_t *)P & 0x9F00001F) | lo | hi;
            break;
        }
        case R_AARCH64_ADD_ABS_LO12_NC:
        case R_AARCH64_LDST8_ABS_LO12_NC:
            *(uint32_t *)P = (*(uint32_t *)P & 0xFFC003FF) | (((S + A) & 0xFFF) << 10); break;
        case R_AARCH64_LDST16_ABS_LO12_NC:
            *(uint32_t *)P = (*(uint32_t *)P & 0xFFC003FF) | ((((S + A) & 0xFFF) >> 1) << 10); break;
        case R_AARCH64_LDST32_ABS_LO12_NC:
            *(uint32_t *)P = (*(uint32_t *)P & 0xFFC003FF) | ((((S + A) & 0xFFF) >> 2) << 10); break;
        case R_AARCH64_LDST64_ABS_LO12_NC:
            *(uint32_t *)P = (*(uint32_t *)P & 0xFFC003FF) | ((((S + A) & 0xFFF) >> 3) << 10); break;
        case R_AARCH64_LDST128_ABS_LO12_NC:
            *(uint32_t *)P = (*(uint32_t *)P & 0xFFC003FF) | ((((S + A) & 0xFFF) >> 4) << 10); break;
        default: break;
        }
    }
    return 0;
}
#endif

/* ── Apply memory protections ── */

static int protect_sections(loaded_section_t *secs, int nsecs, bof_arena_t *arena) {
    for (int i = 0; i < nsecs; i++) {
        int prot;
        if (secs[i].flags & SHF_EXECINSTR)     prot = PROT_READ | PROT_EXEC;
        else if (secs[i].flags & SHF_WRITE)     prot = PROT_READ | PROT_WRITE;
        else                                     prot = PROT_READ;
        uintptr_t start = (uintptr_t)secs[i].base;
        uintptr_t pstart = start & ~(uintptr_t)4095;
        size_t psz = page_align((start - pstart) + secs[i].size);
        if (mprotect((void *)pstart, psz, prot) != 0) return -1;
    }
    /* Trampoline area → RX */
    if (arena->tramp_count > 0 && arena->trampoline) {
        uintptr_t ts = (uintptr_t)arena->trampoline;
        uintptr_t ps = ts & ~(uintptr_t)4095;
        size_t used = (size_t)arena->tramp_count * TRAMPOLINE_SIZE;
        if (mprotect((void *)ps, page_align((ts - ps) + used), PROT_READ | PROT_EXEC) != 0)
            return -1;
    }
#if defined(__aarch64__)
    /* Flush icache on ARM64 */
    for (int i = 0; i < nsecs; i++) {
        if (!(secs[i].flags & SHF_EXECINSTR)) continue;
        uint8_t *s = (uint8_t *)secs[i].base;
        uint8_t *e = s + secs[i].raw_size;
        for (uint8_t *p = s; p < e; p += 64) __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
        __asm__ volatile("dsb ish" ::: "memory");
        for (uint8_t *p = s; p < e; p += 64) __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
        __asm__ volatile("dsb ish\n\tisb" ::: "memory");
    }
    if (arena->tramp_count > 0 && arena->trampoline) {
        uint8_t *s = (uint8_t *)arena->trampoline;
        uint8_t *e = s + arena->tramp_count * TRAMPOLINE_SIZE;
        for (uint8_t *p = s; p < e; p += 64) __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
        __asm__ volatile("dsb ish" ::: "memory");
        for (uint8_t *p = s; p < e; p += 64) __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
        __asm__ volatile("dsb ish\n\tisb" ::: "memory");
    }
#endif
    return 0;
}

/* ── OPSEC cleanup — zero and release arena ── */

static void cleanup_arena(bof_arena_t *arena) {
    if (arena->base && arena->total_size > 0) {
        mprotect(arena->base, arena->total_size, PROT_READ | PROT_WRITE);
        volatile uint8_t *p = (volatile uint8_t *)arena->base;
        for (size_t i = 0; i < arena->total_size; i++) p[i] = 0;
        munmap(arena->base, arena->total_size);
        arena->base = NULL;
        arena->total_size = 0;
    }
}

/* ── Find entry point ──
 *
 * FIX: recibe strtab_size y valida st_name antes de cualquier
 * comparación. strcmp sobre un nombre corrupto es una de las causas
 * del SIGSEGV en libc con AVX2. */
static bof_entry_t find_entry(const char *name,
                              const Elf64_Sym *sym, int nsym,
                              const char *str, size_t str_size,
                              sym_value_t *vals) {
    for (int i = 0; i < nsym; i++) {
        if (sym[i].st_shndx == SHN_UNDEF) continue;
        if (sym[i].st_name == 0) continue;
        if (_strtab_name_len(str, str_size, sym[i].st_name) == 0) continue;
        if (strcmp(str + sym[i].st_name, name) == 0 && vals[i].resolved)
            return (bof_entry_t)(uintptr_t)vals[i].value;
    }
    return NULL;
}


/* ── Collect LIBXXX$ dependency hints from .symtab ──
 *
 * Walks the BOF's symbol table. For every STB_GLOBAL / STB_WEAK
 * undefined symbol whose name contains a '$', extracts the prefix
 * before the '$', lowercases it, and adds it to the output list if
 * not already present.
 *
 * Ignores:
 *   - local symbols
 *   - defined symbols
 *   - symbols without '$'
 *   - empty prefixes ("$foo")
 *
 * Returns 0 on success, -1 on malformed ELF.
 *
 * This function is used by bof_deps_prepare() to learn which shared
 * libraries the BOF needs. It must run before any symbol resolution,
 * because resolution failures for LIBXXX$ are exactly what it
 * prevents. */
int elf_bof_collect_deps(const uint8_t *elf, uint32_t sz,
                         char (*hints)[48], int max_hints, int *out_count) {
    *out_count = 0;
    if (!elf || sz < sizeof(Elf64_Ehdr) || !hints || max_hints <= 0)
        return -1;

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)elf;
    if (validate_elf(eh, sz) != 0) return -1;

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(elf + eh->e_shoff);

    const Elf64_Sym *symtab = NULL;
    const char       *strtab = NULL;
    size_t            strtab_size = 0;
    int               nsym = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_SYMTAB) continue;
        if (shdrs[i].sh_offset > sz ||
            shdrs[i].sh_size > (uint64_t)sz - shdrs[i].sh_offset ||
            shdrs[i].sh_entsize != sizeof(Elf64_Sym))
            return -1;
        symtab = (const Elf64_Sym *)(elf + shdrs[i].sh_offset);
        nsym   = (int)(shdrs[i].sh_size / shdrs[i].sh_entsize);
        int stridx = (int)shdrs[i].sh_link;
        if (stridx < 0 || stridx >= eh->e_shnum) return -1;
        if (shdrs[stridx].sh_offset > sz ||
            shdrs[stridx].sh_size > (uint64_t)sz - shdrs[stridx].sh_offset)
            return -1;
        strtab      = (const char *)(elf + shdrs[stridx].sh_offset);
        strtab_size = (size_t)shdrs[stridx].sh_size;
        break;
    }
    if (!symtab || !strtab || strtab_size == 0 || nsym == 0) return -1;

    for (int i = 0; i < nsym; i++) {
        if (symtab[i].st_shndx != SHN_UNDEF) continue;
        unsigned bind = ELF64_ST_BIND(symtab[i].st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK) continue;

        size_t name_len = _strtab_name_len(strtab, strtab_size,
                                           symtab[i].st_name);
        if (name_len == 0) continue;   /* corrupt or empty, skip */

        const char *name = strtab + symtab[i].st_name;
        const char *dollar = strchr(name, '$');
        if (!dollar || dollar == name) continue;

        size_t plen = (size_t)(dollar - name);
        if (plen >= 48) continue;      /* too long to be a real lib hint */

        /* Normalise to lowercase for dedupe and lookup. */
        char hint[48];
        for (size_t k = 0; k < plen; k++) {
            char c = name[k];
            hint[k] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        hint[plen] = '\0';

        if (strcmp(hint, "rtld") == 0) continue;
        if (strcmp(hint, "libc") == 0) continue;

        /* Dedupe. */
        int dup = 0;
        for (int h = 0; h < *out_count; h++) {
            if (strcmp(hints[h], hint) == 0) { dup = 1; break; }
        }
        if (dup) continue;

        if (*out_count >= max_hints) return -1;   /* table full */
        strcpy(hints[*out_count], hint);
        (*out_count)++;
    }

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * Public API: nax_bof_execute
 * ══════════════════════════════════════════════════════════════ */

int nax_bof_execute(const uint8_t *elf_data, uint32_t elf_size,
                    const uint8_t *args, uint32_t args_size,
                    const char *entry_name,
                    char **output, uint32_t *output_len) {

    loaded_section_t sections[BOF_MAX_SECTIONS];
    int nsecs = 0;
    bof_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    char errbuf[256];

    *output = NULL;
    *output_len = 0;

    /* Default entry */
    if (!entry_name || entry_name[0] == '\0') entry_name = "go";

    /* Step 1: Validate */
    if (elf_size < sizeof(Elf64_Ehdr)) {
        *output = strdup("BOF error: file too small");
        *output_len = (uint32_t)strlen(*output);
        return -1;
    }
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf_data;
    if (validate_elf(ehdr, elf_size) != 0) {
        *output = strdup("BOF error: invalid ELF header (not a .o file or wrong arch)");
        *output_len = (uint32_t)strlen(*output);
        return -1;
    }

    /* Step 2a: Pre-validate and pre-load LIBXXX$ dependencies.
     * Rejects the BOF before any of its code runs if a required library
     * cannot be satisfied. Idempotent: safe to call twice. */
    {
        char dep_err[256];
        if (bof_deps_prepare(elf_data, elf_size, dep_err, sizeof(dep_err))
                != BOF_DEPS_OK) {
            char msg[320];
            snprintf(msg, sizeof(msg), "BOF error: %s",
                     dep_err[0] ? dep_err : "unsatisfied library dependency");
            *output = strdup(msg);
            *output_len = (uint32_t)strlen(*output);
            return -1;
        }
    }

    /* Step 2: Parse section headers */
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(elf_data + ehdr->e_shoff);
    const Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    size_t strtab_size = 0;
    int nsym = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            if (shdrs[i].sh_offset > elf_size ||
                shdrs[i].sh_size > (uint64_t)elf_size - shdrs[i].sh_offset ||
                shdrs[i].sh_entsize != sizeof(Elf64_Sym)) break;
            symtab = (const Elf64_Sym *)(elf_data + shdrs[i].sh_offset);
            nsym   = (int)(shdrs[i].sh_size / shdrs[i].sh_entsize);
            int stridx = (int)shdrs[i].sh_link;
            if (stridx >= 0 && stridx < ehdr->e_shnum &&
                shdrs[stridx].sh_offset <= elf_size &&
                shdrs[stridx].sh_size <= (uint64_t)elf_size - shdrs[stridx].sh_offset) {
                strtab      = (const char *)(elf_data + shdrs[stridx].sh_offset);
                strtab_size = (size_t)shdrs[stridx].sh_size;
            }
            break;
        }
    }
    if (!symtab || !strtab || strtab_size == 0 || nsym == 0) {
        *output = strdup("BOF error: no symbol table");
        *output_len = (uint32_t)strlen(*output);
        return -1;
    }

    /* Step 3: Allocate sections (single contiguous mmap) */
    if (allocate_sections(elf_data, elf_size, ehdr, shdrs, sections, &nsecs, &arena) != 0) {
        *output = strdup("BOF error: mmap failed");
        *output_len = (uint32_t)strlen(*output);
        return -1;
    }

    /* Step 4: Resolve symbols */
    sym_value_t *vals = (sym_value_t *)calloc(nsym, sizeof(sym_value_t));
    if (!vals) {
        cleanup_arena(&arena);
        *output = strdup("BOF error: alloc sym_values failed");
        *output_len = (uint32_t)strlen(*output);
        return -1;
    }
    errbuf[0] = '\0';
    if (resolve_symbols(symtab, nsym, strtab, strtab_size,
                        sections, nsecs, vals, &arena,
                        errbuf, sizeof(errbuf)) != 0) {
        free(vals); cleanup_arena(&arena);
        char msg[320];
        snprintf(msg, sizeof(msg), "BOF error: %s", errbuf);
        *output = strdup(msg);
        *output_len = (uint32_t)strlen(*output);
        return -1;
    }

    /* Step 5: Apply relocations */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_RELA) continue;
        loaded_section_t *target = find_section(sections, nsecs, (int)shdrs[i].sh_info);
        if (!target) continue;
        if (shdrs[i].sh_offset > elf_size ||
            shdrs[i].sh_size > (uint64_t)elf_size - shdrs[i].sh_offset ||
            shdrs[i].sh_entsize != sizeof(Elf64_Rela)) continue;
        const Elf64_Rela *relas = (const Elf64_Rela *)(elf_data + shdrs[i].sh_offset);
        int nrelas = (int)(shdrs[i].sh_size / sizeof(Elf64_Rela));
        int ret;
#if defined(__x86_64__) || defined(_M_X64)
        ret = apply_relocs_x64(relas, nrelas, vals, target);
#elif defined(__aarch64__)
        ret = apply_relocs_arm64(relas, nrelas, vals, target);
#else
        (void)relas; (void)nrelas;
        ret = -1;
#endif
        if (ret != 0) {
            free(vals); cleanup_arena(&arena);
            *output = strdup("BOF error: relocation failed");
            *output_len = (uint32_t)strlen(*output);
            return -1;
        }
    }

    /* Step 6: Protect sections */
    if (protect_sections(sections, nsecs, &arena) != 0) {
        free(vals); cleanup_arena(&arena);
        *output = strdup("BOF error: mprotect failed");
        *output_len = (uint32_t)strlen(*output);
        return -1;
    }

    /* Step 7: Find entry point */
    bof_entry_t entry = find_entry(entry_name, symtab, nsym,
                                   strtab, strtab_size, vals);
    if (!entry) {
        free(vals); cleanup_arena(&arena);
        char msg[320];
        snprintf(msg, sizeof(msg), "BOF error: entry '%s' not found", entry_name);
        *output = strdup(msg);
        *output_len = (uint32_t)strlen(*output);
        return -1;
    }

    /* Step 8: Init output, execute, collect */
    bof_output_init();

    entry((char *)args, (int)args_size);

    uint32_t olen = 0;
    const char *ostr = bof_output_get(&olen);
    int oerr = bof_output_get_error();

    if (olen > 0 && ostr) {
        *output = (char *)malloc(olen + 1);
        if (*output) {
            memcpy(*output, ostr, olen);
            (*output)[olen] = '\0';
            *output_len = olen;
        }
    } else {
        *output = strdup("(no output)");
        *output_len = (uint32_t)strlen(*output);
    }

    bof_output_cleanup();

    /* Step 9: OPSEC cleanup */
    free(vals);
    cleanup_arena(&arena);

    return oerr ? -1 : 0;
}
