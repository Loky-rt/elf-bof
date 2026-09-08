/* elf_bof.c — ELF BOF Loader for Linux Agent
 * In-memory loader for ELF relocatable objects (.o files compiled with gcc -c)
 * Supports x86_64 and ARM64 relocations.
 * OPSEC: mmap(RW) → mprotect per-section → execute → zero → munmap
 *
 * Ported from external agent: replaced nostdlib/syscall with libc,
 * removed msgpack, simplified to single output string interface.
 */

#include "elf_bof.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

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
    if (e->e_shoff + (uint64_t)e->e_shnum * e->e_shentsize > sz) return -1;
    return 0;
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

/* ── Resolve symbols ── */

static int resolve_symbols(const Elf64_Sym *sym, int nsym, const char *str,
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
        /* Undefined — resolve from BOF API table */
        const char *name = str + sym[i].st_name;
        if (sym[i].st_name == 0 || name[0] == '\0') {
            vals[i].resolved = 1;
            continue;
        }
        void *func = bof_resolve_symbol(name);
        if (func) {
            void *tramp = write_trampoline(arena, (uint64_t)(uintptr_t)func);
            vals[i].value = (uint64_t)(uintptr_t)(tramp ? tramp : func);
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

/* ── Find entry point ── */

static bof_entry_t find_entry(const char *name, const Elf64_Sym *sym, int nsym,
                              const char *str, sym_value_t *vals) {
    for (int i = 0; i < nsym; i++) {
        if (sym[i].st_shndx == SHN_UNDEF) continue;
        if (strcmp(str + sym[i].st_name, name) == 0 && vals[i].resolved)
            return (bof_entry_t)(uintptr_t)vals[i].value;
    }
    return NULL;
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

    /* Step 2: Parse section headers */
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(elf_data + ehdr->e_shoff);
    const Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    int nsym = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            if (shdrs[i].sh_offset > elf_size ||
                shdrs[i].sh_size > (uint64_t)elf_size - shdrs[i].sh_offset ||
                shdrs[i].sh_entsize == 0) break;
            symtab = (const Elf64_Sym *)(elf_data + shdrs[i].sh_offset);
            nsym   = (int)(shdrs[i].sh_size / shdrs[i].sh_entsize);
            int stridx = (int)shdrs[i].sh_link;
            if (stridx < ehdr->e_shnum &&
                shdrs[stridx].sh_offset <= elf_size &&
                shdrs[stridx].sh_size <= (uint64_t)elf_size - shdrs[stridx].sh_offset)
                strtab = (const char *)(elf_data + shdrs[stridx].sh_offset);
            break;
        }
    }
    if (!symtab || !strtab || nsym == 0) {
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
    if (resolve_symbols(symtab, nsym, strtab, sections, nsecs, vals, &arena,
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
            shdrs[i].sh_size > (uint64_t)elf_size - shdrs[i].sh_offset) continue;
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
    bof_entry_t entry = find_entry(entry_name, symtab, nsym, strtab, vals);
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
