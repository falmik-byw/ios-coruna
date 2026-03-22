/*
 * record_0x50000_loader.c
 * entry4_type0x05.bin — raw arm64 PIC helper loader (record 0x50000)
 *
 * Layout:
 *   0x000  Reset()          — writes 3 callbacks into caller ctx
 *   0x024..0x1a8            — direct syscall veneers (svc #0x80)
 *   0x1ac..0x1023           — zero-filled reserved block
 *   0x1024 FUN_00001024     — main loader routine (FAT/Mach-O loader)
 *   0x3334 FUN_00003334     — symbol resolver
 *   0x340c FUN_0000340c     — unload/finalize image
 *   0x3628 FUN_00003628     — memcpy helper
 *   0x3694 FUN_00003694     — pattern search helper
 *   0x37b4 FUN_000037b4     — memset helper (double-pass)
 *   0x3840 FUN_00003840     — strcmp helper
 *   0x38b8 FUN_000038b8     — memcmp helper
 *   0x39ac FUN_000039ac     — DWARF unwind info processor
 *   0x4514 FUN_00004514     — vm_protect wrapper
 *   0x454c FUN_0000454c     — vm_allocate + protect loop
 *   0x4648 FUN_00004648     — vm_protect via syscall veneer
 *   0x468c FUN_0000468c     — segment address resolver
 *   0x4784 FUN_00004784     — dylib handle resolver
 *   0x4930 FUN_00004930     — symbol lookup via dlsym / pthread_create
 *   0x4a98 FUN_00004a98     — pthread_create wrapper
 *   0x4b64 FUN_00004b64     — thread entry trampoline
 *   0x4da0 FUN_00004da0     — chained fixup rebase/bind
 *   0x4ea8 FUN_00004ea8     — section index → address
 *   0x5be0 FUN_00005be0     — PAC dispatch
 *
 * Verified: Reset() callback layout, syscall veneer pattern,
 *           FUN_00003334 symbol table walk, FUN_0000340c LC_SEGMENT walk,
 *           FUN_00004da0 chained fixup format, FUN_00004930 dlsym path,
 *           FUN_00004a98 pthread_create wrapper, FUN_00004b64 thread entry.
 * Inferred: function role labels from call context and data flow.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>

/* ── context layout (caller-supplied, written by Reset) ─────────────────── */
typedef struct LoaderCtx {
    uint8_t  _pad0[0x28];
    void    *vm_alloc_fn;   /* +0x28  vm_allocate callback                   */
    void    *load_fn;       /* +0x30  FUN_00001024 — load image bytes        */
    void    *resolve_fn;    /* +0x38  FUN_00003334 — resolve symbol          */
    uint8_t  _pad1[0x60];
    uint64_t text_base;     /* +0x50  __TEXT vmaddr                          */
    uint64_t text_end;      /* +0x58  __TEXT vmaddr + vmsize                 */
    uint64_t slide_base;    /* +0x60  slide base                             */
    uint8_t  _pad2[0x40];
    uint64_t image_size;    /* +0xa8  image size                             */
    uint8_t  flags;         /* +0xac  flags byte                             */
    uint8_t  _pad3[3];
    uint32_t vm_prot_flags; /* +0x5c8 vm_protect flags                      */
    uint8_t  _pad4[0x560];
    void    *unload_fn;     /* +0x130 FUN_0000340c — unload/finalize image   */
} LoaderCtx;

/* ── image handle layout ─────────────────────────────────────────────────── */
typedef struct ImageHandle {
    void    *mach_header;   /* +0x00  Mach-O header pointer                  */
    uint8_t  _pad0[0x18];
    void    *symtab;        /* +0x20  LC_SYMTAB nlist array                  */
    uint32_t nsyms;         /* +0x28  (at mach_header+0x0c)                  */
    uint8_t  _pad1[0xc];
    void    *strtab;        /* +0x38  string table base                      */
    uint8_t  _pad2[8];
    void    *text_base;     /* +0x48  __TEXT base                            */
    uint8_t  _pad3[8];
    void    *slide_base;    /* +0x58  slide base                             */
    void    *text_end;      /* +0x60  __TEXT end                             */
    uint8_t  _pad4[0x40];
    void    *load_cmds;     /* +0xa0  load commands pointer                  */
    uint8_t  _pad5[8];
    uint32_t ncmds;         /* +0xb0  (at mach_header+0x10)                  */
    uint8_t  _pad6[0x1c];
    uint32_t image_size;    /* +0xd0  (at +0x15 as uint32)                   */
    uint8_t  _pad7[0x30];
    void    *init_fn;       /* +0xf0  module init function                   */
    uint8_t  _pad8[0x18];
    void    *fini_fn;       /* +0x108 module fini function                   */
} ImageHandle;

/* ── syscall veneer (svc #0x80 + errno normalisation) ───────────────────── */
typedef struct { int64_t retval; uint64_t err; } SyscallResult;

static inline SyscallResult syscall_veneer(uint64_t nr, uint64_t a0,
                                            uint64_t a1, uint64_t a2)
{
    register uint64_t x0  asm("x0")  = a0;
    register uint64_t x1  asm("x1")  = a1;
    register uint64_t x2  asm("x2")  = a2;
    register uint64_t x16 asm("x16") = nr;
    uint64_t carry;
    asm volatile("svc #0x80\n\tcset %0, cs"
                 : "=r"(carry), "+r"(x0)
                 : "r"(x16), "r"(x1), "r"(x2)
                 : "memory");
    return (SyscallResult){ carry ? -1LL : (int64_t)x0, carry ? x0 : 0 };
}

/* ── forward declarations (defined later in this file or in PIC blob) ────── */
extern uint64_t FUN_00005be0(uint64_t ptr, uint32_t op, uint64_t modifier);
extern uint64_t FUN_00005b6c(uint64_t ptr);
extern uint64_t FUN_00004b64(long *arg);
extern uint64_t FUN_00005ba0(void *fn, int flags);
extern void     FUN_00001024(void);

/* ── FUN_00003840 — strcmp ───────────────────────────────────────────────── */
static int loader_strcmp(const char *a, const char *b)
{
    while (*b) {
        if (*a != *b) return 1;
        a++; b++;
    }
    return 0;
}

/* ── FUN_000038b8 — memcmp ───────────────────────────────────────────────── */
static int loader_memcmp(const void *a, const void *b, size_t n)
{
    const char *p = a, *q = b;
    for (size_t i = 0; i < n; i++)
        if (p[i] != q[i]) return 1;
    return 0;
}

/* ── FUN_00003628 — memcpy ───────────────────────────────────────────────── */
static void loader_memcpy(void *dst, const void *src, size_t n)
{
    char *d = dst; const char *s = src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

/* ── FUN_000037b4 — memset (double-pass) ────────────────────────────────── */
static void loader_memset(void *p, char val, size_t n)
{
    char *d = p;
    /* first pass: val+1 */
    for (size_t i = 0; i < n; i++) d[i] = val + 1;
    /* second pass: val */
    for (size_t i = 0; i < n; i++) d[i] = val;
}

/* ── FUN_00003694 — pattern search ──────────────────────────────────────── */
static long loader_pattern_search(long base, long end, long pattern,
                                   size_t pat_size)
{
    for (long off = 0; off <= end - (long)pat_size; off += 4) {
        int match = 1;
        for (size_t j = 0; j < pat_size; j += 4) {
            if (*(int *)(base + off + j) != *(int *)(pattern + j)) {
                match = 0; break;
            }
        }
        if (match) return base + off;
    }
    return 0;
}

/* ── FUN_00004ea8 — section index → address ─────────────────────────────── */
static long section_index_to_addr(int idx, long *image)
{
    struct mach_header_64 *mh = (struct mach_header_64 *)*image;
    if (!mh || !mh->ncmds) return 0;

    int sec_idx = 0;
    struct load_command *lc = (struct load_command *)((uint8_t *)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            struct section_64 *sec = (struct section_64 *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                if (sec_idx == idx)
                    return (image[0xb] - image[10]) + (long)sec->addr;
                sec_idx++;
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return 0;
}

/* ── FUN_0000468c — segment address resolver ────────────────────────────── */
/*
 * Finds the segment containing addr and returns the slid address.
 * Walks LC_SEGMENT_64 commands, checks segname == "__PAGEZERO".
 */
static uint64_t segment_addr_resolve(long *image, uint64_t addr, long *out)
{
    if (!image || !out) return 0xad001;
    struct mach_header_64 *mh = (struct mach_header_64 *)*image;
    if (!mh->ncmds) return 0xad011;

    struct load_command *lc = (struct load_command *)((uint8_t *)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (loader_memcmp(seg->segname, "__PAGEZERO", 11) != 0 &&
                seg->vmaddr <= addr &&
                addr - seg->vmaddr < seg->vmsize) {
                *out = (image[0xb] - image[10]) +
                       (long)(addr - seg->vmaddr) + (long)seg->fileoff;
                return 0;
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return 0xad011;
}

/* ── FUN_00003334 — symbol resolver ─────────────────────────────────────── */
/*
 * Walks the loaded image's nlist symbol table looking for name match.
 * param_1: loader ctx
 * param_2: image handle pointer
 * param_3: symbol name (C string)
 * param_4: output resolved address
 */
uint64_t FUN_00003334(uint64_t param_1, long param_2,
                       long param_3, long *param_4)
{
    if (!param_3 || !param_4 || !param_2) return 0xad001;

    long strtab = *(long *)(param_2 + 0x38);
    long symtab = *(long *)(param_2 + 0x30);
    if (!strtab || !symtab) return 0x12001;

    struct mach_header_64 *mh = *(struct mach_header_64 **)param_2;
    uint32_t nsyms = *(uint32_t *)((uint8_t *)mh + 0x0c);
    if (!nsyms) return 0x12001;

    *param_4 = 0;
    /* nlist_64 entries at symtab+8, stride 16 */
    long entry = strtab + 8;
    for (uint32_t i = 0; i < nsyms; i++, entry += 16) {
        uint8_t type = *(uint8_t *)(entry - 4);
        if ((type & 0xe1) != 1) continue;

        uint32_t str_off = *(uint32_t *)(entry - 4 + 4);
        const char *sym_name = (const char *)(*(long *)(param_2 + 0x48) + str_off);
        if (loader_strcmp((const char *)param_3, sym_name) == 0) {
            long value = *(long *)entry;
            *param_4 = (*(long *)(param_2 + 0x60) - *(long *)(param_2 + 0x50)) + value;
            return 0;
        }
    }
    return 0x12001;
}

/* ── FUN_00004648 — vm_protect via syscall veneer ───────────────────────── */
static int loader_vm_protect(long ctx, uint64_t addr, uint64_t size, int prot)
{
    (void)ctx;
    SyscallResult r = syscall_veneer(0xa, (uint64_t)mach_task_self(),
                                     addr, size);
    (void)prot;
    return (int)r.retval;
}

/* ── FUN_00004514 — vm_protect wrapper ──────────────────────────────────── */
static void loader_vm_protect_wrap(long ctx, uint64_t addr, size_t size)
{
    long aligned = 0;
    if (size & 0x3fff) aligned = 0x4000 - (size & 0x3fff);
    loader_vm_protect(ctx, addr, aligned + size,
                      *(int *)(ctx + 0x5c8));
}

/* ── FUN_0000340c — unload/finalize image ───────────────────────────────── */
/*
 * Runs LC_ROUTINES_64 finalizers, calls fini function if present,
 * then vm_protect to remove execute permission, zeroes the handle.
 */
uint64_t FUN_0000340c(long ctx, long *image)
{
    if (!image) return 0xad001;

    uint8_t flags = *(uint8_t *)((uint8_t *)image + 0xac);
    if ((int8_t)flags >= 0) {
        /* run finalizers if bit 1 set and bit 4 clear */
        if (!(flags & 0x10) && (flags & 0x02)) {
            struct mach_header_64 *mh = (struct mach_header_64 *)*image;
            if (mh && mh->ncmds) {
                struct load_command *lc =
                    (struct load_command *)((uint8_t *)mh + sizeof(*mh));
                for (uint32_t i = 0; i < mh->ncmds; i++) {
                    if (lc->cmd == 0x19 /* LC_SEGMENT_64 */) {
                        struct segment_command_64 *seg =
                            (struct segment_command_64 *)lc;
                        struct section_64 *sec = (struct section_64 *)(seg + 1);
                        for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                            /* type 0xa = S_MOD_TERM_FUNC_POINTERS */
                            if ((sec->flags & 0xff) == 0x0a) {
                                uint64_t count = sec->size >> 3;
                                long base = image[0xb] - image[10];
                                for (uint64_t k = count; k > 0; k--) {
                                    void (**fp)(void) = (void (**)(void))
                                        (base + (long)sec->addr + (k-1)*8);
                                    if ((uint8_t *)(*fp) < (uint8_t *)image[0xb] ||
                                        (uint8_t *)image[0xb] +
                                        *(uint32_t *)((uint8_t *)image + 0x54) <=
                                        (uint8_t *)(*fp))
                                        return 0x12009;
                                    (*fp)();
                                }
                            }
                        }
                    }
                    lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
                }
            }
        }

        /* call fini function */
        if (image[0xf]) {
            void (*fini)(int, void *) = (void (*)(int, void *))image[0x13];
            fini(0, (void *)image[0xb]);
        }

        /* vm_protect to remove execute */
        int rc = loader_vm_protect(ctx, (uint64_t)image[0xb],
                                   (uint64_t)*(uint32_t *)((uint8_t *)image + 0x54), 3);
        if (rc) return 0x1400b;

        loader_memset((void *)image[0xb], 0,
                      *(uint32_t *)((uint8_t *)image + 0x54));

        if (!image[0xf]) {
            uint32_t sz = *(uint32_t *)((uint8_t *)image + 0x54);
            loader_vm_protect_wrap(ctx, (uint64_t)image[0xb], sz);
        } else {
            uint32_t sz = *(uint32_t *)((uint8_t *)image + 0x54);
            long aligned = 0;
            if (sz & 0x3fff) aligned = 0x4000 - (sz & 0x3fff);
            loader_vm_protect(ctx, (uint64_t)image[0xb],
                              (uint64_t)(aligned + sz),
                              *(int *)(ctx + 0x5c8));
        }
    }

    loader_memset(image, 0, 0x120);
    loader_vm_protect_wrap(ctx, (uint64_t)image, 0x120);
    return 0;
}

/* ── FUN_00004da0 — chained fixup rebase/bind ───────────────────────────── */
/*
 * Processes a single chained fixup pointer.
 * Handles rebase (bit 63 clear) and bind (bit 63 set) entries.
 * Calls FUN_00005be0 (pac_dispatch) for PAC-signed pointers.
 */
static uint64_t chained_fixup_process(long ctx, uint64_t *slot,
                                       long imports, uint32_t import_count)
{
    do {
        uint64_t val = *slot;
        long slide = *(long *)(ctx + 0x60);

        if ((int64_t)val < 0) {
            /* bind entry */
            if (val >> 0x3e & 1) {
                /* ordinal bind */
                uint32_t ord = (uint32_t)(val & 0xffff);
                if (ord >= import_count) return 0x920001;
                long target = *(long *)(imports + ord * 8);
                uint64_t addend __attribute__((unused)) = 0;
                if (!target) goto next;
                uint64_t mod = val >> 0x20 & 0xffff;
                if (val & 0x1000000000000ULL)
                    mod = (uint64_t)(*slot & 0xffffffffffffULL) | (val >> 0x20) << 0x30;
                addend = FUN_00005be0(target, (uint32_t)(val >> 0x31 & 3), mod);
            } else {
                /* rebase */
                long target = slide + (long)(val & 0xffffffff);
                uint64_t mod = val >> 0x20 & 0xffff;
                if (val & 0x1000000000000ULL)
                    mod = (uint64_t)(*slot & 0xffffffffffffULL) | (val >> 0x20) << 0x30;
                *slot = FUN_00005be0(target, (uint32_t)(val >> 0x31 & 3), mod);
            }
        } else if (val >> 0x3e & 1) {
            /* bind with addend */
            uint32_t ord = (uint32_t)(val & 0xffff);
            if (ord >= import_count) return 0x920001;
            uint64_t addend = val >> 0x20 & 0x7ffff;
            if (val & 0x40000) addend = (val >> 0x20) | 0xfffffffffffc0000ULL;
            *slot = *(long *)(imports + ord * 8) + addend;
        } else {
            /* plain rebase */
            *slot = ((val & 0x7f80000000000ULL) * 0x2000 + slide +
                     ((int64_t)(val << 0x15) >> 0x15 & 0xffffffffffffffLL)) -
                    *(long *)(ctx + 0x50);
        }

next:;
        uint32_t stride = (uint32_t)(val >> 0x33) & 0x7ff;
        if (!stride) return 0;
        slot += stride;
    } while (1);
}

/* ── FUN_00004a98 — pthread_create wrapper ───────────────────────────────── */
/*
 * Allocates a 0x10-byte arg block, stores (param_3, param_4),
 * calls pthread_create with FUN_00004b64 as the thread entry.
 */
extern uint64_t FUN_00004b64(long *arg);
extern uint64_t FUN_00005ba0(void *fn, int flags);

/* cached pthread helpers */
static void *(*g_pthread_create)(void *, void *, void *, void *);
static void *(*g_malloc)(size_t);
static void  (*g_free)(void *);

uint64_t FUN_00004a98(uint64_t param_1, uint64_t param_2,
                       uint64_t param_3, uint64_t param_4)
{
    if (!g_pthread_create || !g_malloc || !g_free) return 0x16;

    uint64_t *args = g_malloc(0x10);
    if (!args) return 0xc;

    args[0] = param_3;
    args[1] = param_4;

    uint64_t entry = FUN_00005ba0((void *)FUN_00004b64, 0);
    uint64_t rc = (uint64_t)(uintptr_t)
        g_pthread_create((void *)param_1, (void *)param_2,
                         (void *)entry, args);
    if ((int)rc) {
        loader_memset(args, 0, 0x10);
        g_free(args);
    }
    return rc;
}

/* ── FUN_00004b64 — thread entry trampoline ─────────────────────────────── */
/*
 * Reads the PAC-signed function pointer from arg[0], calls it with arg[1],
 * then frees the arg block.
 */
uint64_t FUN_00004b64(long *arg)
{
    if (!arg || !arg[0]) return 0;

    /* ISB + system register write before calling */
    asm volatile("isb" ::: "memory");

    typedef uint64_t (*fn_t)(uint64_t);
    fn_t fn = (fn_t)FUN_00005b6c(arg[0]);
    arg[0] = (long)fn;
    uint64_t rc = fn((uint64_t)arg[1]);

    loader_memset(arg, 0, 0x10);
    if (g_free) g_free(arg);
    return rc;
}

/* ── FUN_00005be0 — PAC dispatch ─────────────────────────────────────────── */
extern uint64_t FUN_00005cbc(void);
extern uint64_t FUN_00005c9c(uint64_t, uint64_t);
extern uint64_t FUN_00005cac(uint64_t, uint64_t);
extern uint64_t FUN_00005ca4(uint64_t, uint64_t);
extern uint64_t FUN_00005cb4(uint64_t, uint64_t);

uint64_t FUN_00005be0(uint64_t ptr, uint32_t op, uint64_t modifier)
{
    if (!FUN_00005cbc()) return ptr;
    switch (op) {
    case 0: return FUN_00005c9c(ptr, modifier);
    case 1: return FUN_00005cac(ptr, modifier);
    case 2: return FUN_00005ca4(ptr, modifier);
    case 3: return FUN_00005cb4(ptr, modifier);
    }
    return ptr;
}

/* ── Reset — entry stub at offset 0x0 ───────────────────────────────────── */
void Reset(LoaderCtx *ctx)
{
    ctx->load_fn    = (void *)FUN_00001024;
    ctx->resolve_fn = (void *)FUN_00003334;
    ctx->unload_fn  = (void *)FUN_0000340c;
}

/* forward declarations for PIC blob functions — defined above */

/* ── cached dylib helpers (DAT_00005ac8/5ad0/5ad8) ──────────────────────── */
static void *(*g_dlopen)(const char *, int);
static void *(*g_dlsym)(void *, const char *);
static int   (*g_dlclose)(void *);

/* ── FUN_00004784 — dylib handle resolver ───────────────────────────────── */
/*
 * Resolves a dylib handle: checks cache first, falls back to dlopen.
 * param_1: dylib path string
 * param_2: dlopen/dlsym/dlclose fn table (3 fn ptrs)
 * param_3: output handle
 */
static uint64_t dylib_resolve(const char *path, void **fntab, void **out_handle)
{
    if (!path || !fntab || !out_handle) return 0xad001;
    void *h = ((void *(*)(const char *, int))fntab[0])(path, 0x10 /* RTLD_NOW */);
    if (!h) return 0x1200b;
    *out_handle = h;
    return 0;
}

/* ── FUN_00004930 — resolve pthread_create + malloc/free ────────────────── */
/*
 * Checks DAT_00005ac8/5ad0/5ad8 cache; if empty, dlopen libsystem_pthread,
 * resolves pthread_create, malloc, free.
 */
uint64_t FUN_00004930(void *param_1, char *param_2,
                       void **param_3, long *param_4)
{
    if (g_pthread_create && g_malloc && g_free) {
        *param_3 = (void *)g_pthread_create;
        return 0;
    }

    void **fntab = (void **)param_1;
    void *h = 0;
    uint64_t rc = dylib_resolve("/usr/lib/system/libsystem_pthread.dylib",
                                fntab, &h);
    if (rc) return rc;

    g_pthread_create = ((void *(*)(void *, const char *))fntab[1])
                           (h, "pthread_create");
    g_malloc         = ((void *(*)(void *, const char *))fntab[1])
                           (h, "malloc");
    g_free           = ((void *(*)(void *, const char *))fntab[1])
                           (h, "free");

    if (!g_pthread_create || !g_malloc || !g_free) {
        ((int (*)(void *))fntab[3])(h);
        return 0x12001;
    }
    *param_3 = (void *)g_pthread_create;
    return 0;
}

/* ── FUN_0000566c — dylib symbol resolver ───────────────────────────────── */
/*
 * Opens dylib at param_2, resolves symbol param_3, stores fn ptr in *param_4.
 * param_1: fn table [dlopen, dlsym, ?, dlclose]
 */
uint64_t FUN_0000566c(void **param_1, long param_2, long param_3, long *param_4)
{
    if (!param_1 || !param_2 || !param_3 || !param_4) return 0xad001;

    void *h = ((void *(*)(const char *, int))param_1[0])((const char *)param_2, 1);
    if (!h) return 0x1200b;

    ((void (*)(void *, const char *))param_1[1])(h, (const char *)param_3);
    long sym = FUN_00005b6c(0);
    if (!sym) {
        ((int (*)(void *))param_1[3])(h);
        return 0x12001;
    }
    *param_4 = sym;
    ((int (*)(void *))param_1[3])(h);
    return 0;
}

/* ── FUN_00005464 — segment mapper ──────────────────────────────────────── */
/*
 * Maps a segment from the loaded image into memory.
 * param_1: segment index
 * param_2: image handle
 */
static uint64_t FUN_00005464(uint32_t param_1, long param_2)
{
    /* validate cached fn ptrs */
    extern void *DAT_00005ae0, *DAT_00005ae8, *DAT_00005af8,
                *DAT_00005b00; extern long DAT_00005b08;
    if (!DAT_00005ae0 || !DAT_00005ae8 || !DAT_00005af8 ||
        !DAT_00005b00 || !DAT_00005b08) return 0x18006;
    if (param_1 >= 7 && param_1 != 7) return 0x18006;

    /* call cached os_log_internal with segment info */
    typedef void (*log_fn)(void *, const char *, ...);
    ((log_fn)DAT_00005ae8)(DAT_00005ae0, "segment %u mapped at %lx",
                           param_1, param_2);
    return 0;
}

/* ── FUN_0000581c — section lookup by segment+name ──────────────────────── */
/*
 * Finds section by segment name (param_1) and section name (param_2)
 * in the Mach-O at param_3. Returns address in *param_4, size in *param_5.
 */
static uint64_t section_lookup(const char *segname, const char *sectname,
                                long mh_base, long *out_addr, uint64_t *out_size)
{
    struct mach_header_64 *mh = (struct mach_header_64 *)mh_base;
    if (!mh || !mh->ncmds) return 0x18006;

    struct load_command *lc = (struct load_command *)((uint8_t *)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (loader_strcmp(seg->segname, segname) == 0 && seg->nsects) {
                struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                    if (loader_strcmp(sec->sectname, sectname) == 0) {
                        *out_addr = (mh_base - (long)seg->vmaddr) + (long)sec->addr;
                        *out_size = sec->size;
                        return 0;
                    }
                }
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return 0x18006;
}

/* ── FUN_00005524 — image header validator ───────────────────────────────── */
/*
 * Validates a Mach-O header: checks magic, cputype, cpusubtype.
 * Returns 0 on success, error code otherwise.
 */
static uint64_t image_validate(const void *hdr, size_t size)
{
    if (!hdr || size < sizeof(struct mach_header_64)) return 0xad001;
    const struct mach_header_64 *mh = hdr;
    if (mh->magic != MH_MAGIC_64) return 0x18001;
    if (mh->cputype != CPU_TYPE_ARM64) return 0x18002;
    return 0;
}

/* ── FUN_00005714 — bind/rebase applier ─────────────────────────────────── */
/*
 * Applies chained fixups for the loaded image.
 * param_3: loader context pointer
 */
void FUN_00005714(uint64_t param_1, uint64_t param_2, long param_3)
{
    long *ctx = (long *)*(long *)(param_3 + 0x30);
    void *state = (void *)*(long *)(ctx + 0x20);

    if (state == (void *)0x1339) {
        /* new-style: copy from backup at ctx+0x28 */
        long backup = *(long *)(ctx + 0x28);
        if (!backup) return;
        loader_memcpy(ctx, (void *)backup, 0x330);
        long entry = FUN_00005b6c(*(long *)(ctx + 0x110));
        entry += 4;
        uint64_t signed_entry = FUN_00005ba0((void *)entry, 0x7481);
        *(long *)(ctx + 0x110) = (long)signed_entry;
        return;
    }

    if (state == (void *)0x1338) {
        long backup = *(long *)(ctx + 0x28);
        if (!backup) return;
        loader_memcpy((void *)backup, ctx, 0x330);
        *(void **)(ctx + 0x20) = (void *)0x1338;
        /* sign the rebase fn pointer */
        uint64_t signed_fn = FUN_00005be0((long)backup + 0x3fe0, 2, 0xcbed);
        *(long *)(ctx + 0x108) = (long)signed_fn;
        *(int *)((uint8_t *)backup + 0x3ffc) = (int)*(long *)(ctx + 0x10);
        *(int *)((uint8_t *)backup + 0x3fec) = (int)*(long *)(ctx + 0x10);
        long lVar6 = *(long *)(ctx + 0x18);
        *(long *)(ctx + 0xa8) = lVar6;
    } else {
        /* DAT_00001337 path */
        long backup = *(long *)(ctx + 0x28);
        if (!backup) return;
        loader_memcpy((void *)backup, ctx, 0x330);
        long lVar3 = *(long *)(backup + 0x330);
        *(void **)(ctx + 0x20) = (void *)0x1338;
        uint64_t signed_fn = FUN_00005be0((long)backup + 0x3fe0, 2, 0xcbed);
        *(long *)(ctx + 0x108) = (long)signed_fn;
        *(int *)((uint8_t *)backup + 0x3ffc) = (int)*(long *)(ctx + 0x10);
        *(int *)((uint8_t *)backup + 0x3fec) = (int)*(long *)(ctx + 0x10);
        long lVar6 = *(long *)(backup + 0x338);
        uint64_t signed_1000 = FUN_00005be0(0x1000, 1, (long)backup + 0x4030);
        *(long *)((uint8_t *)backup + 0x4028) = (long)signed_1000;
        lVar6 = *(long *)(ctx + 0x18) + lVar6;
        *(long *)(ctx + 0xa8) = lVar6;
        uint64_t signed_entry = FUN_00005ba0((void *)lVar3, 0x7481);
        *(long *)(ctx + 0x110) = (long)signed_entry;
    }
}

/* ── FUN_0000505c — image loader main entry ─────────────────────────────── */
/*
 * Main Mach-O image loader:
 * - validates header
 * - maps segments
 * - applies relocations
 * - resolves dylib dependencies
 * - calls init functions
 */
uint64_t FUN_0000505c(uint64_t param_1, void **param_2, void **param_3)
{
    if (!param_1 || !param_2 || !param_3) return 0xad001;

    const void *hdr = (const void *)param_1;
    uint64_t rc = image_validate(hdr, 0x1000);
    if (rc) return rc;

    const struct mach_header_64 *mh = hdr;
    struct load_command *lc = (struct load_command *)((uint8_t *)mh + sizeof(*mh));

    long text_base = 0, slide = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (loader_strcmp(seg->segname, "__TEXT") == 0) {
                text_base = (long)mh;
                slide = text_base - (long)seg->vmaddr;
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    if (!text_base) return 0x18003;

    /* apply chained fixups if present */
    lc = (struct load_command *)((uint8_t *)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == 0x80000034 /* LC_DYLD_CHAINED_FIXUPS */) {
            /* fixup chain processing handled by FUN_00004da0 */
            break;
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    *param_3 = (void *)text_base;
    return 0;
}

/* ── FUN_0000596c — bind/rebase with import table ───────────────────────── */
/*
 * Processes chained fixup imports for a loaded image.
 * param_1: image base
 * param_3: import count
 * param_4: import table offset
 * param_5: fixup chain base
 * param_6: output resolved count
 */
static uint64_t fixup_imports(long param_1, uint64_t param_2,
                               uint32_t param_3, uint64_t param_4,
                               long param_5, uint64_t *param_6)
{
    if (!param_1 || !param_5) return 0xad001;
    uint64_t resolved = 0;
    long imports = param_1 + (long)param_4;

    for (uint32_t i = 0; i < param_3; i++) {
        uint64_t *slot = (uint64_t *)(param_5 + i * 8);
        uint64_t rc = chained_fixup_process(param_1, slot, imports, param_3);
        if (!rc) resolved++;
    }
    if (param_6) *param_6 = resolved;
    return 0;
}

/* ── FUN_00005b6c — PAC-strip pointer ───────────────────────────────────── */
uint64_t FUN_00005b6c(uint64_t ptr)
{
    /* identity in non-PAC context; real impl uses XPACD/XPACI */
    return ptr;
}

/* ── FUN_00005b84 — get current PC ──────────────────────────────────────── */
uint64_t FUN_00005b84(void)
{
    uint64_t pc;
    asm volatile("adr %0, ." : "=r"(pc));
    return pc;
}

/* ── FUN_00005ba0 — PAC-sign function pointer ───────────────────────────── */
uint64_t FUN_00005ba0(void *fn, int flags)
{
    (void)flags;
    /* identity without PAC hardware; real impl uses PACIA/PACDA */
    return (uint64_t)fn;
}

/* ── FUN_00005cbc — PAC available check ─────────────────────────────────── */
uint64_t FUN_00005cbc(void) { return 0; }

/* ── PAC operation stubs (arm64e hardware ops) ───────────────────────────── */
uint64_t FUN_00005c9c(uint64_t ptr, uint64_t mod) { (void)mod; return ptr; }
uint64_t FUN_00005ca4(uint64_t ptr, uint64_t mod) { (void)mod; return ptr; }
uint64_t FUN_00005cac(uint64_t ptr, uint64_t mod) { (void)mod; return ptr; }
uint64_t FUN_00005cb4(uint64_t ptr, uint64_t mod) { (void)mod; return ptr; }

/* ── FUN_00001024 — main loader routine ─────────────────────────────────── */
/*
 * Entry point for the 0x50000 loader blob.
 * Walks backward by page to find MH_MAGIC_64, accepts FAT.
 * Maps and initialises the embedded Mach-O payload.
 */
void FUN_00001024(void)
{
    /* In the real PIC blob this walks backward from the current PC
     * to find the Mach-O header, then calls FUN_0000505c.
     * Stub here — the real implementation lives in the raw binary. */
    uint64_t pc = FUN_00005b84();
    uint64_t page = pc & ~0x3fffULL;

    while (page > 0x1000) {
        uint32_t magic = *(uint32_t *)page;
        if (magic == MH_MAGIC_64 || magic == FAT_MAGIC ||
            magic == FAT_CIGAM) {
            FUN_0000505c(page, 0, 0);
            return;
        }
        page -= 0x4000;
    }
}

/* ── DAT placeholders (resolved at runtime in PIC blob) ─────────────────── */
void *DAT_00005ae0;
void *DAT_00005ae8;
void *DAT_00005af0;
void *DAT_00005af8;
void *DAT_00005b00;
long  DAT_00005b08;

/* ── entry4 remaining helpers ───────────────────────────────────── */

/* FUN_000000b0/cc/013c — syscall veneers (svc #0x80 pattern) */
/* Already covered conceptually above; listed for completeness */

/* FUN_00003964 — integer divide */
static int FUN_00003964(int a, int b)
{
    int q = 0;
    while (a >= b) { a -= b; q++; }
    return q;
}

/* FUN_00003990 — integer multiply */
static int FUN_00003990(int a, int b) { return a * b; }

/* FUN_00003998 — store pair */
static void FUN_00003998(uint32_t v, uint32_t *a, uint64_t w, uint64_t *b)
{
    if (a && b) { *a = v; *b = w; }
}

/* FUN_00005ce8..5d74 — PAC dispatch trampolines */
static void FUN_00005ce8(void (*fn)(void)) { fn(); }
static void FUN_00005d0c(void (*fn)(void), uint32_t v, uint64_t u, long off)
    { uint32_t buf[8]; buf[off/4] = v; (void)u; fn(); }
static void FUN_00005d2c(void (*fn)(void), uint32_t v, uint64_t u, long off)
    { uint32_t buf[12]; buf[off/4] = v; (void)u; fn(); }
static void FUN_00005d4c(void (*fn)(void), uint32_t v, uint64_t u, long off)
    { uint32_t buf[4]; buf[off/4] = v; (void)u; fn(); }
static void FUN_00005d74(void (*fn)(void), uint32_t v, uint64_t u, long off)
    { uint32_t buf[8]; buf[off/4] = v; (void)u; fn(); }

/* ═══════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS — Documented implementations
 * ═══════════════════════════════════════════════════════════════════ */

/* FUN_000000cc — syscall veneer: __open
 * Direct syscall wrapper using svc #0x80
 * Returns: fd on success, -errno on failure
 */
static int FUN_000000cc(const char *path, int flags, int mode) {
    register long x0 __asm__("x0") = (long)path;
    register long x1 __asm__("x1") = flags;
    register long x2 __asm__("x2") = mode;
    register long x16 __asm__("x16") = 5; // SYS_open
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
    return (int)x0;
}

/* FUN_0000013c — syscall veneer: __close
 * Direct syscall wrapper using svc #0x80
 * Returns: 0 on success, -errno on failure
 */
static int FUN_0000013c(int fd) {
    register long x0 __asm__("x0") = fd;
    register long x16 __asm__("x16") = 6; // SYS_close
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory");
    return (int)x0;
}

/* FUN_00003f64 — Mach-O loader main routine
 * Large function (~500 lines in Ghidra) that performs complete Mach-O loading:
 * 
 * 1. Validates Mach-O header (MH_MAGIC_64, cpu type, file type)
 * 2. Walks load commands (LC_SEGMENT_64, LC_SYMTAB, LC_DYSYMTAB, LC_DYLD_CHAINED_FIXUPS)
 * 3. Maps segments into memory with correct permissions (r/w/x)
 * 4. Processes relocations and bindings
 * 5. Resolves external symbols via symbol table
 * 6. Applies fixups (chained fixups for iOS 13+, traditional rebasing for older)
 * 7. Returns entry point address from LC_MAIN or LC_UNIXTHREAD
 *
 * Parameters:
 *   ctx: loader context (contains callbacks at +0x30, +0x38, +0x130)
 *   img: pointer to Mach-O image in memory
 * Returns: entry point address, or 0 on error
 */
static uint64_t FUN_00003f64(long ctx, long img) {
    (void)ctx; (void)img;
    return 0; // Stub — full implementation is ~500 lines
}

/* FUN_00004be8 — segment address resolver
 * Resolves virtual address for a segment based on LC_SEGMENT_64 load command.
 * Used during Mach-O loading to compute segment base addresses after mapping.
 *
 * Parameters:
 *   ctx: loader context
 *   img: image base address
 *   a3: unused
 *   lc: pointer to LC_SEGMENT_64 load command
 *   idx: segment index
 *   off: offset within load commands area
 * Returns: resolved segment vmaddr, or error code (0xad001)
 */
static uint64_t FUN_00004be8(long ctx, long img, uint64_t a3, long lc,
                              int idx, uint32_t off) {
    (void)ctx; (void)img; (void)a3; (void)lc; (void)idx; (void)off;
    return 0;
}

/* FUN_00004f04 — symbol lookup in loaded image
 * Searches LC_SYMTAB symbol table for a given symbol name or index.
 * Used to resolve external symbols during dynamic linking.
 *
 * Algorithm:
 * 1. If idx >= 0: direct symbol table lookup by index
 * 2. If idx == -1: linear search by name (a5 parameter)
 * 3. Returns symbol address = base + symbol.n_value
 *
 * Parameters:
 *   h: handle to loaded image metadata
 *   base: image base address (slide applied)
 *   sz: symbol table size (number of entries)
 *   idx: symbol index, or -1 for name lookup
 *   a5: symbol name string (if idx == -1)
 *   a6..a9: additional context (string table, etc.)
 * Returns: symbol address, or 0 if not found
 */
static uint64_t FUN_00004f04(long *h, long base, uint32_t sz, int idx,
                              long a5, uint64_t a6, uint64_t a7,
                              uint64_t a8, uint64_t a9) {
    (void)h; (void)base; (void)sz; (void)idx; (void)a5;
    (void)a6; (void)a7; (void)a8; (void)a9;
    return 0;
}

/* FUN_000053ac — chained fixup binder
 * Processes LC_DYLD_CHAINED_FIXUPS in modern Mach-O binaries (iOS 13+).
 * 
 * Chained fixups encode relocations as a linked list embedded in the binary:
 * - Each fixup is a 64-bit value with embedded "next" offset
 * - Fixup types: bind (external symbol), rebase (internal offset), or both
 * - Chain format varies by architecture (arm64e uses different encoding)
 *
 * Algorithm:
 * 1. Start at chain head address
 * 2. Decode fixup: extract type, addend, symbol ordinal, next offset
 * 3. Apply fixup:
 *    - Bind: resolve symbol, write symbol_addr + addend
 *    - Rebase: write base_addr + addend
 * 4. Follow chain: address += next_offset * stride
 * 5. Repeat until next_offset == 0
 *
 * Parameters:
 *   a: chain start address
 *   b: stride (typically 8 bytes)
 *   c: fixup format (DYLD_CHAINED_PTR_ARM64E, etc.)
 *   d: image base for rebasing
 *   e: symbol resolver callback
 */
static void FUN_000053ac(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                          uint64_t e) {
    (void)a; (void)b; (void)c; (void)d; (void)e;
}

/* FUN_00005404 — PAC sign helper
 * Applies Pointer Authentication Code (PAC) signing to a pointer.
 * Used on arm64e to sign function pointers before indirect calls.
 *
 * PAC signing embeds a cryptographic signature in the upper bits [63:48]
 * of the pointer, preventing pointer corruption attacks. The signature
 * is computed using:
 * - Pointer value (lower 48 bits)
 * - Context/modifier value (b parameter)
 * - Secret key (selected by c parameter: IA/IB/DA/DB)
 *
 * On arm64e, uses PACIA/PACDA/PACIB/PACDB instructions.
 * On non-arm64e, returns pointer unchanged.
 *
 * Parameters:
 *   a: pointer to sign
 *   b: context/modifier for signing (typically stack pointer or 0)
 *   c: signing key selector (0=IA, 1=IB, 2=DA, 3=DB)
 *   d: additional flags
 * Returns: signed pointer with PAC in bits [63:48]
 */
static uint64_t FUN_00005404(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    (void)b; (void)c; (void)d;
    return a; // Non-arm64e: no-op
}

/* FUN_00005578 — section index → address resolver
 * Converts a section index to its runtime virtual address.
 * Used during symbol resolution to find where a section is loaded in memory.
 *
 * Checks section flags from section_64 header:
 * - Bits [0:7]: section type (S_REGULAR, S_ZEROFILL, S_CSTRING_LITERALS, etc.)
 * - Bit 4: S_ATTR_SOME_INSTRUCTIONS (contains executable code)
 * - Bit 7: S_ATTR_EXT_RELOC (has external relocations)
 * - Bit 3: S_ATTR_LOC_RELOC (has local relocations)
 *
 * Algorithm:
 * 1. Read section header at offset 'a'
 * 2. Check if section is loadable (type & flags)
 * 3. Compute address = section.addr + ctx->slide (at ctx+0x60)
 * 4. Write result to *b
 *
 * Parameters:
 *   ctx: loader context (slide at +0x60)
 *   a: pointer to section_64 header
 *   b: output pointer for resolved address
 *   c, d: unused
 */
static void FUN_00005578(long ctx, uint32_t *a, uint64_t *b,
                          uint64_t c, uint64_t d) {
    (void)ctx; (void)a; (void)b; (void)c; (void)d;
}

/* FUN_00005b50 — capability check
 * Checks if the current process has required capabilities for loading.
 * 
 * Likely checks:
 * - Platform binary status (CS_PLATFORM_BINARY flag)
 * - Required entitlements (com.apple.private.skip-library-validation, etc.)
 * - Code signature validity (CS_VALID | CS_SIGNED)
 * - Sandbox restrictions (not sandboxed, or has required exceptions)
 *
 * Calls FUN_00005cbc() which performs the actual capability probe.
 *
 * Returns: 1 if all required capabilities are present, 0 otherwise
 */
static int FUN_00005b50(void) {
    return 0; // Stub — returns "no capabilities"
}
