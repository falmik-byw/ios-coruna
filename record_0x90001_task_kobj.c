/* record_0x90001_task_kobj.c
 * sub_34048..sub_353dc — task/proc kobj field resolvers,
 * version-gated offsets, pmap/thread helpers.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_29b78(long state, long addr, long *out);
extern long sub_1972c(long state, long addr);
extern int  sub_36098(long state, uint32_t mask);
extern long sub_33304_pub(long state, long base);
extern int  sub_33098_pub(long state);
extern long sub_33a30_pub(long state);
extern long sub_33ed8_pub(long state);

/* forward decls for functions defined in this file */
static long sub_3412c(long state);
static int  sub_343e0(long state);
static long sub_34358(long state, long port);
static long sub_34048(long state, long port, long *extra);
static long sub_34a40(long state, long port);

/* weak stubs for helpers in other files */
__attribute__((weak)) long sub_32c78_stub2(long s, long p);
__attribute__((weak)) long sub_32c78_stub2(long s, long p) { (void)s; (void)p; return 0; }
__attribute__((weak)) long sub_33e8c_stub(long s);
__attribute__((weak)) long sub_33e8c_stub(long s) { (void)s; return 0; }
__attribute__((weak)) long sub_34754_stub(long s);
__attribute__((weak)) long sub_34754_stub(long s) { (void)s; return 0; }
__attribute__((weak)) uint32_t sub_3338c_stub(long s);
__attribute__((weak)) uint32_t sub_3338c_stub(long s) { (void)s; return 0; }

/* ── sub_34048 — read proc field + optional extra ────────────────── */
static long sub_34048(long state, long port, long *extra)
{
    long base = sub_33ed8_pub(state);
    if (!base) return 0;
    long val = 0;
    if (!sub_28840(state, base, &val)) return 0;
    if (!sub_1972c(state, val)) return 0;
    if (!extra) return val;
    long ex = 0;
    if (!sub_29b78(state, base, &ex)) return 0;
    *extra = ex;
    return val;
    (void)port;
}

void sub_34048_pub(long s, long p, long *e) { sub_34048(s, p, e); }

/* ── sub_340d8 — thin wrapper: sub_32c78 + sub_34048 ────────────── */
void sub_340d8(long state, long port, long *extra)
{
    long h = sub_32c78_stub2(state, port);
    if (!h) return;
    sub_34048(state, h, extra);
}

/* ── sub_3412c — version-gated proc kobj field offset ───────────── */
static long sub_3412c(long state)
{
    long base = sub_32c78_stub2(state, 0);
    if (!base) return 0;
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off;

    if (build - 0x1f53U < 2 || build == 0x1c1b) {
        if (ver < 0x1c1b1914600000ULL) {
            int cap = sub_36098(state, 0x5584201);
            off = cap ? 0x460 : 0x418;
        } else {
            if      (sub_36098(state, 0x100000)) off = 0x4f0;
            else if (sub_36098(state, 0x84000))  off = 0x4e8;
            else if (sub_36098(state, 1))         off = 0x4e0;
            else {
                int cap = sub_36098(state, 0x200);
                off = cap ? 0x510 : 0x4d0;
            }
        }
    } else if (build == 0x1809) {
        off = 0x3f8;
    } else if (build == 0x2258 || build == 0x225c || build == 0x2712) {
        off = 0x5a0;
    } else return 0;

    long val = 0;
    if (!sub_28840(state, base + off, &val)) return 0;
    if (!sub_1972c(state, val)) return 0;
    return val;
}

void sub_3412c_pub(long s) { sub_3412c(s); }

/* ── sub_34298 — proc field at version-dependent offset ─────────── */
long sub_34298(long state)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (ver < 0x1f530f02800000ULL) {
        long base = sub_3412c(state);
        if (!base) return 0;
        int build = *(int *)(state + 0x140);
        long off;
        if      (build == 0x1f53) off = 0x120;
        else if (build == 0x1c1b) off = 0x128;
        else if (build == 0x1809)
            off = ver < 0x18090a09600000ULL ? 0x150 : 0x128;
        else return 0;
        return base + off;
    }
    long h = sub_34358(state, 0);
    return h ? h + 8 : 0;
}

/* ── sub_343e0 — version-gated offset (task field) ───────────────── */
static int sub_343e0(long state)
{
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (build < 0x225c) {
        if (build - 0x1f53U < 2) {
            int cap = sub_36098(state, 0x5584001);
            if (ver < 0x1f530f02800000ULL) return cap ? 0x3b0 : 0x3a8;
            return cap ? 0x398 : 0x390;
        }
        if (build == 0x1809) return 0x2e8;
        if (build == 0x1c1b) {
            int cap = sub_36098(state, 0x5584001);
            return ver < 0x1c1b1914600000ULL ? (cap ? 0x2f8 : 0x2f0)
                                              : (cap ? 0x308 : 0x300);
        }
        return 0;
    }
    if (build == 0x2258 || build == 0x225c || build == 0x2712) return 0x3c0;
    return 0;
}

void sub_343e0_pub(long s) { sub_343e0(s); }

/* ── sub_34358 — resolve task kobj via port + offset ─────────────── */
static long sub_34358(long state, long port)
{
    uint32_t off = (uint32_t)sub_343e0(state);
    if (!off) return 0;
    long base = sub_32c78_stub2(state, port);
    if (!base) return 0;
    long val = 0;
    if (!sub_28840(state, base + off, &val)) return 0;
    if (!sub_1972c(state, val)) return 0;
    return val;
}

void sub_34358_pub(long s, long p) { sub_34358(s, p); }

/* ── sub_345d4 — proc field at older version offset ─────────────── */
long sub_345d4(long state)
{
    long base = sub_3412c(state);
    if (!base) return 0;
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off;
    if      (build == 0x1809) off = ver < 0x18090a09600000ULL ? 0x130 : 0x108;
    else if (build == 0x1c1b) off = 0x108;
    else if (build == 0x1f53) off = 0x100;
    else if (build == 0x1f54) off = 0xf0;
    else return 0;
    return base + off;
}

/* ── sub_34680 — pmap field at version-dependent offset ─────────── */
long sub_34680(long state)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long base = ver < 0x1f530f02800000ULL
        ? sub_33e8c_stub(state)
        : sub_34754_stub(state);
    if (!base) return 0;
    int build = *(int *)(state + 0x140);
    long off;
    if (build < 0x2258) {
        if (build - 0x1f53U < 2)
            off = ver < 0x1f530f02800000ULL ? 0x300 : 0x1c;
        else if (build == 0x1809) off = 0x298;
        else if (build == 0x1c1b) off = 0x280;
        else return 0;
    } else if (build == 0x2258 || build == 0x225c || build == 0x2712) {
        off = ver < 0x1f530f02800000ULL ? 0x300 : 0x1c;
    } else return 0;
    return base + off;
}

__attribute__((weak)) long sub_33e8c_stub_unused(long s) { (void)s; return 0; }
__attribute__((weak)) long sub_34754_stub_unused(long s) { (void)s; return 0; }

/* ── sub_34754 — resolve pmap kobj via port + newer offset ──────── */
long sub_34754(long state, long port)
{
    uint32_t off = (uint32_t)sub_33098_pub(state);
    if (!off) return 0;
    long base = sub_32c78_stub2(state, port);
    if (!base) return 0;
    long v1 = 0, v2 = 0;
    if (!sub_28840(state, base + off, &v1)) return 0;
    if (!sub_1972c(state, v1)) return 0;
    if (!sub_28840(state, v1 + 8, &v2)) return 0;
    if (!sub_1972c(state, v2)) return 0;
    return v2;
}

/* ── sub_3481c — version-gated offset (ipc_space field) ─────────── */
uint64_t sub_3481c(long state)
{
    int build = *(int *)(state + 0x140);
    if (build == 0x1809 || build == 0x1c1b) return 0x10c;
    if (build == 0x1f53) return 0x11c;
    if (build == 0x1f54) return 0x94;
    if (build == 0x2258 || build == 0x225c) return 0xb4;
    if (build == 0x2712) return 200;
    return 0;
}

/* ── sub_348bc — version-gated offset (0x48 or 0x40) ────────────── */
uint64_t sub_348bc(long state)
{
    int build = *(int *)(state + 0x140);
    if (build == 0x1809 || build == 0x1c1b || build == 0x1f53) return 0x48;
    if (build == 0x1f54 || build == 0x2258 || build == 0x225c || build == 0x2712) return 0x40;
    return 0;
}

/* ── sub_3492c — walk two kobj fields ───────────────────────────── */
long sub_3492c(long state, long base)
{
    uint32_t off1 = sub_3338c_stub(state);
    if (!off1) return 0;
    long v1 = 0;
    if (!sub_28840(state, base + off1, &v1)) return 0;
    if (!sub_1972c(state, v1)) return 0;
    uint64_t off2 = sub_348bc(state);
    if (!off2) return 0;
    long v2 = 0;
    if (!sub_28840(state, v1 + off2, &v2)) return 0;
    if (!sub_1972c(state, v2)) return 0;
    return v2;
}


/* ── sub_349c8 — thin wrapper ────────────────────────────────────── */
long sub_349c8(long state, long port)
{
    return sub_3492c(state, port);
}

/* ── sub_34a40 — read pmap fields into state ─────────────────────── */
static long sub_34a40(long state, long port)
{
    long base = sub_34048(state, port, NULL);
    if (!base) return 0;
    long v = 0;
    if (!sub_28840(state, base + 0x78, &v)) return 0;
    if (!sub_1972c(state, v)) return 0;

    int build = *(int *)(state + 0x140);
    if (build < 0x2258 && build - 0x1f53U > 1 && build != 0x1809 && build != 0x1c1b) return 0;
    if (build >= 0x2258 && build != 0x2258 && build != 0x2712 && build != 0x225c) return 0;

    uint32_t stride = *(uint32_t *)(state + 0x168);
    long r1 = 0;
    if (!sub_28840(state, v + stride * 2, &r1)) return 0;

    uint64_t ver = *(uint64_t *)(state + 0x158);
    uint64_t pmap_a = (uint64_t)r1;
    if (ver > 0x1f52ffffffffffffULL) {
        if ((*(uint32_t *)state & 0x5584001) && !(pmap_a & 0x7fffffffffULL)) {
            pmap_a = 0;
        } else if (ver < 0x1f530f02800000ULL) {
            /* keep */
        }
    }
    *(uint64_t *)(state + 0xe8 * 2) = pmap_a;

    long r2 = 0;
    sub_28840(state, v + stride * 4, &r2);
    *(uint64_t *)(state + 0xea * 2) = (uint64_t)r2;
    *(uint64_t *)(state + 0xe4 * 2) = (uint64_t)r1;
    *(uint64_t *)(state + 0xe6 * 2) = (uint64_t)r2;
    *(long *)(state + 0x63c * 2) = v;
    return 1;
}

void sub_34a40_pub(long s, long p) { sub_34a40(s, p); }

/* ── sub_34d14 — thin wrapper: sub_32c78 + sub_34a40 ────────────── */
long sub_34d14(long state, uint32_t tag)
{
    long h = sub_32c78_stub2(state, 0);
    if (!h) return 0;
    if (!sub_34a40(state, h)) return 0;
    *(uint32_t *)(state + 0x18f8 / 4) = tag;
    return 1;
}

/* ── sub_34d58 — version-gated kobj field offset (task flags) ────── */
long sub_34d58(long state, long port, int mode)
{
    if (mode == 0) {
        long base = sub_32c78_stub2(state, port);
        if (!base) return 0;
        int build = *(int *)(state + 0x140);
        uint64_t ver = *(uint64_t *)(state + 0x158);
        long off;
        if (build - 0x1f53U < 2) {
            if (sub_36098(state, 0x100000))
                off = ver < 0x1f530f02800000ULL ? 0x41c : 0x3ec;
            else {
                int cap = sub_36098(state, 0x5584001);
                off = ver < 0x1f530f02800000ULL ? (cap ? 0x40c : 0x3e8) : (cap ? 0x3dc : 0x3b8);
            }
        } else if (build == 0x1809) {
            int cap = sub_36098(state, 0x5584001);
            off = cap ? 0x3c0 : 0x3b8;
        } else if (build == 0x1c1b) {
            uint64_t v2 = ver;
            int cap = sub_36098(state, 0x5584001);
            long a = cap ? 0x3f4 : 0x3d8;
            long b = cap ? 0x404 : 0x3e0;
            off = v2 > 0x1c1b19145fffffULL ? b : a;
        } else if (build == 0x2258 || build == 0x225c || build == 0x2712) {
            off = 0x4c0;
        } else return 0;
        long val = 0;
        if (!sub_28840(state, base + off, &val)) return 0;
        return val;
    }
    /* mode != 0: newer path */
    return sub_34754(state, port);
}

/* ── sub_34f5c — thin wrapper with cnt output ────────────────────── */
long sub_34f5c(long state, long port, int mode, uint32_t *cnt)
{
    long r = sub_34d58(state, port, mode);
    if (r && cnt) *cnt = (uint32_t)r;
    return r;
}

/* ── sub_34ff8 — thin wrapper ────────────────────────────────────── */
void sub_34ff8(long state, long port, long a3)
{
    sub_34f5c(state, port, 0, (uint32_t *)a3);
}

/* ── sub_35004 — processor count + kobj scan ─────────────────────── */
uint32_t sub_35004(long state, int build2, long kext, uint32_t *out)
{
    int build = *(int *)(state + 0x140);
    long off;
    if (build < 0x2258) {
        if (build - 0x1f53U > 1) {
            if (build == 0x1809)      off = 0x20;
            else if (build == 0x1c1b) {
                uint64_t ver = *(uint64_t *)(state + 0x158);
                off = ver < 0x1c1b1401000000ULL ? 0x20 : 0x28;
            } else return 0x28007;
        } else {
            int cap = sub_36098(state, 0x4000000);
            off = cap ? 0x9b0 : 0x8ac;
        }
    } else if (build == 0x2258 || build == 0x225c || build == 0x2712) {
        int cap = sub_36098(state, 0x4000000);
        off = cap ? 0x9b0 : 0x8ac;
    } else return 0x28007;

    if (out) *out = (uint32_t)off;
    (void)build2; (void)kext;
    return 0;
}

/* ── sub_353dc — version-gated offset (0x58/0x60) ───────────────── */
uint64_t sub_353dc(long state)
{
    int build = *(int *)(state + 0x140);
    if (build - 0x1f53U > 1 && build != 0x1c1b) {
        if (build == 0x1809) return 0x58;
        return 0;
    }
    return 0x60;
}
