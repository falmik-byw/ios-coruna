/* record_0x90001_ipc_utils.c
 * sub_35420..sub_361dc — ipc_space/thread kobj field resolvers,
 * capability flag helpers, kread/kwrite wrappers, port-table ops.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_2572c(long state, long addr, uint32_t sz, void *out);
extern int  sub_2a188(long state, long addr, void *val, int sz);
extern int  sub_2a574(long state, long addr, int val);
extern int  sub_295b4(long state, long addr, int *out);
extern int  sub_28dfc(long state, long addr, int val);
extern long sub_1972c(long state, long addr);
extern int  sub_36098(long state, uint32_t mask);
extern long sub_32b10(long state);
extern long sub_33a30(long state);
extern long sub_328a4(long state, long h);
extern long sub_35500_pub(long state);

/* forward decls */
static long sub_35420(long state, long base);
__attribute__((weak)) long sub_32c78_s(long s, long p);
static long sub_35500(long state);
static long sub_354a4(long state, long port);
static long sub_360a8(long state);

/* ── sub_35420 — version-gated offset + base ─────────────────────── */
static long sub_35420(long state, long base)
{
    int build = *(int *)(state + 0x140);
    long off;
    if      (build == 0x1809 || build == 0x1c1b) off = 0x40;
    else if (build == 0x1f53)                    off = 0x30;
    else if (build == 0x1f54 || build == 0x2258 ||
             build == 0x225c || build == 0x2712) off = 0x20;
    else return 0;
    return off + base;
}

void sub_35420_pub(long s, long b) { sub_35420(s, b); }

/* ── sub_354a4 — resolve thread kobj via self task ───────────────── */
static long sub_354a4(long state, long port)
{
    long h = sub_33a30(state);
    if (!h) return 0;
    return sub_35420(state, h);
    (void)port;
}

long sub_354a4_pub(long s, long p) { return sub_354a4(s, p); }

/* ── sub_35500 — kread at thread kobj field ──────────────────────── */
static long sub_35500(long state)
{
    long base = sub_354a4(state, 0);
    if (!base) return base;
    long val = 0;
    if (!sub_28840(state, base, &val)) return 0;
    if (!sub_1972c(state, val)) return 0;
    return val;
}

void sub_35500_pub2(long s) { sub_35500(s); }

/* ── sub_35568 — walk ipc_space chain ───────────────────────────── */
long sub_35568(long state)
{
    long base = sub_35500(state);
    if (!base) return 0;
    uint64_t ver = *(uint64_t *)(state + 0x158);
    int build = *(int *)(state + 0x140);
    long off;
    if (build - 0x1f53U < 2)
        off = ver < 0x1f530f02800000ULL ? 0x10 : 0x18;
    else if (build == 0x1809 || build == 0x1c1b) off = 0x18;
    else if (build == 0x2258 || build == 0x225c || build == 0x2712) off = 0x18;
    else return 0;
    long val = 0;
    if (!sub_28840(state, base + off, &val)) return 0;
    if (!sub_1972c(state, val)) return 0;
    return val;
}

/* ── sub_35610 — get thread kobj at index ────────────────────────── */
long sub_35610(long state, int idx)
{
    long cached = *(long *)(state + 0x1a8);
    if (!cached) {
        mach_port_t t = (mach_port_t)sub_32b10(state);
        if (!MACH_PORT_VALID(t)) return 0;
        cached = sub_33a30(state);
        if (!cached) return 0;
        *(long *)(state + 0x1a8) = cached;
    }
    if (idx == 1) return cached;
    long h = sub_328a4(state, cached);
    if (!h) return 0;
    long val = 0;
    int stride = *(int *)(state + 0x168);
    if (!sub_28840(state, h + (uint64_t)(stride * idx) + 0x10, &val)) return 0;
    return val;
}

/* ── sub_356c8 — resolve ipc_entry kobj ─────────────────────────── */
long sub_356c8(long state, long port, long *out)
{
    int build = *(int *)(state + 0x140);
    if (build < 0x1f53 && build != 0x1809 && build != 0x1c1b) return 0x28007;
    if (build - 0x1f53U > 1 && build != 0x2258) return 0x28007;

    long base = sub_32c78_s(state, port);
    if (!base) return 0x28025;
    long val = 0;
    if (!sub_28840(state, base + 0x38, &val)) return 0x2800f;
    if (!sub_1972c(state, val)) return 0x28026;
    *out = val;
    return 0;
}

__attribute__((weak)) long sub_32c78_s(long s, long p) { (void)s; (void)p; return 0; }

/* ── sub_3579c — resolve ipc_space field at version offset ──────── */
long sub_3579c(long state, int idx, long *out)
{
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off;
    if (build - 0x1f53U < 2)
        off = ver < 0x1f530f02800000ULL ? 0x100 : 0xf8;
    else if (build == 0x1809 || build == 0x1c1b) off = 0x108;
    else if (build == 0x2258 || build == 0x225c || build == 0x2712) off = 0xf8;
    else return 0x28007;

    long base = sub_35610(state, idx);
    if (!base) return 0x28025;
    long v1 = 0, v2 = 0;
    if (!sub_28840(state, base + off, &v1)) return 0x2800f;
    if (!sub_1972c(state, v1)) return 0x28026;
    if (!sub_28840(state, v1 + 8, &v2)) return 0x2800f;
    if (!sub_1972c(state, v2)) return 0x28026;
    *out = v2;
    return 0;
}

/* ── sub_35938 — resolve ipc_space kobj ─────────────────────────── */
long sub_35938(long state, long port, long *out)
{
    long base = sub_35568(state);
    if (!base) return 0x28025;
    long val = 0;
    if (!sub_28840(state, base, &val)) return 0x2800f;
    if (!sub_1972c(state, val)) return 0x28026;
    *out = val;
    (void)port;
    return 0;
}

/* ── sub_35a50 — read ipc_entry count ───────────────────────────── */
long sub_35a50(long state, int idx, uint32_t *out)
{
    long base = sub_35610(state, idx);
    if (!base) return 0;
    int val = 0;
    if (!sub_295b4(state, base + 0x10, &val)) return 0;
    if (out) *out = (uint32_t)val;
    return 1;
}

/* ── sub_35ae0 — ipc_entry table grow ───────────────────────────── */
uint64_t sub_35ae0(uint32_t *state, uint32_t new_cnt, uint32_t *out)
{
    /* read current count, grow if needed */
    int cur = 0;
    if (!sub_295b4((long)state, (long)(state + 4), &cur)) return 0;
    if ((uint32_t)cur >= new_cnt) { if (out) *out = (uint32_t)cur; return 1; }
    if (!sub_2a574((long)state, (long)(state + 4), (int)new_cnt)) return 0;
    if (out) *out = new_cnt;
    return 1;
}

/* ── sub_35d94 — kwrite +1 to ipc_entry field ───────────────────── */
uint64_t sub_35d94(long state, long base, int delta)
{
    int val = 0;
    if (!sub_2572c(state, base + 4, 4, &val)) return 0;
    val += delta;
    return (uint64_t)(sub_2a188(state, base + 4, &val, 4) != 0);
}

/* ── sub_35e18 — kwrite +delta to field+4 ───────────────────────── */
uint64_t sub_35e18(long state, long base, int delta)
{
    int val = 0;
    if (!sub_2572c(state, base + 4, 4, &val)) return 0;
    val += delta;
    return (uint64_t)(sub_2a188(state, base + 4, &val, 4) != 0);
}

/* ── sub_35e8c — thin wrapper: sub_35e18 + sub_35d94 ────────────── */
long sub_35e8c(long state, long base)
{
    sub_35e18(state, base, 1);
    sub_35d94(state, base, 1);
    return 0;
}

/* ── sub_35ecc — ipc_entry refcount bump ────────────────────────── */
long sub_35ecc(long state, long base, int delta)
{
    int val = 0;
    if (!sub_295b4(state, base + 0x10, &val)) return 0;
    if ((uint32_t)(val - 1) >> 20) return 0;
    if (!sub_2a574(state, base + 0x10, val + delta)) return 0;
    if (*(uint64_t *)(state + 0x158) > 0x1f530f027fffffULL) {
        long v2 = 0;
        if (!sub_28840(state, base, &v2)) return 0;
        if (!sub_1972c(state, v2)) return 0;
        long off = *(int *)(state + 0x140) < 0x2712 ? 0x18 : 0;
        int v3 = 0;
        if (!sub_295b4(state, v2 + off, &v3)) return 0;
        if ((uint32_t)(v3 - 1) >> 20) return 0;
        if (!sub_28dfc(state, v2 + off, v3 + delta)) return 0;
    }
    return 1;
}

/* ── sub_35fd8 — thin wrapper ────────────────────────────────────── */
uint32_t sub_35fd8(long state, long base)
{
    return sub_35ecc(state, base, 0x10) ? 0 : 0x1001;
}

/* ── sub_36000 — ipc_entry slot check ───────────────────────────── */
uint32_t sub_36000(long state, long base)
{
    int val = 0;
    if (!sub_295b4(state, base + 0x10, &val)) return 0x2800f;
    if (!val) return 0x28011;
    return sub_28dfc(state, base + 0x10, val + 4) ? 0 : 0x28010;
}

/* ── sub_36078 — set capability bits ────────────────────────────── */
void sub_36078(uint32_t *flags, uint32_t mask) { *flags |= mask; }

/* ── sub_360a8 — get/cache ipc_space table base ─────────────────── */
static long sub_360a8(long state)
{
    if (*(long *)(state + 0x210)) return *(long *)(state + 0x210);
    uint32_t off = 0;
    /* version-gated offset lookup */
    int build = *(int *)(state + 0x140);
    if (build == 0x1809)      off = 0x444;
    else if (build == 0x1c1b) off = 0x4b4;
    else                      off = 0x8ac;
    long base = sub_35610(state, 0);
    if (!base) return 0;
    long val = 0;
    if (!sub_28840(state, base + off, &val)) return 0;
    if (!sub_1972c(state, val)) return 0;
    *(long *)(state + 0x210) = val;
    return val;
}

void sub_360a8_pub(long s) { sub_360a8(s); }

/* ── sub_36160 — read ipc_entry slot at index ───────────────────── */
long sub_36160(long state, uint32_t idx, long *out)
{
    if (idx >= 0xe) return 0;
    long base = sub_360a8(state);
    if (!base) return 0;
    long val = 0;
    int stride = *(int *)(state + 0x168);
    if (!sub_28840(state, base + (uint64_t)(stride * (int)idx), &val)) return 0;
    *out = val;
    return 1;
}

/* ── sub_361dc — write ipc_entry slot at index ──────────────────── */
long sub_361dc(long state, uint32_t idx, long val)
{
    if (idx >= 0xe) return 0;
    int stride = *(int *)(state + 0x168);
    long base = sub_360a8(state);
    if (!base) return 0;
    return (long)(sub_2a188(state, base + (uint64_t)(stride * (int)idx), &val, stride) != 0);
}
