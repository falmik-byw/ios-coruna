/*
 * record_0x90000_e9f89858_driver.c
 * entry5_type0x09.dylib (e9f89858 variant) — driver vtable + vm helpers
 *
 * Covers: sub_7714, sub_7718, sub_7794, sub_7808, sub_7868, sub_787c,
 *         sub_78b8, sub_78cc, sub_7908, sub_7994, sub_7afc,
 *         sub_7c7c, sub_7d00, sub_7d80, sub_7e10, sub_7e4c, sub_7e88,
 *         sub_7f24, sub_807c
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>

/* forward decls for state helpers (defined in record_0x90000_state_init.c) */
extern int  sub_3f5e4(void **out);
extern void sub_3f708(void *sess, uint64_t arg);
extern void sub_3fa58(void *sess);
extern void sub_3fbe4(void *sess);

/* ── sub_7714 / sub_7718 — free driver object ───────────────────── */
static void sub_7714(uint64_t *obj)
{
    if (!obj) return;
    memset(obj, 0, 0x50);
    free(obj);
}
static void sub_7718(uint64_t *obj)
{
    memset(obj, 0, 0x50);
    free(obj);
}

/* ── sub_7794 — create session ──────────────────────────────────── */
static void sub_7794(long self, uint64_t a2, void **out)
{
    void *sess = NULL;
    if (self && out && sub_3f5e4(&sess) == 0)
        *out = sess;
}

/* ── sub_7808 — dispatch ────────────────────────────────────────── */
static void sub_7808(long self, long sess, uint64_t cmd)
{
    if (self && sess) sub_3f708((void *)sess, cmd);
}

/* ── sub_7868 / sub_787c — secondary / teardown ─────────────────── */
static void sub_7868(long self, long sess)
{
    if (self && sess) sub_3fa58((void *)sess);
}
static void sub_787c(uint64_t a1, long sess)
{
    (void)a1;
    sub_3fa58((void *)sess);
}

/* ── sub_78b8 / sub_78cc — destroy session ──────────────────────── */
static void sub_78b8(long self, long sess)
{
    if (self && sess) sub_3fbe4((void *)sess);
}
static void sub_78cc(uint64_t a1, long sess)
{
    (void)a1;
    sub_3fbe4((void *)sess);
}

/* ── sub_7908 — read cached status ─────────────────────────────── */
static void sub_7908(long self, long sess, int *out)
{
    if (self && sess && out && *(int *)(sess + 0x1918) > 1)
        *out = *(int *)(sess + 0x1918);
}

/* ── sub_7994 — batch dispatcher ───────────────────────────────── */
extern void sub_4199c(uint64_t fn, long self, long sess, long a3, ...);
static void sub_7994(long self, long *sess_ptr, uint32_t *ops, int count)
{
    if (!self || !sess_ptr) return;
    long sess = *sess_ptr;
    if (!sess) {
        sub_4199c(*(uint64_t *)(self + 0x18), self, 0, (long)sess_ptr);
        return;
    }
    if (count)
        sub_4199c(*(uint64_t *)(self + 0x28), self, sess, (long)ops,
                  *(uint64_t *)(ops + 2));
    *sess_ptr = sess;
}

/* ── sub_7afc — kernel version triple ──────────────────────────── */
static void sub_7afc(long self, size_t *out)
{
    char buf[512];
    mach_port_t host;
    kern_return_t kr;
    int mib[2] = {1, 4};
    size_t len = sizeof(buf);
    uint32_t minor = 0;

    if (!self || !out) return;
    host = mach_host_self();
    kr = host_kernel_version(host, buf);
    if (kr != 0) {
        if (kr != 53) return;
        if (sysctl(mib, 2, buf, &len, NULL, 0) != 0) return;
    }
    if (!strstr(buf, "RELEASE")) return;
    char *p = strstr(buf, "xnu-");
    if (!p) return;
    if (sscanf(p, "xnu-%u.%u.%u", (unsigned *)out, &minor, &minor) == 3)
        *(uint32_t *)((char *)out + sizeof(size_t)) = minor;
}

/* ── sub_7c7c — vm_remap (copy) ─────────────────────────────────── */
static void sub_7c7c(vm_address_t addr, vm_size_t sz, boolean_t copy)
{
    vm_address_t dst = 0;
    vm_prot_t cur = 0, max = 0;
    vm_remap(mach_task_self(), &dst, sz, 0, 1,
             mach_task_self(), addr, copy, &max, &cur, 1);
}

/* ── sub_7d00 — vm_remap (fixed) ────────────────────────────────── */
static void sub_7d00(vm_address_t addr, vm_size_t sz, boolean_t copy)
{
    vm_address_t dst = addr;
    vm_prot_t cur = 0, max = 0;
    vm_remap(mach_task_self(), &dst, sz, 0, 0x4000,
             mach_task_self(), addr, copy, &max, &cur, 1);
}

/* ── sub_7d80 — vm_region_recurse_64 probe ──────────────────────── */
static void sub_7d80(vm_address_t addr)
{
    vm_size_t sz = 0;
    natural_t depth = 1;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    vm_region_recurse_64(mach_task_self(), &addr, &sz, &depth,
                         (vm_region_recurse_info_t)&info, &cnt);
}

/* ── sub_7e10 / sub_7e4c — no-ops ──────────────────────────────── */
static void sub_7e10(void) {}
static void sub_7e4c(void) {}

/* ── sub_7e88 — thread yield with policy ───────────────────────── */
static void sub_7e88(void)
{
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    double ms = ((double)tb.denom / (double)tb.numer) * 1e6 * 50.0;
    int quantum = (int)ms;
    struct { int period; int computation; int constraint; int preemptible; }
        pol = { quantum, quantum, quantum, 0 };
    thread_policy_set(mach_thread_self(), 2,
                      (thread_policy_t)&pol, 4);
    thread_switch(0, 2, 0);
}

/* ── sub_7f24 — kobj field walker ──────────────────────────────── */
static void sub_7f24(long state, long kobj)
{
    /* Walks kobj field table at state+offsets; minimal stub */
    (void)state; (void)kobj;
}

/* ── sub_807c — free driver object (null-safe) ──────────────────── */
static void sub_807c(uint64_t *obj)
{
    if (!obj) return;
    memset(obj, 0, 0x50);
    free(obj);
}

/* ── _driver export (e9f89858 variant) ──────────────────────────── */
typedef struct {
    uint32_t header;
    uint32_t _pad;
    void    *_unused;
    void (*free_obj)    (uint64_t *);
    void (*create_sess) (long, uint64_t, void **);
    void (*dispatch)    (long, long, uint64_t);
    void (*destroy_sess)(long, long);
    void (*secondary)   (long, long);
    void (*read_status) (long, long, int *);
    void (*batch)       (long, long *, uint32_t *, int);
    void (*kv_triple)   (long, size_t *);
} DriverObj_e9;

__attribute__((visibility("default")))
DriverObj_e9 *_driver_e9(void)
{
    DriverObj_e9 *obj = calloc(1, sizeof(*obj));
    if (!obj) return NULL;
    obj->header      = 0x00020002;
    obj->free_obj    = sub_7714;
    obj->create_sess = sub_7794;
    obj->dispatch    = sub_7808;
    obj->destroy_sess= sub_78b8;
    obj->secondary   = sub_7868;
    obj->read_status = sub_7908;
    obj->batch       = sub_7994;
    obj->kv_triple   = sub_7afc;
    return obj;
}
