/* record_0x90000_e9f89858_thread_policy.c
 * sub_09fdc..sub_0a878 — thread task-policy setter, suspended-thread
 * join wrapper, ipc_entry low-bits r/w, voucher recipe dispatch,
 * host_priv port resolver, and ipc_entry port-right getter.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <mach/mach.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_295b4(long state, long addr, int *out);
extern int  sub_28dfc(long state, long addr, int val);
extern int  sub_28840(long state, long addr, long *out);
extern long sub_02d6c(long state, mach_port_name_t name);
extern long sub_040d8(long state, long task_type, int fl);
extern long sub_04298(long state, long thr_port);
extern int  sub_0f8c0(long state, long thr_port, uint32_t flags, int set);
extern long sub_05fd8(long state, long base);
extern int  sub_2a0d0(long state, long addr, long val);
extern int  sub_2a63c(void);
extern long sub_09eac(long state, pthread_t *out, long fn, void *arg);
extern long sub_05610(long state, int idx);
extern long sub_06480(long state, long entry_addr, mach_port_name_t *out);
extern int  sub_06098(long state, uint32_t mask);
extern void sub_1ca3c(long state, long h, int a, void *b, int c);

/* ── sub_09fdc — apply task policy to thread ────────────────────── */
long sub_09fdc(long state, long task_type, mach_port_t thr_port)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    uint32_t flags = ver > 0x1f530f027fffffULL ? 1u : 0x4000000u;

    if ((int)task_type != 0) {
        long kobj = sub_040d8(state, task_type, 0);
        if (!kobj) return 0;
        long thr_kobj = sub_04298(state, (long)thr_port);
        if (!thr_kobj) return 0;
        long v = 0;
        if (!sub_28840(state, thr_kobj, &v)) return 0;
        if (!sub_0f8c0(state, (long)thr_port, flags, 1)) return 0;
        sub_05fd8(state, kobj);
        if (ver < 0x1f530f02800000ULL) {
            if (!sub_2a0d0(state, thr_kobj, kobj)) return 0;
        } else {
            if (!sub_2a63c()) return 0;
        }
        return 1;
    }
    return sub_0f8c0(state, (long)thr_port, flags, 0);
}

/* ── sub_0a100 — create + join thread ───────────────────────────── */
int sub_0a100(long state, long fn, void *arg)
{
    pthread_t thr = NULL;
    uint32_t r = (uint32_t)sub_09eac(state, &thr, fn, arg);
    if (r) return 0;
    return pthread_join(thr, NULL) == 0;
}

/* ── sub_0a57c — read-modify-write low 10 bits of ipc_entry field ─ */
long sub_0a57c(long state, long addr, uint32_t new_bits, uint32_t *old_out)
{
    int val = 0;
    if (!sub_295b4(state, addr, &val)) return 0;
    if (old_out) *old_out = (uint32_t)val & 0x3ffu;
    val = (val & (int)0xfffffc00u) | (int)(new_bits & 0x3ffu);
    return (long)(sub_28dfc(state, addr, val) != 0);
}

/* ── sub_0a5f0 — voucher recipe dispatch (version-gated) ────────── */
void sub_0a5f0(long state, long h)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (ver < 0x27120f04b00003ULL) {
        if (ver < 0x225c1e80500000ULL &&
            (ver < 0x225c1980500000ULL ||
             ((*(uint32_t *)state & 0x5584001u) != 0 &&
              (*(uint32_t *)state & 1u) == 0))) {
            sub_1ca3c(state, h, 2, NULL, 3);
            return;
        }
    } else if (*(uint8_t *)state >> 5 & 1) {
        long recipe[2] = {0, 0};
        sub_1ca3c(state, h, 4, recipe, 0xf);
        return;
    }
    sub_1ca3c(state, h, 2, NULL, 3);
}

/* ── sub_0a72c — resolve host_priv port ─────────────────────────── */
long sub_0a72c(long state)
{
    mach_port_t host_priv = mach_host_self();

    if (*(uint32_t *)(state + 0x1920) + 1 >= 2)
        return (long)*(uint32_t *)(state + 0x1920);

    uint32_t local_port = 0;
    kern_return_t kr = host_get_special_port(host_priv, -1, 2, &local_port);
    if (kr) {
        uint64_t ver = *(uint64_t *)(state + 0x158);
        if (ver < 0x1f530000000000ULL ||
            ((*(uint32_t *)state & 0x5584001u) == 0 &&
             ver < 0x22580a06c00000ULL &&
             (ver < 0x1f543c40800000ULL || *(int *)(state + 0x140) <= 0x2257))) {
            long kobj = sub_02d6c(state, host_priv);
            if (!kobj) return 0;
            uint32_t old = 0;
            if (!sub_0a57c(state, kobj, 4, &old)) return 0;
            *(uint32_t *)(state + 0x1920) = local_port;
        }
        return 0;
    }
    *(uint32_t *)(state + 0x1920) = local_port;
    return (long)local_port;
}

/* ── sub_0a878 — get ipc_entry port-right name for thread kobj ──── */
uint32_t sub_0a878(long state)
{
    uint32_t cached = *(uint32_t *)(state + 0x1924);
    if (cached + 1 >= 2) return cached;

    long kobj = sub_05610(state, 0);
    if (!kobj) return 0;

    mach_port_name_t name = 0;
    if (sub_06480(state, kobj, &name)) return 0;
    return (uint32_t)name;
}
