/*
 * record_0x90001_dispatch.c
 * entry1_type0x09.dylib — FUN_0003e580 (sub_3e580 / sub_3e550 wrapper)
 *
 * Command dispatcher for the 0x90001 helper driver.
 * sub_3e550 is a thin wrapper that calls sub_3e580 with a stack arg.
 *
 * Selector families:
 *   Family 0 (sel & 0xFF00 == 0):   general task/kernel ops
 *   Family 1 (sel & 0xFF00 == 0x100): primitive ops
 *   Family 3 (sel & 0xFF00 == 0x300): older-kernel-only ops
 *
 * Key selectors documented below. Unimplemented selectors return 0xad001.
 *
 * Verified: selector constants, family dispatch, capability checks,
 *           0xC000001B readback, 0x4000001B set, family-3 kaddr gate.
 * Inferred: function labels from call graph.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <errno.h>
extern const char *__CFProcessPath(void);

#define ERR_NULL_ARG  0x000ad001u
#define ERR_ALLOC     0x000ad008u
#define KADDR_MID_MIN 0x1F530000000000ULL

/* forward declarations — family 0 */
extern uint64_t sub_3c450(long state, mach_port_t task, int a, int b);
extern uint64_t sub_2e00c(long state, mach_port_t task);
extern int      sub_39fdc(long state, mach_port_t thread_a, mach_port_t thread_b);
extern uint64_t sub_3a150(long state, int uid, int gid, int mode);
extern uint64_t sub_23d30(long state, int mode);
extern uint64_t sub_39cc0(long state, mach_port_t task, int mode,
                           void *buf, uint64_t size);
extern uint64_t sub_2de64(long state, mach_port_t task);
extern uint64_t sub_1503c(long state, mach_port_t task,
                           const char *plist, uint32_t flags);
extern int      sub_36098(long state, uint32_t flag);
extern int      sub_1308c(long state);
extern uint64_t sub_3b524(long state, mach_port_t task,
                           uint32_t *a, long b, long c);
extern uint64_t sub_3bc94(long state, mach_port_t task, int mode, uint32_t *out);
extern uint64_t sub_3fe68(long state, mach_port_t task, int *out);
extern uint64_t sub_2eb4c(long state, mach_port_t task,
                           uint64_t addr, uint32_t *out);
extern uint64_t sub_33e8c(long state, mach_port_t task);
extern uint64_t sub_295b4(long state, uint64_t addr, uint32_t *out);
extern uint64_t sub_28dfc(long state, uint64_t addr, ...);
/* family 1 */
extern uint64_t sub_3f9a0(long state, uint32_t *out);
extern uint64_t sub_14bec(long state, uint32_t *buf, uint32_t *size, uint32_t *out);
extern uint64_t sub_13ebc(long state, long *out);
extern uint64_t sub_14524(long state);
extern uint64_t sub_3fa2c(long state, int mode);
extern uint64_t sub_223a4(long state, uint32_t a, uint32_t b, uint64_t c);
extern uint64_t sub_22464(long state, uint32_t *buf, uint32_t size);
extern uint64_t sub_2f7bc(long state, int fd);
/* family 3 */
extern uint64_t sub_203b0(long state, uint32_t *a, uint32_t *b);
extern uint64_t sub_1fa7c(long state, uint64_t a, uint32_t b, uint32_t *c);
extern uint64_t sub_1fc94(long state);
extern uint64_t sub_1fe38(long state, uint32_t a);
extern uint64_t sub_1fa28(long state, uint32_t a);
extern uint64_t sub_1f900(long state, uint32_t a, uint64_t b, uint64_t c,
                           uint32_t d, uint64_t e);
extern uint64_t sub_20468(long state, uint32_t *buf, uint32_t size);
/* misc */
extern uint64_t sub_3f8c0(long state, mach_port_t thread,
                           uint32_t flags, int mode);

/* ── sub_3e550 — thin wrapper ────────────────────────────────────────────── */
void sub_3e550(uint64_t state, uint64_t sel)
{
    extern uint64_t sub_3e580(long, uint64_t, uint32_t *);
    sub_3e580((long)state, sel, NULL);
}

/* ── sub_3e580 — main dispatcher ─────────────────────────────────────────── */
uint64_t sub_3e580(long state, uint64_t sel, uint32_t *args)
{
    uint32_t family = (uint32_t)((sel >> 8) & 0xff);
    uint32_t cmd    = (uint32_t)sel;
    uint64_t rc     = ERR_NULL_ARG;

    /* guard: if bits 29-30 set, args must be non-NULL */
    if ((sel >> 0x1e & 3) && !args) return ERR_NULL_ARG;

    /* clear cached state */
    *(uint64_t *)(state + 0x18c0) = 0;
    *(uint64_t *)(state + 0x18b8) = 0;
    sub_36098(state, 0x800000);  /* clear flag */

    /* task credential setup */
    rc = sub_3c450(state, mach_task_self(), 0, 0);
    if ((int)rc) return rc;

    /* ── Family 3: older-kernel-only ops ─────────────────────────────── */
    if (family == 3) {
        uint64_t kaddr = *(uint64_t *)(state + 0x158);
        int xnu = *(int *)(state + 0x140);
        if (kaddr <= 0x1f52ffffffffffffULL || xnu >= 0x2258) goto done;

        switch (cmd) {
        case 0x80000306: rc = sub_203b0(state, args, args + 4); break;
        case 0xc0000303: rc = sub_1fa7c(state, *(uint64_t *)args, args[2], args + 3); break;
        case 0x302:      rc = sub_1fc94(state); break;
        case 0x40000301: rc = sub_1fe38(state, *args); break;
        case 0x40000304: rc = sub_1fa28(state, args[3]); break;
        case 0x40000305: rc = sub_1f900(state, *args, *(uint64_t *)(args+2),
                                         *(uint64_t *)(args+4), args[6],
                                         *(uint64_t *)(args+8)); break;
        case 0x40000306: rc = sub_20468(state, args, 0x14); break;
        default: break;
        }
        goto done;
    }

    /* ── Family 1: primitive ops ─────────────────────────────────────── */
    if (family == 1) {
        uint32_t arg0 = args ? (uint32_t)(uintptr_t)args : 0;
        switch (cmd) {
        case 0x8000010d: {
            uint32_t out = 0;
            if (*(uint64_t *)(state + 0x158) >> 0x2b > 0x44a)
                rc = sub_3f9a0(state, &out);
            if ((int)rc == 0) {
                /* pack result */
                if (args) *args = (*args & ~0xffffff00u) | (out & 0xff);
            }
            break;
        }
        case 0xc000010b: {
            /* readback: return available capability bits */
            uint32_t req = args ? *args : 0;
            uint32_t avail = 0;
            uint64_t kaddr = *(uint64_t *)(state + 0x158);
            if ((req & 1) && kaddr >= KADDR_MID_MIN)
                avail |= (*(int *)(state + 0x140) < 0x2258) ? 1 : 0;
            if (req & 4) {
                if (!sub_36098(state, 0x5184001)) {
                    if (sub_36098(state, 0x200) &&
                        *(int *)(state + 0x140) >= 0x1809)
                        avail |= 4;
                } else if (sub_1308c(state)) avail |= 4;
            }
            if (req & 2) {
                if (!sub_36098(state, 0x5184001))
                    avail |= 2;
                else if (sub_1308c(state)) avail |= 2;
            }
            if ((req & 8) && kaddr < KADDR_MID_MIN) avail |= 8;
            if (args) *args = avail;
            rc = 0;
            break;
        }
        case 0x80000108: {
            uint32_t size = 0x400, out = 0;
            if (args) sub_14bec(state, args + 4, &size, &out);
            if (out && args) *args |= 1;
            if (size && args) *args |= 2;
            rc = 0;
            break;
        }
        case 0x80000109: {
            long val = 0;
            int ok = (int)sub_13ebc(state, &val);
            if (ok && args) *args = (uint32_t)val;
            rc = ok ? 0 : ERR_NULL_ARG;
            break;
        }
        case 0x109: {
            uint64_t kaddr = *(uint64_t *)(state + 0x158);
            if (kaddr > 0x1f52ffffffffffffULL) {
                if (args && (*args & 0xf) == 1) rc = 0;
            } else {
                uint32_t mode = args ? (*args & 0xf) : 0;
                if (mode < 3) rc = sub_14524(state);
            }
            break;
        }
        case 0x10c: {
            const char *path = args ? (const char *)args : __CFProcessPath();
            int fd = open(path, 0);
            if (fd < 0) {
                rc = (uint32_t)(-errno) | 0x40000000u;
            } else {
                rc = sub_2f7bc(state, fd);
                close(fd);
            }
            break;
        }
        case 0x10d:
            if (*(uint64_t *)(state + 0x158) >> 0x2b >= 1099)
                rc = sub_3fa2c(state, args ? (*args != 0) : 0);
            break;
        case 0x4000010a:
            if (args) rc = sub_223a4(state, args[0], args[1], *(uint64_t *)(args+4));
            break;
        case 0x40000105:
            if (args) rc = sub_22464(state, args, 0x14);
            break;
        default: rc = ERR_NULL_ARG; break;
        }
        goto done;
    }

    /* ── Family 0: general ops ───────────────────────────────────────── */
    if (family != 0) goto done;

    switch (cmd) {
    case 1: {
        /* read task credential flags */
        long kobj = sub_33e8c(state, (mach_port_t)mach_task_self());
        if (!kobj) break;
        int xnu = *(int *)(state + 0x140);
        long off_a, off_b;
        if      (xnu == 0x1809) { off_a = 0x148; off_b = 0x160; }
        else if (xnu == 0x1c1b) { off_a = 0x130; off_b = 0x148; }
        else if (xnu == 0x1f53) { off_a = 0x1c0; off_b = 0x1dc; }
        else if (xnu == 0x1f54) { off_a = 0x268; off_b = 0x284; }
        else if (xnu == 0x2258) { off_a = 0x260; off_b = 0x27c; }
        else if (xnu == 0x225c || xnu == 0x2712) { off_a = 0x458; off_b = 0x474; }
        else break;
        uint32_t va = 0, vb = 0;
        if (sub_295b4(state, off_a + kobj, &va) &&
            sub_295b4(state, off_b + kobj, &vb)) {
            int older = (xnu < 0x2258) || ((va >> 1) & 1);
            if ((va >> 10) & 1) {
                uint32_t ppid = (uint32_t)getppid();
                if (vb == ppid) {
                    va &= ~0x400u;
                    sub_28dfc(state, off_a + kobj);
                    sub_28dfc(state, off_b + kobj, 0);
                    rc = 0; break;
                }
            }
            rc = older ? 1 : 0;
        }
        break;
    }
    case 2:  rc = sub_3c450(state, args ? (mach_port_t)*args : mach_task_self(), 0, 0); break;
    case 3:  rc = sub_1503c(state, args ? (mach_port_t)*args : mach_task_self(),
                             "<dict><key>task_for_pid-allow</key><true/></dict>", 0); break;
    case 6:  rc = sub_2e00c(state, args ? (mach_port_t)*args : mach_task_self()); break;
    case 7: {
        mach_port_t tself = mach_thread_self();
        mach_port_t cached = *(mach_port_t *)(state + 0x191c);
        if (!cached) cached = *(mach_port_t *)(state + 0x1918);
        if (sub_39fdc(state, cached, tself))
            *(mach_port_t *)(state + 0x192c) = tself;
        rc = 0;
        break;
    }
    case 8:  rc = sub_3a150(state, 0, 0, 0); break;
    case 9:  rc = sub_3c450(state, args ? (mach_port_t)*args : mach_task_self(), 1, 0); break;
    case 10: rc = sub_23d30(state, 1); break;
    case 0xb: rc = sub_39cc0(state, args ? (mach_port_t)*args : mach_task_self(),
                              2, args ? args+1 : NULL, 8); break;
    case 0xc: rc = sub_2de64(state, args ? (mach_port_t)*args : mach_task_self()); break;
    case 0xd: rc = sub_3c450(state, args ? (mach_port_t)*args : mach_task_self(), 0, 1); break;
    case 0xf: rc = sub_1503c(state, args ? (mach_port_t)*args : mach_task_self(),
                              NULL, 1); break;
    /* 0x4000001b: task flag set */
    case 0x4000001b: {
        if (!sub_36098(state, 0x5184001)) {
            if (!sub_36098(state, 0x200)) break;
            if (*(int *)(state + 0x140) < 0x1809) break;
        }
        mach_port_t task = args ? (mach_port_t)*args : mach_task_self();
        uint32_t flags = args ? args[1] : 0;
        rc = sub_3b524(state, task, args ? args+1 : NULL,
                       args ? (long)(args+6) : 0,
                       args ? (long)(args+5) : 0);
        (void)flags;
        break;
    }
    case 0xc000001b: {
        /* readback: return available bits */
        uint32_t req = args ? *args : 0;
        uint32_t avail = 0;
        if (req & 1) avail |= 1;
        if (req & 2) avail |= 2;
        if (req & 4) avail |= 4;
        if (req & 8) avail |= 8;
        if (args) *args = avail;
        rc = 0;
        break;
    }
    case 0x8000001c:
        rc = sub_3fe68(state, args ? (mach_port_t)*args : mach_task_self(),
                       args ? (int *)(args+1) : NULL);
        break;
    case 0xc000001d:
        rc = sub_3bc94(state, args ? (mach_port_t)*args : mach_task_self(),
                       0, args ? args+1 : NULL);
        break;
    case 0xc0000020:
        rc = sub_3fe68(state, args ? (mach_port_t)*args : mach_task_self(),
                       args ? (int *)(args+1) : NULL);
        break;
    case 0xc0000023:
        rc = sub_2eb4c(state, args ? (mach_port_t)*args : mach_task_self(),
                       args ? *(uint64_t *)(args+2) : 0,
                       args ? args+6 : NULL);
        break;
    default: rc = ERR_NULL_ARG; break;
    }

done:
    return rc;
}
