/*
 * record_0x90001_destroy.c
 * entry1_type0x09.dylib — FUN_0003f2e0 (sub_3f2e0)
 *
 * Destroys / tears down the session state object.
 * Sequence:
 *   1. Clear cached state fields at +0x18c0 / +0x18b8
 *   2. sub_36088(state, 0x800000) — clear capability flag
 *   3. sub_21304(state)           — teardown helper
 *   4. sub_3c450(state, task, 0, 0) — task credential cleanup
 *   5. Check capability 0x400 → sub_13ebc validation
 *   6. Check capability 4 → sub_23d30
 *   7. sub_39cc0 if host port cached
 *   8. Thread-self check → sub_3f8c0
 *   9. sub_3a150 credential restore
 *  10. sub_3b7e0 host port restore
 *  11. sub_3e4d0 final cleanup
 *
 * Verified: field clears, capability checks, sub_3e4d0 tail call,
 *           error codes 0x2801f, 0x28020.
 * Inferred: "destroy" label from call context.
 */

#include <stdint.h>
#include <mach/mach.h>

#define ERR_DESTROY  0x0002801fu
#define ERR_VALIDATE 0x00028020u

/* forward declarations */
extern void     sub_36088(long state, uint32_t flag);
extern void     sub_21304(long state);
extern uint64_t sub_3c450(long state, mach_port_t task, int a, int b);
extern int      sub_36098(long state, uint32_t flag);
extern int      sub_13ebc(long state, long *out);
extern int      sub_14524(long state);
extern int      sub_23d30(long state, int mode);
extern int      sub_39cc0(long state, mach_port_t task, int mode,
                           void *buf, int size);
extern int      sub_3f8c0(long state, mach_port_t thread,
                           uint32_t flags, int mode);
extern int      sub_3a150(long state, int uid, int gid, int mode);
extern int      sub_3b7e0(long state, mach_port_t task, mach_port_t host);
extern void     sub_3e4d0(long state);
extern int      sub_1308c(long state);

/* ── sub_3f2e0 — destroy session state ─────────────────────────────────── */
uint64_t sub_3f2e0(long state)
{
    *(uint64_t *)(state + 0x18c0) = 0;
    *(uint64_t *)(state + 0x18b8) = 0;

    sub_36088(state, 0x800000);
    sub_21304(state);

    uint64_t rc = sub_3c450(state, mach_task_self(), 0, 0);
    if ((int)rc != 0) return rc;

    rc = ERR_DESTROY;

    /* capability 0x400: validate state */
    if (sub_36098(state, 0x400)) {
        uint32_t val = 0;
        if (!sub_13ebc(state, (long *)&val)) return ERR_VALIDATE;

        if (val != 3) {
            uint32_t cached = *(uint32_t *)(state + 600);
            if (cached > 1 && cached != 3) return ERR_VALIDATE;
            if (val != cached) {
                if (!sub_14524(state)) return ERR_VALIDATE;
            }
        }
    }

    /* capability 4: sub_23d30 */
    if (!sub_36098(state, 4) || sub_23d30(state, 0)) {
        /* host port cached: sub_39cc0 */
        long host_port = *(long *)(state + 0x1900);
        if (host_port) {
            if (!sub_39cc0(state, (mach_port_t)mach_task_self(), 2,
                           (void *)(state + 0x1908), 8))
                goto done;
        }

        /* thread-self check */
        mach_port_t cached_thread = *(mach_port_t *)(state + 0x192c);
        if (cached_thread + 1U >= 2) {
            mach_port_t self = mach_thread_self();
            if (cached_thread == self) {
                uint32_t flags = 0x4000000;
                if (*(uint64_t *)(state + 0x158) > 0x1f530f027fffffULL)
                    flags = 1;
                if (!sub_3f8c0(state, self, flags, 0))
                    return ERR_DESTROY;
            }
        }

        /* credential restore */
        int uid = *(int *)(state + 0x1910);
        int gid = *(int *)(state + 0x1914);
        if ((uid || gid) && !sub_3a150(state, uid, gid, 0))
            goto done;

        /* host port restore */
        mach_port_t host_self = mach_host_self();
        mach_port_t cached_host = *(mach_port_t *)(state + 0x1928);
        if (host_self != cached_host) {
            if (!sub_36098(state, 0x10) &&
                !sub_3b7e0(state, (mach_port_t)mach_task_self(), cached_host))
                goto done;
        }

        sub_3e4d0(state);
        rc = 0;
    }

done:
    return rc;
}
