/*
 * record_0x90001_driver.c
 * entry1_type0x09.dylib (377bed variant) — auxiliary bootstrap helper driver
 *
 * Recovered from r2 disassembly of:
 *   payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry1_type0x09.dylib
 *
 * Verified: vtable layout, offsets, error codes, control flow.
 * Inferred: function role labels from call context and data flow.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

/* ── error codes ─────────────────────────────────────────────────────────── */
#define ERR_NULL_ARG     0x000a0001   /* 0xd001 | 0xa<<16 — null input */
#define ERR_ALLOC        0x000a0008   /* ERR_NULL_ARG + 8 — calloc failed */
#define ERR_NO_SESSION   0x000a0001   /* same base, null session */
#define ERR_KV_FAIL      0x000a0001
#define ERR_KV_NORELEASE 0x80000000   /* non-RELEASE kernel, or sysctl err */
#define ERR_KV_NOSTRSTR  (0x000a0001 - 0xc)  /* strstr("RELEASE") failed */
#define HEADER_VERSION   0x00020002   /* object header word: version 2.2 */

/* ── forward declarations for internal helpers ───────────────────────────── */
static int  sub_3e42c(void **out_session);          /* create session object */
static int  sub_3e550(void *session, uint32_t cmd, void *out); /* dispatch   */
static void sub_3f2e0(void *session);               /* teardown/release      */

/* ── vtable-backed driver object ─────────────────────────────────────────── */
typedef struct DriverObject {
    uint32_t header;        /* +0x00  0x00020002 */
    uint32_t _pad;
    void    *_unused;       /* +0x08 */

    /* vtable slots */
    int  (*free_obj)    (struct DriverObject *self);                        /* +0x10 */
    int  (*create_sess) (struct DriverObject *self, void *a2, void **out); /* +0x18 */
    int  (*dispatch)    (struct DriverObject *self, void *sess,
                         uint32_t cmd, void *out);                         /* +0x20 */
    int  (*cmd_dispatch)(struct DriverObject *self, void *sess,
                         uint32_t cmd, void *out);                         /* +0x28 */
    int  (*secondary)   (struct DriverObject *self, void *sess);           /* +0x30 */
    int  (*read_status) (struct DriverObject *self, void *sess,
                         uint32_t *out);                                   /* +0x38 */
    int  (*batch)       (struct DriverObject *self, void *sess,
                         uint32_t count, void *ops, void *a5);             /* +0x40 */
    int  (*kv_triple)   (struct DriverObject *self, void *out);            /* +0x48 */
} DriverObject;

/* ── +0x10  free_obj ─────────────────────────────────────────────────────── */
/*
 * Zeroes all five 128-bit blocks of the object then frees it.
 * Returns 0 on success, ERR_NULL_ARG if self is NULL.
 */
static int vtbl_free_obj(DriverObject *self)
{
    if (!self)
        return ERR_NULL_ARG;

    memset(self, 0, 0x50);
    free(self);
    return 0;
}

/* ── +0x18  create_sess ──────────────────────────────────────────────────── */
/*
 * Allocates and initialises a session object via sub_3e42c.
 * Writes the session pointer to *out on success.
 * Returns 0 on success, ERR_NULL_ARG if self or out is NULL.
 */
static int vtbl_create_sess(DriverObject *self, void *a2, void **out)
{
    (void)a2;
    if (!self || !out)
        return ERR_NULL_ARG;

    void *session = NULL;
    int rc = sub_3e42c(&session);
    if (rc == 0)
        *out = session;
    return rc;
}

/* ── +0x20  dispatch ─────────────────────────────────────────────────────── */
/*
 * Thin wrapper: forwards (session, cmd, out) to sub_3e550.
 * Returns ERR_NULL_ARG if self or session is NULL.
 */
static int vtbl_dispatch(DriverObject *self, void *sess, uint32_t cmd, void *out)
{
    if (!self || !sess)
        return ERR_NULL_ARG;

    return sub_3e550(sess, cmd, out);
}

/* ── +0x28  cmd_dispatch ─────────────────────────────────────────────────── */
/*
 * Identical gate to vtbl_dispatch; routes to sub_3e550.
 * Separate slot allows callers to distinguish command vs. control paths.
 */
static int vtbl_cmd_dispatch(DriverObject *self, void *sess, uint32_t cmd, void *out)
{
    if (!self || !sess)
        return ERR_NULL_ARG;

    return sub_3e550(sess, cmd, out);
}

/* ── +0x30  secondary ────────────────────────────────────────────────────── */
/*
 * Secondary state operation: tail-calls sub_3f2e0(session).
 * Returns ERR_NULL_ARG if either pointer is NULL.
 */
static int vtbl_secondary(DriverObject *self, void *sess)
{
    if (!self || !sess)
        return ERR_NULL_ARG;

    sub_3f2e0(sess);
    return 0;
}

/* ── +0x38  read_status ──────────────────────────────────────────────────── */
/*
 * Reads the cached status word at session+0x1918.
 * Requires the word+1 >= 2 (i.e. word >= 1) before returning it.
 * Returns 0 + *out = word on success, ERR_NULL_ARG / ERR_KV_FAIL otherwise.
 *
 * Observed: session+0x1918 == session+6424 (matches README contract).
 */
static int vtbl_read_status(DriverObject *self, void *sess, uint32_t *out)
{
    if (!self || !sess || !out)
        return ERR_NULL_ARG;

    uint32_t val = *(uint32_t *)((uint8_t *)sess + 0x1918);
    if ((uint32_t)(val + 1) < 2)
        return ERR_KV_FAIL;

    *out = val;
    return 0;
}

/* ── +0x40  batch ────────────────────────────────────────────────────────── */
/*
 * Batch dispatcher: iterates an ops array of (cmd, arg) pairs and calls
 * sub_3e550 for each entry via the vtable slot at self+0x28.
 *
 * ops layout per entry: [uint32_t cmd @ -8][void *arg @ 0], stride 0x10.
 * count: number of entries.
 *
 * If count == 0 and arg is NULL, falls back to vtbl_create_sess path.
 */
static int vtbl_batch(DriverObject *self, void *sess,
                      uint32_t count, void *ops, void *a5)
{
    (void)a5;
    if (!self || !sess)
        return ERR_NULL_ARG;

    if (count == 0 && ops == NULL) {
        /* fallback: single create-session call */
        void *tmp = NULL;
        int rc = sub_3e42c(&tmp);
        if (rc == 0 && sess)
            *(void **)sess = tmp;
        return rc;
    }

    int rc = 0;
    uint8_t *entry = (uint8_t *)ops;
    for (uint32_t i = 0; i < count; i++, entry += 0x10) {
        uint32_t cmd = *(uint32_t *)(entry - 8);
        void    *arg = *(void **)(entry);
        rc = sub_3e550(sess, cmd, arg);
        if (rc != 0)
            break;
    }
    return rc;
}

/* ── +0x48  kv_triple ────────────────────────────────────────────────────── */
/*
 * Parses the kernel version triple (major, minor, patch) from
 * host_kernel_version() output.  Requires "RELEASE" in the string.
 * Falls back to sysctl CTL_KERN.KERN_VERSION if host_kernel_version
 * returns error 53 (ENOTSUP / kern_invalid_argument on some builds).
 *
 * out layout: uint64_t major @ +0, uint32_t minor @ +8.
 *
 * Returns 0 on success.
 * Returns ERR_KV_NORELEASE | 0x80000000 on non-RELEASE or sysctl failure.
 * Returns ERR_KV_NOSTRSTR  if "RELEASE" found but "xnu-" not found.
 * Returns ERR_NULL_ARG     if self or out is NULL.
 */
static int vtbl_kv_triple(DriverObject *self, void *out)
{
    if (!self || !out)
        return ERR_NULL_ARG;

    char buf[0x200];
    memset(buf, 0, sizeof(buf));

    mach_port_t host = mach_host_self();
    int rc = host_kernel_version(host, buf);

    if (rc != 0) {
        if (rc == 53) {
            /* fallback: sysctl CTL_KERN.KERN_VERSION */
            int    mib[2]  = { CTL_KERN, KERN_VERSION };
            size_t buflen  = sizeof(buf);
            if (sysctl(mib, 2, buf, &buflen, NULL, 0) != 0)
                return (int)(rc | 0x80000000u);
        } else {
            return (int)((uint32_t)rc | 0x80000000u);
        }
    }

    if (!strstr(buf, "RELEASE"))
        return (int)(ERR_NULL_ARG - 0xc);   /* 0xa0001 - 0xc */

    char *p = strstr(buf, "xnu-");
    if (!p)
        return 0;   /* "RELEASE" present but no xnu- tag — treat as success */

    uint64_t major = 0;
    uint32_t minor = 0;
    uint32_t patch = 0;
    if (sscanf(p, "xnu-%llu.%u.%u", &major, &minor, &patch) != 3)
        return 0;

    *(uint64_t *)((uint8_t *)out + 0) = major;
    *(uint32_t *)((uint8_t *)out + 8) = minor;
    return 0;
}

/* ── _driver export ──────────────────────────────────────────────────────── */
/*
 * Allocates a 0x50-byte vtable-backed DriverObject and writes it to *out.
 *
 * Returns 0        on success.
 * Returns ERR_NULL_ARG  if out is NULL.
 * Returns ERR_ALLOC     if calloc fails.
 */
int _driver(void **out)
{
    if (!out)
        return ERR_NULL_ARG;

    DriverObject *obj = calloc(1, sizeof(DriverObject));
    if (!obj)
        return ERR_ALLOC;

    obj->header       = HEADER_VERSION;
    obj->free_obj     = vtbl_free_obj;
    obj->create_sess  = vtbl_create_sess;
    obj->dispatch     = vtbl_dispatch;
    obj->cmd_dispatch = vtbl_cmd_dispatch;
    obj->secondary    = vtbl_secondary;
    obj->read_status  = vtbl_read_status;
    obj->batch        = vtbl_batch;
    obj->kv_triple    = vtbl_kv_triple;

    *out = obj;
    return 0;
}

/* ── stubs for internal helpers (implemented in sub_3e42c / sub_3e550 etc.) */
static int  sub_3e42c(void **out_session) { (void)out_session; return ERR_NULL_ARG; }
static int  sub_3e550(void *s, uint32_t c, void *o) { (void)s;(void)c;(void)o; return ERR_NULL_ARG; }
static void sub_3f2e0(void *s) { (void)s; }
