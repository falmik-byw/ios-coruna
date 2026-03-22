/*
 * record_0x90001_state_init.c
 * entry1_type0x09.dylib — FUN_0003e42c (sub_3e42c)
 *
 * Allocates and initialises the 0x1D60-byte state object.
 * Calls sub_3cca8 (the main exploit init, same pattern as 0x90000),
 * then sub_13ebc to validate the result, and sub_3e4d0 for cleanup.
 *
 * Verified: calloc(0x1D60,1), sub_3cca8 call, sub_13ebc validation,
 *           error codes 0xad009 (alloc fail), 0x28021 (validate fail).
 * Inferred: "state init" label from call context.
 */

#include <stdint.h>
#include <stdlib.h>
#include <mach/mach.h>

#define ERR_ALLOC   0x000ad009u
#define ERR_VALIDATE 0x00028021u
#define STATE_SIZE  0x1D60

/* forward declarations */
extern uint64_t sub_3cca8(void *state, int mode);
extern int      sub_13ebc(void *state, long arg);
extern void     sub_3e4d0(long state);

/* ── sub_3e42c — allocate + init state object ───────────────────────────── */
uint64_t sub_3e42c(void **out_state, uint32_t param_2)
{
    void *state = calloc(STATE_SIZE, 1);
    if (!state) return ERR_ALLOC;

    /* mode: invert bit 0 of param_2 */
    uint64_t rc = sub_3cca8(state, (int)(~param_2 & 1));
    if ((int)rc == 0) {
        int ok = sub_13ebc(state, (long)state + 600);
        if (ok) {
            *out_state = state;
            sub_3e4d0((long)state);
            return 0;
        }
        sub_3e4d0((long)state);
        rc = ERR_VALIDATE;
    }
    free(state);
    return rc;
}

/* ── sub_3e4d0 — state cleanup / assertion checker ──────────────────────── */
/*
 * Checks that several cached pointer fields are zero.
 * If any non-zero field is found, calls sub_19854 (abort/panic).
 * Verified: field offsets 0x19f8, 0x1d18, 0x1d20, 0x1d28, 0x1d30, 0x1d38.
 */
void sub_3e4d0(long state)
{
    extern void sub_19854(void) __attribute__((noreturn));

    static const long offsets[] = {
        0x19f8, 0x1d18, 0x1d20, 0x1d28, 0x1d30, 0x1d38
    };
    for (int i = 0; i < 6; i++) {
        if (*(long *)(state + offsets[i]) != 0)
            sub_19854();
    }
}
