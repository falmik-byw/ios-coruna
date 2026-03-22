/*
 * record_0x90000_vm_utils.c
 * sub_20154..sub_22390 — vm/pipe/fd/task helpers, pmap walker, kobj scanner
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <IOKit/IOKitLib.h>
#include <sys/sysctl.h>
#include <mach/mach_time.h>

/* ── cross-file externs ──────────────────────────────────────────────────── */
extern int   sub_37238(long state, uint32_t flag);
extern long  sub_33638(long state, io_connect_t conn);
extern long  sub_336ec(long state);
extern void  sub_3579c(long state, long kobj);
extern int   sub_2a90c(long state, uint64_t addr, uint32_t *out);
extern int   sub_2a110(long state, uint64_t addr, uint64_t val);
extern int   sub_29ab4(long state, uint64_t addr, void *out);
extern int   sub_2b614(long state, uint64_t addr, void *buf, uint32_t sz);
extern long  sub_1ad70(long state, uint64_t addr);
extern long  sub_1ad30(void *fn);
extern void  sub_1b50c(void *ctx, ...);
extern void  sub_1b410(void *ctx, long state, const char *seg, const char *sect);
extern long  sub_1b31c(long state, uint64_t addr);
extern uint32_t sub_1b214(long state, uint64_t addr);
extern long  sub_1b624(void *ctx, long state);
extern long  sub_1b9a8(void *ctx, int a, uint64_t addr, int b);
extern long  sub_1f784(void *ctx, const char *pat, int a, int b);
extern long  sub_208e8(long state, uint64_t addr, int mode);
extern long  sub_20508(long state, uint64_t addr);
extern long  sub_2057c(long state, uint64_t addr);
extern long  sub_20410(long state);
extern uint32_t sub_20154(long state);
extern long  sub_33564(long state);
extern long  sub_40838(long state, long a, long b);
extern long  sub_40af0(long state, uint64_t addr, long a, long b);
extern long  sub_33130(long state, uint64_t addr);
extern long  sub_2b090(long state, uint64_t addr);
extern uint32_t sub_33f58(long state);
extern long  sub_39760(long state, long base, long ctx, uint64_t pte);
extern long  sub_39a3c(long state);
extern int   sub_2b860(long state, uint64_t addr, uint32_t sz, void *out, long ctx);
extern void  sub_3b194(void *ctx, long state);
extern void  sub_25f7c(long state, int mode);
extern int   sub_26004(long state, int a, int b);
extern void  sub_2c088(long state, int ms);
extern long  sub_417d4(uint64_t port, uint32_t *out);
extern long  sub_41890(void);
extern long  sub_418c8(void);
extern void  sub_3376c(long state, uint64_t addr);

/* forward declarations */
static void sub_229f0(long param_1, void **param_2);
static void sub_235cc(long param_1, long param_2);
static void sub_2295c(long param_1, void *param_2);
static void sub_233d8(long param_1, long *param_2);
static void sub_234ac(long param_1, uint32_t param_2, int param_3, long param_4);
static void sub_21c90(long param_1, long param_2, uint64_t param_3, uint32_t param_4, uint64_t *param_5);
static int sub_21f80(long param_1, long param_2, uint32_t param_3, uint64_t param_4);
static int sub_21b40(uint64_t param_1, long param_2, uint64_t param_3, int *param_4);
static int sub_21abc(uint64_t param_1, long param_2, uint64_t param_3, int *param_4);
static int sub_21c04(uint64_t param_1, uint64_t param_2, long param_3, uint64_t *param_4);
static void sub_217ac(long param_1, long *param_2, long param_3);
static int sub_218b0(uint64_t *param_1, int param_2, uint64_t param_3);

/* ── sub_20154 — xnu build version gate ─────────────────────────────────── */
uint32_t sub_20154(long param_1)
{
    int xnu = *(int *)(param_1 + 0x70);
    if (xnu < 0x2258) {
        if ((uint32_t)(xnu - 0x1f53) < 2) return 1;
        if (xnu == 0x1809) return 0;
        if (xnu == 0x1c1b) return 0;
    } else {
        if (xnu == 0x2258 || xnu == 0x225c) return 1;
        if (xnu == 0x2712) return 2;
    }
    return 0;
}

/* ── sub_202b4 — align-down + call sub_208e8 ────────────────────────────── */
void sub_202b4(long param_1, uint64_t param_2)
{
    sub_208e8(param_1, param_2 & ~3ULL, 1);
}

/* ── sub_20508 — read insn at addr ──────────────────────────────────────── */
long sub_20508(long param_1, uint64_t param_2)
{
    return (long)sub_1b214(param_1, param_2);
}

/* ── sub_2057c — follow branch/call ─────────────────────────────────────── */
long sub_2057c(long param_1, uint64_t param_2)
{
    return sub_208e8(param_1, param_2, 1);
}

/* ── sub_208e8 — arm64 branch target resolver ───────────────────────────── */
long sub_208e8(long param_1, uint64_t param_2, int param_3)
{
    if (param_2 & 3) return 0;
    uint32_t insn = sub_1b214(param_1, param_2);
    if (insn == 0xd503201f) {
        return (long)sub_1b214(param_1, param_2 + 4);
    }
    if ((insn & 0x9f000000) == 0x90000000 ||
        ((insn & 0x9f000000) == 0x10000000 &&
         (int)sub_1b214(param_1, param_2 + 4) == (int)0xd503201f)) {
        uint32_t rd = insn & 0x1f;
        uint64_t limit = param_2 + 0x20;
        int found_add = 0;
        uint64_t cur = param_2;
        while (1) {
            cur += 4;
            uint32_t i2 = sub_1b214(param_1, cur);
            if ((i2 & 0x7f000000) == 0x11000000 && !found_add) {
                if ((i2 >> 5 & 0x1f) == rd) {
                    if (param_3 == 0) return 0;
                    if (rd != (i2 & 0x1f)) return 0;
                    found_add = 1;
                } else {
                    found_add = 0;
                }
            }
            if ((i2 & 0xbfc00000) == 0xb9400000 && (i2 >> 5 & 0x1f) == rd) return 0;
            if (((i2 & 0xffc00000) == 0xb9800000 || (i2 & 0xffc00000) == 0x39400000) &&
                (i2 >> 5 & 0x1f) == rd) return 0;
            if (i2 == 0xd65f03c0) return 0;
            if (limit < cur) return 0;
        }
    }
    return 0;
}

/* ── sub_20b2c — kernel version string ──────────────────────────────────── */
void sub_20b2c(char *param_1, uint64_t param_2)
{
    char buf[512];
    int rc;
    extern double dyldVersionNumber;
    if (800.0 <= dyldVersionNumber) {
        int mib[2] = {CTL_KERN, KERN_VERSION};
        size_t sz = sizeof(buf);
        rc = sysctl(mib, 2, buf, &sz, NULL, 0);
        if (rc != 0) return;
    } else {
        mach_port_t host = mach_host_self();
        kern_return_t kr = host_kernel_version(host, buf);
        if (kr != 0) return;
    }
    size_t len = strlen(buf);
    if (param_2 < len + 1) return;
    strlcpy(param_1, buf, param_2);
}

/* ── sub_20e98 — mach_vm_page_info wrapper ───────────────────────────────── */
void sub_20e98(vm_map_t param_1, mach_vm_address_t param_2, uint64_t *param_3)
{
    /* mach_vm_page_info not available in SDK; stub */
    (void)param_1; (void)param_2; (void)param_3;
}

/* ── sub_20f14 / sub_20f50 — thin wrappers ───────────────────────────────── */
void sub_20f14(void) { sub_41890(); }
void sub_20f50(void) { sub_418c8(); }

/* ── sub_20f90 — host_page_size ──────────────────────────────────────────── */
void sub_20f90(void)
{
    vm_size_t sz = 0;
    host_page_size(mach_host_self(), &sz);
}

/* ── sub_21040 — task_info TASK_THREAD_TIMES_INFO ───────────────────────── */
void sub_21040(task_name_t param_1, uint64_t *param_2, uint64_t *param_3)
{
    mach_msg_type_number_t cnt = 0x2a;
    integer_t info[0x2a];
    kern_return_t kr = task_info(param_1, 0x16, info, &cnt);
    if (kr == 0 && cnt == 0x2a) {
        *param_2 = *(uint64_t *)(info + 0x40/4);
        *param_3 = *(uint64_t *)(info + 0x48/4);
    }
}

/* ── sub_210d8 — read field from sub_418c8 result ───────────────────────── */
void sub_210d8(uint32_t *param_1)
{
    long r = sub_418c8();
    if (r) *param_1 = *(uint32_t *)(r + 0x80);
}

/* ── sub_2112c — alloc small buffer object ───────────────────────────────── */
void sub_2112c(uint32_t param_1, void **param_2)
{
    if (param_1 <= 3) return;
    uint64_t *obj = calloc(0x10, 1);
    if (!obj) return;
    uint32_t *data = calloc(param_1, 1);
    obj[0] = (uint64_t)(uintptr_t)data;
    if (!data) { free(obj); return; }
    data[0] = 0xd3;
    ((uint32_t *)obj)[2] = 4;
    ((uint32_t *)obj)[3] = param_1;
    *param_2 = obj;
}

/* ── sub_211e0 — append encoded field to buffer ─────────────────────────── */
void sub_211e0(long *param_1, uint32_t param_2, uint32_t param_3, uint64_t *param_4)
{
    if (param_3 & 0xff000000) return;
    uint32_t fam = (param_2 & 0x7f000000) - 0x1000000;
    if (fam >> 24 >= 0xc) return;
    uint32_t bit = 1u << (fam >> 24 & 0x1f);
    uint32_t stride;
    if (bit & 0xc07)       stride = 4;
    else if (bit & 0x380)  stride = (param_3 + 7) & ~3u;
    else if ((fam >> 24) == 3) stride = 0xc;
    else return;

    uint32_t used = (uint32_t)param_1[1];
    uint32_t cap  = *(uint32_t *)((char *)param_1 + 0xc);
    if (stride > cap - used) return;

    long base = *param_1;
    *(uint32_t *)(base + used) = param_3 | param_2;
    param_1[1] = (long)(used + 4);

    uint32_t tail_fam = (param_2 & 0x7f000000) + 0xfc000000;
    uint32_t tail_idx = tail_fam >> 24;
    if (tail_idx - 4 < 3) {
        uint32_t copy_sz = (param_3 + 3) & ~3u;
        memcpy((void *)(base + used + 4), param_4, param_3);
        param_1[1] = (long)(used + 4 + copy_sz);
    } else if (tail_idx == 0) {
        *(uint64_t *)(base + used + 4) = *param_4;
        param_1[1] = (long)(used + 4 + 8);
    }
}

/* ── sub_21310 — export buffer contents ─────────────────────────────────── */
void sub_21310(long *param_1, void **param_2, uint32_t *param_3)
{
    if (!param_1 || !*param_1 || !(uint32_t)param_1[1] ||
        !*(uint32_t *)((char *)param_1 + 0xc)) return;
    uint32_t sz = (uint32_t)param_1[1];
    void *p = malloc(sz);
    *param_2 = p;
    if (!p) return;
    memcpy(p, (void *)*param_1, sz);
    *param_3 = sz;
}

/* ── sub_213bc — free buffer object ─────────────────────────────────────── */
void sub_213bc(void **param_1)
{
    if (*param_1) free(*param_1);
    param_1[0] = NULL;
    param_1[1] = NULL;
    free(param_1);
}

/* ── sub_21418 — pipe() wrapper ─────────────────────────────────────────── */
void sub_21418(int *param_1)
{
    pipe(param_1);
}

/* ── sub_214a8 — drain fd ────────────────────────────────────────────────── */
void sub_214a8(int *param_1)
{
    char buf[256];
    ssize_t n;
    do { n = read(*param_1, buf, sizeof(buf)); } while (n > 0);
}

/* ── sub_21568 — close fd pair ───────────────────────────────────────────── */
void sub_21568(int *param_1)
{
    close(param_1[0]);
    close(param_1[1]);
}

/* ── sub_215bc — fcntl probe ─────────────────────────────────────────────── */
void sub_215bc(int param_1)
{
    if (param_1 == -1) return;
    if (fcntl(param_1, 0x49) == -1 || fcntl(param_1, F_GETFD) == -1 ||
        fcntl(param_1, F_SETFD) == -1 || fcntl(param_1, F_GETFL) == -1 ||
        fcntl(param_1, F_SETFL) == -1) {}
}

/* ── sub_216b4 — write to fd+4 ───────────────────────────────────────────── */
void sub_216b4(long param_1, void *param_2, size_t param_3)
{
    write(*(int *)(param_1 + 4), param_2, param_3);
}

/* ── sub_21730 — read from fd ────────────────────────────────────────────── */
void sub_21730(int *param_1, void *param_2, size_t param_3)
{
    read(*param_1, param_2, param_3);
}

/* ── sub_217ac — memcpy helper with pointer-size stride ─────────────────── */
static void sub_217ac(long param_1, long *param_2, long param_3)
{
    int psz = *(int *)(param_1 + 0x168);
    void *dst;
    void *src;
    if (!param_2[4]) {
        long off = param_3 ? param_3 - (long)(uint32_t)((long *)param_2)[9] : 0;
        dst = (void *)(*param_2 + (uint32_t)((long *)param_2)[9] + 0x200);
        src = &off;
    } else {
        long base = param_2[4] ? param_2[4] : *param_2;
        long *bp  = param_2[4] ? param_2 + 5 : param_2 + 1;
        uint64_t idx = (uint64_t)(uint32_t)((int)param_2[9] + psz * 2);
        long off2 = param_3 ? (long)(idx - (uint64_t)psz) + *bp : 0;
        memcpy((void *)(base + (uint32_t)((int)param_2[9] + psz * 3)), &off2, (size_t)psz);
        dst = (void *)(base + idx);
        src = &param_3;
    }
    memcpy(dst, src, (size_t)psz);
}

/* ── sub_218b0 — pipe round-trip (write+read) ───────────────────────────── */
static int sub_218b0(uint64_t *param_1, int param_2, uint64_t param_3)
{
    int retry;
    ssize_t n;
    if ((param_3 & 1) || (param_2 != 0 && !param_1[4])) {
        retry = 0;
        while ((n = write((int)param_1[3], (void *)param_1[0],
                          (size_t)(uint32_t)param_1[2])) == -1) {
            if (errno != EINTR || retry++ > 99) return 0;
        }
        if ((uint64_t)n >> 32 || (int)param_1[2] != (int)n) return 0;
        retry = 0;
        while ((n = read(*(int *)((char *)param_1 + 0x14), (void *)param_1[0],
                         (size_t)(uint32_t)param_1[2])) == -1) {
            if (errno != EINTR || retry++ > 99) return 0;
        }
        if ((uint64_t)n >> 32 || (int)param_1[2] != (int)n) return 0;
    }
    if (param_1[4] && param_2) {
        retry = 0;
        while ((n = write((int)param_1[7], (void *)param_1[4],
                          (size_t)(uint32_t)param_1[6])) == -1) {
            if (errno != EINTR || retry++ > 99) return 0;
        }
        if ((uint64_t)n >> 32 || (int)param_1[6] != (int)n) return 0;
        retry = 0;
        while ((n = read(*(int *)((char *)param_1 + 0x34), (void *)param_1[4],
                         (size_t)(uint32_t)param_1[6])) == -1) {
            if (errno != EINTR || retry++ > 99) return 0;
        }
    }
    return 0;
}

/* ── sub_21abc — pipe round-trip + pid_for_task ─────────────────────────── */
static int sub_21abc(uint64_t param_1, long param_2, uint64_t param_3, int *param_4)
{
    sub_217ac(param_1, (long *)param_2, (long)param_3);
    if (sub_218b0((uint64_t *)param_2, 0, 1) == 0) {
        int pid = 0;
        if (pid_for_task(*(mach_port_name_t *)((char *)param_2 + 0x3c), &pid) == 0)
            *param_4 = pid;
    }
    return 0;
}

/* ── sub_21b40 — pipe round-trip + mach_port_get_attributes ─────────────── */
static int sub_21b40(uint64_t param_1, long param_2, uint64_t param_3, int *param_4)
{
    if (param_3 & 1) {
        sub_21abc(param_1, param_2, param_3, param_4);
    } else {
        sub_217ac(param_1, (long *)param_2, (long)param_3);
        if (sub_218b0((uint64_t *)param_2, 1, 0) == 0) {
            integer_t info[2] = {0, 1};
            mach_msg_type_number_t cnt = 1;
            if (mach_port_get_attributes(mach_task_self(),
                    *(mach_port_name_t *)((char *)param_2 + 0x3c),
                    3, info, &cnt) == 0)
                *param_4 = info[0];
        }
    }
    return 0;
}

/* ── sub_21c04 — two-field read via sub_21b40 ───────────────────────────── */
static int sub_21c04(uint64_t param_1, uint64_t param_2, long param_3, uint64_t *param_4)
{
    int lo = 0, hi = 0;
    if (sub_21b40(param_1, param_2, (uint64_t)param_3, &lo) == 0 &&
        sub_21b40(param_1, param_2, (uint64_t)(param_3 + 4), &hi) == 0)
        *param_4 = ((uint64_t)(uint32_t)hi << 32) | (uint32_t)lo;
    return 0;
}

/* ── sub_21c90 — kobj type scanner ──────────────────────────────────────── */
static void sub_21c90(long param_1, long param_2, uint64_t param_3,
                       uint32_t param_4, uint64_t *param_5)
{
    long stride = sub_33564(param_1);
    if (!stride || !param_3) return;
    long base  = sub_40838(param_1, stride, stride);
    long limit = sub_40af0(param_1, param_3, stride, base);
    if (!limit) return;

    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    uint32_t type;
    /* scan backward */
    for (uint64_t a = param_3; limit <= a; a -= (uint32_t)stride) {
        int ok;
        if (!param_2) ok = sub_2a90c(param_1, a, &type);
        else { ok = !sub_21b40(param_1, param_2, a, (int *)&type); }
        if (!ok) return;
        uint32_t t = type & 0x3ff;
        if (kaddr < 0x1c1b1914600000ULL) {
            if (t == param_4) { *param_5 = a; return; }
        } else if (param_4 == 2 && t == 2) {
            if (!sub_21f80(param_1, param_2, type, a)) { *param_5 = a; return; }
        } else if (t == param_4) { *param_5 = a; return; }
    }
    /* scan forward */
    for (uint64_t a = param_3 + (uint32_t)stride;
         a <= (uint64_t)((uint32_t)base - (uint32_t)stride + limit); a += (uint32_t)stride) {
        int ok;
        if (!param_2) ok = sub_2a90c(param_1, a, &type);
        else { ok = !sub_21b40(param_1, param_2, a, (int *)&type); }
        if (!ok) return;
        uint32_t t = type & 0x3ff;
        if (kaddr < 0x1c1b1914600000ULL) {
            if (t == param_4) { *param_5 = a; return; }
        } else if (param_4 == 2 && t == 2) {
            if (!sub_21f80(param_1, param_2, type, a)) { *param_5 = a; return; }
        } else if (t == param_4) { *param_5 = a; return; }
    }
}

/* ── sub_21f80 — kobj type-2 validation ─────────────────────────────────── */
static int sub_21f80(long param_1, long param_2, uint32_t param_3, uint64_t param_4)
{
    if ((param_3 & 0x7ff) != 2) return 0;
    long ref = sub_33130(param_1, param_4);
    if (!ref) return 0;
    uint64_t ptr = 0;
    if (!param_2) {
        if (!sub_29ab4(param_1, (uint64_t)ref, &ptr)) return 0;
    } else {
        if (sub_21c04(param_1, (uint64_t)param_2, ref, &ptr)) return 0;
        ptr = (uint64_t)sub_2b090(param_1, ptr);
    }
    if (!sub_1ad70(param_1, ptr)) return 0;
    uint32_t off = sub_33f58(param_1);
    if (!off) return 0;
    uint64_t ptr2 = 0;
    if (!param_2) {
        if (!sub_29ab4(param_1, ptr + off, &ptr2)) return 0;
        if (!sub_29ab4(param_1, ptr2 + 0x20, &ptr2)) return 0;
    } else {
        if (sub_21c04(param_1, (uint64_t)param_2, ptr + off, &ptr2)) return 0;
        ptr2 = (uint64_t)sub_2b090(param_1, ptr2);
        if (sub_21c04(param_1, (uint64_t)param_2, ptr2 + 0x20, &ptr2)) return 0;
    }
    sub_1ad70(param_1, ptr2);
    return 0;
}

/* ── sub_22134 — thin wrapper ────────────────────────────────────────────── */
void sub_22134(long param_1, long param_2, uint64_t param_3,
               uint32_t param_4, uint64_t *param_5)
{
    sub_21c90(param_1, param_2, param_3, param_4, param_5);
}

/* ── sub_22174 — port ref-count bump ────────────────────────────────────── */
void sub_22174(long param_1, uint64_t param_2)
{
    int xnu = *(int *)(param_1 + 0x140);
    if (xnu < 0x1f53) {
        if (xnu != 0x1809 && xnu != 0x1c1b) return;
    } else if ((uint32_t)(xnu - 0x1f53) > 1 && xnu != 0x2258) return;

    uint32_t name = 0;
    if (sub_417d4(param_2, &name)) return;
    long kobj = sub_33638(param_1, (io_connect_t)name);
    if (!kobj) return;
    uint32_t refs = 0;
    if (sub_2a90c(param_1, (uint64_t)kobj + 0x14, &refs) && refs - 1 < 10)
        sub_2a110(param_1, (uint64_t)kobj + 0x14, 0xffff);
}

/* ── sub_22298 — timestamp cache invalidation ───────────────────────────── */
void sub_22298(long param_1)
{
    long ts = *(long *)(param_1 + 0x868);
    uint64_t now = mach_absolute_time();
    if (ts) {
        uint64_t elapsed = 0;
        uint32_t denom = *(uint32_t *)(param_1 + 0x260);
        if (denom)
            elapsed = ((now - (uint64_t)ts) * *(uint32_t *)(param_1 + 0x25c)) / denom;
        if (elapsed < 0x12a153440ULL) return;
        /* clear 16 cache slots */
        for (long i = 0; i < 0x280; i += 0x28) {
            uint64_t *slot = (uint64_t *)(param_1 + 0x5e8 + i);
            slot[0] = slot[1] = slot[2] = slot[3] = slot[4] = 0;
        }
        now = mach_absolute_time();
    }
    *(uint64_t *)(param_1 + 0x868) = now;
}

/* ── sub_2233c — resolve kobj via sub_336ec ─────────────────────────────── */
void sub_2233c(long param_1)
{
    long kobj = sub_336ec(param_1);
    if (kobj) sub_3579c(param_1, kobj);
}

/* ── sub_22390 — pmap page-table walker ─────────────────────────────────── */
void sub_22390(long param_1, uint64_t param_2, long *param_3, uint64_t param_4)
{
    if (!param_3) return;
    param_3[0] = param_3[1] = param_3[2] = param_3[3] = param_3[4] = 0;

    /* check cached slots */
    for (long i = 0; i < 0x280; i += 0x28) {
        long base = *(long *)(param_1 + 0x5e8 + i);
        if (!base) break;
        uint64_t va  = *(uint64_t *)(param_1 + 0x5f0 + i);
        uint64_t sz  = *(uint64_t *)(param_1 + 0x5f8 + i);
        if (va <= param_2 && param_2 < va + sz) {
            if (sub_2b860(param_1, (uint64_t)base, 8,
                          (void *)(param_1 + 0x608 + i), param_4)) {
                param_3[0] = *(long *)(param_1 + 0x5e8 + i);
                param_3[1] = *(long *)(param_1 + 0x5f0 + i);
                param_3[2] = *(long *)(param_1 + 0x5f8 + i);
                param_3[3] = *(long *)(param_1 + 0x600 + i);
                param_3[4] = *(long *)(param_1 + 0x608 + i);
                return;
            }
            break;
        }
    }

    /* populate pmap root if needed */
    if (!*(long *)(param_1 + 0x5d0)) {
        long kobj = 0;
        sub_2233c(param_1);
        if (!kobj) return;
        uint64_t lo = 0, hi = 0;
        if (!sub_29ab4(param_1, (uint64_t)kobj, &lo)) return;
        if (!sub_29ab4(param_1, (uint64_t)kobj + *(int *)(param_1 + 0x168), &hi)) return;
        uint32_t stride = (*(int *)(param_1 + 0x180) != 0x1000) ? 0x800 : 0x200;
        *(uint64_t *)(param_1 + 0x5d0) = lo;
        *(uint64_t *)(param_1 + 0x5d8) = hi;
        *(uint32_t *)(param_1 + 0x5e0) = stride;
        sub_39a3c(param_1);
    }

    int page4k = (*(int *)(param_1 + 0x180) == 0x1000);
    long root  = *(long *)(param_1 + 0x5d0);
    uint64_t ctx2 = *(uint64_t *)(param_1 + 0x5d8);

    if (page4k || sub_37238(param_1, 0x8000)) {
        /* 4-level walk */
        long ttbr = sub_39760(param_1, root, (long)ctx2, ctx2);
        uint64_t l1_idx = (param_2 >> 0x1b) & 0x7f8;
        uint64_t pte = 0;
        if (!sub_2b860(param_1, (uint64_t)(root + l1_idx), 8, &pte, param_4)) return;
        if (!(pte & 3)) return;
        if ((pte & 3) == 1) {
            /* 1GB block */
            param_3[0] = ttbr + l1_idx;
            param_3[1] = param_2 & ~0x3fffffffULL;
            *(uint32_t *)(param_3 + 2) = 0x40000000;
            *(uint8_t *)((char *)param_3 + 0x14) = 1;
            param_3[4] = (long)pte;
        } else {
            if ((pte >> 0x3b) & 1)
                *(uint32_t *)((char *)param_3 + 0x14) |= 0x100;
            long l2 = sub_39760(param_1, root, (long)ctx2, pte & 0xfffffffff000ULL);
            l2 += (param_2 >> 0x12) & 0xff8;
            if (!sub_2b860(param_1, (uint64_t)l2, 8, &pte, param_4)) return;
            if (!(pte & 3)) return;
            if ((pte & 3) == 1) {
                param_3[0] = l2;
                param_3[1] = param_2 & ~0x1fffffULL;
                *(uint32_t *)(param_3 + 2) = 0x200000;
                *(uint8_t *)((char *)param_3 + 0x14) = 1;
                param_3[4] = (long)pte;
            } else {
                if ((pte >> 0x3b) & 1)
                    *(uint32_t *)((char *)param_3 + 0x14) |= 0x100;
                long l3 = sub_39760(param_1, root, (long)ctx2, pte & 0xfffffffff000ULL);
                l3 += (param_2 >> 9) & 0xff8;
                if (!sub_2b860(param_1, (uint64_t)l3, 8, &pte, param_4)) return;
                if (!(pte & 3)) return;
                param_3[0] = l3;
                param_3[1] = param_2 & ~0xfffULL;
                *(uint32_t *)(param_3 + 2) = 0x1000;
                *(uint8_t *)((char *)param_3 + 0x14) = 3;
                param_3[4] = (long)pte;
            }
        }
    } else if (*(int *)(param_1 + 0x180) == 0x4000) {
        /* 16k page walk */
        int has_ext = sub_37238(param_1, 0x5000008);
        uint64_t mask = has_ext ? 0x7ffULL : 7ULL;
        long l1 = root + (mask & (param_2 >> 0x24)) * 8;
        uint64_t pte = 0;
        if (!sub_2b860(param_1, (uint64_t)l1, 8, &pte, param_4)) return;
        if ((~(uint32_t)pte & 3) == 0) {
            if ((pte >> 0x3b) & 1)
                *(uint32_t *)((char *)param_3 + 0x14) |= 0x100;
            long l2 = sub_39760(param_1, root, (long)ctx2, pte & 0xffffffffc000ULL);
            l2 += (param_2 >> 0x16) & 0x3ff8;
            if (!sub_2b860(param_1, (uint64_t)l2, 8, &pte, param_4)) return;
            if (pte & 3) {
                if ((pte & 3) == 1) {
                    param_3[0] = l2;
                    param_3[1] = param_2 & ~0x1ffffffULL;
                    *(uint32_t *)(param_3 + 2) = 0x2000000;
                    *(uint8_t *)((char *)param_3 + 0x14) = 1;
                    param_3[4] = (long)pte;
                } else {
                    if ((pte >> 0x3b) & 1)
                        *(uint32_t *)((char *)param_3 + 0x14) |= 0x100;
                    long l3 = sub_39760(param_1, root, (long)ctx2, pte & 0xffffffffc000ULL);
                    l3 += (param_2 >> 0xb) & 0x3ff8;
                    if (!sub_2b860(param_1, (uint64_t)l3, 8, &pte, param_4)) return;
                    if ((~(uint32_t)pte & 3) == 0) {
                        param_3[0] = l3;
                        param_3[1] = param_2 & ~0x3fffULL;
                        *(uint32_t *)(param_3 + 2) = 0x4000;
                        *(uint8_t *)((char *)param_3 + 0x14) = 3;
                        param_3[4] = (long)pte;
                    }
                }
            }
        }
    }

    /* cache result */
    if (param_3[0]) {
        for (long i = 0; i < 0x280; i += 0x28) {
            if (!*(long *)(param_1 + 0x5e8 + i)) {
                *(long *)(param_1 + 0x5e8 + i) = param_3[0];
                *(long *)(param_1 + 0x5f0 + i) = param_3[1];
                *(long *)(param_1 + 0x5f8 + i) = param_3[2];
                *(long *)(param_1 + 0x600 + i) = param_3[3];
                *(long *)(param_1 + 0x608 + i) = param_3[4];
                return;
            }
        }
    }
}

/* ── sub_22818 — thin wrapper ────────────────────────────────────────────── */
void sub_22818(long param_1, uint64_t param_2, long *param_3, uint64_t param_4)
{
    sub_22390(param_1, param_2, param_3, param_4);
}

/* ── sub_22854 / sub_228d8 — convenience wrappers ───────────────────────── */
void sub_22854(long param_1, uint64_t param_2)
{
    long result[5] = {0};
    sub_22390(param_1, param_2, result, 1);
}

void sub_228d8(long param_1, uint64_t param_2, uint64_t param_3)
{
    long result[5] = {0};
    sub_22390(param_1, param_2, result, param_3);
}

/* ── sub_2295c — free pmap result ────────────────────────────────────────── */
static void sub_2295c(long param_1, void *param_2)
{
    (void)param_1;
    if (!param_2) return;
    uint64_t *p = param_2;
    if (p[3]) free((void *)p[3]);
    p[0] = p[1] = p[2] = p[3] = 0;
    free(p);
}
