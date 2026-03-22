/* record_0x90000_entitlement.c
 * sub_2d110..sub_2e040 — version-gated struct offset resolvers,
 * SHA hash helper, plist/CF helpers, entitlement context ops.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>

/* ── forward decls of helpers used here ─────────────────────────── */
extern int  sub_37238(long state, uint32_t mask);
extern int  sub_29ab4(long state, long addr, long *out);
extern int  sub_2667c(long state, long addr, uint32_t sz, void *out);
extern int  sub_2b614(long state, long addr, void *buf, uint32_t sz);
extern int  sub_150e8(long a, long b);
extern void sub_14e20(long a, long b);
extern long sub_34c1c(long state);
extern long sub_35858(long state, long a2);
extern long sub_35be4(long state, long a2);
extern int  sub_3376c(void);
extern long sub_3330c(long state, long a2);
extern long sub_331d8(long state, long a2);
extern long sub_33eb0(long state, long a2);
extern void sub_29b38(long state, long a2);
extern void sub_3b784(long state, void *fn, void *ctx);
extern void sub_24a60(long state, void *fn, void *ctx);
extern void sub_301ac(void *ctx);
extern void sub_3014c(void *p);
extern void sub_32e78(long h);
extern long sub_30060(long state, int idx, uint32_t magic);
extern long sub_300d8(long a);
extern void sub_3014c_v(long h);
extern void sub_3014c_u(void *p);
extern long sub_2de48(long state, uint32_t idx, uint32_t magic);
extern long sub_2de48_2(void *ctx, uint32_t idx, uint32_t magic);
extern int  sub_32f00(long sock, long a2, void *buf);
extern void sub_4199c(long rt, long a2, void *out);
extern int  sub_2d770(long a, long b, void *out);
/* forward decls for helpers defined later in this file */
static void *sub_2d518_impl(long bytes, long len);
static void *sub_2d69c_impl(long plist, size_t *out_len);

/* ── sub_2d110 — version-gated struct offset resolver (pair A) ──── */
void sub_2d110(long state, uint32_t *off_a, uint32_t *off_b)
{
    int build = *(int *)(state + 0x140);
    uint32_t a, b;

    if (build < 0x1f54) {
        if (build == 0x1809)      { a = 0x238; b = 0x240; }
        else if (build == 0x1c1b) { a = 0x220; b = 0x228; }
        else if (build == 0x1f53) {
            a = *(uint64_t *)(state + 0x158) < 0x1f530f02800000ULL ? 0x2a8 : 0x358;
            b = *(uint64_t *)(state + 0x158) < 0x1f530f02800000ULL ? 0x2b0 : 0x360;
        } else return;
    } else if (build < 0x225c) {
        if (build != 0x1f54 && build != 0x2258) return;
        a = 0x350; b = 0x358;
    } else {
        if (build != 0x225c && build != 0x2712) return;
        a = 0x548; b = 0x550;
    }
    *off_a = a; *off_b = b;
}

/* ── sub_2d210 — version-gated struct offset resolver (pair B) ──── */
void sub_2d210(long state, uint32_t *off_a, uint32_t *off_b)
{
    int build = *(int *)(state + 0x140);
    int ref   = (build < 0x2258) ? 0x1c1b : 0x225c;
    int match = (build < 0x2258)
        ? (build - 0x1f53U < 2 || build == 0x1809)
        : (build == 0x2258 || build == 0x2712);

    if (match || build == ref) {
        if (off_a) *off_a = 0x78;
        if (off_b) *off_b = 0x50;
    }
}

/* ── sub_2d2a4 — SHA hash dispatcher ────────────────────────────── */
void sub_2d2a4(int algo, void *data, uint32_t len, void *out, uint32_t *out_len)
{
    uint32_t digest_len;
    union {
        CC_SHA512_CTX sha512;
        CC_SHA256_CTX sha256;
        CC_SHA1_CTX   sha1;
    } ctx;
    uint8_t buf[64];

    switch (algo) {
    case 1: digest_len = CC_SHA1_DIGEST_LENGTH;   break;
    case 2: digest_len = CC_SHA256_DIGEST_LENGTH;  break;
    case 3: digest_len = CC_SHA256_DIGEST_LENGTH;  break; /* SHA-224 */
    case 4: digest_len = CC_SHA384_DIGEST_LENGTH;  break;
    default: return;
    }
    if (*out_len < digest_len) return;

    if (algo == 2 || algo == 3) {
        CC_SHA256_Init(&ctx.sha256);
        CC_SHA256_Update(&ctx.sha256, data, len);
        CC_SHA256_Final(buf, &ctx.sha256);
    } else if (algo == 4) {
        CC_SHA384_Init(&ctx.sha512);
        CC_SHA384_Update(&ctx.sha512, data, len);
        CC_SHA384_Final(buf, &ctx.sha512);
    } else {
        CC_SHA1_Init(&ctx.sha1);
        CC_SHA1_Update(&ctx.sha1, data, len);
        CC_SHA1_Final(buf, &ctx.sha1);
    }
    memcpy(out, buf, digest_len);
    *out_len = digest_len;
}

/* ── sub_2d42c — plist open/compare/serialize helper ────────────── */
void sub_2d42c(long a1, long a2, long a3, long a4,
               long *out_ref, long *out_data, long a7)
{
    long r1, r2, r3;
    long sz = 0;
    size_t sz2 = 0;

    r1 = (long)sub_2d518_impl(a1, a2);  /* forward — defined below */
    if (!r1) return;
    r2 = (long)sub_2d518_impl(a3, a4);
    if (!r2) { CFRelease((CFTypeRef)r1); return; }

    int eq = sub_150e8(r1, r2);
    if (eq == 0) {
        r3 = (long)sub_2d69c_impl(r1, &sz2);
        if (r3) { *out_data = r3; *out_ref = (long)sz2; }
    }
    CFRelease((CFTypeRef)r2);
    CFRelease((CFTypeRef)r1);
    (void)a7;
}

/* ── sub_2d518 — CFReadStream → CFDictionary ─────────────────────── */
static void *sub_2d518_impl(long bytes, long len)
{
    CFAllocatorRef alloc = kCFAllocatorDefault;
    CFReadStreamRef s = CFReadStreamCreateWithBytesNoCopy(
        alloc, (const UInt8 *)bytes, (CFIndex)len, kCFAllocatorNull);
    if (!s) return NULL;
    if (!CFReadStreamOpen(s)) { CFRelease(s); return NULL; }
    CFErrorRef err = NULL;
    CFTypeRef pl = CFPropertyListCreateWithStream(alloc, s, 0, kCFPropertyListImmutable, NULL, &err);
    CFReadStreamClose(s);
    CFRelease(s);
    if (!pl) { if (err) CFRelease(err); return NULL; }
    if (CFGetTypeID(pl) != CFDictionaryGetTypeID()) { CFRelease(pl); return NULL; }
    return (void *)pl;
}

void sub_2d518(long bytes, long len) { sub_2d518_impl(bytes, len); }

/* ── sub_2d614 — compare two CF objects, set flag ───────────────── */
void sub_2d614(long a, long b, uint8_t *flag)
{
    if (flag) {
        int r = sub_150e8(a, b);
        *flag = (r == 0) ? 1 : 0;
    }
    sub_14e20(a, b);
}

/* ── sub_2d69c — CFPropertyListCreateData → malloc copy ─────────── */
static void *sub_2d69c_impl(long plist, size_t *out_len)
{
    CFErrorRef err = NULL;
    CFDataRef d = CFPropertyListCreateData(kCFAllocatorDefault,
        (CFPropertyListRef)plist, kCFPropertyListXMLFormat_v1_0, 0, &err);
    if (!d) { if (err) CFRelease(err); return NULL; }
    CFIndex sz = CFDataGetLength(d);
    void *buf = NULL;
    if (sz > 0) {
        buf = malloc((size_t)sz);
        if (buf) { memcpy(buf, CFDataGetBytePtr(d), (size_t)sz); *out_len = (size_t)sz; }
    }
    CFRelease(d);
    return buf;
}

void sub_2d69c(long plist, size_t *out_len) { sub_2d69c_impl(plist, out_len); }

/* ── sub_2dee8 — replace LC_CODE_SIGNATURE blob in Mach-O ────────── */
void sub_2dee8(long a1, long a2, long a3)
{
    long lc = sub_30060(a1, (int)a2, 0xfade0c02);
    if (!lc) return;
    long blob = sub_300d8(a3);
    if (!blob) return;
    long old = *(long *)(lc + 8);
    *(long *)(lc + 8) = blob;
    sub_3014c((void *)old);
}

/* ── sub_2df5c — thread-state kwrite dispatcher ─────────────────── */
void sub_2df5c(long state, long a2)
{
    struct { long s; long a; } ctx = { state, a2 };

    if (*(uint64_t *)(state + 0x158) < 0x1c1b1914600000ULL ||
        sub_37238(state, 4)) {
        sub_301ac(&ctx);
    } else {
        int r = sub_37238(state, 0x5584001);
        if (!r || *(uint64_t *)(state + 0x158) > 0x1c1b1e025fffffULL) {
            sub_3b784(state, (void *)sub_301ac, &ctx);
        } else {
            sub_24a60(state, (void *)sub_301ac, &ctx);
        }
    }
}

/* ── sub_2e040 — release CF/handle by type ───────────────────────── */
void sub_2e040(long ctx)
{
    int type = *(int *)(ctx + 0x30);
    long h   = *(long *)(ctx + 0x38);
    if (type == 0)      sub_3014c((void *)h);
    else if (type == 1) sub_32e78(h);
    *(long *)(ctx + 0x38)  = 0;
    *(int  *)(ctx + 0x30)  = -1;
}
