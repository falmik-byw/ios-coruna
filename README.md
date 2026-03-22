Makefile:
THEOS_ROOT := $(HOME)/theos
SDK := $(THEOS_ROOT)/sdks/iPhoneOS16.5.sdk
CC := $(THEOS_ROOT)/toolchain/linux/iphone/bin/clang
AR := $(THEOS_ROOT)/toolchain/linux/iphone/bin/ar
STRIP := $(THEOS_ROOT)/toolchain/linux/iphone/bin/strip

ARCH := arm64e
TARGET := $(ARCH)-apple-ios16.5
CFLAGS := -target $(TARGET) -isysroot $(SDK) -I.
CFLAGS += ONLY FOR LEARNING-Wall -Wextra -O2 -fPIC
CFLAGS += -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-bitwise-op-parentheses
CFLAGS += -Wno-unused-function -Wno-unused-variable -Wno-sometimes-uninitialized
CFLAGS += -Wno-sign-compare -Wno-self-assign -Wno-int-conversion
LDFLAGS := -dynamiclib -install_name @rpath/$(notdir $@)
LDFLAGS_ENTRY5 := $(LDFLAGS) -framework CoreFoundation -framework IOKit -undefined dynamic_lookup -Wl,-w -Wl,-multiply_defined,suppress
LDFLAGS_ENTRY0 := $(LDFLAGS) -framework Foundation -framework IOKit

SRC_DIR := .
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
LIB_DIR := $(BUILD_DIR)/lib

ENTRY1_SRCS := $(wildcard $(SRC_DIR)/record_0x90001_*.c)
ENTRY5_SRCS := $(filter-out $(SRC_DIR)/record_0x90000_kreadwrite.c $(SRC_DIR)/record_0x90000_kext_inherit.c $(SRC_DIR)/record_0x90000_kobj_scan.c $(SRC_DIR)/record_0x90000_kread_backends.c, $(wildcard $(SRC_DIR)/record_0x90000_*.c))
ENTRY4_SRCS := $(SRC_DIR)/record_0x50000_loader.c
ENTRY0_SRCS := $(SRC_DIR)/record_0x80000_beacon.m

ENTRY1_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(ENTRY1_SRCS))
ENTRY5_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(ENTRY5_SRCS))
ENTRY4_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(ENTRY4_SRCS))
ENTRY0_OBJS := $(patsubst $(SRC_DIR)/%.m,$(OBJ_DIR)/%.o,$(ENTRY0_SRCS))


ONLY FOR LEARNING
ONLY FOR LEARNING
ONLY FOR LEARNING
ONLY FOR LEARNING
ONLY FOR LEARNING
