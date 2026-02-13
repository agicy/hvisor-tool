sources ?= $(wildcard *.c) $(wildcard *.cpp) $(wildcard ./virtio/*.c) $(wildcard ./virtio/*.cpp) ../cJSON/cJSON.c

# Include device-specific Makefiles
include ./virtio/devices/blk/Makefile
include ./virtio/devices/console/Makefile
include ./virtio/devices/net/Makefile
include ./virtio/devices/gpu/Makefile

c_objects := $(patsubst %.c,%.o,$(filter %.c,$(sources)))
cpp_objects := $(patsubst %.cpp,%.o,$(filter %.cpp,$(sources)))
objects := $(c_objects) $(cpp_objects)

ivc_demo_object ?= ivc_demo.o
rpmsg_demo_object ?= rpmsg_demo.o
hvisor_objects ?= $(filter-out $(ivc_demo_object) $(rpmsg_demo_object), $(objects))
ROOT ?=
# gnu or musl
LIBC ?= gnu

ifeq ($(filter $(LIBC),gnu musl),)
$(error LIBC must be one of: gnu musl)
endif

ifndef CROSS_COMPILE
	ifeq ($(ARCH), arm64)
		CROSS_COMPILE := aarch64-none-linux-$(LIBC)-
	else ifeq ($(ARCH), riscv)
		CROSS_COMPILE := riscv64-linux-$(LIBC)-
	else ifeq ($(ARCH), loongarch)
		CROSS_COMPILE := loongarch64-unknown-linux-$(LIBC)-
	else ifeq ($(ARCH), x86_64)
		CROSS_COMPILE := x86_64-linux-$(LIBC)-
	else
	$(error "Unsupported architecture $(ARCH)")
	endif
endif

CFLAGS := -Wall -Wextra -DLOG_USE_COLOR -DHLOG=$(LOG) -pthread

# Conditionally add sysroot if ROOT is set
# Otherwise use default flags from cross-compiler
ifneq ($(ROOT),)
CFLAGS += --sysroot=$(ROOT)
endif

include_dirs := -I../include -I./include -I./virtio/include -I../cJSON

ifeq ($(LIBC), musl)
include_dirs += -I./compat/
endif

LDFLAGS := -lpthread -luring -static

ifeq ($(VIRTIO_GPU), y)
	CFLAGS += -DENABLE_VIRTIO_GPU
endif

# include $(sources:.c=.d)

ifeq ($(DEBUG), y)
	CFLAGS += -g -O0
else
	CFLAGS += -O2
endif

CC := $(CROSS_COMPILE)gcc
CXX := $(CROSS_COMPILE)g++

CXXFLAGS := $(CFLAGS) -std=c++20 -fcoroutines

ifeq ($(ARCH), arm64)
	ifeq ($(VIRTIO_GPU), y)
		triplet := $(patsubst %-,%,$(notdir $(CROSS_COMPILE)))
		include_dirs += -I/usr/$(triplet)/include -I/usr/$(triplet)/include/libdrm -L/usr/$(triplet)/lib -ldrm
	endif
else ifeq ($(ARCH), riscv)
	CFLAGS += -static
else ifeq ($(ARCH), loongarch)
	CFLAGS += -DLOONGARCH64 -static
	ifeq ($(VIRTIO_GPU), y)
		include_dirs += -I/opt/libdrm-install/include -L/opt/libdrm-install/lib -I/opt/libdrm-install/include/libdrm -ldrm
	endif
else ifeq ($(ARCH), x86_64)
	CC := x86_64-linux-gnu-gcc
	CXX := x86_64-linux-gnu-g++
	READELF := x86_64-linux-gnu-readelf
	OBJDUMP := x86_64-linux-gnu-objdump
endif

.PHONY: all clean

all: hvisor ivc_demo rpmsg_demo

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(include_dirs) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

%.o: %.c
	$(CC) $(CFLAGS) $(include_dirs) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(include_dirs) -c $< -o $@

hvisor: $(hvisor_objects)
	$(CXX) $(hvisor_objects) $(LDFLAGS) -o hvisor

ivc_demo: $(ivc_demo_object)
	$(CC) $(ivc_demo_object) $(LDFLAGS) -o ivc_demo

rpmsg_demo: $(rpmsg_demo_object)
	$(CC) $(rpmsg_demo_object) $(LDFLAGS) -o rpmsg_demo

clean:
	rm -f $(objects) $(objects:.o=.d) hvisor ivc_demo rpmsg_demo
