# sources ?= $(wildcard *.c) ../cJSON/cJSON.c
# objects ?= $(sources:.c=.o)
c_sources := $(wildcard *.c) ../cJSON/cJSON.c
c_objects := $(c_sources:.c=.o)

cpp_sources := $(wildcard *.cpp) $(wildcard ./virtio_runtime/src/*.cpp) $(wildcard ./virtio_blk/*.cpp) $(wildcard ./virtio_net/*.cpp) $(wildcard ./virtio_console/*.cpp)
cpp_objects := $(cpp_sources:.cpp=.o)

ivc_demo_object ?= ivc_demo.o
rpmsg_demo_object ?= rpmsg_demo.o

# hvisor_objects ?= $(filter-out $(ivc_demo_object) $(rpmsg_demo_object), $(objects))
hvisor_objects := $(filter-out $(ivc_demo_object) $(rpmsg_demo_object), $(c_objects)) $(cpp_objects)
ROOT ?=
# gnu or musl
LIBC ?= gnu

ifeq ($(ARCH), arm64)
	CCARCH := aarch64
else ifeq ($(ARCH), riscv)
	CCARCH := riscv64
else ifeq ($(ARCH), loongarch)
	CCARCH := loongarch64
else ifeq ($(ARCH), x86_64)
	CCARCH := x86_64
else
$(error "Unsupported architecture $(ARCH)")
endif

ifeq ($(filter $(LIBC),gnu musl),)
$(error LIBC must be one of: gnu musl)
endif

ifeq ($(ARCH), loongarch)
toolchain := $(CCARCH)-unknown-linux-$(LIBC)
else ifeq ($(ARCH), arm64)
toolchain := $(CCARCH)-none-linux-$(LIBC)
else
toolchain := $(CCARCH)-linux-$(LIBC)
endif

CFLAGS := -Wall -Wextra -DLOG_USE_COLOR -DHLOG=$(LOG) -pthread

# Conditionally add sysroot if ROOT is set
# Otherwise use default flags from cross-compiler
ifneq ($(ROOT),)
CFLAGS += --sysroot=$(ROOT)
CXXFLAGS += --sysroot=$(ROOT)
endif

include_dirs := -I../include -I./include -I../cJSON -I./virtio_runtime/include

ifeq ($(LIBC), musl)
include_dirs += -I./compat/
endif

LDFLAGS := -lpthread -static -luring -lstdc++

# LIBS := -L$(ROOT)/usr/lib/$(toolchain) -L$(ROOT)/lib
# LIBS := -L/opt/aarch64-linux-musl-cross/aarch64-linux-musl -L/opt/aarch64-linux-musl-cross/lib

ifeq ($(VIRTIO_GPU), y)
	sources += $(wildcard ./virtio_gpu/*.c)
	CFLAGS += -DENABLE_VIRTIO_GPU
endif

# sources += $(wildcard ./virtio_blk/*.c)
# sources += $(wildcard ./virtio_net/*.c)
# sources += $(wildcard ./virtio_console/*.c)

include $(c_sources:.c=.d)
# include $(cpp_sources:.cpp=.d)

ifeq ($(DEBUG), y)
	CFLAGS += -g -O0
	CXXFLAGS += -g -O0
else
	CFLAGS += -O2
	CXXFLAGS += -O2
endif

CC := $(toolchain)-gcc
CXX := $(toolchain)-g++
READELF := $(toolchain)-readelf
OBJDUMP := $(toolchain)-objdump

CXXFLAGS += $(CFLAGS) -std=c++20 -fcoroutines

ifeq ($(ARCH), arm64)
	ifeq ($(VIRTIO_GPU), y)
		include_dirs += -I/usr/$(toolchain)/include -I/usr/$(toolchain)/include/libdrm -L/usr/$(toolchain)/lib -ldrm
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

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(include_dirs) -c $< -o $@

$(c_objects): %.o: %.c
	$(CC) $(CFLAGS) $(include_dirs) $(LIBS) -c -o $@ $<

hvisor: $(hvisor_objects)
	$(CXX) -o $@ $^ $(CFLAGS) $(include_dirs) $(LDFLAGS) $(LIBS)

ivc_demo: $(ivc_demo_object)
	$(CC) -o $@ $^ $(CFLAGS) $(include_dirs) $(LDFLAGS) $(LIBS)

rpmsg_demo: $(rpmsg_demo_object)
	$(CC) -o $@ $^ $(CFLAGS) $(include_dirs) $(LDFLAGS) $(LIBS)

clean:
	@rm -f hvisor ivc_demo rpmsg_demo *.o *.d *.d.* virtio_gpu/*.o virtio_gpu/*.d virtio_gpu/*.d.* virtio_blk/*.o virtio_blk/*.d virtio_blk/*.d.* virtio_net/*.o virtio_net/*.d virtio_net/*.d.* virtio_console/*.o virtio_console/*.d virtio_console/*.d.* ../cJSON/*.o ../cJSON/*.d ../cJSON/*.d.*
