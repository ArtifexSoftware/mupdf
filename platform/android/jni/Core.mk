LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

MY_ROOT := ../..

V8 := v8-3.9

ifeq ($(TARGET_ARCH),arm)
LOCAL_CFLAGS += -DARCH_ARM -DARCH_THUMB -DARCH_ARM_CAN_LOAD_UNALIGNED
ifdef NDK_PROFILER
LOCAL_CFLAGS += -pg -DNDK_PROFILER
endif
endif
LOCAL_CFLAGS += -DAA_BITS=8
ifdef MEMENTO
LOCAL_CFLAGS += -DMEMENTO -DMEMENTO_LEAKONLY
endif

LOCAL_C_INCLUDES := \
	../../thirdparty/jbig2dec \
	../../thirdparty/openjpeg/src/lib/openjp2 \
	../../thirdparty/jpeg \
	../../thirdparty/zlib \
	../../thirdparty/freetype/include \
	../../source/fitz \
	../../source/pdf \
	../../source/xps \
	../../source/cbz \
	../../source/img \
	../../scripts \
	../../generated \
	../../resources \
	../../include \
	../..
ifdef V8_BUILD
LOCAL_C_INCLUDES += ../../thirdparty/$(V8)/include
endif

LOCAL_MODULE    := mupdfcore
LOCAL_SRC_FILES := \
	$(wildcard $(MY_ROOT)/source/fitz/*.c) \
	$(wildcard $(MY_ROOT)/source/pdf/*.c) \
	$(wildcard $(MY_ROOT)/source/xps/*.c) \
	$(wildcard $(MY_ROOT)/source/cbz/*.c) \
	$(wildcard $(MY_ROOT)/source/img/*.c)
ifdef MEMENTO
LOCAL_SRC_FILES += $(MY_ROOT)/fitz/memento.c
endif
ifdef V8_BUILD
LOCAL_SRC_FILES += \
	$(MY_ROOT)/source/pdf/js/pdf-js.c \
	$(MY_ROOT)/source/pdf/js/pdf-jsimp-cpp.c \
	$(MY_ROOT)/source/pdf/js/pdf-jsimp-v8.cpp
else
LOCAL_SRC_FILES += \
	$(MY_ROOT)/source/pdf/js/pdf-js-none.c
endif

LOCAL_LDLIBS    := -lm -llog -ljnigraphics

LOCAL_SRC_FILES := $(addprefix ../, $(LOCAL_SRC_FILES))

include $(BUILD_STATIC_LIBRARY)
