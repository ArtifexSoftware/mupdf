LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

MY_ROOT := ../..

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
ifdef SSL_BUILD
LOCAL_CFLAGS += -DHAVE_OPENSSL
endif

LOCAL_C_INCLUDES := \
	../../thirdparty/jbig2dec \
	../../thirdparty/openjpeg/libopenjpeg \
	../../thirdparty/jpeg \
	../../thirdparty/mujs \
	../../thirdparty/zlib \
	../../thirdparty/freetype/include \
	../../source/fitz \
	../../source/pdf \
	../../source/xps \
	../../source/cbz \
	../../source/img \
	../../source/tiff \
	../../scripts/freetype \
	../../scripts/jpeg \
	../../scripts/openjpeg \
	../../generated \
	../../resources \
	../../include \
	../..
ifdef V8_BUILD
LOCAL_C_INCLUDES += ../../thirdparty/$(V8)/include
endif
ifdef SSL_BUILD
LOCAL_C_INCLUDES += ../../thirdparty/openssl/include
endif

LOCAL_MODULE    := mupdfcore
LOCAL_SRC_FILES := \
	$(wildcard $(MY_ROOT)/source/fitz/*.c) \
	$(wildcard $(MY_ROOT)/source/pdf/*.c) \
	$(wildcard $(MY_ROOT)/source/xps/*.c) \
	$(wildcard $(MY_ROOT)/source/cbz/*.c) \
	$(wildcard $(MY_ROOT)/source/img/*.c) \
	$(wildcard $(MY_ROOT)/source/tiff/*.c)
LOCAL_SRC_FILES += \
	$(MY_ROOT)/source/pdf/js/pdf-js.c \
	$(MY_ROOT)/source/pdf/js/pdf-jsimp-mu.c
ifdef MEMENTO
LOCAL_SRC_FILES += $(MY_ROOT)/source/fitz/memento.c
endif

LOCAL_LDLIBS    := -lm -llog -ljnigraphics

LOCAL_SRC_FILES := $(addprefix ../, $(LOCAL_SRC_FILES))

include $(BUILD_STATIC_LIBRARY)
