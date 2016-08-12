LOCAL_PATH := $(call my-dir)

ifdef FZ_ENABLE_GPRF
include $(CLEAR_VARS)
LOCAL_MODULE := gsso
LOCAL_SRC_FILES := libgs.so
include $(PREBUILT_SHARED_LIBRARY)
endif

include $(CLEAR_VARS)

MY_ROOT := ../../..

LOCAL_CFLAGS += -Wall -Wno-maybe-uninitialized

ifeq ($(TARGET_ARCH),arm)
LOCAL_CFLAGS += -DARCH_ARM -DARCH_THUMB -DARCH_ARM_CAN_LOAD_UNALIGNED
ifdef NDK_PROFILER
LOCAL_CFLAGS += -pg -DNDK_PROFILER
endif
endif
ifdef FZ_ENABLE_GPRF
LOCAL_CFLAGS += -DFZ_ENABLE_GPRF
endif
LOCAL_CFLAGS += -DAA_BITS=8
ifdef MEMENTO
LOCAL_CFLAGS += -DMEMENTO -DMEMENTO_LEAKONLY
endif
ifdef SSL_BUILD
LOCAL_CFLAGS += -DHAVE_OPENSSL
endif

LOCAL_C_INCLUDES := \
	$(MY_ROOT)/thirdparty/harfbuzz/src \
	$(MY_ROOT)/thirdparty/jbig2dec \
	$(MY_ROOT)/thirdparty/openjpeg/src/lib/openjp2 \
	$(MY_ROOT)/thirdparty/jpeg \
	$(MY_ROOT)/thirdparty/mujs \
	$(MY_ROOT)/thirdparty/zlib \
	$(MY_ROOT)/thirdparty/freetype/include \
	$(MY_ROOT)/source/fitz \
	$(MY_ROOT)/source/pdf \
	$(MY_ROOT)/source/xps \
	$(MY_ROOT)/source/svg \
	$(MY_ROOT)/source/cbz \
	$(MY_ROOT)/source/img \
	$(MY_ROOT)/source/tiff \
	$(MY_ROOT)/scripts/freetype \
	$(MY_ROOT)/scripts/jpeg \
	$(MY_ROOT)/generated \
	$(MY_ROOT)/resources \
	$(MY_ROOT)/include \
	$(MY_ROOT)
ifdef V8_BUILD
LOCAL_C_INCLUDES += $(MY_ROOT)/thirdparty/$(V8)/include
endif
ifdef SSL_BUILD
LOCAL_C_INCLUDES += $(MY_ROOT)/thirdparty/openssl/include
endif

LOCAL_MODULE := mupdfcore
LOCAL_SRC_FILES := \
	$(wildcard $(MY_ROOT)/source/fitz/*.c) \
	$(wildcard $(MY_ROOT)/source/pdf/*.c) \
	$(wildcard $(MY_ROOT)/source/xps/*.c) \
	$(wildcard $(MY_ROOT)/source/svg/*.c) \
	$(wildcard $(MY_ROOT)/source/cbz/*.c) \
	$(wildcard $(MY_ROOT)/source/gprf/*.c) \
	$(wildcard $(MY_ROOT)/source/html/*.c) \
	$(wildcard $(MY_ROOT)/generated/*.c)

ifdef FZ_ENABLE_GPRF
LOCAL_SHARED_LIBRARIES := gsso
endif
LOCAL_LDLIBS := -lm -llog -ljnigraphics

LOCAL_SRC_FILES := $(addprefix ../, $(LOCAL_SRC_FILES))

include $(BUILD_STATIC_LIBRARY)
