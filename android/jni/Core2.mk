LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

MY_ROOT := ../..

OPENJPEG := openjpeg
JPEG := jpeg
ZLIB := zlib
FREETYPE := freetype
V8 := v8-3.9

ifeq ($(TARGET_ARCH),arm)
LOCAL_CFLAGS += -DARCH_ARM -DARCH_THUMB -DARCH_ARM_CAN_LOAD_UNALIGNED
ifdef NDK_PROFILER
LOCAL_CFLAGS += -pg -DNDK_PROFILER -O0
NDK_APP_CFLAGS :=
endif
endif
LOCAL_CFLAGS += -DAA_BITS=8
ifdef MEMENTO
LOCAL_CFLAGS += -DMEMENTO -DMEMENTO_LEAKONLY
endif

LOCAL_C_INCLUDES := \
	../thirdparty/jbig2dec \
	../thirdparty/$(OPENJPEG)/src/lib/openjp2 \
	../thirdparty/$(JPEG) \
	../thirdparty/$(ZLIB) \
	../thirdparty/$(FREETYPE)/include \
	../draw \
	../fitz \
	../pdf \
	../xps \
	../cbz \
	../ucdn \
	../scripts \
	..
ifdef V8_BUILD
LOCAL_C_INCLUDES += ../thirdparty/$(V8)/include
endif

LOCAL_MODULE    := mupdfcore2
LOCAL_SRC_FILES := \
	$(MY_ROOT)/fitz/res_shade.c

LOCAL_LDLIBS    := -lm -llog -ljnigraphics

include $(BUILD_STATIC_LIBRARY)
