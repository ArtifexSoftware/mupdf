LOCAL_PATH := $(call my-dir)
TOP_LOCAL_PATH := $(LOCAL_PATH)

MUPDF_ROOT := ../../..

ifdef NDK_PROFILER
include android-ndk-profiler.mk
endif

include $(TOP_LOCAL_PATH)/Core.mk
include $(TOP_LOCAL_PATH)/ThirdParty.mk

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
	jni/andprof \
	$(MUPDF_ROOT)/include \
	$(MUPDF_ROOT)/source/fitz \
	$(MUPDF_ROOT)/source/pdf \
	$(MUPDF_ROOT)/platform/java
LOCAL_CFLAGS := -DHAVE_ANDROID
LOCAL_MODULE := mupdf_java

LOCAL_SRC_FILES := \
	mupdf.c \
	$(MUPDF_ROOT)/../platform/java/mupdf_native.c

LOCAL_STATIC_LIBRARIES := mupdfcore mupdfthirdparty
ifdef NDK_PROFILER
LOCAL_CFLAGS += -pg -DNDK_PROFILER
LOCAL_STATIC_LIBRARIES += andprof
endif
ifdef FZ_ENABLE_GPRF
LOCAL_CFLAGS += -DFZ_ENABLE_GPRF
endif

LOCAL_LDLIBS := -lm -llog -ljnigraphics
ifdef SSL_BUILD
LOCAL_LDLIBS += -L$(MUPDF_ROOT)/thirdparty/openssl/android -lcrypto -lssl
endif

include $(BUILD_SHARED_LIBRARY)
