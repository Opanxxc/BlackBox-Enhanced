# IL2CPP Runtime Dumper - Android.mk
# Builds libil2cpp_dumper.so for injection into target app

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := il2cpp_dumper

LOCAL_SRC_FILES := main.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CFLAGS := -std=c++17
LOCAL_CPPFLAGS := -std=c++17 -w -fvisibility=hidden -ffunction-sections -fdata-sections -fexceptions
LOCAL_LDFLAGS += -Wl,--gc-sections,--strip-all

LOCAL_LDLIBS := -llog -landroid

include $(BUILD_SHARED_LIBRARY)
