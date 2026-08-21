/**
 * IL2CPP Runtime Dumper - ImGui Overlay for MLBB
 * 
 * Based on MLBB-NUSANTARA architecture but repurposed as a dumper.
 * Instead of ESP/cheat features, this dumps IL2CPP metadata from live memory.
 * 
 * Features:
 * - ImGui overlay with dump controls
 * - IL2CPP API enumeration via dlsym
 * - Real method pointers from live memory
 * - dump.cs, il2cpp_methods.txt, il2cpp_classes.txt output
 * - Memory read via direct access (same process)
 */

#pragma once

#include <jni.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <map>

#define TAG "IL2CPPDumper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ==================== IL2CPP API TYPES ====================

typedef void* Il2CppDomain;
typedef void* Il2CppAssembly;
typedef void* Il2CppImage;
typedef void* Il2CppClass;
typedef void* Il2CppMethod;
typedef void* Il2CppField;
typedef void* Il2CppType;
typedef void* Il2CppGenericMethod;

// Minimal IL2CPP structs for accessing method_pointer
struct Il2CppMethodInfo_ {
    const void* klass;
    const void* return_type;
    const void* parameters;
    void* method_pointer;         // +0x18: RUNTIME FUNCTION POINTER!
    void* virtualMethodPointer;
    void* invoker_method;
    const char* name;
    const void* methodDefinition;
    const void* genericMethod;
    int32_t token;
    int16_t flags;
    int16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t is_generic;
    uint8_t is_inflated;
    uint8_t is_marshaled;
};

struct Il2CppFieldInfo_ {
    const char* name;
    const void* type;
    const void* parent;
    int32_t offset;
    int32_t token;
};

// ==================== IL2CPP API FUNCTION POINTERS ====================

typedef const Il2CppDomain* (*fn_domain_get)(void);
typedef const void** (*fn_domain_get_assemblies)(const Il2CppDomain*, uint32_t*);
typedef const Il2CppImage* (*fn_assembly_get_image)(const Il2CppAssembly*);
typedef const char* (*fn_image_get_name)(const Il2CppImage*);
typedef uint32_t (*fn_image_get_class_count)(const Il2CppImage*);
typedef const Il2CppClass* (*fn_image_get_class)(const Il2CppImage*, uint32_t);
typedef const char* (*fn_class_get_name)(const Il2CppClass*);
typedef const char* (*fn_class_get_namespace)(const Il2CppClass*);
typedef const Il2CppMethodInfo_* (*fn_class_get_methods)(const Il2CppClass*, void**);
typedef const Il2CppFieldInfo_* (*fn_class_get_fields)(const Il2CppClass*, void**);
typedef const char* (*fn_method_get_name)(const Il2CppMethodInfo_*);
typedef int32_t (*fn_method_get_param_count)(const Il2CppMethodInfo_*);
typedef const char* (*fn_field_get_name)(const Il2CppFieldInfo_*);
typedef uint32_t (*fn_method_get_token)(const Il2CppMethodInfo_*);

// ==================== DUMP STATE ====================

struct DumpState {
    bool initialized;
    bool dumping;
    bool dumpComplete;
    uintptr_t il2cppBase;
    uintptr_t il2cppSize;
    int totalClasses;
    int totalMethods;
    int totalFields;
    int totalAssemblies;
    char outputPath[512];
    char statusMsg[256];
    float progress; // 0.0 - 1.0
    
    // Resolved API
    fn_domain_get api_domain_get;
    fn_domain_get_assemblies api_domain_get_assemblies;
    fn_assembly_get_image api_assembly_get_image;
    fn_image_get_name api_image_get_name;
    fn_image_get_class_count api_image_get_class_count;
    fn_image_get_class api_image_get_class;
    fn_class_get_name api_class_get_name;
    fn_class_get_namespace api_class_get_namespace;
    fn_class_get_methods api_class_get_methods;
    fn_class_get_fields api_class_get_fields;
    fn_method_get_name api_method_get_name;
    fn_method_get_param_count api_method_get_param_count;
    fn_field_get_name api_field_get_name;
    fn_method_get_token api_method_get_token;
};

extern DumpState g_dumpState;
extern bool g_running;
