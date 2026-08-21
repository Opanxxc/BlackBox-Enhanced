/**
 * IL2CPP Runtime Dumper - Native .so for MLBB & other IL2CPP games
 * 
 * This library is injected into the target process and dumps IL2CPP
 * data directly from live memory - like a cheat menu but for dumping.
 * 
 * Usage: Load via System.loadLibrary() or LD_PRELOAD
 * Output: /storage/emulated/0/Download/black/dump/{pkg}/runtime_dump/
 *
 * Enhanced by Panxcz & Freebuff
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <android/log.h>

#define TAG "NativeDumper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ==================== IL2CPP TYPE DEFINITIONS ====================

typedef void Il2CppDomain;
typedef void Il2CppAssembly;
typedef void Il2CppImage;
typedef void Il2CppClass;
typedef void Il2CppMethod;
typedef void Il2CppField;
typedef void Il2CppType;
typedef void Il2CppString;
typedef void Il2CppObject;
typedef void Il2CppGenericContext;
typedef void Il2CppGenericMethod;
typedef void Il2CppEvent;

typedef struct Il2CppMethodInfo {
    const Il2CppClass* klass;
    const Il2CppType* return_type;
    const void* parameters;
    void* method_pointer;        // RUNTIME FUNCTION POINTER - REAL ADDRESS!
    void* virtualMethodPointer;
    void* invoker_method;
    const char* name;
    void* methodDefinition;
    Il2CppGenericMethod* genericMethod;
    int32_t token;
    int16_t flags;
    int16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t is_generic;
    uint8_t is_inflated;
    uint8_t is_marshaled;
} Il2CppMethodInfo;

typedef struct Il2CppFieldInfo {
    const char* name;
    const Il2CppType* type;
    const Il2CppClass* parent;
    int32_t offset;
    int32_t token;
} Il2CppFieldInfo;

typedef struct Il2CppClass {
    const Il2CppImage* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    // ... more fields follow but we access via API
} Il2CppClass;

typedef struct Il2CppImage {
    const char* name;
    // ... more fields
} Il2CppImage;

// ==================== IL2CPP API FUNCTION TYPES ====================

// We use dlsym to find these at runtime - no static linking needed!
typedef const Il2CppDomain* (*fn_il2cpp_domain_get)(void);
typedef const void* (*fn_il2cpp_domain_get_assemblies)(const Il2CppDomain*, uint32_t*);
typedef const Il2CppImage* (*fn_il2cpp_assembly_get_image)(const Il2CppAssembly*);
typedef const char* (*fn_il2cpp_image_get_name)(const Il2CppImage*);
typedef uint32_t (*fn_il2cpp_image_get_class_count)(const Il2CppImage*);
typedef const Il2CppClass* (*fn_il2cpp_image_get_class)(const Il2CppImage*, uint32_t);
typedef const char* (*fn_il2cpp_class_get_name)(const Il2CppClass*);
typedef const char* (*fn_il2cpp_class_get_namespace)(const Il2CppClass*);
typedef uint32_t (*fn_il2cpp_class_get_method_count)(const Il2CppClass*, uint32_t*);
typedef const Il2CppMethodInfo* (*fn_il2cpp_class_get_methods)(const Il2CppClass*, void**);
typedef uint32_t (*fn_il2cpp_class_get_field_count)(const Il2CppClass*);
typedef const Il2CppFieldInfo* (*fn_il2cpp_class_get_fields)(const Il2CppClass*, void**);
typedef const Il2CppMethodInfo* (*fn_il2cpp_method_get_from_name)(const Il2CppClass*, const char*, int32_t);
typedef const char* (*fn_il2cpp_method_get_name)(const Il2CppMethodInfo*);
typedef const char* (*fn_il2cpp_field_get_name)(const Il2CppFieldInfo*);
typedef int32_t (*fn_il2cpp_method_get_param_count)(const Il2CppMethodInfo*);
typedef const Il2CppType* (*fn_il2cpp_method_get_return_type)(const Il2CppMethodInfo*);
typedef const Il2CppType* (*fn_il2cpp_field_get_type)(const Il2CppFieldInfo*);
typedef uint32_t (*fn_il2cpp_method_get_token)(const Il2CppMethodInfo*);
typedef int32_t (*fn_il2cpp_class_get_flags)(const Il2CppClass*);
typedef uint32_t (*fn_il2cpp_class_get_image)(const Il2CppClass*);
typedef const Il2CppMethodInfo* (*fn_il2cpp_class_get_methods_by_name)(const Il2CppClass*, const char*, int32_t, int32_t, void**);
typedef const char* (*fn_il2cpp_type_get_name)(const Il2CppType*);

// ==================== FUNCTION POINTERS ====================

static fn_il2cpp_domain_get p_domain_get = NULL;
static fn_il2cpp_domain_get_assemblies p_domain_get_assemblies = NULL;
static fn_il2cpp_assembly_get_image p_assembly_get_image = NULL;
static fn_il2cpp_image_get_name p_image_get_name = NULL;
static fn_il2cpp_image_get_class_count p_image_get_class_count = NULL;
static fn_il2cpp_image_get_class p_image_get_class = NULL;
static fn_il2cpp_class_get_name p_class_get_name = NULL;
static fn_il2cpp_class_get_namespace p_class_get_namespace = NULL;
static fn_il2cpp_class_get_method_count p_class_get_method_count = NULL;
static fn_il2cpp_class_get_methods p_class_get_methods = NULL;
static fn_il2cpp_class_get_field_count p_class_get_field_count = NULL;
static fn_il2cpp_class_get_fields p_class_get_fields = NULL;
static fn_il2cpp_method_get_name p_method_get_name = NULL;
static fn_il2cpp_method_get_param_count p_method_get_param_count = NULL;
static fn_il2cpp_method_get_return_type p_method_get_return_type = NULL;
static fn_il2cpp_field_get_name p_field_get_name = NULL;
static fn_il2cpp_field_get_type p_field_get_type = NULL;
static fn_il2cpp_method_get_token p_method_get_token = NULL;

// ==================== LIBRARY BASE DETECTION ====================

static uintptr_t g_il2cpp_base = 0;
static uintptr_t g_il2cpp_size = 0;

/**
 * Parse /proc/self/maps to find libil2cpp.so base address and size
 */
static int find_il2cpp_base(void) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Cannot open /proc/self/maps");
        return -1;
    }

    char line[512];
    g_il2cpp_base = 0;
    g_il2cpp_size = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libil2cpp.so") && strstr(line, "r-xp")) {
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                g_il2cpp_base = start;
                g_il2cpp_size = end - start;
                LOGI("Found libil2cpp.so: base=0x%lx size=0x%lx", g_il2cpp_base, g_il2cpp_size);
                fclose(fp);
                return 0;
            }
        }
    }

    fclose(fp);
    LOGE("libil2cpp.so not found in maps!");
    return -1;
}

// ==================== IL2CPP API RESOLUTION ====================

static int resolve_il2cpp_api(void) {
    void* handle = dlopen("libil2cpp.so", RTLD_NOW | RTLD_NOLOAD);
    if (!handle) {
        LOGE("Cannot dlopen libil2cpp.so: %s", dlerror());
        return -1;
    }

    #define RESOLVE(name, type) do { \
        p_##name = reinterpret_cast<type>(dlsym(handle, #name)); \
        if (!p_##name) LOGE("Failed to resolve: %s", #name); \
    } while(0)

    RESOLVE(il2cpp_domain_get, fn_il2cpp_domain_get);
    RESOLVE(il2cpp_domain_get_assemblies, fn_il2cpp_domain_get_assemblies);
    RESOLVE(il2cpp_assembly_get_image, fn_il2cpp_assembly_get_image);
    RESOLVE(il2cpp_image_get_name, fn_il2cpp_image_get_name);
    RESOLVE(il2cpp_image_get_class_count, fn_il2cpp_image_get_class_count);
    RESOLVE(il2cpp_image_get_class, fn_il2cpp_image_get_class);
    RESOLVE(il2cpp_class_get_name, fn_il2cpp_class_get_name);
    RESOLVE(il2cpp_class_get_namespace, fn_il2cpp_class_get_namespace);
    RESOLVE(il2cpp_class_get_method_count, fn_il2cpp_class_get_method_count);
    RESOLVE(il2cpp_class_get_methods, fn_il2cpp_class_get_methods);
    RESOLVE(il2cpp_class_get_field_count, fn_il2cpp_class_get_field_count);
    RESOLVE(il2cpp_class_get_fields, fn_il2cpp_class_get_fields);
    RESOLVE(il2cpp_method_get_name, fn_il2cpp_method_get_name);
    RESOLVE(il2cpp_method_get_param_count, fn_il2cpp_method_get_param_count);
    RESOLVE(il2cpp_method_get_return_type, fn_il2cpp_method_get_return_type);
    RESOLVE(il2cpp_field_get_name, fn_il2cpp_field_get_name);
    RESOLVE(il2cpp_field_get_type, fn_il2cpp_field_get_type);
    RESOLVE(il2cpp_method_get_token, fn_il2cpp_method_get_token);

    #undef RESOLVE

    int resolved = 0;
    if (p_domain_get) resolved++;
    if (p_class_get_methods) resolved++;
    if (p_class_get_fields) resolved++;

    LOGI("Resolved %d/18 IL2CPP API functions", resolved);
    
    if (!p_domain_get || !p_class_get_methods) {
        LOGE("Critical API functions missing - cannot dump");
        dlclose(handle);
        return -1;
    }

    dlclose(handle);
    return 0;
}

// ==================== DUMP OUTPUT ====================

static FILE* g_dump_cs = NULL;
static FILE* g_dump_classes = NULL;
static FILE* g_dump_methods = NULL;
static FILE* g_dump_strings = NULL;
static FILE* g_dump_offsets = NULL;
static FILE* g_dump_raw = NULL;

static int g_total_classes = 0;
static int g_total_methods = 0;
static int g_total_fields = 0;

static const char* get_type_name(const Il2CppType* type) {
    if (!type) return "void";
    // Simplified - use il2cpp API for proper names
    return "object";
}

static void dump_class(const Il2CppClass* klass, const char* image_name) {
    if (!klass) return;

    const char* class_name = p_class_get_name ? p_class_get_name(klass) : "Unknown";
    const char* ns = p_class_get_namespace ? p_class_get_namespace(klass) : "";
    if (!class_name || !class_name[0]) return;

    g_total_classes++;

    // Full class name
    char full_name[512];
    if (ns && ns[0]) {
        snprintf(full_name, sizeof(full_name), "%s.%s", ns, class_name);
    } else {
        snprintf(full_name, sizeof(full_name), "%s", class_name);
    }

    // Write to classes list
    if (g_dump_classes) {
        fprintf(g_dump_classes, "[%d] %s (from %s)\n", g_total_classes, full_name, image_name);
    }

    // Write to dump.cs
    if (g_dump_cs) {
        // Access flags
        fprintf(g_dump_cs, "// Image: %s\n", image_name);
        fprintf(g_dump_cs, "public class %s\n{\n", class_name);

        // Fields
        if (p_class_get_fields) {
            void* iter = NULL;
            const Il2CppFieldInfo* field;
            while ((field = p_class_get_fields(klass, &iter)) != NULL) {
                const char* fname = p_field_get_name ? p_field_get_name(field) : "field";
                if (!fname) continue;
                
                g_total_fields++;
                
                // Get field offset from the struct (offset is at known position)
                int32_t offset = 0;
                // offset is at byte 32 in Il2CppFieldInfo on arm64
                // field->offset access - use raw pointer since we defined the struct
                const char* raw = (const char*)field;
                memcpy(&offset, raw + 32, sizeof(int32_t));

                fprintf(g_dump_cs, "    public object %s; // 0x%04x\n", fname, offset);
                
                if (g_dump_offsets) {
                    fprintf(g_dump_offsets, "FIELD %s::%s offset=0x%x\n", full_name, fname, offset);
                }
            }
        }

        fprintf(g_dump_cs, "\n");

        // Methods with RUNTIME ADDRESSES (the real deal!)
        if (p_class_get_methods) {
            void* iter = NULL;
            const Il2CppMethodInfo* method;
            while ((method = p_class_get_methods(klass, &iter)) != NULL) {
                const char* mname = p_method_get_name ? p_method_get_name(method) : "method";
                if (!mname) continue;
                
                g_total_methods++;

                // RUNTIME FUNCTION POINTER - this is what makes it a REAL dumper!
                void* method_ptr = method->method_pointer;
                uintptr_t rva = 0;
                if (method_ptr && g_il2cpp_base) {
                    rva = (uintptr_t)method_ptr - g_il2cpp_base;
                }

                int param_count = 0;
                if (p_method_get_param_count) {
                    param_count = p_method_get_param_count(method);
                }

                uint32_t token = 0;
                if (p_method_get_token) {
                    token = p_method_get_token(method);
                }

                fprintf(g_dump_cs, "    public extern void %s(); // RVA: 0x%08x ptr: %p token: 0x%x params: %d\n",
                    mname, (uint32_t)rva, method_ptr, token, param_count);

                if (g_dump_methods) {
                    fprintf(g_dump_methods, "  %s.%s rva=0x%08x ptr=%p token=0x%x params=%d\n",
                        class_name, mname, (uint32_t)rva, method_ptr, token, param_count);
                }

                if (g_dump_raw) {
                    fprintf(g_dump_raw, "METHOD %s::%s rva=0x%08x ptr=0x%lx token=0x%x\n",
                        full_name, mname, (uint32_t)rva, (uintptr_t)method_ptr, token);
                }
            }
        }

        fprintf(g_dump_cs, "}\n\n");
    }
}

// ==================== MAIN DUMP FUNCTION ====================

static void* dump_thread(void* arg) {
    const char* output_dir = (const char*)arg;
    LOGI("=== Native IL2CPP Runtime Dumper ===");
    LOGI("Output: %s", output_dir);

    // Step 1: Find libil2cpp.so base
    if (find_il2cpp_base() != 0) {
        LOGE("Cannot find libil2cpp.so - not an IL2CPP app?");
        free((void*)output_dir);
        return NULL;
    }

    // Step 2: Resolve IL2CPP API via dlsym
    if (resolve_il2cpp_api() != 0) {
        LOGE("Cannot resolve IL2CPP API");
        free((void*)output_dir);
        return NULL;
    }

    // Step 3: Create output directory
    mkdir("/storage/emulated/0/Download/black/dump", 0777);
    char dump_dir[512];
    snprintf(dump_dir, sizeof(dump_dir), "%s/runtime", output_dir);
    mkdir(dump_dir, 0777);

    // Step 4: Open output files
    char path[512];
    
    snprintf(path, sizeof(path), "%s/dump.cs", dump_dir);
    g_dump_cs = fopen(path, "w");
    
    snprintf(path, sizeof(path), "%s/il2cpp_classes.txt", dump_dir);
    g_dump_classes = fopen(path, "w");
    
    snprintf(path, sizeof(path), "%s/il2cpp_methods.txt", dump_dir);
    g_dump_methods = fopen(path, "w");
    
    snprintf(path, sizeof(path), "%s/il2cpp_offsets.h", dump_dir);
    g_dump_offsets = fopen(path, "w");

    snprintf(path, sizeof(path), "%s/il2cpp_raw.txt", dump_dir);
    g_dump_raw = fopen(path, "w");

    if (!g_dump_cs) {
        LOGE("Cannot open output files - check permissions!");
        free((void*)output_dir);
        return NULL;
    }

    // Write headers
    fprintf(g_dump_cs, "// ═══════ IL2CPP Runtime Dump (Native) ═══════\n");
    fprintf(g_dump_cs, "// Generated by BlackBox Enhanced Native Dumper\n");
    fprintf(g_dump_cs, "// Method pointers are REAL runtime addresses!\n");
    fprintf(g_dump_cs, "// libil2cpp.so base: 0x%lx\n", g_il2cpp_base);
    fprintf(g_dump_cs, "// libil2cpp.so size: 0x%lx\n\n", g_il2cpp_size);
    fprintf(g_dump_cs, "using System;\nusing System.Collections.Generic;\n\n");

    if (g_dump_offsets) {
        fprintf(g_dump_offsets, "// ═══════ IL2CPP Runtime Offsets (Native) ═══════\n");
        fprintf(g_dump_offsets, "// libil2cpp.so base: 0x%lx\n\n", g_il2cpp_base);
        fprintf(g_dump_offsets, "#define IL2CPP_BASE 0x%lx\n", g_il2cpp_base);
        fprintf(g_dump_offsets, "#define IL2CPP_SIZE 0x%lx\n\n", g_il2cpp_size);
    }

    if (g_dump_raw) {
        fprintf(g_dump_raw, "# BlackBox Enhanced - Raw IL2CPP Runtime Dump\n");
        fprintf(g_dump_raw, "# Base: 0x%lx Size: 0x%lx\n\n", g_il2cpp_base, g_il2cpp_size);
    }

    // Step 5: Get IL2CPP domain and enumerate everything
    LOGI("Getting IL2CPP domain...");
    const Il2CppDomain* domain = p_domain_get();
    if (!domain) {
        LOGE("il2cpp_domain_get() returned NULL");
        // Still write what we can
    } else {
        LOGI("Domain obtained, enumerating assemblies...");
        
        uint32_t assembly_count = 0;
        const void** assemblies = NULL;
        if (p_domain_get_assemblies) {
            assemblies = (const void**)p_domain_get_assemblies(domain, &assembly_count);
        }

        LOGI("Found %u assemblies", assembly_count);

        for (uint32_t i = 0; i < assembly_count && assemblies; i++) {
            const Il2CppAssembly* assembly = (const Il2CppAssembly*)assemblies[i];
            if (!assembly) continue;

            const Il2CppImage* image = p_assembly_get_image ? p_assembly_get_image(assembly) : NULL;
            if (!image) continue;

            const char* image_name = p_image_get_name ? p_image_get_name(image) : "Unknown";
            if (!image_name) image_name = "Unknown";

            LOGI("Assembly[%u]: %s", i, image_name);

            if (g_dump_cs) {
                fprintf(g_dump_cs, "\n// ═══════ Assembly: %s ═══════\n\n", image_name);
            }

            // Enumerate classes in this image
            uint32_t class_count = 0;
            if (p_image_get_class_count) {
                class_count = p_image_get_class_count(image);
            }

            for (uint32_t j = 0; j < class_count; j++) {
                const Il2CppClass* klass = p_image_get_class ? p_image_get_class(image, j) : NULL;
                if (klass) {
                    dump_class(klass, image_name);
                }
            }
        }
    }

    // Step 6: Write summary
    if (g_dump_cs) {
        fprintf(g_dump_cs, "\n// ═══════ DUMP SUMMARY ═══════\n");
        fprintf(g_dump_cs, "// Total classes: %d\n", g_total_classes);
        fprintf(g_dump_cs, "// Total methods: %d\n", g_total_methods);
        fprintf(g_dump_cs, "// Total fields: %d\n", g_total_fields);
        fprintf(g_dump_cs, "// libil2cpp base: 0x%lx\n", g_il2cpp_base);
        fprintf(g_dump_cs, "// Method pointers are absolute runtime addresses\n");
        fprintf(g_dump_cs, "// RVA = absolute_addr - libil2cpp_base\n");
    }

    // Step 7: Write ELF info from maps
    char maps_path[512];
    snprintf(maps_path, sizeof(maps_path), "%s/maps.txt", dump_dir);
    FILE* maps_file = fopen(maps_path, "w");
    if (maps_file) {
        FILE* maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            while (fgets(line, sizeof(line), maps)) {
                if (strstr(line, "libil2cpp.so")) {
                    fprintf(maps_file, "%s", line);
                }
            }
            fclose(maps);
        }
        fclose(maps_file);
    }

    // Close all files
    if (g_dump_cs) fclose(g_dump_cs);
    if (g_dump_classes) fclose(g_dump_classes);
    if (g_dump_methods) fclose(g_dump_methods);
    if (g_dump_offsets) fclose(g_dump_offsets);
    if (g_dump_raw) fclose(g_dump_raw);

    LOGI("=== DUMP COMPLETE ===");
    LOGI("  Classes: %d", g_total_classes);
    LOGI("  Methods: %d", g_total_methods);
    LOGI("  Fields:  %d", g_total_fields);
    LOGI("  Output:  %s/runtime/", output_dir);

    free((void*)output_dir);
    return NULL;
}

// ==================== JNI INTERFACE ====================

/**
 * Main entry point - called from Java to start native dump.
 * 
 * Java: NativeDumper.dump(packageName, outputDir)
 */
JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_core_system_dumper_NativeDumper_nativeDump(
    JNIEnv* env,
    jobject thiz,
    jstring packageName,
    jstring outputDir)
{
    const char* pkg = (*env)->GetStringUTFChars(env, packageName, NULL);
    const char* out = (*env)->GetStringUTFChars(env, outputDir, NULL);

    LOGI("Native dump requested for: %s -> %s", pkg, out);

    // Copy strings to heap (thread will free)
    char* pkg_copy = strdup(pkg);
    char* out_copy = strdup(out);

    (*env)->ReleaseStringUTFChars(env, packageName, pkg);
    (*env)->ReleaseStringUTFChars(env, outputDir, out);

    // Run in a separate thread to avoid blocking
    pthread_t thread;
    pthread_create(&thread, NULL, dump_thread, out_copy);
    pthread_detach(thread);
}

/**
 * Quick dump - synchronous (blocks until done)
 */
JNIEXPORT jstring JNICALL
Java_top_niunaijun_blackbox_core_system_dumper_NativeDumper_nativeQuickDump(
    JNIEnv* env,
    jobject thiz,
    jstring outputDir)
{
    const char* out = (*env)->GetStringUTFChars(env, outputDir, NULL);

    // Find base
    find_il2cpp_base();

    // Build status string
    char status[256];
    snprintf(status, sizeof(status),
        "libil2cpp.so: base=0x%lx size=0x%lx classes=%d methods=%d fields=%d",
        g_il2cpp_base, g_il2cpp_size, g_total_classes, g_total_methods, g_total_fields);

    (*env)->ReleaseStringUTFChars(env, outputDir, out);

    return (*env)->NewStringUTF(env, status);
}

/**
 * Get libil2cpp.so base address
 */
JNIEXPORT jlong JNICALL
Java_top_niunaijun_blackbox_core_system_dumper_NativeDumper_getIl2CppBase(
    JNIEnv* env,
    jobject thiz)
{
    find_il2cpp_base();
    return (jlong)g_il2cpp_base;
}

/**
 * Get libil2cpp.so size
 */
JNIEXPORT jlong JNICALL
Java_top_niunaijun_blackbox_core_system_dumper_NativeDumper_getIl2CppSize(
    JNIEnv* env,
    jobject thiz)
{
    if (g_il2cpp_size == 0) find_il2cpp_base();
    return (jlong)g_il2cpp_size;
}
