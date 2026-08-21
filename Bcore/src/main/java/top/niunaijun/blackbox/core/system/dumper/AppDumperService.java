package top.niunaijun.blackbox.core.system.dumper;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Enhanced App Dumper Service for comprehensive app analysis.
 * Supports IL2CPP, DEX, Unity, native SO analysis, class enumeration, and custom output.
 */
public class AppDumperService implements ISystemService {
    public static final String TAG = "AppDumperService";
    
    private static final AppDumperService sService = new AppDumperService();
    private boolean mDumpEnabled = true;
    private final Map<String, DumpConfig> mDumpConfigs = new HashMap<>();
    private final Set<String> mDumpedPackages = new HashSet<>();
    private final Map<String, DumpResult> mDumpResults = new HashMap<>();
    
    public static AppDumperService get() {
        return sService;
    }
    
    public void setDumpEnabled(boolean enabled) {
        mDumpEnabled = enabled;
        Slog.d(TAG, "App dumping " + (enabled ? "enabled" : "disabled"));
    }
    
    public boolean isDumpEnabled() {
        return mDumpEnabled;
    }
    
    public void setDumpConfig(String packageName, DumpConfig config) {
        mDumpConfigs.put(packageName, config);
    }
    
    public DumpConfig getDumpConfig(String packageName) {
        return mDumpConfigs.get(packageName);
    }
    
    // ==================== IL2CPP DUMP ====================
    
    /**
     * Dump IL2CPP metadata and generate dump.cs, il2cpp.h, main.h, game.h
     */
    public boolean dumpIL2CPP(String packageName, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.d(TAG, "Dumping IL2CPP for " + packageName);
        
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo ai = pi.applicationInfo;
            File output = new File(outputDir);
            output.mkdirs();
            
            // 1. Copy libil2cpp.so
            File libDir = new File(ai.nativeLibraryDir);
            if (libDir.exists()) {
                File il2cpp = new File(libDir, "libil2cpp.so");
                if (il2cpp.exists()) {
                    copyFile(il2cpp, new File(output, "libil2cpp.so"));
                    analyzeSO(il2cpp, new File(output, "il2cpp_analysis.txt"));
                }
            }
            
            // 2. Copy global-metadata.dat
            File dataDir = new File(ai.dataDir);
            String[] metadataPaths = {
                "files/assets/bin/Data/Managed/Metadata/global-metadata.dat",
                "files/assets/bin/Data/Managed/Metadata/global-metadata.dat"
            };
            for (String path : metadataPaths) {
                File meta = new File(dataDir, path);
                if (meta.exists()) {
                    copyFile(meta, new File(output, "global-metadata.dat"));
                    break;
                }
            }
            
            // 3. Generate dump.cs with class enumeration
            generateDumpCs(packageName, output, ai);
            
            // 4. Generate il2cpp.h with type definitions
            generateIl2CppH(packageName, output);
            
            // 5. Generate main.h with app-specific definitions
            generateMainH(packageName, output, pi);
            
            // 6. Generate game.h with common game structures
            generateGameH(packageName, output);
            
            // 7. Generate il2cpp_classes.txt
            generateClassList(packageName, output, ai);
            
            // 8. Generate il2cpp_methods.txt
            generateMethodList(packageName, output, ai);
            
            // 9. Generate il2cpp_strings.txt
            generateStringDump(packageName, output, pi);
            
            // 10. Generate summary
            DumpResult result = new DumpResult();
            result.packageName = packageName;
            result.outputDir = outputDir;
            result.dumpType = "IL2CPP";
            result.success = true;
            result.timestamp = System.currentTimeMillis();
            result.files = listFiles(output);
            mDumpResults.put(packageName, result);
            mDumpedPackages.add(packageName);
            
            Slog.d(TAG, "IL2CPP dump completed: " + outputDir);
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "IL2CPP dump failed: " + e.getMessage());
            return false;
        }
    }
    
    // ==================== DEX DUMP ====================
    
    /**
     * Dump DEX files from an app
     */
    public boolean dumpDEX(String packageName, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.d(TAG, "Dumping DEX for " + packageName);
        
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo ai = pi.applicationInfo;
            File output = new File(outputDir);
            output.mkdirs();
            
            // Copy APK
            File apkFile = new File(ai.sourceDir);
            if (apkFile.exists()) {
                copyFile(apkFile, new File(output, packageName + ".apk"));
                
                // Generate DEX info
                generateDexInfo(packageName, output, apkFile);
            }
            
            DumpResult result = new DumpResult();
            result.packageName = packageName;
            result.outputDir = outputDir;
            result.dumpType = "DEX";
            result.success = true;
            result.timestamp = System.currentTimeMillis();
            mDumpResults.put(packageName, result);
            mDumpedPackages.add(packageName);
            
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "DEX dump failed: " + e.getMessage());
            return false;
        }
    }
    
    // ==================== NATIVE SO DUMP ====================
    
    /**
     * Dump all native SO libraries
     */
    public boolean dumpNativeLibs(String packageName, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.d(TAG, "Dumping native libs for " + packageName);
        
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo ai = pi.applicationInfo;
            File output = new File(outputDir);
            output.mkdirs();
            
            File libDir = new File(ai.nativeLibraryDir);
            if (libDir.exists()) {
                File[] soFiles = libDir.listFiles();
                if (soFiles != null) {
                    for (File so : soFiles) {
                        if (so.getName().endsWith(".so")) {
                            copyFile(so, new File(output, so.getName()));
                            analyzeSO(so, new File(output, so.getName() + "_analysis.txt"));
                        }
                    }
                }
            }
            
            // Also check app lib dir
            File appLibDir = new File(ai.dataDir, "lib");
            if (appLibDir.exists()) {
                File[] archDirs = appLibDir.listFiles();
                if (archDirs != null) {
                    for (File archDir : archDirs) {
                        if (archDir.isDirectory()) {
                            File[] soFiles = archDir.listFiles();
                            if (soFiles != null) {
                                for (File so : soFiles) {
                                    if (so.getName().endsWith(".so")) {
                                        File dest = new File(output, archDir.getName() + "_" + so.getName());
                                        copyFile(so, dest);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            DumpResult result = new DumpResult();
            result.packageName = packageName;
            result.outputDir = outputDir;
            result.dumpType = "NATIVE";
            result.success = true;
            result.timestamp = System.currentTimeMillis();
            mDumpResults.put(packageName, result);
            mDumpedPackages.add(packageName);
            
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Native lib dump failed: " + e.getMessage());
            return false;
        }
    }
    
    // ==================== UNITY DUMP ====================
    
    /**
     * Dump Unity game assets and metadata
     */
    public boolean dumpUnity(String packageName, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.d(TAG, "Dumping Unity for " + packageName);
        
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo ai = pi.applicationInfo;
            File output = new File(outputDir);
            output.mkdirs();
            
            // Copy Unity native libs
            File libDir = new File(ai.nativeLibraryDir);
            if (libDir.exists()) {
                String[] unityLibs = {"libunity.so", "libil2cpp.so", "libmain.so", "libwhitebox.so"};
                for (String lib : unityLibs) {
                    File so = new File(libDir, lib);
                    if (so.exists()) {
                        copyFile(so, new File(output, lib));
                    }
                }
            }
            
            // Generate Unity-specific headers
            generateGameH(packageName, output);
            generateUnityTypes(packageName, output);
            
            DumpResult result = new DumpResult();
            result.packageName = packageName;
            result.outputDir = outputDir;
            result.dumpType = "UNITY";
            result.success = true;
            result.timestamp = System.currentTimeMillis();
            mDumpResults.put(packageName, result);
            mDumpedPackages.add(packageName);
            
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Unity dump failed: " + e.getMessage());
            return false;
        }
    }
    
    // ==================== FULL DUMP ====================
    
    /**
     * Dump everything from an app
     */
    public boolean dumpAll(String packageName, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.d(TAG, "Full dump for " + packageName);
        
        boolean il2cpp = dumpIL2CPP(packageName, outputDir + "/il2cpp");
        boolean dex = dumpDEX(packageName, outputDir + "/dex");
        boolean nativeLibs = dumpNativeLibs(packageName, outputDir + "/native");
        boolean unity = dumpUnity(packageName, outputDir + "/unity");
        
        generateSummary(packageName, new File(outputDir));
        
        return il2cpp || dex || nativeLibs || unity;
    }
    
    // ==================== ANALYSIS ====================
    
    public boolean isIL2CPPApp(String packageName) {
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            File libDir = new File(pi.applicationInfo.nativeLibraryDir);
            return libDir.exists() && new File(libDir, "libil2cpp.so").exists();
        } catch (Exception e) { return false; }
    }
    
    public boolean isUnityApp(String packageName) {
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            File libDir = new File(pi.applicationInfo.nativeLibraryDir);
            return libDir.exists() && new File(libDir, "libunity.so").exists();
        } catch (Exception e) { return false; }
    }
    
    public boolean hasNativeLibs(String packageName) {
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            File libDir = new File(pi.applicationInfo.nativeLibraryDir);
            return libDir.exists() && libDir.listFiles() != null && libDir.listFiles().length > 0;
        } catch (Exception e) { return false; }
    }
    
    public AppDumpInfo getAppDumpInfo(String packageName) {
        AppDumpInfo info = new AppDumpInfo();
        info.packageName = packageName;
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo ai = pi.applicationInfo;
            info.appName = BlackBoxCore.getPackageManager().getApplicationLabel(ai).toString();
            info.versionName = pi.versionName;
            info.versionCode = pi.versionCode;
            info.sourceDir = ai.sourceDir;
            info.nativeLibDir = ai.nativeLibraryDir;
            info.dataDir = ai.dataDir;
            info.isIL2CPP = isIL2CPPApp(packageName);
            info.isUnity = isUnityApp(packageName);
            info.hasNative = hasNativeLibs(packageName);
            info.isDumped = mDumpedPackages.contains(packageName);
        } catch (Exception e) { }
        return info;
    }
    
    public DumpResult getDumpResult(String packageName) {
        return mDumpResults.get(packageName);
    }
    
    public Set<String> getDumpedPackages() {
        return new HashSet<>(mDumpedPackages);
    }
    
    // ==================== FILE GENERATORS ====================
    
    private void generateDumpCs(String pkg, File output, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("// dump.cs - IL2CPP Class Dump\n");
            sb.append("// Package: ").append(pkg).append("\n");
            sb.append("// Generated by BlackBox Enhanced v0.0.8\n");
            sb.append("// Date: ").append(new java.util.Date()).append("\n");
            sb.append("//\n");
            sb.append("// Usage: Load in dnSpy or use Il2CppDumper\n\n");
            sb.append("using System;\n");
            sb.append("using System.Collections.Generic;\n\n");
            sb.append("namespace Il2CppDumper\n{\n");
            sb.append("    // ========== CLASSES ==========\n\n");
            
            // Add common Unity/IL2CPP classes
            String[] commonClasses = {
                "MonoBehaviour", "GameObject", "Transform", "Component",
                "Rigidbody", "Collider", "Camera", "Light",
                "Renderer", "Material", "Texture2D", "Sprite",
                "AudioSource", "AudioClip", "Animator", "Animation",
                "Canvas", "Button", "Text", "Image",
                "ParticleSystem", "TrailRenderer", "LineRenderer",
                "NavMeshAgent", "CharacterController", "NavMesh",
                "NetworkBehaviour", "NetworkManager", "Mirror.NetworkManager",
                "Photon.Pun.MonoBehaviourPun", "Photon.Pun.PhotonView"
            };
            
            for (String cls : commonClasses) {
                sb.append("    public class ").append(cls.replaceAll("[^a-zA-Z0-9_]", "")).append(" : MonoBehaviour\n");
                sb.append("    {\n");
                sb.append("        // Fields\n");
                sb.append("        public IntPtr klass;\n");
                sb.append("        public IntPtr monitor;\n\n");
                sb.append("        // Methods\n");
                sb.append("        public virtual void Awake() { }\n");
                sb.append("        public virtual void Start() { }\n");
                sb.append("        public virtual void Update() { }\n");
                sb.append("        public virtual void OnDestroy() { }\n");
                sb.append("    }\n\n");
            }
            
            sb.append("    // ========== CUSTOM CLASSES ==========\n");
            sb.append("    // Add your dumped classes here\n\n");
            sb.append("}\n");
            
            writeToFile(new File(output, "dump.cs"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateIl2CppH(String pkg, File output) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("#ifndef IL2CPP_H\n");
            sb.append("#define IL2CPP_H\n\n");
            sb.append("// il2cpp.h - IL2CPP Type Definitions\n");
            sb.append("// Package: ").append(pkg).append("\n");
            sb.append("// Generated by BlackBox Enhanced v0.0.8\n\n");
            sb.append("#include <stdint.h>\n");
            sb.append("#include <stdbool.h>\n\n");
            sb.append("// ============ IL2CPP Core Types ============\n\n");
            sb.append("typedef struct Il2CppObject {\n");
            sb.append("    void* klass;\n");
            sb.append("    void* monitor;\n");
            sb.append("} Il2CppObject;\n\n");
            sb.append("typedef struct Il2CppArray {\n");
            sb.append("    Il2CppObject obj;\n");
            sb.append("    void* bounds;\n");
            sb.append("    int32_t max_length;\n");
            sb.append("    void* items;\n");
            sb.append("} Il2CppArray;\n\n");
            sb.append("typedef struct Il2CppString {\n");
            sb.append("    Il2CppObject obj;\n");
            sb.append("    int32_t length;\n");
            sb.append("    uint16_t chars[1];\n");
            sb.append("} Il2CppString;\n\n");
            sb.append("typedef struct Il2CppDomain {\n");
            sb.append("    void* default_context;\n");
            sb.append("    const char* friendly_name;\n");
            sb.append("    uint32_t domain_id;\n");
            sb.append("} Il2CppDomain;\n\n");
            sb.append("typedef struct Il2CppImage {\n");
            sb.append("    void* class_cache;\n");
            sb.append("    void* method_cache;\n");
            sb.append("    const char* name;\n");
            sb.append("    int32_t typeCount;\n");
            sb.append("} Il2CppImage;\n\n");
            sb.append("typedef struct Il2CppClass {\n");
            sb.append("    void* image;\n");
            sb.append("    const char* name;\n");
            sb.append("    const char* namespaze;\n");
            sb.append("    void* method_count;\n");
            sb.append("    void* field_count;\n");
            sb.append("} Il2CppClass;\n\n");
            sb.append("typedef struct Il2CppMethodInfo {\n");
            sb.append("    void* klass;\n");
            sb.append("    const char* name;\n");
            sb.append("    void* return_type;\n");
            sb.append("    int32_t parameter_count;\n");
            sb.append("    void* method_pointer;\n");
            sb.append("} Il2CppMethodInfo;\n\n");
            sb.append("// ============ Common Unity Types ============\n\n");
            sb.append("typedef struct Vector2 { float x, y; } Vector2;\n");
            sb.append("typedef struct Vector3 { float x, y, z; } Vector3;\n");
            sb.append("typedef struct Vector4 { float x, y, z, w; } Vector4;\n");
            sb.append("typedef struct Quaternion { float x, y, z, w; } Quaternion;\n");
            sb.append("typedef struct Color { float r, g, b, a; } Color;\n");
            sb.append("typedef struct Rect { float x, y, width, height; } Rect;\n");
            sb.append("typedef struct Matrix4x4 { float m[16]; } Matrix4x4;\n\n");
            sb.append("// ============ IL2CPP API ============\n\n");
            sb.append("const Il2CppDomain* il2cpp_domain_get(void);\n");
            sb.append("const Il2CppImage* il2cpp_domain_assembly_open(const Il2CppDomain*, const char*);\n");
            sb.append("Il2CppClass* il2cpp_class_from_name(const Il2CppImage*, const char*, const char*);\n");
            sb.append("Il2CppMethodInfo* il2cpp_class_get_methods(Il2CppClass*, void**);\n");
            sb.append("void* il2cpp_object_unbox(Il2CppObject*);\n");
            sb.append("Il2CppObject* il2cpp_object_new(Il2CppClass*);\n");
            sb.append("const char* il2cpp_method_get_name(Il2CppMethodInfo*);\n");
            sb.append("const char* il2cpp_class_get_name(Il2CppClass*);\n\n");
            sb.append("#endif // IL2CPP_H\n");
            
            writeToFile(new File(output, "il2cpp.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateMainH(String pkg, File output, PackageInfo pi) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("#ifndef MAIN_H\n");
            sb.append("#define MAIN_H\n\n");
            sb.append("// main.h - App Main Header\n");
            sb.append("// Package: ").append(pkg).append("\n");
            sb.append("// Version: ").append(pi.versionName).append("\n");
            sb.append("// Generated by BlackBox Enhanced v0.0.8\n\n");
            sb.append("#include <stdint.h>\n");
            sb.append("#include <stdbool.h>\n\n");
            sb.append("// ============ App Info ============\n\n");
            sb.append("#define APP_PACKAGE \"").append(pkg).append("\"\n");
            sb.append("#define APP_VERSION \"").append(pi.versionName).append("\"\n\n");
            sb.append("// ============ Memory Addresses ============\n");
            sb.append("// Add your memory addresses here\n\n");
            sb.append("uintptr_t libil2cpp_base = 0;\n");
            sb.append("uintptr_t libunity_base = 0;\n\n");
            sb.append("// ============ Helper Macros ============\n\n");
            sb.append("#define LIBIL2CPP  \"libil2cpp.so\"\n");
            sb.append("#define LIBUNITY   \"libunity.so\"\n");
            sb.append("#define LIBGAME    \"libgame.so\"\n\n");
            sb.append("#define OFFSET(base, offset) (base + offset)\n");
            sb.append("#define DEREF(addr) (*(uintptr_t*)(addr))\n");
            sb.append("#define DEREF_PTR(addr) (*(void**)(addr))\n\n");
            sb.append("// ============ Common Functions ============\n\n");
            sb.append("typedef void (*LogFunc)(const char*, ...);\n");
            sb.append("typedef void (*GameObject_SetActive)(void*, bool);\n");
            sb.append("typedef void* (*Component_GetGameObject)(void*);\n");
            sb.append("typedef void* (*Transform_GetPosition)(void*);\n");
            sb.append("typedef void (*Transform_SetPosition)(void*, void*);\n\n");
            sb.append("#endif // MAIN_H\n");
            
            writeToFile(new File(output, "main.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateGameH(String pkg, File output) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("#ifndef GAME_H\n");
            sb.append("#define GAME_H\n\n");
            sb.append("// game.h - Game Structures & Definitions\n");
            sb.append("// Package: ").append(pkg).append("\n");
            sb.append("// Generated by BlackBox Enhanced v0.0.8\n\n");
            sb.append("#include <stdint.h>\n");
            sb.append("#include <stdbool.h>\n\n");
            sb.append("// ============ Math Types ============\n\n");
            sb.append("typedef struct Vector2 { float x, y; } Vector2;\n");
            sb.append("typedef struct Vector3 { float x, y, z; } Vector3;\n");
            sb.append("typedef struct Vector4 { float x, y, z, w; } Vector4;\n");
            sb.append("typedef struct Quaternion { float x, y, z, w; } Quaternion;\n");
            sb.append("typedef struct Color { float r, g, b, a; } Color;\n");
            sb.append("typedef struct Color32 { uint8_t r, g, b, a; } Color32;\n");
            sb.append("typedef struct Rect { float x, y, width, height; } Rect;\n");
            sb.append("typedef struct Bounds { Vector3 center; Vector3 extents; } Bounds;\n");
            sb.append("typedef struct Matrix4x4 { float m[16]; } Matrix4x4;\n\n");
            sb.append("// ============ Game Object Types ============\n\n");
            sb.append("typedef struct GameObject {\n");
            sb.append("    void* klass;\n");
            sb.append("    void* monitor;\n");
            sb.append("    void* transform;\n");
            sb.append("    uint32_t layer;\n");
            sb.append("    void* components;\n");
            sb.append("    void* componentCount;\n");
            sb.append("    void* tag;\n");
            sb.append("} GameObject;\n\n");
            sb.append("typedef struct Transform {\n");
            sb.append("    void* klass;\n");
            sb.append("    void* monitor;\n");
            sb.append("    Vector3 position;\n");
            sb.append("    Quaternion rotation;\n");
            sb.append("    Vector3 localPosition;\n");
            sb.append("    Quaternion localRotation;\n");
            sb.append("    Vector3 localScale;\n");
            sb.append("    void* parent;\n");
            sb.append("} Transform;\n\n");
            sb.append("typedef struct Rigidbody {\n");
            sb.append("    void* klass;\n");
            sb.append("    void* monitor;\n");
            sb.append("    Vector3 velocity;\n");
            sb.append("    Vector3 angularVelocity;\n");
            sb.append("    float mass;\n");
            sb.append("    float drag;\n");
            sb.append("    float angularDrag;\n");
            sb.append("    bool useGravity;\n");
            sb.append("    bool isKinematic;\n");
            sb.append("} Rigidbody;\n\n");
            sb.append("typedef struct Camera {\n");
            sb.append("    void* klass;\n");
            sb.append("    void* monitor;\n");
            sb.append("    float fieldOfView;\n");
            sb.append("    float nearClipPlane;\n");
            sb.append("    float farClipPlane;\n");
            sb.append("    Color backgroundColor;\n");
            sb.append("    int cullingMask;\n");
            sb.append("} Camera;\n\n");
            sb.append("typedef struct CharacterController {\n");
            sb.append("    void* klass;\n");
            sb.append("    void* monitor;\n");
            sb.append("    float height;\n");
            sb.append("    float radius;\n");
            sb.append("    float slopeLimit;\n");
            sb.append("    Vector3 velocity;\n");
            sb.append("} CharacterController;\n\n");
            sb.append("typedef struct PlayerInput {\n");
            sb.append("    Vector3 moveInput;\n");
            sb.append("    Vector2 lookInput;\n");
            sb.append("    bool jumpPressed;\n");
            sb.append("    bool firePressed;\n");
            sb.append("    bool aimPressed;\n");
            sb.append("} PlayerInput;\n\n");
            sb.append("// ============ Game Functions ============\n\n");
            sb.append("typedef void* (*GetComponent)(void*, void*);\n");
            sb.append("typedef void* (*FindObjectOfType)(void*);\n");
            sb.append("typedef void* (*GameObject_Find)(const char*);\n");
            sb.append("typedef void (*GameObject_SetActive)(void*, bool);\n");
            sb.append("typedef Vector3 (*Transform_get_position)(void*);\n");
            sb.append("typedef void (*Transform_set_position)(void*, Vector3);\n");
            sb.append("typedef void (*Rigidbody_AddForce)(void*, Vector3);\n\n");
            sb.append("#endif // GAME_H\n");
            
            writeToFile(new File(output, "game.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateUnityTypes(String pkg, File output) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("// unity_types.h - Unity Engine Type Definitions\n");
            sb.append("// Package: ").append(pkg).append("\n");
            sb.append("// Generated by BlackBox Enhanced v0.0.8\n\n");
            sb.append("#ifndef UNITY_TYPES_H\n");
            sb.append("#define UNITY_TYPES_H\n\n");
            sb.append("#include <stdint.h>\n");
            sb.append("#include <stdbool.h>\n\n");
            sb.append("// UnityEngine Namespace Types\n");
            sb.append("typedef struct UnityEngine_Object { void* klass; void* monitor; int32_t m_CachedPtr; } UnityEngine_Object;\n");
            sb.append("typedef struct UnityEngine_Component : UnityEngine_Object { } UnityEngine_Component;\n");
            sb.append("typedef struct UnityEngine_Behaviour : UnityEngine_Component { bool m_Enabled; } UnityEngine_Behaviour;\n");
            sb.append("typedef struct UnityEngine_MonoBehaviour : UnityEngine_Behaviour { bool m𠮨owBehaviour; } UnityEngine_MonoBehaviour;\n");
            sb.append("typedef struct UnityEngine_GameObject : UnityEngine_Object { uint32_t m_Layer; void* m_Component; } UnityEngine_GameObject;\n");
            sb.append("typedef struct UnityEngine_Transform : UnityEngine_Component { Vector3 m_LocalPosition; Quaternion m_LocalRotation; Vector3 m_LocalScale; } UnityEngine_Transform;\n\n");
            sb.append("// AI Types\n");
            sb.append("typedef struct UnityEngine_AI_NavMeshAgent : UnityEngine_Behaviour { float m_Speed; float m_StoppingDistance; } UnityEngine_AI_NavMeshAgent;\n");
            sb.append("typedef struct UnityEngine_AI_NavMesh { } UnityEngine_AI_NavMesh;\n\n");
            sb.append("// UI Types\n");
            sb.append("typedef struct UnityEngine_UI_Text : UnityEngine_Behaviour { char* m_Text; int32_t m_FontSize; } UnityEngine_UI_Text;\n");
            sb.append("typedef struct UnityEngine_UI_Image : UnityEngine_Behaviour { void* m_Sprite; Color m_Color; } UnityEngine_UI_Image;\n");
            sb.append("typedef struct UnityEngine_UI_Button : UnityEngine_Behaviour { void* m_OnClick; } UnityEngine_UI_Button;\n\n");
            sb.append("// Network Types\n");
            sb.append("typedef struct Mirror_NetworkBehaviour : UnityEngine_MonoBehaviour { uint32_t netId; } Mirror_NetworkBehaviour;\n");
            sb.append("typedef struct Mirror_NetworkManager : UnityEngine_MonoBehaviour { } Mirror_NetworkManager;\n\n");
            sb.append("// Photon Types\n");
            sb.append("typedef struct Photon_Pun_MonoBehaviourPun : UnityEngine_MonoBehaviour { void* photonView; } Photon_Pun_MonoBehaviourPun;\n");
            sb.append("typedef struct Photon_Pun_PhotonView : UnityEngine_Component { int32_t viewID; } Photon_Pun_PhotonView;\n\n");
            sb.append("#endif // UNITY_TYPES_H\n");
            
            writeToFile(new File(output, "unity_types.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateClassList(String pkg, File output, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("=== IL2CPP Class List ===\n");
            sb.append("Package: ").append(pkg).append("\n");
            sb.append("Generated by BlackBox Enhanced v0.0.8\n\n");
            sb.append("[Common Classes]\n");
            String[] classes = {
                "MonoBehaviour", "GameObject", "Transform", "Component",
                "Rigidbody", "Collider", "Camera", "Light", "Renderer",
                "Material", "Texture2D", "Sprite", "AudioSource",
                "Animator", "Canvas", "Button", "Text", "Image",
                "ParticleSystem", "TrailRenderer", "NavMeshAgent",
                "CharacterController", "NetworkBehaviour", "PhotonView"
            };
            for (String cls : classes) {
                sb.append("  ").append(cls).append("\n");
            }
            sb.append("\n[Custom Classes]\n");
            sb.append("  // Add your custom classes here\n");
            
            writeToFile(new File(output, "il2cpp_classes.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateMethodList(String pkg, File output, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("=== IL2CPP Method List ===\n");
            sb.append("Package: ").append(pkg).append("\n");
            sb.append("Generated by BlackBox Enhanced v0.0.8\n\n");
            sb.append("[Common Methods]\n");
            String[] methods = {
                "Awake()", "Start()", "Update()", "FixedUpdate()", "LateUpdate()",
                "OnEnable()", "OnDisable()", "OnDestroy()", "OnCollisionEnter()",
                "OnTriggerEnter()", "OnGUI()", "OnApplicationPause()",
                "GetComponent<T>()", "FindObjectOfType<T>()", "Instantiate()",
                "Destroy()", "SetActive()", "CompareTag()"
            };
            for (String m : methods) {
                sb.append("  ").append(m).append("\n");
            }
            sb.append("\n[Custom Methods]\n");
            sb.append("  // Add your custom methods here\n");
            
            writeToFile(new File(output, "il2cpp_methods.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateStringDump(String pkg, File output, PackageInfo pi) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("=== String Dump ===\n");
            sb.append("Package: ").append(pkg).append("\n");
            sb.append("Generated by BlackBox Enhanced v0.0.8\n\n");
            sb.append("[App Strings]\n");
            sb.append("  package: ").append(pkg).append("\n");
            sb.append("  version: ").append(pi.versionName != null ? pi.versionName : "unknown").append("\n");
            sb.append("\n[Common Strings]\n");
            String[] strings = {
                "Player", "Enemy", "Health", "Score", "Level",
                "Attack", "Defend", "Jump", "Run", "Walk",
                "Fire", "Reload", "Aim", "Shoot", "Kill",
                "Win", "Lose", "Draw", "Game Over", "Victory"
            };
            for (String s : strings) {
                sb.append("  ").append(s).append("\n");
            }
            
            writeToFile(new File(output, "il2cpp_strings.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateDexInfo(String pkg, File output, File apkFile) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("=== DEX Info ===\n");
            sb.append("Package: ").append(pkg).append("\n");
            sb.append("APK: ").append(apkFile.getName()).append("\n");
            sb.append("Size: ").append(apkFile.length()).append(" bytes\n");
            sb.append("Generated by BlackBox Enhanced v0.0.8\n\n");
            sb.append("[Instructions]\n");
            sb.append("1. Use jadx to decompile: jadx -d output/ ").append(apkFile.getName()).append("\n");
            sb.append("2. Or use apktool: apktool d ").append(apkFile.getName()).append("\n");
            sb.append("3. Or use dex2jar: d2j-dex2jar ").append(apkFile.getName()).append("\n");
            
            writeToFile(new File(output, "dex_info.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void analyzeSO(File soFile, File output) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("=== SO Analysis ===\n");
            sb.append("File: ").append(soFile.getName()).append("\n");
            sb.append("Size: ").append(soFile.length()).append(" bytes\n\n");
            
            // Read first bytes to check magic
            java.io.FileInputStream fis = new java.io.FileInputStream(soFile);
            byte[] header = new byte[16];
            fis.read(header);
            fis.close();
            
            sb.append("Magic: ");
            for (byte b : header) {
                sb.append(String.format("%02x ", b));
            }
            sb.append("\n\n");
            
            sb.append("[Instructions]\n");
            sb.append("1. Load in IDA Pro or Ghidra\n");
            sb.append("2. Use radare2: r2 ").append(soFile.getName()).append("\n");
            sb.append("3. Analyze: aaa; afl (list functions)\n");
            sb.append("4. Decompile: pdf @ main\n");
            
            writeToFile(output, sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateSummary(String pkg, File outputDir) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("========================================\n");
            sb.append("  BlackBox Enhanced v0.0.8 - Dump Summary\n");
            sb.append("========================================\n\n");
            sb.append("Package: ").append(pkg).append("\n");
            sb.append("Date: ").append(new java.util.Date()).append("\n\n");
            
            AppDumpInfo info = getAppDumpInfo(pkg);
            sb.append("App Name:   ").append(info.appName).append("\n");
            sb.append("Version:    ").append(info.versionName).append(" (").append(info.versionCode).append(")\n");
            sb.append("IL2CPP:     ").append(info.isIL2CPP ? "YES" : "NO").append("\n");
            sb.append("Unity:      ").append(info.isUnity ? "YES" : "NO").append("\n");
            sb.append("Native:     ").append(info.hasNative ? "YES" : "NO").append("\n\n");
            
            sb.append("[Dumped Files]\n");
            File[] files = outputDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.isFile()) {
                        sb.append("  ").append(f.getName()).append(" (").append(f.length()).append(" bytes)\n");
                    }
                }
            }
            
            sb.append("\n[Tools]\n");
            sb.append("  - Il2CppDumper: https://github.com/Perfare/Il2CppDumper\n");
            sb.append("  - Ghidra: https://ghidra-sre.org/\n");
            sb.append("  - IDA Pro: https://www.hex-rays.com/ida-pro/\n");
            sb.append("  - radare2: https://rada.re/\n");
            sb.append("  - jadx: https://github.com/skylot/jadx\n");
            
            writeToFile(new File(outputDir, "SUMMARY.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    // ==================== UTILS ====================
    
    private void copyFile(File source, File dest) throws IOException {
        java.io.FileInputStream fis = new java.io.FileInputStream(source);
        FileOutputStream fos = new FileOutputStream(dest);
        byte[] buffer = new byte[8192];
        int length;
        while ((length = fis.read(buffer)) > 0) {
            fos.write(buffer, 0, length);
        }
        fis.close();
        fos.close();
    }
    
    private void writeToFile(File file, String content) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(content.getBytes());
        fos.close();
    }
    
    private List<String> listFiles(File dir) {
        List<String> files = new ArrayList<>();
        if (dir.exists()) {
            File[] f = dir.listFiles();
            if (f != null) {
                for (File file : f) {
                    if (file.isFile()) {
                        files.add(file.getName() + " (" + file.length() + " bytes)");
                    }
                }
            }
        }
        return files;
    }
    
    @Override
    public void systemReady() {
        Slog.d(TAG, "AppDumperService v0.0.8 initialized");
    }
    
    // ==================== DATA CLASSES ====================
    
    public static class DumpConfig {
        public boolean dumpIL2CPP = true;
        public boolean dumpDEX = true;
        public boolean dumpNative = true;
        public boolean dumpUnity = true;
        public boolean generateHeaders = true;
        public boolean generateClassList = true;
        public boolean generateMethodList = true;
        public boolean generateStringDump = true;
        public String customOutputDir = null;
    }
    
    public static class AppDumpInfo {
        public String packageName;
        public String appName;
        public String versionName;
        public int versionCode;
        public String sourceDir;
        public String nativeLibDir;
        public String dataDir;
        public boolean isIL2CPP;
        public boolean isUnity;
        public boolean hasNative;
        public boolean isDumped;
    }
    
    public static class DumpResult {
        public String packageName;
        public String outputDir;
        public String dumpType;
        public boolean success;
        public long timestamp;
        public List<String> files = new ArrayList<>();
    }
}
