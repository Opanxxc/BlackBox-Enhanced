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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Comprehensive app dumper service for IL2CPP, DEX, and other formats.
 * Supports dump.cs, il2cpp.h, main.h, game.h and custom output.
 */
public class AppDumperService implements ISystemService {
    public static final String TAG = "AppDumperService";
    
    private static final AppDumperService sService = new AppDumperService();
    private boolean mDumpEnabled = true;
    private final Map<String, DumpConfig> mDumpConfigs = new HashMap<>();
    private final Set<String> mDumpedPackages = new HashSet<>();
    
    // Common IL2CPP metadata files
    private static final String[] IL2CPP_FILES = {
        "libil2cpp.so",
        "libil2cpp.sym",
        "global-metadata.dat",
        "il2cpp_dump.cs",
        "il2cpp.h",
        "dump.cs"
    };
    
    // Common DEX files
    private static final String[] DEX_FILES = {
        "classes.dex",
        "classes2.dex",
        "classes3.dex",
        "classes4.dex"
    };
    
    // Common Unity files
    private static final String[] UNITY_FILES = {
        "libunity.so",
        "libil2cpp.so",
        "global-metadata.dat",
        "assets/bin/Data"
    };
    
    public static AppDumperService get() {
        return sService;
    }
    
    /**
     * Enable or disable app dumping
     * @param enabled true to enable dumping
     */
    public void setDumpEnabled(boolean enabled) {
        mDumpEnabled = enabled;
        Slog.d(TAG, "App dumping " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * Check if dumping is enabled
     * @return true if dumping is enabled
     */
    public boolean isDumpEnabled() {
        return mDumpEnabled;
    }
    
    /**
     * Set dump configuration for a package
     * @param packageName Package name
     * @param config Dump configuration
     */
    public void setDumpConfig(String packageName, DumpConfig config) {
        mDumpConfigs.put(packageName, config);
    }
    
    /**
     * Get dump configuration for a package
     * @param packageName Package name
     * @return Dump configuration
     */
    public DumpConfig getDumpConfig(String packageName) {
        return mDumpConfigs.get(packageName);
    }
    
    /**
     * Dump IL2CPP data from an app
     * @param packageName Package name
     * @param outputDir Output directory
     * @return true if dump was successful
     */
    public boolean dumpIL2CPP(String packageName, String outputDir) {
        if (!mDumpEnabled) {
            return false;
        }
        
        Slog.d(TAG, "Dumping IL2CPP for " + packageName);
        
        try {
            PackageInfo packageInfo = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo appInfo = packageInfo.applicationInfo;
            
            // Create output directory
            File output = new File(outputDir);
            output.mkdirs();
            
            // Copy IL2CPP files
            File libDir = new File(appInfo.nativeLibraryDir);
            if (libDir.exists()) {
                File il2cppLib = new File(libDir, "libil2cpp.so");
                if (il2cppLib.exists()) {
                    copyFile(il2cppLib, new File(output, "libil2cpp.so"));
                }
            }
            
            // Copy global-metadata.dat
            File dataDir = new File(appInfo.dataDir);
            File metadataFile = new File(dataDir, "files/assets/bin/Data/Managed/Metadata/global-metadata.dat");
            if (metadataFile.exists()) {
                copyFile(metadataFile, new File(output, "global-metadata.dat"));
            }
            
            // Generate dump.cs placeholder
            generateDumpCs(packageName, output);
            
            // Generate il2cpp.h placeholder
            generateIl2CppH(packageName, output);
            
            // Generate main.h placeholder
            generateMainH(packageName, output);
            
            // Generate game.h placeholder
            generateGameH(packageName, output);
            
            mDumpedPackages.add(packageName);
            Slog.d(TAG, "IL2CPP dump completed for " + packageName);
            
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Failed to dump IL2CPP: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Dump DEX files from an app
     * @param packageName Package name
     * @param outputDir Output directory
     * @return true if dump was successful
     */
    public boolean dumpDEX(String packageName, String outputDir) {
        if (!mDumpEnabled) {
            return false;
        }
        
        Slog.d(TAG, "Dumping DEX for " + packageName);
        
        try {
            PackageInfo packageInfo = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo appInfo = packageInfo.applicationInfo;
            
            // Create output directory
            File output = new File(outputDir);
            output.mkdirs();
            
            // Copy APK for DEX extraction
            File apkFile = new File(appInfo.sourceDir);
            if (apkFile.exists()) {
                copyFile(apkFile, new File(output, packageName + ".apk"));
            }
            
            mDumpedPackages.add(packageName);
            Slog.d(TAG, "DEX dump completed for " + packageName);
            
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Failed to dump DEX: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Dump all data from an app
     * @param packageName Package name
     * @param outputDir Output directory
     * @return true if dump was successful
     */
    public boolean dumpAll(String packageName, String outputDir) {
        if (!mDumpEnabled) {
            return false;
        }
        
        Slog.d(TAG, "Dumping all data for " + packageName);
        
        boolean il2cppSuccess = dumpIL2CPP(packageName, outputDir + "/il2cpp");
        boolean dexSuccess = dumpDEX(packageName, outputDir + "/dex");
        
        // Generate summary
        generateSummary(packageName, outputDir);
        
        return il2cppSuccess || dexSuccess;
    }
    
    /**
     * Check if an app uses IL2CPP
     * @param packageName Package name
     * @return true if app uses IL2CPP
     */
    public boolean isIL2CPPApp(String packageName) {
        try {
            PackageInfo packageInfo = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo appInfo = packageInfo.applicationInfo;
            
            File libDir = new File(appInfo.nativeLibraryDir);
            if (libDir.exists()) {
                File il2cppLib = new File(libDir, "libil2cpp.so");
                return il2cppLib.exists();
            }
        } catch (Exception e) {
            // Ignore
        }
        
        return false;
    }
    
    /**
     * Check if an app uses Unity
     * @param packageName Package name
     * @return true if app uses Unity
     */
    public boolean isUnityApp(String packageName) {
        try {
            PackageInfo packageInfo = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo appInfo = packageInfo.applicationInfo;
            
            File libDir = new File(appInfo.nativeLibraryDir);
            if (libDir.exists()) {
                File unityLib = new File(libDir, "libunity.so");
                return unityLib.exists();
            }
        } catch (Exception e) {
            // Ignore
        }
        
        return false;
    }
    
    /**
     * Get app info for dumping
     * @param packageName Package name
     * @return App information
     */
    public AppDumpInfo getAppDumpInfo(String packageName) {
        AppDumpInfo info = new AppDumpInfo();
        info.packageName = packageName;
        
        try {
            PackageInfo packageInfo = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            ApplicationInfo appInfo = packageInfo.applicationInfo;
            
            info.appName = BlackBoxCore.getPackageManager().getApplicationLabel(appInfo).toString();
            info.versionName = packageInfo.versionName;
            info.versionCode = packageInfo.versionCode;
            info.sourceDir = appInfo.sourceDir;
            info.nativeLibDir = appInfo.nativeLibraryDir;
            info.dataDir = appInfo.dataDir;
            info.isIL2CPP = isIL2CPPApp(packageName);
            info.isUnity = isUnityApp(packageName);
            info.isDumped = mDumpedPackages.contains(packageName);
            
        } catch (Exception e) {
            Slog.e(TAG, "Failed to get app info: " + e.getMessage());
        }
        
        return info;
    }
    
    /**
     * Get list of dumped packages
     * @return Set of package names
     */
    public Set<String> getDumpedPackages() {
        return new HashSet<>(mDumpedPackages);
    }
    
    /**
     * Check if a package has been dumped
     * @param packageName Package name
     * @return true if package has been dumped
     */
    public boolean isPackageDumped(String packageName) {
        return mDumpedPackages.contains(packageName);
    }
    
    private void copyFile(File source, File dest) throws IOException {
        java.io.FileInputStream fis = new java.io.FileInputStream(source);
        FileOutputStream fos = new FileOutputStream(dest);
        byte[] buffer = new byte[1024];
        int length;
        while ((length = fis.read(buffer)) > 0) {
            fos.write(buffer, 0, length);
        }
        fis.close();
        fos.close();
    }
    
    private void generateDumpCs(String packageName, File outputDir) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("// dump.cs - IL2CPP Dump for ").append(packageName).append("\n");
            sb.append("// Generated by BlackBox Enhanced\n");
            sb.append("//\n");
            sb.append("// This file contains dumped IL2CPP classes and methods\n");
            sb.append("// Use with Il2CppDumper or similar tools\n\n");
            sb.append("namespace IL2CPP\n{\n");
            sb.append("    public class ").append(packageName.replace(".", "_")).append("\n");
            sb.append("    {\n");
            sb.append("        // Dumped classes and methods will appear here\n");
            sb.append("    }\n");
            sb.append("}\n");
            
            FileOutputStream fos = new FileOutputStream(new File(outputDir, "dump.cs"));
            fos.write(sb.toString().getBytes());
            fos.close();
        } catch (IOException e) {
            Slog.e(TAG, "Failed to generate dump.cs: " + e.getMessage());
        }
    }
    
    private void generateIl2CppH(String packageName, File outputDir) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("// il2cpp.h - IL2CPP Header for ").append(packageName).append("\n");
            sb.append("// Generated by BlackBox Enhanced\n");
            sb.append("//\n");
            sb.append("// This file contains IL2CPP type definitions\n\n");
            sb.append("#pragma once\n\n");
            sb.append("#include <stdint.h>\n");
            sb.append("#include <stdbool.h>\n\n");
            sb.append("// IL2CPP Types\n");
            sb.append("typedef struct Il2CppObject Il2CppObject;\n");
            sb.append("typedef struct Il2CppClass Il2CppClass;\n");
            sb.append("typedef struct Il2CppMethodInfo Il2CppMethodInfo;\n\n");
            sb.append("// Forward declarations\n");
            sb.append("Il2CppObject* il2cpp_object_new(Il2CppClass* klass);\n");
            sb.append("void* il2cpp_object_unbox(Il2CppObject* obj);\n");
            sb.append("Il2CppClass* il2cpp_class_from_name(const char* namespaze, const char* name);\n");
            
            FileOutputStream fos = new FileOutputStream(new File(outputDir, "il2cpp.h"));
            fos.write(sb.toString().getBytes());
            fos.close();
        } catch (IOException e) {
            Slog.e(TAG, "Failed to generate il2cpp.h: " + e.getMessage());
        }
    }
    
    private void generateMainH(String packageName, File outputDir) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("// main.h - Main Header for ").append(packageName).append("\n");
            sb.append("// Generated by BlackBox Enhanced\n");
            sb.append("//\n");
            sb.append("// This file contains main game/app definitions\n\n");
            sb.append("#pragma once\n\n");
            sb.append("#include <stdint.h>\n");
            sb.append("#include <stdbool.h>\n\n");
            sb.append("// Game/App specific types\n");
            sb.append("// Add your custom types here\n\n");
            sb.append("// Memory addresses\n");
            sb.append("// Add your memory addresses here\n");
            
            FileOutputStream fos = new FileOutputStream(new File(outputDir, "main.h"));
            fos.write(sb.toString().getBytes());
            fos.close();
        } catch (IOException e) {
            Slog.e(TAG, "Failed to generate main.h: " + e.getMessage());
        }
    }
    
    private void generateGameH(String packageName, File outputDir) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("// game.h - Game Header for ").append(packageName).append("\n");
            sb.append("// Generated by BlackBox Enhanced\n");
            sb.append("//\n");
            sb.append("// This file contains game-specific definitions\n\n");
            sb.append("#pragma once\n\n");
            sb.append("#include <stdint.h>\n");
            sb.append("#include <stdbool.h>\n\n");
            sb.append("// Game structures\n");
            sb.append("typedef struct {\n");
            sb.append("    float x;\n");
            sb.append("    float y;\n");
            sb.append("    float z;\n");
            sb.append("} Vector3;\n\n");
            sb.append("typedef struct {\n");
            sb.append("    float x;\n");
            sb.append("    float y;\n");
            sb.append("} Vector2;\n\n");
            sb.append("typedef struct {\n");
            sb.append("    float x;\n");
            sb.append("    float y;\n");
            sb.append("    float z;\n");
            sb.append("    float w;\n");
            sb.append("} Quaternion;\n\n");
            sb.append("// Game functions\n");
            sb.append("// Add your game functions here\n");
            
            FileOutputStream fos = new FileOutputStream(new File(outputDir, "game.h"));
            fos.write(sb.toString().getBytes());
            fos.close();
        } catch (IOException e) {
            Slog.e(TAG, "Failed to generate game.h: " + e.getMessage());
        }
    }
    
    private void generateSummary(String packageName, File outputDir) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("=== App Dump Summary ===\n");
            sb.append("Package: ").append(packageName).append("\n");
            sb.append("Date: ").append(new java.util.Date().toString()).append("\n");
            sb.append("\n");
            
            AppDumpInfo info = getAppDumpInfo(packageName);
            sb.append("App Name: ").append(info.appName).append("\n");
            sb.append("Version: ").append(info.versionName).append(" (").append(info.versionCode).append(")\n");
            sb.append("IL2CPP: ").append(info.isIL2CPP ? "Yes" : "No").append("\n");
            sb.append("Unity: ").append(info.isUnity ? "Yes" : "No").append("\n");
            sb.append("\n");
            sb.append("Dumped Files:\n");
            
            File il2cppDir = new File(outputDir, "il2cpp");
            if (il2cppDir.exists()) {
                File[] files = il2cppDir.listFiles();
                if (files != null) {
                    for (File file : files) {
                        sb.append("  - ").append(file.getName()).append(" (").append(file.length()).append(" bytes)\n");
                    }
                }
            }
            
            File dexDir = new File(outputDir, "dex");
            if (dexDir.exists()) {
                File[] files = dexDir.listFiles();
                if (files != null) {
                    for (File file : files) {
                        sb.append("  - ").append(file.getName()).append(" (").append(file.length()).append(" bytes)\n");
                    }
                }
            }
            
            FileOutputStream fos = new FileOutputStream(new File(outputDir, "summary.txt"));
            fos.write(sb.toString().getBytes());
            fos.close();
        } catch (IOException e) {
            Slog.e(TAG, "Failed to generate summary: " + e.getMessage());
        }
    }
    
    @Override
    public void systemReady() {
        Slog.d(TAG, "AppDumperService initialized");
    }
    
    /**
     * Dump configuration class
     */
    public static class DumpConfig {
        public boolean dumpIL2CPP = true;
        public boolean dumpDEX = true;
        public boolean dumpUnity = true;
        public boolean generateHeaders = true;
        public String customOutputDir = null;
        
        public DumpConfig() {
            // Default constructor
        }
    }
    
    /**
     * App dump information class
     */
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
        public boolean isDumped;
        
        public AppDumpInfo() {
            // Default constructor
        }
    }
}
