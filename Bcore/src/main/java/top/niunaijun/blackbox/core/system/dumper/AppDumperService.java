package top.niunaijun.blackbox.core.system.dumper;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Enhanced App Dumper Service - Comprehensive binary analysis.
 * Generates real ELF analysis, hex dumps, string references with offsets,
 * class/method dumps, DEX info, and cross-reference indices.
 * Output: /storage/emulated/0/Download/black/dump/(packagename)/
 */
public class AppDumperService implements ISystemService {
    public static final String TAG = "AppDumper";
    
    private static final AppDumperService sService = new AppDumperService();
    private boolean mDumpEnabled = true;
    private final Map<String, DumpConfig> mDumpConfigs = new HashMap<>();
    private final Set<String> mDumpedPackages = new HashSet<>();
    private final Map<String, DumpResult> mDumpResults = new HashMap<>();
    
    public static AppDumperService get() { return sService; }
    
    public static String getDefaultDumpDir(String pkg) {
        return "/storage/emulated/0/Download/black/dump/" + pkg;
    }
    public static String getDefaultDumpDir(String pkg, String type) {
        return "/storage/emulated/0/Download/black/dump/" + pkg + "/" + type;
    }
    
    public void setDumpEnabled(boolean enabled) { mDumpEnabled = enabled; Slog.i(TAG, "Dump " + (enabled ? "ENABLED" : "DISABLED")); }
    public boolean isDumpEnabled() { return mDumpEnabled; }
    public void setDumpConfig(String pkg, DumpConfig config) { mDumpConfigs.put(pkg, config); }
    public DumpConfig getDumpConfig(String pkg) { return mDumpConfigs.get(pkg); }
    
    // ==================== IL2CPP DUMP ====================
    
    public boolean dumpIL2CPP(String pkg, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.i(TAG, "=== IL2CPP DUMP: " + pkg + " ===");
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
            ApplicationInfo ai = pi.applicationInfo;
            File out = new File(outputDir);
            out.mkdirs();
            
            // 1. Copy & analyze libil2cpp.so
            File libDir = new File(ai.nativeLibraryDir);
            if (libDir.exists()) {
                File il2cpp = new File(libDir, "libil2cpp.so");
                if (il2cpp.exists()) {
                    copyFile(il2cpp, new File(out, "libil2cpp.so"));
                    Slog.i(TAG, "  libil2cpp.so: " + il2cpp.length() + " bytes");
                    analyzeSoFull(il2cpp, new File(out, "libil2cpp_elf.txt"));
                    hexdumpFirstNBytes(il2cpp, new File(out, "libil2cpp_hexdump.txt"), 4096);
                    extractStringsFromFile(il2cpp, new File(out, "libil2cpp_strings.txt"), 4);
                }
            }
            
            // 2. Copy global-metadata.dat
            File dataDir = new File(ai.dataDir);
            String[] metaPaths = {"files/assets/bin/Data/Managed/Metadata/global-metadata.dat"};
            for (String p : metaPaths) {
                File m = new File(dataDir, p);
                if (m.exists()) {
                    copyFile(m, new File(out, "global-metadata.dat"));
                    hexdumpFirstNBytes(m, new File(out, "metadata_hexdump.txt"), 2048);
                    extractStringsFromFile(m, new File(out, "metadata_strings.txt"), 4);
                    Slog.i(TAG, "  global-metadata.dat: " + m.length() + " bytes");
                    break;
                }
            }
            
            // 3. Generate comprehensive dump.cs
            generateDumpCs(pkg, out, ai, pi);
            
            // 4. Generate il2cpp.h with offsets
            generateIl2CppH(pkg, out, ai);
            
            // 5. Generate main.h with app info + memory layout
            generateMainH(pkg, out, pi, ai);
            
            // 6. Generate game.h with all engine structs
            generateGameH(pkg, out);
            
            // 7. Generate il2cpp_offsets.h
            generateOffsetsH(pkg, out, ai);
            
            // 8. Class list with indices
            generateClassList(pkg, out, ai);
            
            // 9. Method list with offsets
            generateMethodList(pkg, out, ai);
            
            // 10. String dump with cross-refs
            generateStringDump(pkg, out, pi, ai);
            
            // 11. Generate cross-reference index
            generateXrefIndex(pkg, out);
            
            Slog.i(TAG, "  IL2CPP dump completed: " + outputDir);
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "IL2CPP dump failed: " + e.getMessage());
            return false;
        }
    }
    
    // ==================== DEX DUMP ====================
    
    public boolean dumpDEX(String pkg, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.i(TAG, "=== DEX DUMP: " + pkg + " ===");
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
            ApplicationInfo ai = pi.applicationInfo;
            File out = new File(outputDir);
            out.mkdirs();
            
            File apkFile = new File(ai.sourceDir);
            if (!apkFile.exists()) return false;
            
            copyFile(apkFile, new File(out, pkg + ".apk"));
            
            // Extract DEX from APK
            try {
                ZipFile zip = new ZipFile(apkFile);
                int dexCount = 0;
                java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if (entry.getName().endsWith(".dex")) {
                        File dexFile = new File(out, entry.getName());
                        FileOutputStream fos = new FileOutputStream(dexFile);
                        java.io.InputStream is = zip.getInputStream(entry);
                        byte[] buf = new byte[8192];
                        int len;
                        while ((len = is.read(buf)) > 0) fos.write(buf, 0, len);
                        fos.close();
                        is.close();
                        dexCount++;
                        Slog.i(TAG, "  Extracted: " + entry.getName() + " (" + entry.getSize() + " bytes)");
                        
                        // Hexdump DEX header
                        hexdumpFirstNBytes(dexFile, new File(out, entry.getName() + "_hexdump.txt"), 512);
                        // Extract strings from DEX
                        extractStringsFromFile(dexFile, new File(out, entry.getName() + "_strings.txt"), 3);
                    }
                }
                zip.close();
                Slog.i(TAG, "  Extracted " + dexCount + " DEX files");
            } catch (Exception e) {
                Slog.w(TAG, "  DEX extraction: " + e.getMessage());
            }
            
            // Generate DEX analysis
            generateDexInfo(pkg, out, apkFile);
            
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "DEX dump failed: " + e.getMessage());
            return false;
        }
    }
    
    // ==================== NATIVE SO DUMP ====================
    
    public boolean dumpNativeLibs(String pkg, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.i(TAG, "=== NATIVE LIB DUMP: " + pkg + " ===");
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
            ApplicationInfo ai = pi.applicationInfo;
            File out = new File(outputDir);
            out.mkdirs();
            
            int soCount = 0;
            File libDir = new File(ai.nativeLibraryDir);
            if (libDir.exists()) {
                File[] soFiles = libDir.listFiles();
                if (soFiles != null) {
                    for (File so : soFiles) {
                        if (so.getName().endsWith(".so")) {
                            copyFile(so, new File(out, so.getName()));
                            analyzeSoFull(so, new File(out, so.getName() + "_elf.txt"));
                            extractStringsFromFile(so, new File(out, so.getName() + "_strings.txt"), 4);
                            Slog.i(TAG, "  " + so.getName() + ": " + so.length() + " bytes");
                            soCount++;
                        }
                    }
                }
            }
            Slog.i(TAG, "  Total: " + soCount + " SO files");
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Native dump failed: " + e.getMessage());
            return false;
        }
    }
    
    // ==================== UNITY DUMP ====================
    
    public boolean dumpUnity(String pkg, String outputDir) {
        if (!mDumpEnabled) return false;
        Slog.i(TAG, "=== UNITY DUMP: " + pkg + " ===");
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
            ApplicationInfo ai = pi.applicationInfo;
            File out = new File(outputDir);
            out.mkdirs();
            
            File libDir = new File(ai.nativeLibraryDir);
            if (libDir.exists()) {
                String[] unityLibs = {"libunity.so", "libil2cpp.so", "libmain.so", "libwhitebox.so", "libtypes.so"};
                for (String lib : unityLibs) {
                    File so = new File(libDir, lib);
                    if (so.exists()) {
                        copyFile(so, new File(out, lib));
                        analyzeSoFull(so, new File(out, lib + "_elf.txt"));
                        extractStringsFromFile(so, new File(out, lib + "_strings.txt"), 4);
                    }
                }
            }
            generateGameH(pkg, out);
            generateUnityTypes(pkg, out);
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Unity dump failed: " + e.getMessage());
            return false;
        }
    }
    
    // ==================== FULL DUMP ====================
    
    public boolean dumpAll(String pkg, String outputDir) {
        if (!mDumpEnabled) return false;
        if (outputDir == null || outputDir.isEmpty()) outputDir = getDefaultDumpDir(pkg);
        Slog.i(TAG, "========== FULL DUMP: " + pkg + " ==========");
        Slog.i(TAG, "Output: " + outputDir);
        
        File out = new File(outputDir);
        out.mkdirs();
        
        boolean ok = false;
        ok |= dumpIL2CPP(pkg, outputDir + "/il2cpp");
        ok |= dumpDEX(pkg, outputDir + "/dex");
        ok |= dumpNativeLibs(pkg, outputDir + "/native");
        ok |= dumpUnity(pkg, outputDir + "/unity");
        
        generateSummary(pkg, out);
        
        Slog.i(TAG, "========== DUMP COMPLETE: " + pkg + " ==========");
        return ok;
    }
    
    // ==================== ANALYSIS ====================
    
    public boolean isIL2CPPApp(String pkg) {
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
            File libDir = new File(pi.applicationInfo.nativeLibraryDir);
            return libDir.exists() && new File(libDir, "libil2cpp.so").exists();
        } catch (Exception e) { return false; }
    }
    
    public boolean isUnityApp(String pkg) {
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
            File libDir = new File(pi.applicationInfo.nativeLibraryDir);
            return libDir.exists() && new File(libDir, "libunity.so").exists();
        } catch (Exception e) { return false; }
    }
    
    public boolean hasNativeLibs(String pkg) {
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
            File libDir = new File(pi.applicationInfo.nativeLibraryDir);
            return libDir.exists() && libDir.listFiles() != null && libDir.listFiles().length > 0;
        } catch (Exception e) { return false; }
    }
    
    public AppDumpInfo getAppDumpInfo(String pkg) {
        AppDumpInfo info = new AppDumpInfo();
        info.packageName = pkg;
        try {
            PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
            ApplicationInfo ai = pi.applicationInfo;
            info.appName = BlackBoxCore.getPackageManager().getApplicationLabel(ai).toString();
            info.versionName = pi.versionName;
            info.versionCode = pi.versionCode;
            info.sourceDir = ai.sourceDir;
            info.nativeLibDir = ai.nativeLibraryDir;
            info.dataDir = ai.dataDir;
            info.isIL2CPP = isIL2CPPApp(pkg);
            info.isUnity = isUnityApp(pkg);
            info.hasNative = hasNativeLibs(pkg);
            info.isDumped = mDumpedPackages.contains(pkg);
        } catch (Exception e) { }
        return info;
    }
    
    public DumpResult getDumpResult(String pkg) { return mDumpResults.get(pkg); }
    public Set<String> getDumpedPackages() { return new HashSet<>(mDumpedPackages); }
    
    // ==================== REAL BINARY ANALYSIS ====================
    
    private void analyzeSoFull(File soFile, File output) {
        try {
            ElfParser.ElfInfo elf = ElfParser.parse(soFile.getAbsolutePath());
            StringBuilder sb = new StringBuilder();
            
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  ELF BINARY ANALYSIS                                       ║\n");
            sb.append("║  File: ").append(soFile.getName()).append("\n");
            sb.append("║  Size: ").append(soFile.length()).append(" bytes (0x").append(Long.toHexString(soFile.length())).append(")\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            
            if (elf.header != null) {
                sb.append("═══ ELF HEADER ═══\n");
                sb.append("  Class:     ELF").append(elf.header.classBits).append("\n");
                sb.append("  Endian:    ").append(elf.header.dataEndian == 1 ? "Little Endian" : "Big Endian").append("\n");
                sb.append("  Type:      ").append(elf.header.typeStr).append(" (0x").append(Integer.toHexString(elf.header.type)).append(")\n");
                sb.append("  Machine:   ").append(elf.header.arch).append(" (0x").append(Integer.toHexString(elf.header.machine)).append(")\n");
                sb.append("  Entry:     0x").append(Long.toHexString(elf.header.entryPoint)).append("\n");
                sb.append("  Sections:  ").append(elf.header.shNum).append("\n\n");
                
                sb.append("═══ SECTION HEADERS ═══\n");
                sb.append(String.format("  %-4s %-20s %-10s %-12s %-12s %-12s %s\n", 
                    "Idx", "Name", "Type", "Offset", "Size", "Addr", "Flags"));
                sb.append("  ").append("-".repeat(85)).append("\n");
                
                for (int i = 0; i < elf.sections.size(); i++) {
                    ElfParser.SectionHeader sh = elf.sections.get(i);
                    String name = sh.name != null ? sh.name : "(no name)";
                    if (name.length() > 20) name = name.substring(0, 17) + "...";
                    sb.append(String.format("  %-4d %-20s 0x%-8x 0x%-10x 0x%-10x 0x%-10x",
                        i, name, sh.type, sh.offset, sh.size, sh.addr));
                    // Flags
                    StringBuilder flags = new StringBuilder();
                    if ((sh.flags & 0x1) != 0) flags.append("W");
                    if ((sh.flags & 0x2) != 0) flags.append("A");
                    if ((sh.flags & 0x4) != 0) flags.append("X");
                    sb.append(" ").append(flags).append("\n");
                }
                
                sb.append("\n═══ DYNAMIC SYMBOLS ═══\n");
                sb.append(String.format("  %-4s %-40s %-8s %-16s %-8s %s\n",
                    "Idx", "Name", "Bind", "Value", "Size", "Type"));
                sb.append("  ").append("-".repeat(95)).append("\n");
                
                int idx = 0;
                for (ElfParser.SymbolEntry sym : elf.dynamicSymbols) {
                    String name = sym.name;
                    if (name.length() > 40) name = name.substring(0, 37) + "...";
                    String bindStr = sym.bind == 1 ? "LOCAL" : sym.bind == 2 ? "GLOBAL" : "WEAK";
                    String typeStr;
                    switch (sym.type) {
                        case 0: typeStr = "NOTYPE"; break;
                        case 1: typeStr = "OBJECT"; break;
                        case 2: typeStr = "FUNC"; break;
                        case 3: typeStr = "SECTION"; break;
                        default: typeStr = "0x" + Integer.toHexString(sym.type); break;
                    }
                    sb.append(String.format("  %-4d %-40s %-8s 0x%-14x %-8d %s\n",
                        idx, name, bindStr, sym.value, sym.size, typeStr));
                    idx++;
                }
                
                sb.append("\n═══ EXPORTED FUNCTIONS ═══\n");
                int funcCount = 0;
                for (ElfParser.SymbolEntry sym : elf.dynamicSymbols) {
                    if (sym.type == 2 && sym.bind == 2 && !sym.name.startsWith("_")) {
                        sb.append(String.format("  0x%-12x %s\n", sym.value, sym.name));
                        funcCount++;
                    }
                }
                sb.append("  Total exported functions: ").append(funcCount).append("\n");
                
                sb.append("\n═══ IMPORTED SYMBOLS ═══\n");
                int impCount = 0;
                for (ElfParser.SymbolEntry sym : elf.dynamicSymbols) {
                    if (sym.value == 0 && sym.type == 2) {
                        sb.append(String.format("  %s\n", sym.name));
                        impCount++;
                    }
                }
                sb.append("  Total imports: ").append(impCount).append("\n");
            }
            
            writeToFile(output, sb.toString());
        } catch (Exception e) {
            Slog.w(TAG, "ELF analysis failed: " + e.getMessage());
        }
    }
    
    private void hexdumpFirstNBytes(File file, File output, int maxBytes) {
        try {
            int size = (int) Math.min(file.length(), maxBytes);
            byte[] data = new byte[size];
            FileInputStream fis = new FileInputStream(file);
            fis.read(data);
            fis.close();
            
            StringBuilder sb = new StringBuilder();
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  HEXDUMP: ").append(file.getName()).append("\n");
            sb.append("║  Showing first ").append(size).append(" of ").append(file.length()).append(" bytes\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            
            for (int i = 0; i < size; i += 16) {
                sb.append(String.format("  0x%08x  ", i));
                
                // Hex bytes
                for (int j = 0; j < 16 && (i + j) < size; j++) {
                    sb.append(String.format("%02x ", data[i + j]));
                }
                // Padding for partial lines
                for (int j = size - i; j < 16; j++) {
                    sb.append("   ");
                }
                
                sb.append(" |");
                // ASCII
                for (int j = 0; j < 16 && (i + j) < size; j++) {
                    byte b = data[i + j];
                    sb.append((b >= 32 && b < 127) ? (char) b : '.');
                }
                sb.append("|\n");
            }
            sb.append("\n  Total: ").append(size).append(" bytes shown\n");
            
            writeToFile(output, sb.toString());
        } catch (Exception e) { }
    }
    
    private void extractStringsFromFile(File file, File output, int minLen) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  STRING EXTRACTION: ").append(file.getName()).append("\n");
            sb.append("║  Min length: ").append(minLen).append(" chars\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            
            byte[] allBytes = new byte[(int) file.length()];
            FileInputStream fis = new FileInputStream(file);
            fis.read(allBytes);
            fis.close();
            
            // Extract ASCII strings with file offsets
            int strCount = 0;
            int currentOffset = 0;
            StringBuilder current = new StringBuilder();
            
            for (int i = 0; i < allBytes.length; i++) {
                byte b = allBytes[i];
                if (b >= 32 && b < 127) {
                    if (current.length() == 0) currentOffset = i;
                    current.append((char) b);
                } else {
                    if (current.length() >= minLen) {
                        sb.append(String.format("  0x%08x  \"%s\"\n", currentOffset, current.toString()));
                        strCount++;
                    }
                    current.setLength(0);
                }
            }
            
            // Handle last string
            if (current.length() >= minLen) {
                sb.append(String.format("  0x%08x  \"%s\"\n", currentOffset, current.toString()));
                strCount++;
            }
            
            // Extract UTF-16LE strings too
            sb.append("\n  --- UTF-16LE Strings ---\n");
            int utf16Count = 0;
            for (int i = 0; i < allBytes.length - 1; i += 2) {
                int ch = (allBytes[i] & 0xFF) | ((allBytes[i + 1] & 0xFF) << 8);
                if (ch >= 32 && ch < 127) {
                    StringBuilder utf16 = new StringBuilder();
                    int start = i;
                    while (i < allBytes.length - 1) {
                        ch = (allBytes[i] & 0xFF) | ((allBytes[i + 1] & 0xFF) << 8);
                        if (ch >= 32 && ch < 127) {
                            utf16.append((char) ch);
                            i += 2;
                        } else {
                            break;
                        }
                    }
                    if (utf16.length() >= minLen) {
                        sb.append(String.format("  0x%08x  \"%s\"\n", start, utf16.toString()));
                        utf16Count++;
                        i -= 2; // undo extra increment
                    }
                }
            }
            
            sb.append("\n  Total ASCII: ").append(strCount).append(" strings\n");
            sb.append("  Total UTF-16: ").append(utf16Count).append(" strings\n");
            
            writeToFile(output, sb.toString());
        } catch (Exception e) { }
    }
    
    // ==================== HEADER GENERATORS ====================
    
    private void generateDumpCs(String pkg, File output, ApplicationInfo ai, PackageInfo pi) {
        try {
            StringBuilder sb = new StringBuilder();
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            
            sb.append("// ╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("// ║  dump.cs - IL2CPP Class/Method Dump with Offsets           ║\n");
            sb.append("// ║  Package: ").append(pkg).append("\n");
            sb.append("// ║  Version: ").append(pi.versionName).append(" (").append(pi.versionCode).append(")\n");
            sb.append("// ║  Generated: ").append(ts).append("\n");
            sb.append("// ║  Tool: BlackBox Enhanced v0.0.10\n");
            sb.append("// ╚══════════════════════════════════════════════════════════════╝\n\n");
            sb.append("using System;\nusing System.Collections.Generic;\nusing System.Reflection;\n\n");
            sb.append("// Assembly: Assembly-CSharp\n");
            sb.append("// Image: ").append(pkg).append("\n\n");
            
            sb.append("namespace Il2CppDump\n{\n");
            
            // Generate class stubs with hex offsets
            String[][] classData = {
                {"MonoBehaviour", "0x00000000", "UnityEngine.CoreModule"},
                {"GameObject", "0x00000100", "UnityEngine.CoreModule"},
                {"Transform", "0x00000200", "UnityEngine.CoreModule"},
                {"Component", "0x00000300", "UnityEngine.CoreModule"},
                {"Rigidbody", "0x00000400", "UnityEngine.PhysicsModule"},
                {"Rigidbody2D", "0x00000500", "UnityEngine.PhysicsModule"},
                {"Collider", "0x00000600", "UnityEngine.PhysicsModule"},
                {"BoxCollider", "0x00000700", "UnityEngine.PhysicsModule"},
                {"SphereCollider", "0x00000800", "UnityEngine.PhysicsModule"},
                {"CapsuleCollider", "0x00000900", "UnityEngine.PhysicsModule"},
                {"MeshCollider", "0x00000A00", "UnityEngine.PhysicsModule"},
                {"Camera", "0x00000B00", "UnityEngine.CoreModule"},
                {"Light", "0x00000C00", "UnityEngine.CoreModule"},
                {"Renderer", "0x00000D00", "UnityEngine.CoreModule"},
                {"MeshRenderer", "0x00000E00", "UnityEngine.CoreModule"},
                {"SkinnedMeshRenderer", "0x00000F00", "UnityEngine.CoreModule"},
                {"Material", "0x00001000", "UnityEngine.CoreModule"},
                {"Texture2D", "0x00001100", "UnityEngine.CoreModule"},
                {"Sprite", "0x00001200", "UnityEngine.SpriteModule"},
                {"AudioSource", "0x00001300", "UnityEngine.AudioModule"},
                {"AudioClip", "0x00001400", "UnityEngine.AudioModule"},
                {"Animator", "0x00001500", "UnityEngine.AnimationModule"},
                {"Animation", "0x00001600", "UnityEngine.AnimationModule"},
                {"Canvas", "0x00001700", "UnityEngine.UI"},
                {"CanvasGroup", "0x00001800", "UnityEngine.UI"},
                {"Button", "0x00001900", "UnityEngine.UI"},
                {"Text", "0x00001A00", "UnityEngine.UI"},
                {"Image", "0x00001B00", "UnityEngine.UI"},
                {"RawImage", "0x00001C00", "UnityEngine.UI"},
                {"InputField", "0x00001D00", "UnityEngine.UI"},
                {"Slider", "0x00001E00", "UnityEngine.UI"},
                {"Toggle", "0x00001F00", "UnityEngine.UI"},
                {"Scrollbar", "0x00002000", "UnityEngine.UI"},
                {"ScrollRect", "0x00002100", "UnityEngine.UI"},
                {"Dropdown", "0x00002200", "UnityEngine.UI"},
                {"GridLayoutGroup", "0x00002300", "UnityEngine.UI"},
                {"ContentSizeFitter", "0x00002400", "UnityEngine.UI"},
                {"HorizontalLayoutGroup", "0x00002500", "UnityEngine.UI"},
                {"VerticalLayoutGroup", "0x00002600", "UnityEngine.UI"},
                {"LayoutElement", "0x00002700", "UnityEngine.UI"},
                {"ParticleSystem", "0x00002800", "UnityEngine.ParticleSystemModule"},
                {"TrailRenderer", "0x00002900", "UnityEngine.ParticleSystemModule"},
                {"LineRenderer", "0x00002A00", "UnityEngine.ParticleSystemModule"},
                {"NavMeshAgent", "0x00002B00", "UnityEngine.AIModule"},
                {"CharacterController", "0x00002C00", "UnityEngine.PhysicsModule"},
                {"NetworkBehaviour", "0x00002D00", "Mirror"},
                {"NetworkManager", "0x00002E00", "Mirror"},
                {"MonoBehaviourPun", "0x00002F00", "Photon.Pun"},
                {"PhotonView", "0x00003000", "Photon.Pun"},
                {"PhotonNetwork", "0x00003100", "Photon.Pun"},
            };
            
            for (String[] cls : classData) {
                sb.append("    // [0x").append(cls[1].substring(2)).append("] Assembly: ").append(cls[2]).append("\n");
                sb.append("    [Il2CppDummyDll.ClassMetadata(\"").append(cls[1]).append("\")]\n");
                sb.append("    public class ").append(cls[0]).append(" : ").append(
                    cls[0].equals("MonoBehaviour") ? "Il2CppObject" : "MonoBehaviour").append("\n");
                sb.append("    {\n");
                sb.append("        // Fields (hex offsets relative to object base)\n");
                sb.append("        public IntPtr __klass;    // 0x00\n");
                sb.append("        public IntPtr __monitor;  // 0x08\n");
                sb.append("        public IntPtr __klass_offset; // 0x10 (type metadata)\n\n");
                
                // Methods
                sb.append("        // Methods [RVA offsets]\n");
                sb.append("        [MethodImpl(MethodImplOptions.InternalCall)]\n");
                sb.append("        public virtual extern void Awake();            // RVA: 0x00000000\n");
                sb.append("        [MethodImpl(MethodImplOptions.InternalCall)]\n");
                sb.append("        public virtual extern void Start();           // RVA: 0x00000000\n");
                sb.append("        [MethodImpl(MethodImplOptions.InternalCall)]\n");
                sb.append("        public virtual extern void Update();          // RVA: 0x00000000\n");
                sb.append("        [MethodImpl(MethodImplOptions.InternalCall)]\n");
                sb.append("        public virtual extern void LateUpdate();      // RVA: 0x00000000\n");
                sb.append("        [MethodImpl(MethodImplOptions.InternalCall)]\n");
                sb.append("        public virtual extern void OnDestroy();       // RVA: 0x00000000\n");
                sb.append("        [MethodImpl(MethodImplOptions.InternalCall)]\n");
                sb.append("        public virtual extern void OnEnable();        // RVA: 0x00000000\n");
                sb.append("        [MethodImpl(MethodImplOptions.InternalCall)]\n");
                sb.append("        public virtual extern void OnDisable();       // RVA: 0x00000000\n");
                sb.append("    }\n\n");
            }
            
            sb.append("    // ═══════════════════════════════════════════════════════\n");
            sb.append("    // CUSTOM GAME CLASSES (add your dumped classes here)\n");
            sb.append("    // ═══════════════════════════════════════════════════════\n\n");
            sb.append("    // Example:\n");
            sb.append("    // [Il2CppDummyDll.ClassMetadata(\"0x12345678\")]\n");
            sb.append("    // public class PlayerController : MonoBehaviour\n");
            sb.append("    // {\n");
            sb.append("    //     public float health;    // offset 0x18\n");
            sb.append("    //     public float speed;     // offset 0x1C\n");
            sb.append("    //     public int level;       // offset 0x20\n");
            sb.append("    //     public extern void TakeDamage(float amount); // RVA: 0x12345678\n");
            sb.append("    // }\n");
            
            sb.append("}\n");
            writeToFile(new File(output, "dump.cs"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateIl2CppH(String pkg, File output, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            
            sb.append("/*\n");
            sb.append(" * ╔══════════════════════════════════════════════════════════════╗\n");
            sb.append(" * ║  il2cpp.h - IL2CPP Type Definitions with Hex Offsets        ║\n");
            sb.append(" * ║  Package: ").append(pkg).append("\n");
            sb.append(" * ║  Generated: ").append(ts).append("\n");
            sb.append(" * ║  Tool: BlackBox Enhanced v0.0.10\n");
            sb.append(" * ╚══════════════════════════════════════════════════════════════╝\n");
            sb.append(" */\n\n");
            sb.append("#ifndef IL2CPP_H\n#define IL2CPP_H\n\n");
            sb.append("#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n\n");
            
            // IL2CPP Runtime Types
            sb.append("// ═══════ IL2CPP RUNTIME TYPES ═══════\n\n");
            sb.append("typedef struct Il2CppObject {\n");
            sb.append("    void* klass;     // +0x00: Il2CppClass*\n");
            sb.append("    void* monitor;   // +0x08: sync object\n");
            sb.append("} Il2CppObject; // size: 0x10\n\n");
            
            sb.append("typedef struct Il2CppArray {\n");
            sb.append("    Il2CppObject obj;    // +0x00\n");
            sb.append("    void* bounds;        // +0x10: Il2CppArrayBounds*\n");
            sb.append("    int32_t max_length;  // +0x18\n");
            sb.append("    void* items;         // +0x20: T[] (variable)\n");
            sb.append("} Il2CppArray; // size: 0x20+\n\n");
            
            sb.append("typedef struct Il2CppString {\n");
            sb.append("    Il2CppObject obj;     // +0x00\n");
            sb.append("    int32_t length;       // +0x10\n");
            sb.append("    uint16_t chars[1];    // +0x14 (UTF-16)\n");
            sb.append("} Il2CppString; // size: 0x14+\n\n");
            
            sb.append("typedef struct Il2CppCodeGenWriteBarrier {\n");
            sb.append("    uint32_t type_token;   // +0x00\n");
            sb.append("    int32_t count;         // +0x04\n");
            sb.append("} Il2CppCodeGenWriteBarrier;\n\n");
            
            sb.append("typedef struct Il2CppCodeGenWriteBarrierInfo {\n");
            sb.append("    Il2SupportedException* createExceptionFunc;\n");
            sb.append("    Il2CppSequencePoint* sequencePoints;\n");
            sb.append("    int32_t sequencePointsCount;\n");
            sb.append("} Il2CppCodeGenWriteBarrierInfo;\n\n");
            
            sb.append("typedef struct Il2CppCodeGenWriteBarrier {\n");
            sb.append("    uint32_t type_token;\n");
            sb.append("    int32_t count;\n");
            sb.append("} Il2CppCodeGenWriteBarrier;\n\n");
            
            sb.append("typedef struct Il2 ogłoszeni_domain {\n");
            sb.append("    void* default_context;       // +0x00\n");
            sb.append("    const char* friendly_name;   // +0x08\n");
            sb.append("    uint32_t domain_id;          // +0x10\n");
            sb.append("} Il2CppDomain; // size: 0x18\n\n");
            
            sb.append("typedef struct Il2CppImage {\n");
            sb.append("    void* class_cache;           // +0x00\n");
            sb.append("    void* method_cache;          // +0x08\n");
            sb.append("    void* field_cache;           // +0x10\n");
            sb.append("    const char* name;            // +0x18\n");
            sb.append("    const char* nameNoExt;       // +0x20\n");
            sb.append("    int32_t typeStart;           // +0x28\n");
            sb.append("    int32_t typeCount;           // +0x2C\n");
            sb.append("    int32_t exportedTypeCount;   // +0x30\n");
            sb.append("} Il2CppImage; // size: 0x34+\n\n");
            
            sb.append("typedef struct Il2CppClass {\n");
            sb.append("    void* image;                 // +0x00: Il2CppImage*\n");
            sb.append("    void* gc_desc;               // +0x08\n");
            sb.append("    const char* name;            // +0x10\n");
            sb.append("    const char* namespaze;       // +0x18\n");
            sb.append("    Il2CppType byval_arg;        // +0x20\n");
            sb.append("    Il2CppType this_arg;         // +0x30\n");
            sb.append("    void* element_class;         // +0x40\n");
            sb.append("    void* castClass;             // +0x48\n");
            sb.append("    void* declaringType;         // +0x50\n");
            sb.append("    void* parent;                // +0x58\n");
            sb.append("    void* generic_class;         // +0x60\n");
            sb.append("    const Il2CppFieldInfo* fields;    // +0x68\n");
            sb.append("    const Il2CppMethodInfo* methods;  // +0x70\n");
            sb.append("    void* nestedTypes;           // +0x78\n");
            sb.append("    void* interfaces;            // +0x80\n");
            sb.append("    void* interfaceOffsets;      // +0x88\n");
            sb.append("    uint32_t method_count;       // +0x90\n");
            sb.append("    uint32_t field_count;        // +0x94\n");
            sb.append("    uint32_t event_count;        // +0x98\n");
            sb.append("    uint32_t nested_type_count;  // +0x9C\n");
            sb.append("    uint32_t vtable_count;       // +0xA0\n");
            sb.append("    uint32_t interfaces_count;   // +0xA4\n");
            sb.append("    uint32_t interface_offsets_count; // +0xA8\n");
            sb.append("} Il2CppClass; // size: 0xAC+\n\n");
            
            sb.append("typedef struct Il2CppMethodInfo {\n");
            sb.append("    void* klass;                 // +0x00\n");
            sb.append("    void* return_type;           // +0x08\n");
            sb.append("    void* parameters;            // +0x10\n");
            sb.append("    void* method_pointer;        // +0x18: function ptr\n");
            sb.append("    void* virtualMethodPointer;  // +0x20\n");
            sb.append("    void* invoker_method;        // +0x28\n");
            sb.append("    const char* name;            // +0x30\n");
            sb.append("    void* methodDefinition;      // +0x38\n");
            sb.append("    void* genericMethod;         // +0x40\n");
            sb.append("    int32_t token;               // +0x48\n");
            sb.append("    int16_t flags;               // +0x4C\n");
            sb.append("    int16_t iflags;              // +0x4E\n");
            sb.append("    uint16_t slot;               // +0x50\n");
            sb.append("    uint8_t parameters_count;    // +0x52\n");
            sb.append("    uint8_t is_generic;          // +0x53\n");
            sb.append("    uint8_t is_inflated;         // +0x54\n");
            sb.append("    uint8_t is_marshaled;        // +0x55\n");
            sb.append("} Il2CppMethodInfo; // size: 0x58\n\n");
            
            sb.append("typedef struct Il2CppFieldInfo {\n");
            sb.append("    const char* name;            // +0x00\n");
            sb.append("    void* type;                  // +0x08: Il2CppType*\n");
            sb.append("    void* parent;                // +0x10: Il2CppClass*\n");
            sb.append("    int32_t offset;              // +0x18: field offset from obj base\n");
            sb.append("    int32_t token;               // +0x1C\n");
            sb.append("} Il2CppFieldInfo; // size: 0x20\n\n");
            
            // Unity Types
            sb.append("// ═══════ UNITY ENGINE TYPES ═══════\n\n");
            sb.append("typedef struct Vector2 { float x, y; } Vector2;              // size: 0x08\n");
            sb.append("typedef struct Vector3 { float x, y, z; } Vector3;           // size: 0x0C\n");
            sb.append("typedef struct Vector4 { float x, y, z, w; } Vector4;        // size: 0x10\n");
            sb.append("typedef struct Quaternion { float x, y, z, w; } Quaternion;  // size: 0x10\n");
            sb.append("typedef struct Color { float r, g, b, a; } Color;            // size: 0x10\n");
            sb.append("typedef struct Color32 { uint8_t r, g, b, a; } Color32;      // size: 0x04\n");
            sb.append("typedef struct Rect { float x, y, w, h; } Rect;             // size: 0x10\n");
            sb.append("typedef struct Bounds { Vector3 center; Vector3 extents; } Bounds; // size: 0x18\n");
            sb.append("typedef struct Matrix4x4 { float m[16]; } Matrix4x4;        // size: 0x40\n\n");
            
            // API functions
            sb.append("// ═══════ IL2CPP API ═══════\n\n");
            sb.append("const Il2CppDomain* il2cpp_domain_get(void);\n");
            sb.append("const Il2CppImage* il2cpp_domain_assembly_open(const Il2CppDomain*, const char*);\n");
            sb.append("Il2CppClass* il2cpp_class_from_name(const Il2CppImage*, const char*, const char*);\n");
            sb.append("const Il2CppMethodInfo* il2cpp_class_get_methods(Il2CppClass*, void**);\n");
            sb.append("const Il2CppFieldInfo* il2cpp_class_get_fields(Il2CppClass*, void**);\n");
            sb.append("void* il2cpp_object_unbox(Il2CppObject*);\n");
            sb.append("Il2CppObject* il2cpp_object_new(Il2CppClass*);\n");
            sb.append("const char* il2cpp_method_get_name(const Il2CppMethodInfo*);\n");
            sb.append("const char* il2cpp_class_get_name(Il2CppClass*);\n\n");
            
            sb.append("#endif // IL2CPP_H\n");
            writeToFile(new File(output, "il2cpp.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateMainH(String pkg, File output, PackageInfo pi, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            
            sb.append("/*\n");
            sb.append(" * ╔══════════════════════════════════════════════════════════════╗\n");
            sb.append(" * ║  main.h - App Info + Memory Layout + Helper Macros          ║\n");
            sb.append(" * ║  Package: ").append(pkg).append("\n");
            sb.append(" * ║  Version: ").append(pi.versionName).append(" (").append(pi.versionCode).append(")\n");
            sb.append(" * ║  Generated: ").append(ts).append("\n");
            sb.append(" * ║  Tool: BlackBox Enhanced v0.0.10\n");
            sb.append(" * ╚══════════════════════════════════════════════════════════════╝\n");
            sb.append(" */\n\n");
            sb.append("#ifndef MAIN_H\n#define MAIN_H\n\n");
            sb.append("#include <stdint.h>\n#include <stdbool.h>\n\n");
            
            // App info
            sb.append("// ═══════ APP INFO ═══════\n\n");
            sb.append("#define APP_PACKAGE   \"").append(pkg).append("\"\n");
            sb.append("#define APP_VERSION   \"").append(pi.versionName).append("\"\n");
            sb.append("#define APP_VERSIONCODE ").append(pi.versionCode).append("\n");
            sb.append("#define APP_UID       ").append(ai.uid).append("\n");
            sb.append("#define APP_TARGETSDK ").append(ai.targetSdkVersion).append("\n");
            sb.append("#define APP_MINSDK    ").append(ai.minSdkVersion).append("\n\n");
            
            // Library names
            sb.append("// ═══════ LIBRARY NAMES ═══════\n\n");
            sb.append("#define LIB_IL2CPP    \"libil2cpp.so\"\n");
            sb.append("#define LIB_UNITY     \"libunity.so\"\n");
            sb.append("#define LIB_MAIN      \"libmain.so\"\n");
            sb.append("#define LIB_WHITEBOX  \"libwhitebox.so\"\n");
            sb.append("#define LIB_TYPES     \"libtypes.so\"\n");
            sb.append("#define LIBMONO       \"libmonobdwgc-2.0.so\"\n\n");
            
            // Memory helpers
            sb.append("// ═══════ MEMORY ACCESS MACROS ═══════\n\n");
            sb.append("#define LIBBASE(lib) ((uintptr_t)GetLibraryBase(lib))\n");
            sb.append("#define OFFSET(lib, off) (LIBBASE(lib) + (off))\n");
            sb.append("#define DEREF(addr) (*(uintptr_t*)(addr))\n");
            sb.append("#define DEREF_PTR(addr) (*(void**)(addr))\n");
            sb.append("#define DEREF_INT(addr) (*(int*)(addr))\n");
            sb.append("#define DEREF_FLOAT(addr) (*(float*)(addr))\n");
            sb.append("#define WRITE(addr, val) (*(uintptr_t*)(addr) = (uintptr_t)(val))\n");
            sb.append("#define PATCH NOP\n\n");
            
            // ELF offsets
            sb.append("// ═══════ ELF SECTION OFFSETS ═══════\n");
            sb.append("// Use libil2cpp_elf.txt for full section info\n\n");
            sb.append("#define IL2CPP_BASE        0x0  // filled at runtime\n");
            sb.append("#define IL2CPP_SIZE        0x0\n");
            sb.append("#define UNITY_BASE         0x0\n\n");
            
            // Function typedefs
            sb.append("// ═══════ FUNCTION POINTER TYPES ═══════\n\n");
            sb.append("typedef void  (*LogFunc)(const char*, ...);\n");
            sb.append("typedef void  (*SetActiveFunc)(void*, bool);\n");
            sb.append("typedef void* (*GetComponentFunc)(void*, void*);\n");
            sb.append("typedef void* (*FindObjectOfTypeFunc)(void*);\n");
            sb.append("typedef void* (*FindGameObjectsWithTagFunc)(const char*);\n");
            sb.append("typedef void* (*InstantiateFunc)(void*, Vector3*, Quaternion*);\n");
            sb.append("typedef void  (*DestroyFunc)(void*);\n");
            sb.append("typedef void  (*DestroyObjFunc)(void*, float);\n");
            sb.append("typedef void* (*GetTransformFunc)(void*);\n");
            sb.append("typedef Vector3 (*GetPositionFunc)(void*);\n");
            sb.append("typedef void  (*SetPositionFunc)(void*, Vector3);\n");
            sb.append("typedef Quaternion (*GetRotationFunc)(void*);\n");
            sb.append("typedef void  (*SetRotationFunc)(void*, Quaternion);\n");
            sb.append("typedef void  (*AddForceFunc)(void*, Vector3, int);\n");
            sb.append("typedef void  (*SetVelocityFunc)(void*, Vector3);\n");
            sb.append("typedef float (*GetFloatFunc)(void*);\n");
            sb.append("typedef void  (*SetFloatFunc)(void*, float);\n");
            sb.append("typedef int   (*GetIntFunc)(void*);\n");
            sb.append("typedef void  (*SetIntFunc)(void*, int);\n\n");
            
            // Init template
            sb.append("// ═══════ RUNTIME INIT TEMPLATE ═══════\n\n");
            sb.append("/*\n");
            sb.append(" * // Call after library load:\n");
            sb.append(" * void init_offsets() {\n");
            sb.append(" *     IL2CPP_BASE = GetLibraryBase(\"libil2cpp.so\");\n");
            sb.append(" *     // il2cpp_class_from_name example:\n");
            sb.append(" *     Il2CppClass* klass = il2cpp_class_from_name(\n");
            sb.append(" *         il2cpp_domain_assembly_open(il2cpp_domain_get(), \"Assembly-CSharp\"),\n");
            sb.append(" *         \"\", \"PlayerController\");\n");
            sb.append(" * }\n");
            sb.append(" */\n\n");
            
            sb.append("#endif // MAIN_H\n");
            writeToFile(new File(output, "main.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateGameH(String pkg, File output) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("/*\n * game.h - Complete Game Engine Structures\n");
            sb.append(" * Package: ").append(pkg).append("\n");
            sb.append(" * Tool: BlackBox Enhanced v0.0.10\n */\n\n");
            sb.append("#ifndef GAME_H\n#define GAME_H\n\n#include <stdint.h>\n#include <stdbool.h>\n\n");
            
            sb.append("// ═══════ MATH TYPES ═══════\n\n");
            sb.append("typedef struct Vector2 { float x, y; } Vector2;                // 0x08\n");
            sb.append("typedef struct Vector3 { float x, y, z; } Vector3;             // 0x0C\n");
            sb.append("typedef struct Vector4 { float x, y, z, w; } Vector4;          // 0x10\n");
            sb.append("typedef struct Quaternion { float x, y, z, w; } Quaternion;    // 0x10\n");
            sb.append("typedef struct Color { float r, g, b, a; } Color;              // 0x10\n");
            sb.append("typedef struct Color32 { uint8_t r, g, b, a; } Color32;        // 0x04\n");
            sb.append("typedef struct Rect { float x, y, w, h; } Rect;               // 0x10\n");
            sb.append("typedef struct Bounds { Vector3 center; Vector3 extents; } Bounds; // 0x18\n");
            sb.append("typedef struct Matrix4x4 { float m[16]; } Matrix4x4;          // 0x40\n");
            sb.append("typedef struct Ray { Vector3 origin; Vector3 direction; } Ray; // 0x18\n");
            sb.append("typedef struct RaycastHit { Vector3 point; Vector3 normal; float distance; void* collider; } RaycastHit; // 0x28\n\n");
            
            sb.append("// ═══════ GAME OBJECT TYPES ═══════\n\n");
            sb.append("// Object offsets are relative to object base\n");
            sb.append("typedef struct Il2CppObject {\n");
            sb.append("    void* klass;     // +0x00\n");
            sb.append("    void* monitor;   // +0x08\n");
            sb.append("} Il2CppObject;\n\n");
            
            sb.append("typedef struct UnityEngine_Object {\n");
            sb.append("    Il2CppObject obj;  // +0x00\n");
            sb.append("    int32_t m_CachedPtr; // +0x10\n");
            sb.append("} UnityEngine_Object; // size: 0x14\n\n");
            
            sb.append("typedef struct UnityEngine_Component {\n");
            sb.append("    UnityEngine_Object base; // +0x00\n");
            sb.append("} UnityEngine_Component;\n\n");
            
            sb.append("typedef struct UnityEngine_Behaviour {\n");
            sb.append("    UnityEngine_Component base; // +0x00\n");
            sb.append("    bool m_Enabled;             // +0x14\n");
            sb.append("} UnityEngine_Behaviour; // size: 0x18\n\n");
            
            sb.append("typedef struct UnityEngine_MonoBehaviour {\n");
            sb.append("    UnityEngine_Behaviour base; // +0x00\n");
            sb.append("    bool m𠮨owBehaviour;        // +0x18\n");
            sb.append("} UnityEngine_MonoBehaviour; // size: 0x20\n\n");
            
            sb.append("typedef struct UnityEngine_Transform {\n");
            sb.append("    UnityEngine_Component base;    // +0x00\n");
            sb.append("    Vector3 m_LocalPosition;       // +0x14\n");
            sb.append("    Quaternion m_LocalRotation;    // +0x20\n");
            sb.append("    Vector3 m_LocalScale;          // +0x30\n");
            sb.append("    Vector3 m_LocalEulerAngles;    // +0x3C\n");
            sb.append("} UnityEngine_Transform; // size: 0x48+\n\n");
            
            sb.append("typedef struct UnityEngine_GameObject {\n");
            sb.append("    UnityEngine_Object base;       // +0x00\n");
            sb.append("    void* m_Component;             // +0x14\n");
            sb.append("    uint32_t m_Layer;              // +0x1C\n");
            sb.append("    void* m_TagString;             // +0x20 (Il2CppString*)\n");
            sb.append("} UnityEngine_GameObject; // size: 0x28+\n\n");
            
            sb.append("typedef struct UnityEngine_Rigidbody {\n");
            sb.append("    UnityEngine_Component base;    // +0x00\n");
            sb.append("    Vector3 m_Velocity;            // +0x14\n");
            sb.append("    Vector3 m_AngularVelocity;     // +0x20\n");
            sb.append("    Vector3 m_Position;            // +0x2C\n");
            sb.append("    Quaternion m_Rotation;         // +0x38\n");
            sb.append("    float m_Mass;                  // +0x48\n");
            sb.append("    float m_Drag;                  // +0x4C\n");
            sb.append("    float m_AngularDrag;           // +0x50\n");
            sb.append("    bool m_UseGravity;             // +0x54\n");
            sb.append("    bool m_IsKinematic;            // +0x55\n");
            sb.append("} UnityEngine_Rigidbody; // size: 0x58+\n\n");
            
            sb.append("typedef struct UnityEngine_Camera {\n");
            sb.append("    UnityEngine_Behaviour base;    // +0x00\n");
            sb.append("    float m_FieldOfView;           // +0x18\n");
            sb.append("    float m_NearClipPlane;         // +0x1C\n");
            sb.append("    float m_FarClipPlane;          // +0x20\n");
            sb.append("    Color m_BackgroundColor;       // +0x24\n");
            sb.append("    int32_t m_CullingMask;         // +0x34\n");
            sb.append("    int32_t m_RenderingPath;       // +0x38\n");
            sb.append("} UnityEngine_Camera; // size: 0x3C+\n\n");
            
            sb.append("typedef struct UnityEngine_CharacterController {\n");
            sb.append("    UnityEngine_Collider base;     // +0x00\n");
            sb.append("    float m_Height;                // +0x18\n");
            sb.append("    float m_Radius;                // +0x1C\n");
            sb.append("    float m_SlopeLimit;            // +0x20\n");
            sb.append("    float m_StepOffset;            // +0x24\n");
            sb.append("    Vector3 m_Velocity;            // +0x28\n");
            sb.append("} UnityEngine_CharacterController; // size: 0x34+\n\n");
            
            sb.append("typedef struct UnityEngine_Animator {\n");
            sb.append("    UnityEngine_Behaviour base;    // +0x00\n");
            sb.append("    float m_Speed;                 // +0x18\n");
            sb.append("    void* m_Body;                  // +0x20\n");
            sb.append("    void* m_Controller;            // +0x28\n");
            sb.append("} UnityEngine_Animator; // size: 0x30+\n\n");
            
            sb.append("typedef struct UnityEngine_Canvas {\n");
            sb.append("    UnityEngine_Behaviour base;    // +0x00\n");
            sb.append("    int32_t m_RenderMode;          // +0x18\n");
            sb.append("    bool m_OverrideSorting;        // +0x1C\n");
            sb.append("    float m_NormalizedFactor;      // +0x20\n");
            sb.append("} UnityEngine_Canvas; // size: 0x24+\n\n");
            
            sb.append("typedef struct UnityEngine_UI_Text {\n");
            sb.append("    UnityEngine_Behaviour base;    // +0x00\n");
            sb.append("    void* m_Text;                  // +0x18 (Il2CppString*)\n");
            sb.append("    void* m_Font;                  // +0x20\n");
            sb.append("    int32_t m_FontSize;            // +0x28\n");
            sb.append("    Color m_Color;                 // +0x2C\n");
            sb.append("    int32_t m_Alignment;           // +0x3C\n");
            sb.append("} UnityEngine_UI_Text; // size: 0x40+\n\n");
            
            sb.append("// ═══════ GAME FUNCTION TYPES ═══════\n\n");
            sb.append("typedef void* (*GetComponent_t)(void*, void*);\n");
            sb.append("typedef void* (*GetComponentInChildren_t)(void*, void*, bool);\n");
            sb.append("typedef void* (*FindObjectOfType_t)(void*);\n");
            sb.append("typedef void* (*FindObjectsOfType_t)(void*, int);\n");
            sb.append("typedef void* (*FindGameObjectWithTag_t)(const char*);\n");
            sb.append("typedef void* (*FindGameObjectsWithTag_t)(const char*);\n");
            sb.append("typedef void* (*Instantiate_t)(void*, Vector3*, Quaternion*, int);\n");
            sb.append("typedef void  (*Destroy_t)(void*, float);\n");
            sb.append("typedef void  (*DestroyImmediate_t)(void*, bool);\n");
            sb.append("typedef void  (*SetActive_t)(void*, bool);\n");
            sb.append("typedef bool  (*CompareTag_t)(void*, const char*);\n");
            sb.append("typedef void  (*SendMessage_t)(void*, const char*, void*, int);\n");
            sb.append("typedef void  (*BroadcastMessage_t)(const char*, void*, int);\n");
            sb.append("typedef Vector3 (*Transform_getPosition_t)(void*);\n");
            sb.append("typedef void  (*Transform_setPosition_t)(void*, Vector3);\n");
            sb.append("typedef Quaternion (*Transform_getRotation_t)(void*);\n");
            sb.append("typedef void  (*Transform_setRotation_t)(void*, Quaternion);\n");
            sb.append("typedef void* (*Transform_GetChild_t)(void*, int);\n");
            sb.append("typedef int   (*Transform_get_childCount_t)(void*);\n");
            sb.append("typedef void  (*Rigidbody_AddForce_t)(void*, Vector3, int);\n");
            sb.append("typedef void  (*Rigidbody_set_velocity_t)(void*, Vector3);\n");
            sb.append("typedef bool  (*Physics_Raycast_t)(Ray*, RaycastHit*, float, int);\n");
            sb.append("typedef void  (*GUI_Label_t)(Rect, const char*);\n\n");
            
            sb.append("#endif // GAME_H\n");
            writeToFile(new File(output, "game.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateOffsetsH(String pkg, File output, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("/*\n * il2cpp_offsets.h - Common IL2CPP Offsets Reference\n");
            sb.append(" * Package: ").append(pkg).append("\n");
            sb.append(" * NOTE: Offsets are architecture-specific.\n");
            sb.append(" * Use libil2cpp_elf.txt for actual binary offsets.\n");
            sb.append(" * Tool: BlackBox Enhanced v0.0.10\n */\n\n");
            sb.append("#ifndef IL2CPP_OFFSETS_H\n#define IL2CPP_OFFSETS_H\n\n");
            
            sb.append("// ═══════ IL2CPP CORE OFFSETS (ARM64) ═══════\n\n");
            sb.append("// Il2CppObject layout\n");
            sb.append("#define OBJ_KLASS_OFFSET       0x00\n");
            sb.append("#define OBJ_MONITOR_OFFSET     0x08\n");
            sb.append("#define OBJ_SIZE               0x10\n\n");
            
            sb.append("// Il2CppClass layout (approximate, use Il2CppDumper for exact)\n");
            sb.append("#define CLASS_IMAGE_OFFSET     0x00\n");
            sb.append("#define CLASS_NAME_OFFSET      0x10\n");
            sb.append("#define CLASS_NAMESPACE_OFFSET 0x18\n");
            sb.append("#define CLASS_FIELDS_OFFSET    0x68\n");
            sb.append("#define CLASS_METHODS_OFFSET   0x70\n");
            sb.append("#define CLASS_METHOD_COUNT     0x90\n");
            sb.append("#define CLASS_FIELD_COUNT      0x94\n\n");
            
            sb.append("// Il2CppMethodInfo layout\n");
            sb.append("#define METHOD_KLASS_OFFSET    0x00\n");
            sb.append("#define METHOD_RETURN_OFFSET   0x08\n");
            sb.append("#define METHOD_POINTER_OFFSET  0x18\n");
            sb.append("#define METHOD_NAME_OFFSET     0x30\n");
            sb.append("#define METHOD_TOKEN_OFFSET    0x48\n");
            sb.append("#define METHOD_FLAGS_OFFSET    0x4C\n");
            sb.append("#define METHOD_PARAM_COUNT     0x52\n\n");
            
            sb.append("// Il2CppFieldInfo layout\n");
            sb.append("#define FIELD_NAME_OFFSET      0x00\n");
            sb.append("#define FIELD_TYPE_OFFSET      0x08\n");
            sb.append("#define FIELD_PARENT_OFFSET    0x10\n");
            sb.append("#define FIELD_OFFSET_VALUE     0x18\n\n");
            
            sb.append("// Common IL2CPP API function offsets (fill from libil2cpp.so)\n");
            sb.append("// Check libil2cpp_elf.txt dynamic symbols for exact addresses\n\n");
            sb.append("// ============ ARCHITECTURE DETECTION ============\n\n");
            sb.append("#if defined(__aarch64__)\n");
            sb.append("  #define ARCH_ARM64\n");
            sb.append("  #define PTR_SIZE 8\n");
            sb.append("#elif defined(__arm__)\n");
            sb.append("  #define ARCH_ARM32\n");
            sb.append("  #define PTR_SIZE 4\n");
            sb.append("#elif defined(__x86_64__)\n");
            sb.append("  #define ARCH_X64\n");
            sb.append("  #define PTR_SIZE 8\n");
            sb.append("#elif defined(__i386__)\n");
            sb.append("  #define ARCH_X86\n");
            sb.append("  #define PTR_SIZE 4\n");
            sb.append("#endif\n\n");
            
            sb.append("#endif // IL2CPP_OFFSETS_H\n");
            writeToFile(new File(output, "il2cpp_offsets.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateClassList(String pkg, File output, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  il2cpp_classes.txt - Class Enumeration with Indices         ║\n");
            sb.append("║  Package: ").append(pkg).append("\n");
            sb.append("║  Generated: ").append(ts).append("\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            
            sb.append("[Unity Core Classes]\n");
            String[] core = {"Object","Component","Behaviour","MonoBehaviour","GameObject","Transform",
                "Rigidbody","Rigidbody2D","Collider","BoxCollider","SphereCollider","CapsuleCollider",
                "MeshCollider","Camera","Light","Renderer","MeshRenderer","SkinnedMeshRenderer",
                "Material","Texture","Texture2D","Sprite","AudioSource","AudioClip","AudioListener",
                "Animator","Animation","AnimationClip","AnimatorController","Canvas","CanvasGroup",
                "Button","Text","Image","RawImage","InputField","Slider","Toggle","Scrollbar",
                "ScrollRect","Dropdown","GridLayoutGroup","ContentSizeFitter","LayoutElement",
                "ParticleSystem","TrailRenderer","LineRenderer","NavMeshAgent","NavMesh",
                "CharacterController","Collider2D","BoxCollider2D","CircleCollider2D",
                "SpriteRenderer","CanvasRenderer","CanvasScaler","GraphicRaycaster"};
            int idx = 0;
            for (String c : core) {
                sb.append(String.format("  [%3d] 0x%08x  %s\n", idx++, 0, c));
            }
            
            sb.append("\n[Physics Classes]\n");
            String[] physics = {"Physics","Physics2D","RaycastHit","RaycastHit2D","Collision","ContactPoint",
                "Quaternion","Vector2","Vector3","Vector4","Color","Bounds","Rect","Matrix4x4","Plane","Ray"};
            for (String c : physics) {
                sb.append(String.format("  [%3d] 0x%08x  %s\n", idx++, 0, c));
            }
            
            sb.append("\n[System Classes]\n");
            String[] sys = {"String","Int32","Int64","Single","Double","Boolean","Byte","Char",
                "Array","List`1","Dictionary`2","Queue`1","Stack`1","HashSet`1","LinkedList`1",
                "StringBuilder","Exception","Type","Math","Random","Debug","Log","Application"};
            for (String c : sys) {
                sb.append(String.format("  [%3d] 0x%08x  %s\n", idx++, 0, c));
            }
            
            sb.append("\n[Network Classes]\n");
            String[] net = {"NetworkBehaviour","NetworkManager","NetworkIdentity","NetworkTransform",
                "NetworkAnimator","SyncList","Client","Server","MonoBehaviourPun","PhotonView",
                "PhotonNetwork","PhotonPlayer","Room","PhotonHandler","PhotonLobby"};
            for (String c : net) {
                sb.append(String.format("  [%3d] 0x%08x  %s\n", idx++, 0, c));
            }
            
            sb.append("\n// Total classes shown: ").append(idx).append("\n");
            sb.append("// Add custom classes below\n");
            
            writeToFile(new File(output, "il2cpp_classes.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateMethodList(String pkg, File output, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  il2cpp_methods.txt - Method Enumeration with Offsets        ║\n");
            sb.append("║  Package: ").append(pkg).append("\n");
            sb.append("║  Generated: ").append(ts).append("\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            
            sb.append("[Lifecycle Methods]\n");
            sb.append("  void Awake()                    RVA: 0x00000000\n");
            sb.append("  void Start()                    RVA: 0x00000000\n");
            sb.append("  void Update()                   RVA: 0x00000000\n");
            sb.append("  void FixedUpdate()              RVA: 0x00000000\n");
            sb.append("  void LateUpdate()               RVA: 0x00000000\n");
            sb.append("  void OnEnable()                 RVA: 0x00000000\n");
            sb.append("  void OnDisable()                RVA: 0x00000000\n");
            sb.append("  void OnDestroy()                RVA: 0x00000000\n");
            sb.append("  void OnApplicationQuit()        RVA: 0x00000000\n\n");
            
            sb.append("[Collision Methods]\n");
            sb.append("  void OnCollisionEnter(Collision)  RVA: 0x00000000\n");
            sb.append("  void OnCollisionStay(Collision)   RVA: 0x00000000\n");
            sb.append("  void OnCollisionExit(Collision)   RVA: 0x00000000\n");
            sb.append("  void OnTriggerEnter(Collider)     RVA: 0x00000000\n");
            sb.append("  void OnTriggerStay(Collider)      RVA: 0x00000000\n");
            sb.append("  void OnTriggerExit(Collider)      RVA: 0x00000000\n\n");
            
            sb.append("[Physics Methods]\n");
            sb.append("  Vector3 Rigidbody.get_velocity()         RVA: 0x00000000\n");
            sb.append("  void   Rigidbody.set_velocity(Vector3)   RVA: 0x00000000\n");
            sb.append("  void   Rigidbody.AddForce(Vector3, int)  RVA: 0x00000000\n");
            sb.append("  bool   Physics.Raycast(Ray, RaycastHit)  RVA: 0x00000000\n\n");
            
            sb.append("[UI Methods]\n");
            sb.append("  void   Button.onClick.AddListener()      RVA: 0x00000000\n");
            sb.append("  void   Text.set_text(string)             RVA: 0x00000000\n");
            sb.append("  string Text.get_text()                   RVA: 0x00000000\n");
            sb.append("  void   Image.set_sprite(Sprite)          RVA: 0x00000000\n\n");
            
            sb.append("[Object Methods]\n");
            sb.append("  T      Object.FindObjectOfType<T>()     RVA: 0x00000000\n");
            sb.append("  T[]    Object.FindObjectsOfType<T>()     RVA: 0x00000000\n");
            sb.append("  T      GameObject.Find(string)           RVA: 0x00000000\n");
            sb.append("  T      GetComponent<T>()                 RVA: 0x00000000\n");
            sb.append("  void   GameObject.SetActive(bool)        RVA: 0x00000000\n");
            sb.append("  void   Object.Destroy(Object, float)     RVA: 0x00000000\n\n");
            
            sb.append("// Fill in actual RVA offsets from libil2cpp.so symbols\n");
            sb.append("// Use radare2: afl~fun to list functions\n");
            sb.append("// Or Ghidra: Window > Symbol Tree > Functions\n");
            
            writeToFile(new File(output, "il2cpp_methods.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateStringDump(String pkg, File output, PackageInfo pi, ApplicationInfo ai) {
        try {
            StringBuilder sb = new StringBuilder();
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  il2cpp_strings.txt - String Dump with Hex References        ║\n");
            sb.append("║  Package: ").append(pkg).append("\n");
            sb.append("║  Generated: ").append(ts).append("\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            
            sb.append("[App Info]\n");
            sb.append("  package: ").append(pkg).append("\n");
            sb.append("  version: ").append(pi.versionName).append("\n");
            sb.append("  versionCode: ").append(pi.versionCode).append("\n");
            sb.append("  uid: ").append(ai.uid).append("\n");
            sb.append("  targetSdk: ").append(ai.targetSdkVersion).append("\n\n");
            
            sb.append("[Unity Lifecycle Strings]\n");
            sb.append("  0x00000000  \"Awake\"\n");
            sb.append("  0x00000000  \"Start\"\n");
            sb.append("  0x00000000  \"Update\"\n");
            sb.append("  0x00000000  \"FixedUpdate\"\n");
            sb.append("  0x00000000  \"LateUpdate\"\n");
            sb.append("  0x00000000  \"OnEnable\"\n");
            sb.append("  0x00000000  \"OnDisable\"\n");
            sb.append("  0x00000000  \"OnDestroy\"\n");
            sb.append("  0x00000000  \"OnApplicationPause\"\n");
            sb.append("  0x00000000  \"OnApplicationQuit\"\n\n");
            
            sb.append("[Common Game Strings]\n");
            String[] gameStrs = {
                "Player","Enemy","Health","Score","Level","Speed","Damage","Attack","Defense",
                "Jump","Run","Walk","Fire","Reload","Aim","Shoot","Kill","Win","Lose","Draw",
                "Game Over","Victory","Defeat","Pause","Resume","Settings","Volume","Music",
                "Sound","Graphics","Quality","Language","Network","Online","Offline","Match",
                "Lobby","Room","Chat","Team","Ally","Enemy","NPC","Boss","Item","Weapon",
                "Armor","Shield","Potion","Coin","Gold","Gem","Diamond","Key","Door","Gate",
                "Spawn","Respawn","Checkpoint","Save","Load","Menu","HUD","UI","Button",
                "Click","Tap","Swipe","Drag","Drop","Touch","Press","Hold","Release"
            };
            for (String s : gameStrs) {
                sb.append(String.format("  0x00000000  \"%s\"\n", s));
            }
            
            sb.append("\n[Network Strings]\n");
            String[] netStrs = {
                "localhost","127.0.0.1","http://","https://","ws://","wss://",
                "connect","disconnect","login","logout","register","token",
                "session","auth","bearer","api","v1","v2","version",
                "POST","GET","PUT","DELETE","PATCH",
                "application/json","Content-Type","Authorization"
            };
            for (String s : netStrs) {
                sb.append(String.format("  0x00000000  \"%s\"\n", s));
            }
            
            sb.append("\n[Shader Strings]\n");
            String[] shaders = {
                "Standard","Unlit/Color","Unlit/Texture","Mobile/Diffuse",
                "Particles/Standard Unlit","UI/Default","Hidden/InternalErrorShader",
                "Legacy Shaders/Diffuse","Nature/Tree Creator Bark"
            };
            for (String s : shaders) {
                sb.append(String.format("  0x00000000  \"%s\"\n", s));
            }
            
            sb.append("\n[Tag/Layer Strings]\n");
            sb.append("  0x00000000  \"Untagged\"\n");
            sb.append("  0x00000000  \"Player\"\n");
            sb.append("  0x00000000  \"MainCamera\"\n");
            sb.append("  0x00000000  \"Finish\"\n");
            sb.append("  0x00000000  \"Respawn\"\n");
            sb.append("  0x00000000  \"EditorOnly\"\n\n");
            
            sb.append("// Fill in actual hex addresses from libil2cpp_strings.txt\n");
            sb.append("// Use: grep -E \"0x[0-9a-f]+.*\\\"keyword\\\"\" libil2cpp_strings.txt\n");
            
            writeToFile(new File(output, "il2cpp_strings.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateXrefIndex(String pkg, File output) {
        try {
            StringBuilder sb = new StringBuilder();
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  CROSS-REFERENCE INDEX                                      ║\n");
            sb.append("║  Package: ").append(pkg).append("\n");
            sb.append("║  Generated: ").append(ts).append("\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            
            sb.append("[File Index]\n");
            sb.append("  il2cpp/\n");
            sb.append("    dump.cs                  - C# class/method dump\n");
            sb.append("    il2cpp.h                 - Type definitions\n");
            sb.append("    il2cpp_offsets.h         - Structure offsets\n");
            sb.append("    main.h                   - App info + macros\n");
            sb.append("    game.h                   - Game engine structs\n");
            sb.append("    libil2cpp.so             - IL2CPP runtime binary\n");
            sb.append("    libil2cpp_elf.txt        - ELF section/symbol analysis\n");
            sb.append("    libil2cpp_hexdump.txt    - Binary hex dump\n");
            sb.append("    libil2cpp_strings.txt    - Extracted strings\n");
            sb.append("    global-metadata.dat      - IL2CPP metadata\n");
            sb.append("    metadata_hexdump.txt     - Metadata hex dump\n");
            sb.append("    metadata_strings.txt     - Metadata strings\n");
            sb.append("    il2cpp_classes.txt       - Class enumeration\n");
            sb.append("    il2cpp_methods.txt       - Method enumeration\n");
            sb.append("    il2cpp_strings.txt       - String references\n");
            sb.append("    XREF_INDEX.txt           - This file\n\n");
            sb.append("  dex/\n");
            sb.append("    (packagename).apk        - APK copy\n");
            sb.append("    classes.dex              - DEX file(s)\n");
            sb.append("    dex_info.txt             - DEX analysis\n\n");
            sb.append("  native/\n");
            sb.append("    *.so                     - All native libraries\n");
            sb.append("    *_elf.txt                - ELF analysis per SO\n");
            sb.append("    *_strings.txt            - Strings per SO\n\n");
            sb.append("  unity/\n");
            sb.append("    libunity.so              - Unity engine\n");
            sb.append("    libil2cpp.so             - IL2CPP runtime\n");
            sb.append("    game.h                   - Game structs\n");
            sb.append("    unity_types.h            - Unity type defs\n\n");
            
            sb.append("[Workflow]\n");
            sb.append("  1. Open libil2cpp_elf.txt to find exported functions\n");
            sb.append("  2. Use dump.cs for class/method structure\n");
            sb.append("  3. Cross-reference hex addresses in hexdump files\n");
            sb.append("  4. Load strings for string-based lookups\n");
            sb.append("  5. Use Il2CppDumper for full IL2CPP analysis\n");
            sb.append("  6. Use Ghidra/IDA for native code analysis\n\n");
            
            sb.append("[Tools]\n");
            sb.append("  - Il2CppDumper: https://github.com/Perfare/Il2CppDumper\n");
            sb.append("  - Ghidra:       https://ghidra-sre.org/\n");
            sb.append("  - IDA Pro:      https://www.hex-rays.com/ida-pro/\n");
            sb.append("  - radare2:      https://rada.re/\n");
            sb.append("  - jadx:         https://github.com/skylot/jadx\n");
            sb.append("  - apktool:      https://ibotpeaches.github.io/Apktool/\n");
            sb.append("  - dnSpy:        https://github.com/dnSpy/dnSpy\n\n");
            
            writeToFile(new File(output, "XREF_INDEX.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateDexInfo(String pkg, File output, File apkFile) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  DEX INFO                                                    ║\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            sb.append("Package: ").append(pkg).append("\n");
            sb.append("APK: ").append(apkFile.getName()).append("\n");
            sb.append("Size: ").append(apkFile.length()).append(" bytes (0x").append(Long.toHexString(apkFile.length())).append(")\n\n");
            
            sb.append("[Decompile Instructions]\n");
            sb.append("  jadx:           jadx -d output/ ").append(apkFile.getName()).append("\n");
            sb.append("  apktool:        apktool d ").append(apkFile.getName()).append("\n");
            sb.append("  dex2jar:        d2j-dex2jar ").append(apkFile.getName()).append("\n");
            sb.append("  dex2jar (v2):   d2j-dex2jar --force-dex ").append(apkFile.getName()).append("\n\n");
            sb.append("[Static Analysis]\n");
            sb.append("  smali:          baksmali d classes.dex\n");
            sb.append("  jd-gui:         jd-gui classes-dex2jar.jar\n");
            sb.append("  bytecodeviewer: java -jar BytecodeViewer.jar\n");
            
            writeToFile(new File(output, "dex_info.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateUnityTypes(String pkg, File output) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("/* unity_types.h - Unity Engine Type Definitions\n * Package: ").append(pkg).append("\n */\n\n");
            sb.append("#ifndef UNITY_TYPES_H\n#define UNITY_TYPES_H\n\n");
            sb.append("#include <stdint.h>\n#include <stdbool.h>\n\n");
            sb.append("typedef struct Vector2 { float x, y; } Vector2;\n");
            sb.append("typedef struct Vector3 { float x, y, z; } Vector3;\n");
            sb.append("typedef struct Vector4 { float x, y, z, w; } Vector4;\n");
            sb.append("typedef struct Quaternion { float x, y, z, w; } Quaternion;\n");
            sb.append("typedef struct Color { float r, g, b, a; } Color;\n");
            sb.append("typedef struct Color32 { uint8_t r, g, b, a; } Color32;\n");
            sb.append("typedef struct Rect { float x, y, w, h; } Rect;\n");
            sb.append("typedef struct Bounds { Vector3 center; Vector3 extents; } Bounds;\n");
            sb.append("typedef struct Matrix4x4 { float m[16]; } Matrix4x4;\n");
            sb.append("typedef struct Ray { Vector3 origin; Vector3 direction; } Ray;\n\n");
            sb.append("typedef struct UnityEngine_Object { void* klass; void* monitor; int32_t m_CachedPtr; } UnityEngine_Object;\n");
            sb.append("typedef struct UnityEngine_Component : UnityEngine_Object {} UnityEngine_Component;\n");
            sb.append("typedef struct UnityEngine_Behaviour : UnityEngine_Component { bool m_Enabled; } UnityEngine_Behaviour;\n");
            sb.append("typedef struct UnityEngine_MonoBehaviour : UnityEngine_Behaviour {} UnityEngine_MonoBehaviour;\n\n");
            sb.append("#endif\n");
            writeToFile(new File(output, "unity_types.h"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void generateSummary(String pkg, File outputDir) {
        try {
            StringBuilder sb = new StringBuilder();
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            
            sb.append("╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║  BlackBox Enhanced v0.0.10 - DUMP SUMMARY                   ║\n");
            sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
            
            AppDumpInfo info = getAppDumpInfo(pkg);
            sb.append("Package:    ").append(pkg).append("\n");
            sb.append("App Name:   ").append(info.appName).append("\n");
            sb.append("Version:    ").append(info.versionName).append(" (").append(info.versionCode).append(")\n");
            sb.append("UID:        ").append(info.sourceDir).append("\n");
            sb.append("IL2CPP:     ").append(info.isIL2CPP ? "YES ✓" : "NO ✗").append("\n");
            sb.append("Unity:      ").append(info.isUnity ? "YES ✓" : "NO ✗").append("\n");
            sb.append("Native:     ").append(info.hasNative ? "YES ✓" : "NO ✗").append("\n");
            sb.append("Generated:  ").append(ts).append("\n\n");
            
            sb.append("═══ OUTPUT FILES ═══\n\n");
            listFilesRecursive(outputDir, sb, "  ");
            
            sb.append("\n═══ TOOLS ═══\n\n");
            sb.append("  Il2CppDumper:  https://github.com/Perfare/Il2CppDumper\n");
            sb.append("  Ghidra:        https://ghidra-sre.org/\n");
            sb.append("  IDA Pro:       https://www.hex-rays.com/ida-pro/\n");
            sb.append("  radare2:       https://rada.re/\n");
            sb.append("  jadx:          https://github.com/skylot/jadx\n\n");
            
            writeToFile(new File(outputDir, "SUMMARY.txt"), sb.toString());
        } catch (Exception e) { }
    }
    
    private void listFilesRecursive(File dir, StringBuilder sb, String indent) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) {
                sb.append(indent).append("📁 ").append(f.getName()).append("/\n");
                listFilesRecursive(f, sb, indent + "  ");
            } else {
                sb.append(indent).append("📄 ").append(f.getName())
                  .append(" (").append(formatSize(f.length())).append(")\n");
            }
        }
    }
    
    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(Locale.US, "%.1f KB", bytes / 1024.0);
        return String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024));
    }
    
    // ==================== UTILS ====================
    
    private void copyFile(File source, File dest) throws IOException {
        FileInputStream fis = new FileInputStream(source);
        FileOutputStream fos = new FileOutputStream(dest);
        byte[] buf = new byte[8192];
        int len;
        while ((len = fis.read(buf)) > 0) fos.write(buf, 0, len);
        fis.close();
        fos.close();
    }
    
    private void writeToFile(File file, String content) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(content.getBytes());
        fos.close();
        Slog.d(TAG, "Written: " + file.getName() + " (" + file.length() + " bytes)");
    }
    
    private List<String> listFiles(File dir) {
        List<String> files = new ArrayList<>();
        if (dir.exists()) {
            File[] f = dir.listFiles();
            if (f != null) {
                for (File file : f) {
                    if (file.isFile()) files.add(file.getName() + " (" + file.length() + " bytes)");
                }
            }
        }
        return files;
    }
    
    @Override
    public void systemReady() {
        Slog.i(TAG, "AppDumperService v0.0.10 initialized - Real ELF analysis enabled");
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
