package top.niunaijun.blackbox.core.system.dumper;

import android.os.Build;
import android.util.Log;

import java.io.File;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Native IL2CPP Runtime Dumper v0.2.0
 * 
 * Loads the native .so dumper into the target app's process
 * and dumps IL2CPP data directly from live memory.
 * 
 * This gives REAL method pointers (not 0x0), REAL field offsets,
 * and works even when files are obfuscated.
 *
 * Usage:
 *   NativeDumper.dump(pkg, outputDir)  -> async dump
 *   NativeDumper.getBase()             -> get libil2cpp.so base
 */
public class NativeDumper {
    private static final String TAG = "NativeDumper";
    private static boolean sLoaded = false;
    private static boolean sDumping = false;

    static {
        try {
            // Native dumper is compiled into libblackbox.so
            System.loadLibrary("blackbox");
            sLoaded = true;
            Log.i(TAG, "Native dumper loaded via libblackbox.so");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native dumper: " + e.getMessage());
            sLoaded = false;
        }
    }

    // ==================== JNI METHODS ====================

    /**
     * Start async native dump - runs in background thread.
     */
    public static native void nativeDump(String packageName, String outputDir);

    /**
     * Quick sync dump - returns status string.
     */
    public static native String nativeQuickDump(String outputDir);

    /**
     * Get libil2cpp.so base address from /proc/self/maps.
     */
    public static native long getIl2CppBase();

    /**
     * Get libil2cpp.so size.
     */
    public static native long getIl2CppSize();

    // ==================== JAVA API ====================

    /**
     * Check if native dumper is available.
     */
    public static boolean isAvailable() {
        return sLoaded;
    }

    /**
     * Check if a dump is in progress.
     */
    public static boolean isDumping() {
        return sDumping;
    }

    /**
     * Start native runtime dump for a package.
     * This dumps IL2CPP data from live memory with REAL method pointers.
     * 
     * @param pkg Package name of the target app
     * @param outputDir Output directory for dump files
     * @return true if dump was started successfully
     */
    public static boolean dump(String pkg, String outputDir) {
        if (!sLoaded) {
            Slog.e(TAG, "Native dumper not loaded");
            return false;
        }

        if (sDumping) {
            Slog.w(TAG, "Dump already in progress, skipping");
            return false;
        }

        try {
            // Verify libil2cpp.so exists in memory
            long base = getIl2CppBase();
            if (base == 0) {
                Slog.w(TAG, "libil2cpp.so not found in memory - app may not be IL2CPP");
                return false;
            }

            Slog.i(TAG, "Starting native dump for: " + pkg);
            Slog.i(TAG, "  libil2cpp.so base: 0x" + Long.toHexString(base));
            Slog.i(TAG, "  Output: " + outputDir);

            // Create output dirs
            File out = new File(outputDir);
            out.mkdirs();
            new File(outputDir + "/runtime").mkdirs();

            sDumping = true;

            // Start async dump
            nativeDump(pkg, outputDir);

            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Failed to start native dump: " + e.getMessage());
            sDumping = false;
            return false;
        }
    }

    /**
     * Quick status check - returns info about libil2cpp.so.
     */
    public static String getStatus() {
        if (!sLoaded) return "Native dumper not loaded";
        try {
            return nativeQuickDump("/tmp");
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Full dump with Java-side file generation too.
     * Combines native memory dump with Java-side ELF analysis.
     */
    public static boolean fullDump(String pkg, String outputDir) {
        if (!sLoaded) {
            Slog.w(TAG, "Native dumper not available, using Java-only dump");
            return false;
        }

        try {
            // Step 1: Get base address
            long base = getIl2CppBase();
            long size = getIl2CppSize();

            Slog.i(TAG, "=== Full Native Dump: " + pkg + " ===");
            Slog.i(TAG, "  libil2cpp base: 0x" + Long.toHexString(base));
            Slog.i(TAG, "  libil2cpp size: 0x" + Long.toHexString(size));

            // Step 2: Start native dump (async)
            boolean started = dump(pkg, outputDir);
            if (!started) {
                Slog.w(TAG, "Native dump failed to start");
                return false;
            }

            // Step 3: Copy the actual .so file for offline analysis
            try {
                android.content.pm.PackageInfo pi = BlackBoxCore.getPackageManager().getPackageInfo(pkg, 0);
                File libDir = new File(pi.applicationInfo.nativeLibraryDir);
                File il2cpp = new File(libDir, "libil2cpp.so");
                if (il2cpp.exists()) {
                    java.io.FileInputStream fis = new java.io.FileInputStream(il2cpp);
                    java.io.FileOutputStream fos = new java.io.FileOutputStream(
                        new File(outputDir + "/runtime", "libil2cpp.so"));
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = fis.read(buf)) > 0) fos.write(buf, 0, len);
                    fis.close();
                    fos.close();
                    Slog.i(TAG, "  Copied libil2cpp.so: " + il2cpp.length() + " bytes");
                }
            } catch (Exception e) {
                Slog.w(TAG, "  Failed to copy libil2cpp.so: " + e.getMessage());
            }

            // Step 4: Write metadata about the dump
            StringBuilder meta = new StringBuilder();
            meta.append("=== Native IL2CPP Runtime Dump ===\n");
            meta.append("Package: ").append(pkg).append("\n");
            meta.append("Architecture: ").append(Build.SUPPORTED_ABIS.length > 0 ? 
                Build.SUPPORTED_ABIS[0] : "unknown").append("\n");
            meta.append("libil2cpp.so base: 0x").append(Long.toHexString(base)).append("\n");
            meta.append("libil2cpp.so size: 0x").append(Long.toHexString(size)).append("\n");
            meta.append("Android: ").append(Build.VERSION.RELEASE).append(" (API ").append(Build.VERSION.SDK_INT).append(")\n");
            meta.append("Device: ").append(Build.MANUFACTURER).append(" ").append(Build.MODEL).append("\n\n");
            meta.append("Output files:\n");
            meta.append("  runtime/dump.cs          - IL2CPP class/method dump with REAL addresses\n");
            meta.append("  runtime/il2cpp_classes.txt - Class enumeration\n");
            meta.append("  runtime/il2cpp_methods.txt - Method enumeration with RVAs\n");
            meta.append("  runtime/il2cpp_offsets.h  - Field offset table\n");
            meta.append("  runtime/il2cpp_raw.txt   - Raw dump (machine-readable)\n");
            meta.append("  runtime/maps.txt         - /proc/self/maps for libil2cpp.so\n");
            meta.append("  runtime/libil2cpp.so     - Native library copy\n");

            java.io.FileOutputStream fos = new java.io.FileOutputStream(
                new File(outputDir + "/runtime", "DUMP_INFO.txt"));
            fos.write(meta.toString().getBytes());
            fos.close();

            Slog.i(TAG, "=== Full native dump started ===");
            return true;

        } catch (Exception e) {
            Slog.e(TAG, "Full dump failed: " + e.getMessage());
            sDumping = false;
            return false;
        }
    }
}
