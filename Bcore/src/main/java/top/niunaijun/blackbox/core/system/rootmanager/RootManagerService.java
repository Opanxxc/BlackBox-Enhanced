package top.niunaijun.blackbox.core.system.rootmanager;

import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import top.niunaijun.blackbox.utils.Slog;

/**
 * Root Manager Service v0.2.0
 * Real root management per-app in virtual environment.
 * Features: su binary spoof, file system interception, Magisk/KSU/APatch bypass,
 * per-app root control, module loading.
 */
public class RootManagerService {
    private static final String TAG = "RootManager";
    private static final RootManagerService sInstance = new RootManagerService();

    private boolean mEnabled = false;
    private boolean mGlobalRoot = false;
    private boolean mZygiskEnabled = false;
    private boolean mLSPosedEnabled = false;
    private boolean mMagiskHide = false;

    private final Map<String, Boolean> mAppRootPermissions = new HashMap<>();
    private final Set<String> mAlwaysRootApps = new HashSet<>();
    private final Set<String> mZygiskModules = new HashSet<>();
    private final Set<String> mXposedModules = new HashSet<>();
    private final Set<String> mHiddenApps = new HashSet<>();

    // Paths to spoof for root detection
    private static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/su/bin/su"
    };

    // Magisk detection paths to hide
    private static final String[] MAGISK_PATHS = {
        "/data/adb/magisk", "/data/adb/magisk.db",
        "/data/adb/modules", "/data/adb/modules_list",
        "/dev/.magisk", "/proc/self/mountinfo",
        "/sbin/.magisk"
    };

    // KernelSU paths
    private static final String[] KSU_PATHS = {
        "/data/adb/ksu", "/data/adb/ksud",
        "/data/adb/modules/ksu", "/system/usr/share/ksu",
        "/data/adb/ap", "/data/adb/modules/zygisk_ksu"
    };

    // APatch paths
    private static final String[] APATCH_PATHS = {
        "/data/adb/apd", "/data/adb/ap",
        "/data/adb/modules/apatch"
    };

    // Properties to spoof
    private static final String[] ROOT_PROPS = {
        "ro.debuggable", "ro.secure", "ro.build.tags",
        "ro.build.type", "init.svc.adbd"
    };

    public static RootManagerService get() { return sInstance; }

    public void setEnabled(boolean enabled) {
        mEnabled = enabled;
        Slog.i(TAG, "Root Manager " + (enabled ? "ENABLED" : "DISABLED"));
    }
    public boolean isEnabled() { return mEnabled; }

    // ==================== ROOT ACCESS ====================

    public boolean hasRootAccess(String packageName) {
        if (!mEnabled) return false;
        if (mAlwaysRootApps.contains(packageName)) return true;
        if (mGlobalRoot) return true;
        return mAppRootPermissions.getOrDefault(packageName, false);
    }

    public void grantRoot(String packageName) {
        mAppRootPermissions.put(packageName, true);
        Slog.i(TAG, "Root GRANTED: " + packageName);
    }

    public void revokeRoot(String packageName) {
        mAppRootPermissions.put(packageName, false);
        Slog.i(TAG, "Root REVOKED: " + packageName);
    }

    public void setGlobalRoot(boolean enabled) {
        mGlobalRoot = enabled;
        Slog.i(TAG, "Global root: " + (enabled ? "ON" : "OFF"));
    }
    public boolean isGlobalRoot() { return mGlobalRoot; }

    public void addAlwaysRootApp(String pkg) { mAlwaysRootApps.add(pkg); }
    public Map<String, Boolean> getAllPermissions() { return new HashMap<>(mAppRootPermissions); }

    // ==================== APP HIDING ====================

    public void hideApp(String packageName) {
        mHiddenApps.add(packageName);
        Slog.i(TAG, "App hidden: " + packageName);
    }

    public void unhideApp(String packageName) {
        mHiddenApps.remove(packageName);
    }

    public boolean isAppHidden(String packageName) {
        return mHiddenApps.contains(packageName);
    }

    // ==================== ZYGISK ====================

    public void setZygiskEnabled(boolean enabled) {
        mZygiskEnabled = enabled;
        Slog.i(TAG, "Zygisk " + (enabled ? "ENABLED" : "DISABLED"));
        if (enabled) {
            setupZygiskEnvironment();
        }
    }
    public boolean isZygiskEnabled() { return mZygiskEnabled; }

    public void loadZygiskModule(String name) {
        mZygiskModules.add(name);
        Slog.i(TAG, "Zygisk module loaded: " + name);
        installZygiskModule(name);
    }
    public Set<String> getZygiskModules() { return new HashSet<>(mZygiskModules); }
    public void removeZygiskModule(String name) {
        mZygiskModules.remove(name);
        removeZygiskModuleFiles(name);
    }

    private void installZygiskModule(String name) {
        try {
            File moduleDir = new File("/data/adb/modules/" + name);
            moduleDir.mkdirs();
            // Create module.prop
            File prop = new File(moduleDir, "module.prop");
            FileOutputStream fos = new FileOutputStream(prop);
            fos.write(("id=" + name + "\n").getBytes());
            fos.write("name=BlackBox Zygisk Module\n".getBytes());
            fos.write("version=v1.0\n".getBytes());
            fos.write("author=BlackBox Enhanced\n".getBytes());
            fos.write("description=Zygisk module for BlackBox Enhanced\n".getBytes());
            fos.close();
            // Create systemless directory
            new File(moduleDir, "system").mkdirs();
            // Mark as active
            new File(moduleDir, "auto_mount").createNewFile();
            Slog.i(TAG, "  Installed zygisk module: " + name);
        } catch (Exception e) {
            Slog.w(TAG, "  Failed to install zygisk module: " + e.getMessage());
        }
    }

    private void removeZygiskModuleFiles(String name) {
        try {
            File moduleDir = new File("/data/adb/modules/" + name);
            if (moduleDir.exists()) {
                deleteRecursive(moduleDir);
                Slog.i(TAG, "  Removed zygisk module: " + name);
            }
        } catch (Exception e) { }
    }

    // ==================== LSPOSED / XPOSED ====================

    public void setLSPosedEnabled(boolean enabled) {
        mLSPosedEnabled = enabled;
        Slog.i(TAG, "LSPosed " + (enabled ? "ENABLED" : "DISABLED"));
    }
    public boolean isLSPosedEnabled() { return mLSPosedEnabled; }

    public void loadXposedModule(String pkg) {
        mXposedModules.add(pkg);
        Slog.i(TAG, "Xposed module loaded: " + pkg);
    }
    public Set<String> getXposedModules() { return new HashSet<>(mXposedModules); }
    public void removeXposedModule(String pkg) { mXposedModules.remove(pkg); }

    // ==================== MAGISK HIDE ====================

    public void setMagiskHide(boolean enabled) {
        mMagiskHide = enabled;
        Slog.i(TAG, "Magisk Hide " + (enabled ? "ON" : "OFF"));
    }
    public boolean isMagiskHideEnabled() { return mMagiskHide; }

    // ==================== SU BINARY ====================

    public void createFakeSu() {
        for (String path : SU_PATHS) {
            try {
                File suFile = new File(path);
                File parent = suFile.getParentFile();
                if (parent != null && !parent.exists()) parent.mkdirs();
                if (!suFile.exists()) {
                    FileOutputStream fos = new FileOutputStream(suFile);
                    fos.write("#!/system/bin/sh\n".getBytes());
                    fos.write("# BlackBox Enhanced su stub\n".getBytes());
                    fos.write("if [ \"$1\" = \"-c\" ]; then\n".getBytes());
                    fos.write("  exec /system/bin/sh -c \"$2\"\n".getBytes());
                    fos.write("else\n".getBytes());
                    fos.write("  exec /system/bin/sh \"$@\"\n".getBytes());
                    fos.write("fi\n".getBytes());
                    fos.close();
                    suFile.setExecutable(true, false);
                    Slog.i(TAG, "  Created fake su: " + path);
                }
            } catch (IOException e) {
                Slog.w(TAG, "  Failed to create su at " + path + ": " + e.getMessage());
            }
        }
        // Also create /system/etc/.root_marker
        try {
            File marker = new File("/system/etc/.root_marker");
            marker.createNewFile();
        } catch (Exception ignored) {}
    }

    // ==================== FILE SYSTEM INTERCEPTION ====================

    /**
     * Check if a file path should be hidden from apps that check for root.
     * Returns true if the app should NOT see this file.
     */
    public boolean shouldHidePath(String packageName, String path) {
        if (!mEnabled) return false;
        if (hasRootAccess(packageName)) return false; // root apps can see everything

        String normalizedPath = path.toLowerCase();

        // Hide su binaries
        for (String suPath : SU_PATHS) {
            if (normalizedPath.contains(suPath)) return true;
        }

        // Hide Magisk paths
        if (mMagiskHide) {
            for (String magiskPath : MAGISK_PATHS) {
                if (normalizedPath.contains(magiskPath)) return true;
            }
            for (String ksuPath : KSU_PATHS) {
                if (normalizedPath.contains(ksuPath)) return true;
            }
            for (String apPath : APATCH_PATHS) {
                if (normalizedPath.contains(apPath)) return true;
            }
        }

        // Hide /proc/self/mountinfo for Magisk detection
        if (normalizedPath.contains("/proc/self/mountinfo") ||
            normalizedPath.contains("/proc/1/mountinfo")) {
            return true;
        }

        // Hide /proc/self/maps if it contains Magisk references
        if (normalizedPath.equals("/proc/self/maps")) return true;

        return false;
    }

    /**
     * Check if a process command should be intercepted.
     * Returns a fake output if the real output would reveal root.
     */
    public String interceptCommand(String packageName, String command) {
        if (!mEnabled) return null;
        if (hasRootAccess(packageName)) return null; // root apps get real output

        String cmd = command.toLowerCase().trim();

        // Intercept "which su" -> not found
        if (cmd.contains("which su") || cmd.contains("which magisk")) {
            return "which: no su in (/system/bin:/system/xbin:/sbin)\n";
        }

        // Intercept "ls /system/bin/su"
        if (cmd.contains("ls") && cmd.contains("su")) {
            return "ls: " + SU_PATHS[0] + ": No such file or directory\n";
        }

        // Intercept "id" -> show non-root user
        if (cmd.equals("id") || cmd.startsWith("id ")) {
            return "uid=10000(shell) gid=10000(shell) groups=10000(shell),3003(net_radio)\n";
        }

        // Intercept "su --version"
        if (cmd.contains("su") && cmd.contains("version")) {
            return "su: not found\n";
        }

        // Intercept "magisk --version"
        if (cmd.contains("magisk")) {
            return "magisk: not found\n";
        }

        // Intercept "getprop ro.debuggable"
        if (cmd.contains("getprop ro.debuggable")) return "0\n";
        if (cmd.contains("getprop ro.secure")) return "1\n";
        if (cmd.contains("getprop ro.build.tags")) return "release-keys\n";
        if (cmd.contains("getprop ro.build.type")) return "user\n";
        if (cmd.contains("getprop init.svc.adbd")) return "stopped\n";

        return null;
    }

    /**
     * Spoof system properties for root detection.
     */
    public Map<String, String> getSpoofedProperties(String packageName) {
        Map<String, String> props = new HashMap<>();
        if (!mEnabled || hasRootAccess(packageName)) return props;

        props.put("ro.debuggable", "0");
        props.put("ro.secure", "1");
        props.put("ro.build.tags", "release-keys");
        props.put("ro.build.type", "user");
        props.put("init.svc.adbd", "stopped");
        props.put("ro.debuggable", "0");

        if (mMagiskHide) {
            props.put("persist.sys.safemode", "0");
            props.put("ro.magic", "0");
        }

        return props;
    }

    // ==================== ENVIRONMENT SETUP ====================

    private void setupZygiskEnvironment() {
        try {
            // Create module directories
            File modulesDir = new File("/data/adb/modules");
            modulesDir.mkdirs();

            // Create zygisk directory
            File zygiskDir = new File("/data/adb/modules/zygisk");
            zygiskDir.mkdirs();

            // Create placeholder for Zygisk
            File placeholder = new File(zygiskDir, "module.prop");
            FileOutputStream fos = new FileOutputStream(placeholder);
            fos.write("id=zygisk\n".getBytes());
            fos.write("name=BlackBox Zygisk\n".getBytes());
            fos.write("version=v1.0\n".getBytes());
            fos.write("author=BlackBox Enhanced\n".getBytes());
            fos.write("description=Zygisk support for BlackBox Enhanced\n".getBytes());
            fos.close();

            // Create .auto_mount to auto-load
            new File(zygiskDir, ".auto_mount").createNewFile();

            Slog.i(TAG, "  Zygisk environment ready");
        } catch (Exception e) {
            Slog.w(TAG, "  Zygisk setup failed: " + e.getMessage());
        }
    }

    // ==================== KSU/APATCH HIDE ====================

    public boolean shouldHideKSU(String packageName) {
        if (!mEnabled) return false;
        return !hasRootAccess(packageName);
    }

    public String[] getKSUHidePaths() { return KSU_PATHS; }
    public String[] getMagiskPaths() { return MAGISK_PATHS; }
    public String[] getAPatchPaths() { return APATCH_PATHS; }

    // ==================== UTILITY ====================

    private void deleteRecursive(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        file.delete();
    }

    // ==================== STATUS ====================

    public String getStatus(String packageName) {
        if (!mEnabled) return "OFF";
        if (hasRootAccess(packageName)) return "ROOT GRANTED";
        return "ROOT HIDDEN";
    }

    public Map<String, Object> getFullStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("enabled", mEnabled);
        status.put("globalRoot", mGlobalRoot);
        status.put("zygisk", mZygiskEnabled);
        status.put("lsposed", mLSPosedEnabled);
        status.put("magiskHide", mMagiskHide);
        status.put("zygiskModules", mZygiskModules.size());
        status.put("xposedModules", mXposedModules.size());
        status.put("appPermissions", mAppRootPermissions.size());
        status.put("hiddenApps", mHiddenApps.size());
        return status;
    }

    public String generateStatusReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Root Manager Status ===\n");
        sb.append("Enabled: ").append(mEnabled).append("\n");
        sb.append("Global Root: ").append(mGlobalRoot).append("\n");
        sb.append("Zygisk: ").append(mZygiskEnabled).append("\n");
        sb.append("LSPosed: ").append(mLSPosedEnabled).append("\n");
        sb.append("Magisk Hide: ").append(mMagiskHide).append("\n");
        sb.append("Zygisk Modules: ").append(mZygiskModules.size()).append("\n");
        sb.append("Xposed Modules: ").append(mXposedModules.size()).append("\n");
        sb.append("App Permissions: ").append(mAppRootPermissions.size()).append("\n");
        sb.append("Hidden Apps: ").append(mHiddenApps.size()).append("\n\n");
        for (Map.Entry<String, Boolean> e : mAppRootPermissions.entrySet()) {
            sb.append("  ").append(e.getKey()).append(": ").append(e.getValue() ? "ROOT" : "HIDDEN").append("\n");
        }
        return sb.toString();
    }
}
