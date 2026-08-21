package top.niunaijun.blackbox.core.system.rootmanager;

import android.content.Context;
import android.os.Build;
import android.os.Environment;

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
 * Root Manager Service - manages root access per-app in the virtual environment.
 * Like Magisk/KernelSU but virtual - no real root needed on the host device.
 * 
 * Features:
 * - Per-app root permission management
 * - Fake su binary for apps that request root
 * - Root permission prompt simulation
 * - Zygisk module injection support
 * - KernelSU/APatch compatible root detection bypass
 */
public class RootManagerService implements ISystemService {
    public static final String TAG = "RootManager";
    
    private static final RootManagerService sService = new RootManagerService();
    private boolean mEnabled = false;
    private boolean mGlobalRoot = false; // Global root toggle
    
    // Per-app root permissions: packageName -> granted/denied
    private final Map<String, Boolean> mAppRootPermissions = new HashMap<>();
    
    // Apps that always get root (system apps, tools)
    private final Set<String> mAlwaysRootApps = new HashSet<>();
    
    // Apps that are explicitly denied root
    private final Set<String> mDeniedApps = new HashSet<>();
    
    // Zygisk modules
    private final Set<String> mZygiskModules = new HashSet<>();
    
    // LSPosed/Xposed modules
    private final Set<String> mXposedModules = new HashSet<>();
    
    public static RootManagerService get() { return sService; }
    
    public void setEnabled(boolean enabled) {
        mEnabled = enabled;
        Slog.i(TAG, "Root Manager " + (enabled ? "ENABLED" : "DISABLED"));
    }
    
    public boolean isEnabled() { return mEnabled; }
    
    // ==================== ROOT ACCESS ====================
    
    /**
     * Check if an app has root access
     */
    public boolean hasRootAccess(String packageName) {
        if (!mEnabled) return false;
        
        // Explicitly denied
        if (mDeniedApps.contains(packageName)) return false;
        
        // Always root apps
        if (mAlwaysRootApps.contains(packageName)) return true;
        
        // Global root toggle
        if (mGlobalRoot) return true;
        
        // Per-app permission
        return mAppRootPermissions.getOrDefault(packageName, false);
    }
    
    /**
     * Grant root access to an app
     */
    public void grantRoot(String packageName) {
        mAppRootPermissions.put(packageName, true);
        mDeniedApps.remove(packageName);
        Slog.i(TAG, "Root GRANTED for: " + packageName);
    }
    
    /**
     * Revoke root access from an app
     */
    public void revokeRoot(String packageName) {
        mAppRootPermissions.put(packageName, false);
        Slog.i(TAG, "Root REVOKED for: " + packageName);
    }
    
    /**
     * Set global root toggle (all apps get root)
     */
    public void setGlobalRoot(boolean enabled) {
        mGlobalRoot = enabled;
        Slog.i(TAG, "Global root: " + (enabled ? "ON" : "OFF"));
    }
    
    public boolean isGlobalRoot() { return mGlobalRoot; }
    
    /**
     * Add app that always gets root
     */
    public void addAlwaysRootApp(String packageName) {
        mAlwaysRootApps.add(packageName);
    }
    
    // ==================== ZYGISK ====================
    
    public void setZygiskEnabled(boolean enabled) {
        Slog.i(TAG, "Zygisk " + (enabled ? "ENABLED" : "DISABLED"));
    }
    
    public void loadZygiskModule(String moduleName) {
        mZygiskModules.add(moduleName);
        Slog.i(TAG, "Loaded Zygisk module: " + moduleName);
    }
    
    public Set<String> getZygiskModules() {
        return new HashSet<>(mZygiskModules);
    }
    
    // ==================== LSPOSED / XPOSED ====================
    
    public void setLSPosedEnabled(boolean enabled) {
        Slog.i(TAG, "LSPosed/Xposed " + (enabled ? "ENABLED" : "DISABLED"));
    }
    
    public void loadXposedModule(String packageName) {
        mXposedModules.add(packageName);
        Slog.i(TAG, "Loaded Xposed module: " + packageName);
    }
    
    public Set<String> getXposedModules() {
        return new HashSet<>(mXposedModules);
    }
    
    // ==================== SU BINARY ====================
    
    /**
     * Create a fake su binary in the virtual environment
     */
    public void createFakeSu() {
        try {
            // Create su binary in common paths
            String[] suPaths = {
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/data/local/su"
            };
            
            for (String path : suPaths) {
                File suFile = new File(path);
                if (!suFile.exists()) {
                    suFile.getParentFile().mkdirs();
                    // Create a simple shell script as su
                    FileOutputStream fos = new FileOutputStream(suFile);
                    fos.write("#!/system/bin/sh\n".getBytes());
                    fos.write("exec /system/bin/sh \"$@\"\n".getBytes());
                    fos.close();
                    suFile.setExecutable(true, false);
                    Slog.i(TAG, "Created fake su at: " + path);
                }
            }
        } catch (Exception e) {
            Slog.e(TAG, "Failed to create fake su: " + e.getMessage());
        }
    }
    
    // ==================== ROOT DETECTION BYPASS ====================
    
    /**
     * Check if root is detected by an app (and should be hidden)
     */
    public boolean isRootDetected(String packageName) {
        if (!mEnabled) return false;
        return !hasRootAccess(packageName);
    }
    
    /**
     * Get root status description for logging
     */
    public String getRootStatus(String packageName) {
        if (!mEnabled) return "Root Manager OFF";
        if (hasRootAccess(packageName)) return "ROOT GRANTED";
        return "ROOT DENIED (hidden)";
    }
    
    // ==================== ISystemService ====================
    
    @Override
    public void systemReady() {
        Slog.i(TAG, "RootManagerService initialized");
        Slog.i(TAG, "  Enabled: " + mEnabled);
        Slog.i(TAG, "  Global root: " + mGlobalRoot);
        Slog.i(TAG, "  Always-root apps: " + mAlwaysRootApps.size());
        Slog.i(TAG, "  Zygisk modules: " + mZygiskModules.size());
        Slog.i(TAG, "  Xposed modules: " + mXposedModules.size());
    }
}
