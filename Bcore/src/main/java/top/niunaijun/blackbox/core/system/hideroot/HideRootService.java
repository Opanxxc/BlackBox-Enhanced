package top.niunaijun.blackbox.core.system.hideroot;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Service for hiding root status from applications.
 * Makes rooted devices appear non-rooted to apps running in the virtual environment.
 */
public class HideRootService implements ISystemService {
    public static final String TAG = "HideRootService";
    
    private static final HideRootService sService = new HideRootService();
    private final Set<String> mRootApps = new HashSet<>();
    private final Set<String> mRootPaths = new HashSet<>();
    private final Set<String> mRootPackages = new HashSet<>();
    private boolean mHideRootEnabled = true;
    
    // Common root detection paths
    private static final String[] COMMON_ROOT_PATHS = {
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/su/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/system/usr/we-need-root",
        "/cache/su",
        "/data/su",
        "/dev/su"
    };
    
    // Common root packages
    private static final String[] COMMON_ROOT_PACKAGES = {
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.noshufou.android.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiquion.root",
        "com.alephzain.framaroot",
        "com.exceet.rootcloak",
        "com.devadvance.rootcloak",
        "com.saurik.substrate",
        "com.amphoras.hidemyroot",
        "com.amphoras.rootcloak"
    };
    
    // Common root binary names
    private static final String[] ROOT_BINARY_NAMES = {
        "su",
        "busybox",
        "Superuser.apk",
        "SuperSU.apk",
        "magisk",
        "magiskinit",
        "magiskdaemon",
        "magiskhide"
    };
    
    public static HideRootService get() {
        return sService;
    }
    
    /**
     * Enable or disable root hiding
     * @param enabled true to hide root, false to show root
     */
    public void setHideRootEnabled(boolean enabled) {
        mHideRootEnabled = enabled;
        Slog.d(TAG, "Root hiding " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * Check if root hiding is enabled
     * @return true if root is being hidden
     */
    public boolean isHideRootEnabled() {
        return mHideRootEnabled;
    }
    
    /**
     * Add a custom root app path to hide
     * @param path Path to the root app
     */
    public void addRootAppPath(String path) {
        mRootApps.add(path);
    }
    
    /**
     * Remove a custom root app path
     * @param path Path to remove
     */
    public void removeRootAppPath(String path) {
        mRootApps.remove(path);
    }
    
    /**
     * Add a custom root path to hide
     * @param path Path to hide
     */
    public void addRootPath(String path) {
        mRootPaths.add(path);
    }
    
    /**
     * Remove a custom root path
     * @param path Path to remove
     */
    public void removeRootPath(String path) {
        mRootPaths.remove(path);
    }
    
    /**
     * Add a root package to hide
     * @param packageName Package name to hide
     */
    public void addRootPackage(String packageName) {
        mRootPackages.add(packageName);
    }
    
    /**
     * Remove a root package
     * @param packageName Package name to remove
     */
    public void removeRootPackage(String packageName) {
        mRootPackages.remove(packageName);
    }
    
    /**
     * Check if a file path should be hidden
     * @param path File path to check
     * @return true if the path should be hidden
     */
    public boolean shouldHidePath(String path) {
        if (!mHideRootEnabled) {
            return false;
        }
        
        // Check against common root paths
        for (String rootPath : COMMON_ROOT_PATHS) {
            if (path.contains(rootPath)) {
                return true;
            }
        }
        
        // Check against custom root paths
        for (String rootPath : mRootPaths) {
            if (path.contains(rootPath)) {
                return true;
            }
        }
        
        // Check for root binary names
        String fileName = new File(path).getName();
        for (String binaryName : ROOT_BINARY_NAMES) {
            if (fileName.equals(binaryName)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if a package is a root app
     * @param packageName Package name to check
     * @return true if the package is a root app
     */
    public boolean isRootPackage(String packageName) {
        if (!mHideRootEnabled) {
            return false;
        }
        
        // Check against common root packages
        for (String rootPackage : COMMON_ROOT_PACKAGES) {
            if (packageName.equals(rootPackage)) {
                return true;
            }
        }
        
        // Check against custom root packages
        return mRootPackages.contains(packageName);
    }
    
    /**
     * Get modified file listing that hides root files
     * @param directory Directory to list
     * @return List of files excluding root files
     */
    public String[] getModifiedFileListing(File directory) {
        if (!mHideRootEnabled) {
            String[] files = directory.list();
            return files != null ? files : new String[0];
        }
        
        List<String> filteredFiles = new ArrayList<>();
        String[] files = directory.list();
        
        if (files != null) {
            for (String file : files) {
                String fullPath = new File(directory, file).getAbsolutePath();
                if (!shouldHidePath(fullPath)) {
                    filteredFiles.add(file);
                }
            }
        }
        
        return filteredFiles.toArray(new String[0]);
    }
    
    /**
     * Check if a file exists and is not a hidden root file
     * @param path File path to check
     * @return true if file exists and is not hidden
     */
    public boolean fileExists(String path) {
        File file = new File(path);
        if (!file.exists()) {
            return false;
        }
        
        if (mHideRootEnabled && shouldHidePath(path)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Get modified file length that hides root files
     * @param path File path
     * @return File length or -1 if file is hidden
     */
    public long getFileLength(String path) {
        File file = new File(path);
        if (!file.exists()) {
            return -1;
        }
        
        if (mHideRootEnabled && shouldHidePath(path)) {
            return -1;
        }
        
        return file.length();
    }
    
    /**
     * Check if /system is mounted as read-write (common root indicator)
     * @return true if /system appears to be read-only
     */
    public boolean isSystemReadOnly() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/mounts"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("/system")) {
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 4) {
                        String mountOptions = parts[3];
                        return !mountOptions.contains("rw");
                    }
                }
            }
            reader.close();
        } catch (IOException e) {
            // If we can't read mounts, assume read-only
            return true;
        }
        return true;
    }
    
    /**
     * Get build properties that don't indicate root
     * @return Modified build properties
     */
    public java.util.Map<String, String> getModifiedBuildProperties() {
        java.util.Map<String, String> properties = new java.util.HashMap<>();
        
        // Add standard build properties
        properties.put("ro.build.display.id", Build.DISPLAY);
        properties.put("ro.build.version.sdk", String.valueOf(Build.VERSION.SDK_INT));
        properties.put("ro.build.version.release", Build.VERSION.RELEASE);
        properties.put("ro.product.model", Build.MODEL);
        properties.put("ro.product.brand", Build.BRAND);
        properties.put("ro.product.manufacturer", Build.MANUFACTURER);
        
        // Ensure these don't indicate root
        properties.put("ro.build.tags", "release-keys");
        properties.put("ro.build.type", "user");
        properties.put("ro.secure", "1");
        properties.put("ro.debuggable", "0");
        properties.put("ro.build.selinux", "1");
        
        return properties;
    }
    
    /**
     * Check if Magisk Hide should be activated
     * @return true if Magisk Hide should be activated
     */
    public boolean shouldActivateMagiskHide() {
        return mHideRootEnabled;
    }
    
    /**
     * Get list of packages to hide from
     * @return List of package names
     */
    public Set<String> getPackagesToHideFrom() {
        Set<String> packages = new HashSet<>(COMMON_ROOT_PACKAGES);
        packages.addAll(mRootPackages);
        return packages;
    }
    
    @Override
    public void systemReady() {
        Slog.d(TAG, "HideRootService initialized");
    }
}
