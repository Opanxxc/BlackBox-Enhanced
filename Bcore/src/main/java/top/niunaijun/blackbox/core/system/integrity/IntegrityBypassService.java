package top.niunaijun.blackbox.core.system.integrity;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Service for bypassing SafetyNet and Play Integrity checks.
 * Makes rooted or modified devices appear legitimate to apps.
 */
public class IntegrityBypassService implements ISystemService {
    public static final String TAG = "IntegrityBypassService";
    
    private static final IntegrityBypassService sService = new IntegrityBypassService();
    private boolean mBypassEnabled = true;
    private final Map<String, IntegrityConfig> mPackageConfigs = new HashMap<>();
    private final Set<String> mProtectedPackages = new HashSet<>();
    
    // Common SafetyNet/Play Integrity detection methods
    private static final String[] DETECTION_PACKAGES = {
        "com.google.android.gms",
        "com.android.vending",
        "com.google.android.apps.walletnfcrel",
        "com.google.android.gms.unstable"
    };
    
    // Build properties that indicate rooted device
    private static final String[] ROOT_INDICATORS = {
        "ro.build.tags=test-keys",
        "ro.build.type=userdebug",
        "ro.secure=0",
        "ro.debuggable=1",
        "ro.build.selinux=0"
    };
    
    public static IntegrityBypassService get() {
        return sService;
    }
    
    /**
     * Enable or disable integrity bypass
     * @param enabled true to enable bypass
     */
    public void setBypassEnabled(boolean enabled) {
        mBypassEnabled = enabled;
        Slog.d(TAG, "Integrity bypass " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * Check if integrity bypass is enabled
     * @return true if bypass is enabled
     */
    public boolean isBypassEnabled() {
        return mBypassEnabled;
    }
    
    /**
     * Add a package to protect from integrity checks
     * @param packageName Package name
     */
    public void addProtectedPackage(String packageName) {
        mProtectedPackages.add(packageName);
    }
    
    /**
     * Remove a protected package
     * @param packageName Package name
     */
    public void removeProtectedPackage(String packageName) {
        mProtectedPackages.remove(packageName);
    }
    
    /**
     * Set integrity configuration for a package
     * @param packageName Package name
     * @param config Integrity configuration
     */
    public void setIntegrityConfig(String packageName, IntegrityConfig config) {
        mPackageConfigs.put(packageName, config);
    }
    
    /**
     * Get integrity configuration for a package
     * @param packageName Package name
     * @return Integrity configuration
     */
    public IntegrityConfig getIntegrityConfig(String packageName) {
        return mPackageConfigs.get(packageName);
    }
    
    /**
     * Check if a package should be protected
     * @param packageName Package name
     * @return true if package should be protected
     */
    public boolean isProtectedPackage(String packageName) {
        if (!mBypassEnabled) {
            return false;
        }
        
        // Check against common detection packages
        for (String detectionPackage : DETECTION_PACKAGES) {
            if (packageName.equals(detectionPackage)) {
                return true;
            }
        }
        
        // Check against custom protected packages
        return mProtectedPackages.contains(packageName);
    }
    
    /**
     * Get modified build properties that pass SafetyNet
     * @return Modified build properties
     */
    public Map<String, String> getModifiedBuildProperties() {
        Map<String, String> properties = new HashMap<>();
        
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
        
        // Add additional properties for SafetyNet
        properties.put("ro.build.flavor", "user");
        properties.put("ro.build.description", Build.DISPLAY);
        properties.put("ro.build.version.codename", Build.VERSION.CODENAME);
        
        return properties;
    }
    
    /**
     * Check if device passes SafetyNet check
     * @return true if device appears safe
     */
    public boolean passesSafetyNet() {
        if (!mBypassEnabled) {
            return false;
        }
        
        // Check build properties
        for (String indicator : ROOT_INDICATORS) {
            String[] parts = indicator.split("=");
            if (parts.length == 2) {
                String prop = getSystemProperty(parts[0]);
                if (prop != null && prop.equals(parts[1])) {
                    return false;
                }
            }
        }
        
        // Check for root files
        String[] rootFiles = {
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su"
        };
        
        for (String rootFile : rootFiles) {
            if (new File(rootFile).exists()) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check if device passes Play Integrity check
     * @return true if device appears legitimate
     */
    public boolean passesPlayIntegrity() {
        if (!mBypassEnabled) {
            return false;
        }
        
        // Similar to SafetyNet but with additional checks
        return passesSafetyNet();
    }
    
    /**
     * Get modified package info that passes integrity checks
     * @param packageName Package name
     * @return Modified package info
     */
    public PackageInfo getModifiedPackageInfo(String packageName) {
        try {
            PackageInfo packageInfo = BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
            
            // Modify package info to appear legitimate
            // This is a simplified version - in production, you'd need to handle this more carefully
            
            return packageInfo;
        } catch (PackageManager.NameNotFoundException e) {
            Slog.e(TAG, "Package not found: " + packageName);
            return null;
        }
    }
    
    /**
     * Get modified installer package name
     * @param packageName Package name
     * @return Installer package name
     */
    public String getModifiedInstallerPackageName(String packageName) {
        // Return legitimate installer packages
        String[] legitimateInstallers = {
            "com.android.vending", // Google Play Store
            "com.android.packageinstaller",
            "com.google.android.packageinstaller"
        };
        
        return legitimateInstallers[0]; // Default to Google Play Store
    }
    
    /**
     * Check if package is from legitimate source
     * @param packageName Package name
     * @return true if package appears legitimate
     */
    public boolean isLegitimateSource(String packageName) {
        try {
            String installer = BlackBoxCore.getPackageManager().getInstallerPackageName(packageName);
            
            // Check if installer is legitimate
            return installer != null && (
                installer.equals("com.android.vending") ||
                installer.equals("com.android.packageinstaller") ||
                installer.equals("com.google.android.packageinstaller")
            );
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get modified signature hash
     * @param packageName Package name
     * @return Modified signature hash
     */
    public String getModifiedSignatureHash(String packageName) {
        try {
            PackageInfo packageInfo = BlackBoxCore.getPackageManager().getPackageInfo(
                packageName, PackageManager.GET_SIGNATURES);
            
            if (packageInfo.signatures != null && packageInfo.signatures.length > 0) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] signatureBytes = packageInfo.signatures[0].toByteArray();
                byte[] hash = md.digest(signatureBytes);
                return Base64.encodeToString(hash, Base64.NO_WRAP);
            }
        } catch (Exception e) {
            Slog.e(TAG, "Failed to get signature hash: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Get system property value
     * @param prop Property name
     * @return Property value or null
     */
    private String getSystemProperty(String prop) {
        try {
            Process process = Runtime.getRuntime().exec("getprop " + prop);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String value = reader.readLine();
            reader.close();
            return value;
        } catch (IOException e) {
            return null;
        }
    }
    
    /**
     * Check if device is emulator
     * @return true if device is emulator
     */
    public boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
            || Build.FINGERPRINT.startsWith("unknown")
            || Build.MODEL.contains("google_sdk")
            || Build.MODEL.contains("Emulator")
            || Build.MODEL.contains("Android SDK built for x86")
            || Build.MANUFACTURER.contains("Genymotion")
            || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
            || "google_sdk".equals(Build.PRODUCT)
            || Build.HARDWARE.contains("goldfish")
            || Build.HARDWARE.contains("ranchu");
    }
    
    /**
     * Get modified device fingerprint
     * @return Modified fingerprint
     */
    public String getModifiedFingerprint() {
        // Return a legitimate-looking fingerprint
        return Build.BRAND + "/" + Build.PRODUCT + "/" + Build.DEVICE + ":" +
               Build.VERSION.RELEASE + "/" + Build.ID + "/" + Build.DISPLAY + ":user/release-keys";
    }
    
    /**
     * Check if SafetyNet bypass should be activated
     * @return true if bypass should be activated
     */
    public boolean shouldActivateBypass() {
        return mBypassEnabled;
    }
    
    /**
     * Get list of packages that need bypass
     * @return Set of package names
     */
    public Set<String> getPackagesNeedingBypass() {
        Set<String> packages = new HashSet<>(mProtectedPackages);
        for (String pkg : DETECTION_PACKAGES) {
            packages.add(pkg);
        }
        return packages;
    }
    
    @Override
    public void systemReady() {
        Slog.d(TAG, "IntegrityBypassService initialized");
    }
    
    /**
     * Integrity configuration class
     */
    public static class IntegrityConfig {
        public boolean bypassSafetyNet;
        public boolean bypassPlayIntegrity;
        public boolean hideRoot;
        public boolean hideEmulator;
        public boolean spoofFingerprint;
        public String customFingerprint;
        
        public IntegrityConfig() {
            this.bypassSafetyNet = true;
            this.bypassPlayIntegrity = true;
            this.hideRoot = true;
            this.hideEmulator = false;
            this.spoofFingerprint = false;
            this.customFingerprint = null;
        }
    }
}
