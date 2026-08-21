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
import java.io.InputStreamReader;
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
 * Enhanced Integrity Bypass Service.
 * Supports SafetyNet, Play Integrity, MeowBox, YuriKey, and custom device integrity.
 * Spoofs device properties, installer, fingerprint, and attestation.
 */
public class IntegrityBypassService implements ISystemService {
    public static final String TAG = "IntegrityBypass";
    
    private static final IntegrityBypassService sService = new IntegrityBypassService();
    private boolean mBypassEnabled = true;
    private final Map<String, IntegrityConfig> mPackageConfigs = new HashMap<>();
    private final Set<String> mProtectedPackages = new HashSet<>();
    
    // Integrity bypass modes
    public static final int MODE_SAFETYNET = 0;
    public static final int MODE_PLAY_INTEGRITY = 1;
    public static final int MODE_MEOWBOX = 2;
    public static final int MODE_YURIKEY = 3;
    public static final int MODE_FULL = 4;
    
    private int mBypassMode = MODE_FULL;
    
    // Spoofed device properties for MeowBox/YuriKey
    private String mSpoofedBrand = "samsung";
    private String mSpoofedModel = "SM-S918B";
    private String mSpoofedDevice = "s5e8835";
    private String mSpoofedProduct = "s5e8835xxx";
    private String mSpoofedFingerprint = "samsung/s5e8835xxx/s5e8835:14/UP1A.231005.007/S918BXXS3AWJ1:user/release-keys";
    private String mSpoofedBuildId = "UP1A.231005.007";
    private String mSpoofedDisplay = "S918BXXS3AWJ1";
    private String mSpoofedIncremental = "S918BXXS3AWJ1";
    
    // Common detection packages
    private static final String[] DETECTION_PACKAGES = {
        "com.google.android.gms",
        "com.android.vending",
        "com.google.android.apps.walletnfcrel",
        "com.google.android.gms.unstable",
        "com.google.android.gms.chimera",
        "com.google.android.gms.persistent"
    };
    
    // Root indicators
    private static final String[] ROOT_INDICATORS = {
        "ro.build.tags=test-keys",
        "ro.build.type=userdebug",
        "ro.secure=0",
        "ro.debuggable=1",
        "ro.build.selinux=0",
        "ro.debuggable=2"
    };
    
    // Root files to hide
    private static final String[] ROOT_FILES = {
        "/system/xbin/su", "/system/bin/su", "/sbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/su/bin/su", "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk", "/data/adb/magisk",
        "/data/adb/ksu", "/data/adb/apatch",
        "/cache/su", "/system/usr/we-need-root"
    };
    
    // Magisk-related paths
    private static final String[] MAGISK_PATHS = {
        "/sbin/.magisk", "/data/adb/magisk",
        "/data/adb/magisk.db", "/data/adb/modules",
        "/data/adb/.mrwatchdog"
    };
    
    public static IntegrityBypassService get() {
        return sService;
    }
    
    public void setBypassEnabled(boolean enabled) {
        mBypassEnabled = enabled;
        Slog.i(TAG, "Integrity bypass " + (enabled ? "ENABLED" : "DISABLED"));
    }
    
    public boolean isBypassEnabled() {
        return mBypassEnabled;
    }
    
    public void setBypassMode(int mode) {
        mBypassMode = mode;
        String modeName;
        switch (mode) {
            case MODE_SAFETYNET: modeName = "SafetyNet"; break;
            case MODE_PLAY_INTEGRITY: modeName = "Play Integrity"; break;
            case MODE_MEOWBOX: modeName = "MeowBox"; break;
            case MODE_YURIKEY: modeName = "YuriKey"; break;
            case MODE_FULL: modeName = "Full (All)"; break;
            default: modeName = "Unknown"; break;
        }
        Slog.i(TAG, "Bypass mode set to: " + modeName);
    }
    
    public int getBypassMode() {
        return mBypassMode;
    }
    
    /**
     * Set MeowBox-style spoofing (aggressive device spoof)
     */
    public void setMeowBoxMode() {
        mBypassMode = MODE_MEOWBOX;
        // Use Samsung Galaxy S24 Ultra as target device (known to pass)
        mSpoofedBrand = "samsung";
        mSpoofedModel = "SM-S928B";
        mSpoofedDevice = "e3q";
        mSpoofedProduct = "e3qxxx";
        mSpoofedFingerprint = "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXS3AWJ1:user/release-keys";
        mSpoofedBuildId = "UP1A.231005.007";
        mSpoofedDisplay = "S928BXXS3AWJ1";
        mSpoofedIncremental = "S928BXXS3AWJ1";
        Slog.i(TAG, "MeowBox mode activated - Samsung Galaxy S24 Ultra spoofed");
    }
    
    /**
     * Set YuriKey-style spoofing (stealth mode)
     */
    public void setYuriKeyMode() {
        mBypassMode = MODE_YURIKEY;
        // Use Pixel 8 Pro as target device (AOSP device, passes all checks)
        mSpoofedBrand = "google";
        mSpoofedModel = "Pixel 8 Pro";
        mSpoofedDevice = "husky";
        mSpoofedProduct = "husky";
        mSpoofedFingerprint = "google/husky/husky:14/UP1A.231005.007/10754064:user/release-keys";
        mSpoofedBuildId = "UP1A.231005.007";
        mSpoofedDisplay = "10754064";
        mSpoofedIncremental = "10754064";
        Slog.i(TAG, "YuriKey mode activated - Google Pixel 8 Pro spoofed");
    }
    
    /**
     * Set custom device spoofing
     */
    public void setCustomSpoof(String brand, String model, String device, String fingerprint) {
        mSpoofedBrand = brand;
        mSpoofedModel = model;
        mSpoofedDevice = device;
        mSpoofedFingerprint = fingerprint;
        Slog.i(TAG, "Custom spoof: " + brand + " " + model);
    }
    
    public void addProtectedPackage(String packageName) {
        mProtectedPackages.add(packageName);
        Slog.d(TAG, "Protected package added: " + packageName);
    }
    
    public void removeProtectedPackage(String packageName) {
        mProtectedPackages.remove(packageName);
    }
    
    public void setIntegrityConfig(String packageName, IntegrityConfig config) {
        mPackageConfigs.put(packageName, config);
    }
    
    public IntegrityConfig getIntegrityConfig(String packageName) {
        return mPackageConfigs.get(packageName);
    }
    
    public boolean isProtectedPackage(String packageName) {
        if (!mBypassEnabled) return false;
        for (String pkg : DETECTION_PACKAGES) {
            if (packageName.equals(pkg)) return true;
        }
        return mProtectedPackages.contains(packageName);
    }
    
    // ==================== SAFETYNET ====================
    
    /**
     * Get modified build properties that pass SafetyNet/Play Integrity
     */
    public Map<String, String> getModifiedBuildProperties() {
        Map<String, String> props = new HashMap<>();
        
        // Base device properties
        props.put("ro.build.display.id", mSpoofedDisplay);
        props.put("ro.build.version.sdk", String.valueOf(Build.VERSION.SDK_INT));
        props.put("ro.build.version.release", Build.VERSION.RELEASE);
        props.put("ro.build.version.codename", "REL");
        props.put("ro.build.version.security_patch", "2024-08-01");
        
        // Spoofed device identity
        props.put("ro.product.model", mSpoofedModel);
        props.put("ro.product.brand", mSpoofedBrand);
        props.put("ro.product.device", mSpoofedDevice);
        props.put("ro.product.name", mSpoofedProduct);
        props.put("ro.product.manufacturer", mSpoofedBrand);
        props.put("ro.product.board", mSpoofedDevice);
        
        // SafetyNet-critical properties
        props.put("ro.build.tags", "release-keys");
        props.put("ro.build.type", "user");
        props.put("ro.secure", "1");
        props.put("ro.debuggable", "0");
        props.put("ro.build.selinux", "1");
        props.put("ro.build.flavor", mSpoofedProduct + "-user");
        props.put("ro.build.description", mSpoofedProduct + ":14/" + mSpoofedBuildId + "/" + mSpoofedIncremental + ":user/release-keys");
        props.put("ro.build.fingerprint", mSpoofedFingerprint);
        props.put("ro.build.id", mSpoofedBuildId);
        props.put("ro.build.incremental", mSpoofedIncremental);
        
        // Kernel/ABI properties
        props.put("ro.product.cpu.abi", Build.CPU_ABI);
        props.put("ro.product.cpu.abilist", Build.SUPPORTED_ABIS[0]);
        
        // Additional integrity bypass
        props.put("ro.boot.verifiedbootstate", "green");
        props.put("ro.boot.vbmeta.device_state", "locked");
        props.put("ro.build.weekly", "false");
        props.put("ro.build.version.preview_sdk", "0");
        props.put("ro.build.version.all_preview_sdk", "0");
        props.put("ro.build.characteristics", "default");
        props.put("ro.com.google.clientidbase", "android-google");
        props.put("ro.com.google.gmsversion", "14.3.15");
        
        Slog.d(TAG, "Build properties spoofed for: " + mSpoofedBrand + " " + mSpoofedModel);
        return props;
    }
    
    public boolean passesSafetyNet() {
        if (!mBypassEnabled) return false;
        for (String indicator : ROOT_INDICATORS) {
            String[] parts = indicator.split("=");
            if (parts.length == 2) {
                String prop = getSystemProperty(parts[0]);
                if (prop != null && prop.equals(parts[1])) {
                    Slog.w(TAG, "Root indicator found: " + indicator);
                    return false;
                }
            }
        }
        for (String rootFile : ROOT_FILES) {
            if (new File(rootFile).exists()) {
                Slog.w(TAG, "Root file found: " + rootFile);
                return false;
            }
        }
        return true;
    }
    
    public boolean passesPlayIntegrity() {
        if (!mBypassEnabled) return false;
        // Play Integrity uses device attestation - we need strong spoofing
        if (mBypassMode == MODE_MEOWBOX || mBypassMode == MODE_YURIKEY || mBypassMode == MODE_FULL) {
            return passesSafetyNet() && hasValidFingerprint();
        }
        return passesSafetyNet();
    }
    
    private boolean hasValidFingerprint() {
        return mSpoofedFingerprint != null && mSpoofedFingerprint.contains(":user/release-keys");
    }
    
    // ==================== HIDE ROOT ====================
    
    /**
     * Check if a root-related path should be hidden
     */
    public boolean shouldHidePath(String path) {
        if (!mBypassEnabled) return false;
        for (String rootFile : ROOT_FILES) {
            if (path.contains(rootFile)) return true;
        }
        for (String magiskPath : MAGISK_PATHS) {
            if (path.contains(magiskPath)) return true;
        }
        // Also hide /proc/self/maps root indicators
        if (path.contains("/proc/") && (path.contains("magisk") || path.contains("ksu") || path.contains("supersu"))) {
            return true;
        }
        return false;
    }
    
    /**
     * Get modified /proc/self/maps content (hides root traces)
     */
    public String filterMapsContent(String mapsContent) {
        if (!mBypassEnabled || mapsContent == null) return mapsContent;
        StringBuilder filtered = new StringBuilder();
        String[] lines = mapsContent.split("\n");
        for (String line : lines) {
            if (!shouldHidePath(line)) {
                filtered.append(line).append("\n");
            }
        }
        return filtered.toString();
    }
    
    // ==================== INSTALLER SPOOF ====================
    
    public String getModifiedInstallerPackageName(String packageName) {
        // Always return Google Play Store as installer
        return "com.android.vending";
    }
    
    public boolean isLegitimateSource(String packageName) {
        // Always appear as Play Store install
        return true;
    }
    
    // ==================== SIGNATURE ====================
    
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
    
    // ==================== DEVICE INFO ====================
    
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
    
    public String getModifiedFingerprint() {
        return mSpoofedFingerprint;
    }
    
    public PackageInfo getModifiedPackageInfo(String packageName) {
        try {
            return BlackBoxCore.getPackageManager().getPackageInfo(packageName, 0);
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }
    }
    
    public boolean shouldActivateBypass() {
        return mBypassEnabled;
    }
    
    public Set<String> getPackagesNeedingBypass() {
        Set<String> packages = new HashSet<>(mProtectedPackages);
        for (String pkg : DETECTION_PACKAGES) {
            packages.add(pkg);
        }
        return packages;
    }
    
    private String getSystemProperty(String prop) {
        try {
            Process process = Runtime.getRuntime().exec("getprop " + prop);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String value = reader.readLine();
            reader.close();
            process.destroy();
            return value;
        } catch (Exception e) {
            return null;
        }
    }
    
    // ==================== SYSTEM SERVICE ====================
    
    @Override
    public void systemReady() {
        Slog.i(TAG, "IntegrityBypassService v0.0.10 initialized - Mode: " + mBypassMode);
        Slog.i(TAG, "  MeowBox support: YES");
        Slog.i(TAG, "  YuriKey support: YES");
        Slog.i(TAG, "  Play Integrity spoof: " + mSpoofedBrand + " " + mSpoofedModel);
    }
    
    // ==================== DATA CLASSES ====================
    
    public static class IntegrityConfig {
        public boolean bypassSafetyNet = true;
        public boolean bypassPlayIntegrity = true;
        public boolean hideRoot = true;
        public boolean hideEmulator = false;
        public boolean spoofFingerprint = true;
        public boolean spoofInstaller = true;
        public boolean filterProcMaps = true;
        public String customFingerprint = null;
        public String customDevice = null;
        public int bypassMode = MODE_FULL;
    }
}
