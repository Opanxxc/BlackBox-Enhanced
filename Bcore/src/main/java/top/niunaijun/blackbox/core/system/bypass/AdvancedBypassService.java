package top.niunaijun.blackbox.core.system.bypass;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.core.system.hideroot.HideRootService;
import top.niunaijun.blackbox.core.system.hidevpn.HideVpnService;
import top.niunaijun.blackbox.core.system.integrity.IntegrityBypassService;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Advanced bypass service - all-in-one detection bypass.
 * Combines root hiding, hook bypass, integrity spoof, emulator bypass.
 * Auto-applies on app launch for maximum protection.
 */
public class AdvancedBypassService implements ISystemService {
    public static final String TAG = "AdvancedBypass";
    
    private static final AdvancedBypassService sService = new AdvancedBypassService();
    private boolean mEnabled = true;
    private final Map<String, BypassConfig> mPackageConfigs = new HashMap<>();
    private final Set<String> mProtectedApps = new HashSet<>();
    
    public static AdvancedBypassService get() {
        return sService;
    }
    
    public void setAdvancedBypassEnabled(boolean enabled) {
        mEnabled = enabled;
        Slog.i(TAG, "Advanced bypass " + (enabled ? "ENABLED" : "DISABLED"));
    }
    
    public boolean isAdvancedBypassEnabled() {
        return mEnabled;
    }
    
    public void addProtectedApp(String pkg) {
        mProtectedApps.add(pkg);
    }
    
    public void removeProtectedApp(String pkg) {
        mProtectedApps.remove(pkg);
    }
    
    public void setBypassConfig(String pkg, BypassConfig config) {
        mPackageConfigs.put(pkg, config);
    }
    
    public BypassConfig getBypassConfig(String pkg) {
        return mPackageConfigs.get(pkg);
    }
    
    /**
     * Apply ALL bypasses for a package - call this on app launch
     */
    public void applyAllBypasses(String packageName) {
        if (!mEnabled) return;
        
        Slog.i(TAG, "=== Applying ALL bypasses for: " + packageName + " ===");
        
        // 1. Root hiding
        HideRootService.get().setHideRootEnabled(true);
        HideRootService.get().addRootPackage(packageName);
        Slog.d(TAG, "  [1/7] Root hiding: ON");
        
        // 2. VPN hiding
        HideVpnService.get().setHideVpnEnabled(true);
        HideVpnService.get().addVpnPackage(packageName);
        Slog.d(TAG, "  [2/7] VPN hiding: ON");
        
        // 3. Integrity bypass
        IntegrityBypassService.get().setBypassEnabled(true);
        IntegrityBypassService.get().addProtectedPackage(packageName);
        Slog.d(TAG, "  [3/7] Integrity bypass: ON");
        
        // 4. Hook detection bypass
        HookDetectionBypassService.get().setBypassEnabled(true);
        HookDetectionBypassService.get().addProtectedPackage(packageName);
        Slog.d(TAG, "  [4/7] Hook bypass: ON");
        
        // 5. Hide Frida
        HookDetectionBypassService.get().addProtectedPackage("frida-server");
        HookDetectionBypassService.get().addProtectedPackage("re.frida.server");
        Slog.d(TAG, "  [5/7] Frida hiding: ON");
        
        // 6. Hide Xposed
        HookDetectionBypassService.get().addProtectedPackage("de.robv.android.xposed.installer");
        HookDetectionBypassService.get().addProtectedPackage("org.meowcat.edxposed.manager");
        HookDetectionBypassService.get().addProtectedPackage("io.github.lsposed.manager");
        Slog.d(TAG, "  [6/7] Xposed hiding: ON");
        
        // 7. Hide Magisk
        HookDetectionBypassService.get().addProtectedPackage("com.topjohnwu.magisk");
        Slog.d(TAG, "  [7/7] Magisk hiding: ON");
        
        mProtectedApps.add(packageName);
        
        Slog.i(TAG, "=== ALL bypasses applied for: " + packageName + " ===");
        Slog.i(TAG, "  Status: " + getBypassStatus().toString());
    }
    
    /**
     * Remove all bypasses for a package
     */
    public void removeAllBypasses(String packageName) {
        Slog.i(TAG, "Removing bypasses for: " + packageName);
        
        HideRootService.get().removeRootPackage(packageName);
        HideVpnService.get().removeVpnPackage(packageName);
        IntegrityBypassService.get().removeProtectedPackage(packageName);
        HookDetectionBypassService.get().removeProtectedPackage(packageName);
        
        mPackageConfigs.remove(packageName);
        mProtectedApps.remove(packageName);
    }
    
    /**
     * Get combined bypass status
     */
    public BypassStatus getBypassStatus() {
        BypassStatus status = new BypassStatus();
        status.rootHidden = HideRootService.get().isHideRootEnabled();
        status.vpnHidden = HideVpnService.get().isHideVpnEnabled();
        status.integrityPassed = IntegrityBypassService.get().passesSafetyNet();
        status.playIntegrityPassed = IntegrityBypassService.get().passesPlayIntegrity();
        status.hooksBypassed = HookDetectionBypassService.get().isBypassEnabled();
        status.emulatorHidden = !IntegrityBypassService.get().isEmulator();
        status.protectedAppsCount = mProtectedApps.size();
        return status;
    }
    
    /**
     * Check if a detection method is bypassed
     */
    public boolean isDetectionBypassed(String pkg, String method) {
        if (!mEnabled) return false;
        
        BypassConfig config = mPackageConfigs.getOrDefault(pkg, new BypassConfig());
        
        switch (method) {
            case "root": return config.bypassRoot && HideRootService.get().isHideRootEnabled();
            case "vpn": return config.bypassVpn && HideVpnService.get().isHideVpnEnabled();
            case "safetynet": return config.bypassSafetyNet && IntegrityBypassService.get().passesSafetyNet();
            case "integrity": return config.bypassPlayIntegrity && IntegrityBypassService.get().passesPlayIntegrity();
            case "frida": return config.bypassFrida;
            case "xposed": return config.bypassXposed;
            case "magisk": return config.bypassMagisk;
            case "hook": return config.bypassHook && HookDetectionBypassService.get().isBypassEnabled();
            case "emulator": return config.bypassEmulator && !IntegrityBypassService.get().isEmulator();
            default: return false;
        }
    }
    
    public Map<String, String> getModifiedSystemProperties() {
        Map<String, String> props = new HashMap<>();
        props.putAll(IntegrityBypassService.get().getModifiedBuildProperties());
        props.put("persist.sys.usb.config", "none");
        props.put("ro.adb.secure", "1");
        return props;
    }
    
    public boolean appearsLegitimate() {
        if (!mEnabled) return false;
        BypassStatus status = getBypassStatus();
        return status.isFullyProtected();
    }
    
    public String[] getBypassRecommendations(String pkg) {
        java.util.List<String> recs = new java.util.ArrayList<>();
        BypassStatus status = getBypassStatus();
        
        if (!status.rootHidden) recs.add("Enable root hiding");
        if (!status.vpnHidden) recs.add("Enable VPN hiding");
        if (!status.integrityPassed) recs.add("Enable SafetyNet bypass");
        if (!status.hooksBypassed) recs.add("Enable hook bypass");
        if (!status.emulatorHidden) recs.add("Enable emulator bypass");
        if (recs.isEmpty()) recs.add("All bypasses active - fully protected!");
        
        return recs.toArray(new String[0]);
    }
    
    @Override
    public void systemReady() {
        Slog.i(TAG, "AdvancedBypassService v0.0.10 initialized");
        Slog.i(TAG, "  Protected apps: " + mProtectedApps.size());
    }
    
    // ==================== DATA CLASSES ====================
    
    public static class BypassConfig {
        public boolean bypassRoot = true;
        public boolean bypassVpn = true;
        public boolean bypassEmulator = true;
        public boolean bypassSafetyNet = true;
        public boolean bypassPlayIntegrity = true;
        public boolean bypassFrida = true;
        public boolean bypassXposed = true;
        public boolean bypassMagisk = true;
        public boolean bypassHook = true;
        public boolean bypassMemoryDump = true;
    }
    
    public static class BypassStatus {
        public boolean rootHidden;
        public boolean vpnHidden;
        public boolean integrityPassed;
        public boolean playIntegrityPassed;
        public boolean hooksBypassed;
        public boolean emulatorHidden;
        public int protectedAppsCount;
        
        public boolean isFullyProtected() {
            return rootHidden && vpnHidden && integrityPassed && hooksBypassed && emulatorHidden;
        }
        
        @Override
        public String toString() {
            return "Root:" + rootHidden + " VPN:" + vpnHidden + 
                   " Integrity:" + integrityPassed + " PlayInt:" + playIntegrityPassed +
                   " Hooks:" + hooksBypassed + " Emulator:" + emulatorHidden +
                   " ProtectedApps:" + protectedAppsCount;
        }
    }
}
