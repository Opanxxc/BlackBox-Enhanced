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
 * Service for bypassing hook detection mechanisms.
 * Protects against Frida, Xposed, Substrate, and other hooking frameworks.
 */
public class HookDetectionBypassService implements ISystemService {
    public static final String TAG = "HookDetectionBypassService";
    
    private static final HookDetectionBypassService sService = new HookDetectionBypassService();
    private boolean mBypassEnabled = true;
    private final Set<String> mProtectedPackages = new HashSet<>();
    
    // Frida detection paths
    private static final String[] FRIDA_PATHS = {
        "/tmp/frida-",
        "/data/local/tmp/frida",
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida-gadget.so",
        "/data/local/tmp/frida-agent.so",
        "/data/local/tmp/frida-inject"
    };
    
    // Xposed detection paths
    private static final String[] XPOSED_PATHS = {
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/system/bin/app_process_orig",
        "/system/bin/app_process32_original",
        "/system/bin/app_process64_original",
        "/system/etc/security/permissions/de.robv.android.xposed.installer.xml"
    };
    
    // Substrate detection paths
    private static final String[] SUBSTRATE_PATHS = {
        "/system/Library/Frameworks/CydiaSubstrate.framework",
        "/system/lib/libsubstrate-dw.so",
        "/system/lib/libsubstrate.so"
    };
    
    // Common hook detection packages
    private static final String[] HOOK_PACKAGES = {
        "de.robv.android.xposed.installer",
        "com.devadvance.rootcloakplus",
        "com.zphr.fridahider",
        "com.hazard.xposedlanger",
        "org.meowcat.edxposed.manager",
        "org.lsposed.manager",
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "io.github.vvb2060.apatch"
    };
    
    public static HookDetectionBypassService get() {
        return sService;
    }
    
    /**
     * Enable or disable hook detection bypass
     * @param enabled true to enable bypass
     */
    public void setBypassEnabled(boolean enabled) {
        mBypassEnabled = enabled;
        Slog.d(TAG, "Hook detection bypass " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * Check if bypass is enabled
     * @return true if bypass is enabled
     */
    public boolean isBypassEnabled() {
        return mBypassEnabled;
    }
    
    /**
     * Add a protected package
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
     * Check if Frida is installed
     * @return true if Frida is detected
     */
    public boolean isFridaInstalled() {
        if (!mBypassEnabled) {
            return false;
        }
        
        // Check common Frida paths
        for (String path : FRIDA_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        
        // Check for running Frida server
        try {
            Process process = Runtime.getRuntime().exec("ps -A");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida")) {
                    reader.close();
                    return true;
                }
            }
            reader.close();
        } catch (IOException e) {
            // Ignore
        }
        
        return false;
    }
    
    /**
     * Check if Xposed is installed
     * @return true if Xposed is detected
     */
    public boolean isXposedInstalled() {
        if (!mBypassEnabled) {
            return false;
        }
        
        // Check common Xposed paths
        for (String path : XPOSED_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        
        // Check for Xposed classes in memory
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (ClassNotFoundException e) {
            // Xposed not found
        }
        
        return false;
    }
    
    /**
     * Check if Substrate is installed
     * @return true if Substrate is detected
     */
    public boolean isSubstrateInstalled() {
        if (!mBypassEnabled) {
            return false;
        }
        
        // Check common Substrate paths
        for (String path : SUBSTRATE_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if any hook framework is installed
     * @return true if any hook framework is detected
     */
    public boolean isAnyHookInstalled() {
        return isFridaInstalled() || isXposedInstalled() || isSubstrateInstalled();
    }
    
    /**
     * Get modified Frida status
     * @return Modified Frida status
     */
    public String getModifiedFridaStatus() {
        return "not_found";
    }
    
    /**
     * Get modified Xposed status
     * @return Modified Xposed status
     */
    public String getModifiedXposedStatus() {
        return "not_installed";
    }
    
    /**
     * Get modified Substrate status
     * @return Modified Substrate status
     */
    public String getModifiedSubstrateStatus() {
        return "not_installed";
    }
    
    /**
     * Check if a hook package is installed
     * @param packageName Package name
     * @return true if package is a hook framework
     */
    public boolean isHookPackage(String packageName) {
        if (!mBypassEnabled) {
            return false;
        }
        
        for (String hookPackage : HOOK_PACKAGES) {
            if (packageName.equals(hookPackage)) {
                return true;
            }
        }
        
        return mProtectedPackages.contains(packageName);
    }
    
    /**
     * Get modified package list excluding hook frameworks
     * @param packages Original package list
     * @return Modified package list
     */
    public String[] getModifiedPackageList(String[] packages) {
        if (!mBypassEnabled) {
            return packages;
        }
        
        java.util.List<String> modifiedList = new java.util.ArrayList<>();
        for (String pkg : packages) {
            if (!isHookPackage(pkg)) {
                modifiedList.add(pkg);
            }
        }
        return modifiedList.toArray(new String[0]);
    }
    
    /**
     * Check if a library is a hook library
     * @param libraryPath Library path
     * @return true if library is a hook library
     */
    public boolean isHookLibrary(String libraryPath) {
        if (!mBypassEnabled) {
            return false;
        }
        
        String lowerPath = libraryPath.toLowerCase();
        return lowerPath.contains("frida") ||
               lowerPath.contains("xposed") ||
               lowerPath.contains("substrate") ||
               lowerPath.contains("hook") ||
               lowerPath.contains("inject");
    }
    
    /**
     * Get modified library list excluding hook libraries
     * @param libraries Original library list
     * @return Modified library list
     */
    public String[] getModifiedLibraryList(String[] libraries) {
        if (!mBypassEnabled) {
            return libraries;
        }
        
        java.util.List<String> modifiedList = new java.util.ArrayList<>();
        for (String lib : libraries) {
            if (!isHookLibrary(lib)) {
                modifiedList.add(lib);
            }
        }
        return modifiedList.toArray(new String[0]);
    }
    
    /**
     * Check if memory mapping should be hidden
     * @param memoryPath Memory path
     * @return true if memory path should be hidden
     */
    public boolean shouldHideMemoryMapping(String memoryPath) {
        if (!mBypassEnabled) {
            return false;
        }
        
        String lowerPath = memoryPath.toLowerCase();
        return lowerPath.contains("frida") ||
               lowerPath.contains("xposed") ||
               lowerPath.contains("substrate") ||
               lowerPath.contains("hook") ||
               lowerPath.contains("inject");
    }
    
    /**
     * Get modified /proc/self/maps content
     * @return Modified maps content
     */
    public String getModifiedMapsContent() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (!shouldHideMemoryMapping(line)) {
                    sb.append(line).append("\n");
                }
            }
            reader.close();
            return sb.toString();
        } catch (IOException e) {
            return "";
        }
    }
    
    /**
     * Get modified /proc/self/status content
     * @return Modified status content
     */
    public String getModifiedStatusContent() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                // Hide thread count and other indicators
                if (!line.startsWith("Threads:") && !line.startsWith("voluntary_ctxt_switches:")) {
                    sb.append(line).append("\n");
                }
            }
            reader.close();
            return sb.toString();
        } catch (IOException e) {
            return "";
        }
    }
    
    @Override
    public void systemReady() {
        Slog.d(TAG, "HookDetectionBypassService initialized");
    }
}
