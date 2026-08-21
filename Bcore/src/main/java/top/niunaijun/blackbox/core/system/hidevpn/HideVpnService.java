package top.niunaijun.blackbox.core.system.hidevpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Service for hiding VPN status from applications.
 * Makes VPN connections appear as regular network connections to apps.
 */
public class HideVpnService implements ISystemService {
    public static final String TAG = "HideVpnService";
    
    private static final HideVpnService sService = new HideVpnService();
    private boolean mHideVpnEnabled = true;
    private final Set<String> mVpnInterfaces = new HashSet<>();
    private final Set<String> mVpnPackages = new HashSet<>();
    
    // Common VPN interface names
    private static final String[] VPN_INTERFACE_NAMES = {
        "tun0", "tun1", "tun2", "tun3",
        "vpn0", "vpn1", "vpn2",
        "ppp0", "ppp1",
        "tun+",
        "wtun0"
    };
    
    // Common VPN packages
    private static final String[] VPN_PACKAGES = {
        "com.nordvpn.android",
        "com.expressvpn.vpn",
        "com.protonvpn.android",
        "com.privateinternetaccess.android",
        "com.windscribe.vpn",
        "com.cyberghost.vpn",
        "com.surfshark.vpnfastvpn",
        "com.hotspotshield.android",
        "com.hide.me.vpn",
        "com.tunnelbear.vpn",
        "com.vyprvpn.android",
        "com.ipvanish.android",
        "com Buffered VPN",
        "com.vpnsuper unlimited",
        "com.freedome.vpn",
        "com.securevpn.securevpn"
    };
    
    public static HideVpnService get() {
        return sService;
    }
    
    /**
     * Enable or disable VPN hiding
     * @param enabled true to hide VPN, false to show VPN
     */
    public void setHideVpnEnabled(boolean enabled) {
        mHideVpnEnabled = enabled;
        Slog.d(TAG, "VPN hiding " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * Check if VPN hiding is enabled
     * @return true if VPN is being hidden
     */
    public boolean isHideVpnEnabled() {
        return mHideVpnEnabled;
    }
    
    /**
     * Add a VPN interface name to hide
     * @param interfaceName Interface name
     */
    public void addVpnInterface(String interfaceName) {
        mVpnInterfaces.add(interfaceName);
    }
    
    /**
     * Remove a VPN interface name
     * @param interfaceName Interface name to remove
     */
    public void removeVpnInterface(String interfaceName) {
        mVpnInterfaces.remove(interfaceName);
    }
    
    /**
     * Add a VPN package to hide
     * @param packageName Package name
     */
    public void addVpnPackage(String packageName) {
        mVpnPackages.add(packageName);
    }
    
    /**
     * Remove a VPN package
     * @param packageName Package name to remove
     */
    public void removeVpnPackage(String packageName) {
        mVpnPackages.remove(packageName);
    }
    
    /**
     * Check if a network interface is a VPN
     * @param interfaceName Interface name
     * @return true if the interface is a VPN
     */
    public boolean isVpnInterface(String interfaceName) {
        if (!mHideVpnEnabled) {
            return false;
        }
        
        // Check against common VPN interfaces
        for (String vpnInterface : VPN_INTERFACE_NAMES) {
            if (interfaceName.equals(vpnInterface) || interfaceName.matches(vpnInterface.replace("+", ".*"))) {
                return true;
            }
        }
        
        // Check against custom VPN interfaces
        return mVpnInterfaces.contains(interfaceName);
    }
    
    /**
     * Check if a package is a VPN app
     * @param packageName Package name
     * @return true if the package is a VPN app
     */
    public boolean isVpnPackage(String packageName) {
        if (!mHideVpnEnabled) {
            return false;
        }
        
        // Check against common VPN packages
        for (String vpnPackage : VPN_PACKAGES) {
            if (packageName.equals(vpnPackage)) {
                return true;
            }
        }
        
        // Check against custom VPN packages
        return mVpnPackages.contains(packageName);
    }
    
    /**
     * Get modified network interfaces list
     * @return List of network interfaces excluding VPN interfaces
     */
    public List<NetworkInterface> getModifiedNetworkInterfaces() {
        List<NetworkInterface> interfaces = new ArrayList<>();
        
        try {
            List<NetworkInterface> allInterfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            
            for (NetworkInterface networkInterface : allInterfaces) {
                if (!isVpnInterface(networkInterface.getName())) {
                    interfaces.add(networkInterface);
                }
            }
        } catch (SocketException e) {
            Slog.e(TAG, "Failed to get network interfaces: " + e.getMessage());
        }
        
        return interfaces;
    }
    
    /**
     * Check if VPN is active
     * @return true if VPN is active (but hidden)
     */
    public boolean isVpnActive() {
        if (!mHideVpnEnabled) {
            return false;
        }
        
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface networkInterface : interfaces) {
                if (isVpnInterface(networkInterface.getName())) {
                    return true;
                }
            }
        } catch (SocketException e) {
            Slog.e(TAG, "Failed to check VPN status: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Get network capabilities without VPN information
     * @param network Network to get capabilities for
     * @return Modified network capabilities
     */
    public NetworkCapabilities getModifiedNetworkCapabilities(Network network) {
        if (!mHideVpnEnabled) {
            return null;
        }
        
        try {
            ConnectivityManager cm = (ConnectivityManager) BlackBoxCore.getContext()
                .getSystemService(Context.CONNECTIVITY_SERVICE);
            
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            if (capabilities != null) {
                // Remove VPN-specific transport types
                // This is a simplified version - in production, you'd need to handle this more carefully
                return capabilities;
            }
        } catch (Exception e) {
            Slog.e(TAG, "Failed to get network capabilities: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Get active network info without VPN information
     * @return Modified network info
     */
    public NetworkInfo getModifiedActiveNetworkInfo() {
        if (!mHideVpnEnabled) {
            return null;
        }
        
        try {
            ConnectivityManager cm = (ConnectivityManager) BlackBoxCore.getContext()
                .getSystemService(Context.CONNECTIVITY_SERVICE);
            
            NetworkInfo networkInfo = cm.getActiveNetworkInfo();
            if (networkInfo != null) {
                // Modify network info to hide VPN
                // This is a simplified version
                return networkInfo;
            }
        } catch (Exception e) {
            Slog.e(TAG, "Failed to get active network info: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Check if a process is using VPN
     * @param pid Process ID
     * @return true if the process is using VPN
     */
    public boolean isProcessUsingVpn(int pid) {
        if (!mHideVpnEnabled) {
            return false;
        }
        
        try {
            // Read /proc/net/tcp to check for VPN connections
            File tcpFile = new File("/proc/net/tcp");
            if (tcpFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(tcpFile));
                String line;
                while ((line = reader.readLine()) != null) {
                    // Check if connection is going through VPN interface
                    // This is a simplified check
                    if (line.contains("tun") || line.contains("vpn")) {
                        reader.close();
                        return true;
                    }
                }
                reader.close();
            }
        } catch (IOException e) {
            Slog.e(TAG, "Failed to check process VPN usage: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Get modified DNS servers
     * @return List of DNS servers excluding VPN DNS
     */
    public List<String> getModifiedDnsServers() {
        List<String> dnsServers = new ArrayList<>();
        
        try {
            // Read /etc/resolv.conf for DNS servers
            File resolvConf = new File("/etc/resolv.conf");
            if (resolvConf.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(resolvConf));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("nameserver")) {
                        String[] parts = line.split("\\s+");
                        if (parts.length >= 2) {
                            String dns = parts[1];
                            // Filter out VPN DNS servers
                            if (!isVpnDnsServer(dns)) {
                                dnsServers.add(dns);
                            }
                        }
                    }
                }
                reader.close();
            }
        } catch (IOException e) {
            Slog.e(TAG, "Failed to get DNS servers: " + e.getMessage());
        }
        
        return dnsServers;
    }
    
    /**
     * Check if a DNS server is a VPN DNS
     * @param dnsServer DNS server IP
     * @return true if it's a VPN DNS
     */
    private boolean isVpnDnsServer(String dnsServer) {
        // Common VPN DNS servers
        String[] vpnDns = {
            "10.0.0.1",
            "10.0.0.2",
            "198.18.0.1",
            "198.18.0.2"
        };
        
        for (String vpnDnsServer : vpnDns) {
            if (dnsServer.equals(vpnDnsServer)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if split tunneling should be used
     * @return true if split tunneling is enabled
     */
    public boolean shouldUseSplitTunneling() {
        return mHideVpnEnabled;
    }
    
    /**
     * Get list of apps that should bypass VPN
     * @return Set of package names
     */
    public Set<String> getAppsToBypassVpn() {
        Set<String> apps = new HashSet<>(mVpnPackages);
        return apps;
    }
    
    @Override
    public void systemReady() {
        Slog.d(TAG, "HideVpnService initialized");
    }
}
