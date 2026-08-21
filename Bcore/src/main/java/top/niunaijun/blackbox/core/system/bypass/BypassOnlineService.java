package top.niunaijun.blackbox.core.system.bypass;

import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import top.niunaijun.blackbox.utils.Slog;

/**
 * Online Bypass Service v0.2.0
 * Blocks anti-cheat/integrity detection from phoning home.
 * Features: DNS-level blocking, hosts file generation, property spoofing,
 * comprehensive anti-cheat/anti-tamper host list.
 */
public class BypassOnlineService {
    private static final String TAG = "BypassOnline";
    private static final BypassOnlineService sInstance = new BypassOnlineService();
    private boolean mActive = false;
    private final Set<String> mBlockedHosts = new HashSet<>();
    private final Set<String> mCustomBlockedHosts = new HashSet<>();
    private final Map<String, String> mSpoofedDns = new HashMap<>();

    // ==================== HOST CATEGORIES ====================

    private static final String[] ANALYTICS_HOSTS = {
        "app-measurement.com", "app-measurement.cn",
        "config.ioam.de", "report.datadoghq.com",
        "collect.tealiumiq.com", "cdn-settings.talkingdata.com",
        "sdkapi.arabi.com", "stats.ipinyou.com",
        "analytics.gokwik.co", "sb.scorecardresearch.com",
        "ad.atdmt.com", "cdn.flashtalking.com",
        "mathtag.com", "adnxs.com",
        "adskeeper.co.uk", "serving-sys.com",
        "bidswitch.net", "exelator.com"
    };

    private static final String[] CRASH_HOSTS = {
        "sentry.io", "sentry-cdn.com",
        "crashlytics.com", "e.crashlytics.com",
        "bugsnag.com", "notify.bugsnag.com",
        "newrelic.com", "rpm.newrelic.com",
        "collect.tearsheet.com",
        "bugreport.devicebug.com",
        "crash-android.example.com"
    };

    private static final String[] AD_HOSTS = {
        "adservice.google.com", "pagead2.googlesyndication.com",
        "doubleclick.net", "googleadservices.com",
        "admob.google.com", "ad.doubleclick.net",
        "static.criteo.net", "cdn.criteo.net",
        "widget.fanatics.com",
        "ad.atdmt.com", "moatads.com",
        "unity3d.com", "unityads.unity3d.com",
        "advertising.com", "adsrvr.org",
        "rubiconproject.com", "casalemedia.com",
        "pubmatic.com", "openx.net",
        "sharethrough.com", "outbrain.com",
        "taboola.com", "amazon-adsystem.com",
        "ironsrc.mobi", "ironsrc-mobile-assets.com"
    };

    private static final String[] TRACKING_HOSTS = {
        "appsflyer.com", "gcdsdk.appsflyer.com",
        "adjust.com", "view.adjust.com",
        "branch.io", "api.branch.io",
        "singular.net", "sdk.singular.net",
        "kochava.com", "control.kochava.com",
        "graph.facebook.com", "pixel.facebook.com",
        "graph.facebook.net",
        "mixpanel.com", "api.mixpanel.com",
        "amplitude.com", "api.amplitude.com",
        "segment.io", "api.segment.io",
        "clevertap.com", "wzrkt.com",
        "netscore.com", "metrics.imvu.com",
        "onesignal.com", "onesignal.com"
    };

    private static final String[] ANTI_ROOT_HOSTS = {
        "mcc.miui.com", "tracking.miui.com",
        "data.mistat.xiaomi.com", "sdkconfig.ad.xiaomi.com",
        "api.ad.xiaomi.com", "globalapi.ad.xiaomi.com",
        "data.mistat.india.xiaomi.com",
        "sdk.blueocean.me", "iolr.com",
        "cert.zeroace.dev",
        "zygisk-related-detection.com",
        "proof-key-for-cloud-play.com",
        "attestation.android.com",
        "api(devicecheck.apple.com"
    };

    private static final String[] ANTI_CHEAT_HOSTS = {
        "anticheat-callback.com",
        "game-integrity-api.com",
        "secure-cloud-gaming.com",
        "player-protection.com",
        "behavioral-anticheat.com",
        "real-time-detection.com",
        "anti-tamper-service.com",
        "device-fingerprint.com",
        "cheat-detection-api.com",
        "integrity-check-api.com",
        "online-protection.com",
        "cloud-verify.com",
        "xigncode3.com",
        "easyanticheat.net",
        "nprotect.com",
        "bakly.ai"
    };

    private static final String[] TELEMETRY_HOSTS = {
        "telemetry.microsoft.com",
        "vortex.data.microsoft.com",
        "settings-win.data.microsoft.com",
        "watson.telemetry.microsoft.com",
        "arc.msn.com",
        "aucFutureTense.com",
        "vortex-win.data.microsoft.com",
        "c.bing.com"
    };

    public static BypassOnlineService get() { return sInstance; }

    // ==================== ACTIVATION ====================

    public void activate() {
        mActive = true;
        Slog.i(TAG, "=== Online Bypass ACTIVATED ===");
        loadAllBlockedHosts();
        setupSpoofedDNS();
        Slog.i(TAG, "  Total blocked hosts: " + mBlockedHosts.size());
    }

    public void deactivate() {
        mActive = false;
        mBlockedHosts.clear();
        mSpoofedDns.clear();
        Slog.i(TAG, "=== Online Bypass DEACTIVATED ===");
    }

    private void loadAllBlockedHosts() {
        mBlockedHosts.clear();

        // Analytics
        for (String h : ANALYTICS_HOSTS) mBlockedHosts.add(h);
        Slog.i(TAG, "  Analytics: " + ANALYTICS_HOSTS.length + " hosts");

        // Crash reporting
        for (String h : CRASH_HOSTS) mBlockedHosts.add(h);
        Slog.i(TAG, "  Crash: " + CRASH_HOSTS.length + " hosts");

        // Advertising
        for (String h : AD_HOSTS) mBlockedHosts.add(h);
        Slog.i(TAG, "  Ads: " + AD_HOSTS.length + " hosts");

        // Tracking
        for (String h : TRACKING_HOSTS) mBlockedHosts.add(h);
        Slog.i(TAG, "  Tracking: " + TRACKING_HOSTS.length + " hosts");

        // Anti-root
        for (String h : ANTI_ROOT_HOSTS) mBlockedHosts.add(h);
        Slog.i(TAG, "  Anti-root: " + ANTI_ROOT_HOSTS.length + " hosts");

        // Anti-cheat
        for (String h : ANTI_CHEAT_HOSTS) mBlockedHosts.add(h);
        Slog.i(TAG, "  Anti-cheat: " + ANTI_CHEAT_HOSTS.length + " hosts");

        // Telemetry
        for (String h : TELEMETRY_HOSTS) mBlockedHosts.add(h);
        Slog.i(TAG, "  Telemetry: " + TELEMETRY_HOSTS.length + " hosts");

        // Custom hosts
        mBlockedHosts.addAll(mCustomBlockedHosts);
    }

    // ==================== DNS SPOOFING ====================

    private void setupSpoofedDNS() {
        // Spoof blocked host DNS to 127.0.0.1
        for (String host : mBlockedHosts) {
            mSpoofedDns.put(host, "127.0.0.1");
        }
    }

    /**
     * Get spoofed IP for a host (returns null if not spoofed).
     */
    public String getSpoofedIP(String host) {
        if (!mActive || host == null) return null;
        for (Map.Entry<String, String> entry : mSpoofedDns.entrySet()) {
            if (host.contains(entry.getKey())) return entry.getValue();
        }
        return null;
    }

    // ==================== HOST CHECKING ====================

    /**
     * Check if a host is blocked.
     */
    public boolean isBlocked(String host) {
        if (!mActive || host == null) return false;
        for (String blocked : mBlockedHosts) {
            if (host.contains(blocked)) return true;
        }
        return false;
    }

    /**
     * Block specific host.
     */
    public void blockHost(String host) {
        mCustomBlockedHosts.add(host);
        mBlockedHosts.add(host);
        mSpoofedDns.put(host, "127.0.0.1");
        Slog.i(TAG, "  Custom host blocked: " + host);
    }

    /**
     * Unblock a host.
     */
    public void unblockHost(String host) {
        mCustomBlockedHosts.remove(host);
        mBlockedHosts.remove(host);
        mSpoofedDns.remove(host);
    }

    // ==================== HOSTS FILE GENERATION ====================

    /**
     * Generate /etc/hosts style file for network blocking.
     */
    public boolean generateHostsFile(File output) {
        try {
            FileWriter fw = new FileWriter(output);
            fw.write("# BlackBox Enhanced - Online Bypass Hosts v0.2.0\n");
            fw.write("# Generated by BypassOnlineService\n");
            fw.write("# Total blocked: " + mBlockedHosts.size() + " hosts\n\n");
            fw.write("127.0.0.1 localhost\n");
            fw.write("::1 localhost\n\n");

            fw.write("# ═══════ ANALYTICS ═══════\n");
            writeHostGroup(fw, ANALYTICS_HOSTS);

            fw.write("\n# ═══════ CRASH REPORTING ═══════\n");
            writeHostGroup(fw, CRASH_HOSTS);

            fw.write("\n# ═══════ ADVERTISING ═══════\n");
            writeHostGroup(fw, AD_HOSTS);

            fw.write("\n# ═══════ TRACKING ═══════\n");
            writeHostGroup(fw, TRACKING_HOSTS);

            fw.write("\n# ═══════ ANTI-ROOT DETECTION ═══════\n");
            writeHostGroup(fw, ANTI_ROOT_HOSTS);

            fw.write("\n# ═══════ ANTI-CHEAT ═══════\n");
            writeHostGroup(fw, ANTI_CHEAT_HOSTS);

            fw.write("\n# ═══════ TELEMETRY ═══════\n");
            writeHostGroup(fw, TELEMETRY_HOSTS);

            fw.write("\n# ═══════ CUSTOM BLOCKS ═══════\n");
            for (String host : mCustomBlockedHosts) {
                fw.write("0.0.0.0 " + host + "\n");
            }

            fw.close();
            Slog.i(TAG, "  Generated hosts file: " + output.getAbsolutePath());
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "  Hosts file generation failed: " + e.getMessage());
            return false;
        }
    }

    private void writeHostGroup(FileWriter fw, String[] hosts) throws IOException {
        for (String host : hosts) {
            fw.write("0.0.0.0 " + host + "\n");
            fw.write("0.0.0.0 www." + host + "\n");
        }
    }

    // ==================== DEVICE PROPERTY SPOOFING ====================

    /**
     * Spoof device properties for integrity checks.
     */
    public Map<String, String> getSpoofedDeviceProps() {
        Map<String, String> props = new HashMap<>();

        // Hide root indicators
        props.put("ro.build.tags", "release-keys");
        props.put("ro.build.type", "user");
        props.put("ro.debuggable", "0");
        props.put("ro.secure", "1");

        // Hide SELinux permissive
        props.put("ro.build.selinux", "1");

        // Basic device info (keep real)
        props.put("ro.build.fingerprint", Build.FINGERPRINT);
        props.put("ro.build.manufacturer", Build.MANUFACTURER);
        props.put("ro.build.model", Build.MODEL);
        props.put("ro.build.product", Build.PRODUCT);

        Slog.i(TAG, "  Device props spoofed for integrity checks");
        return props;
    }

    // ==================== STATUS ====================

    public boolean isActive() { return mActive; }
    public int getBlockedCount() { return mBlockedHosts.size(); }
    public Set<String> getBlockedHosts() { return new HashSet<>(mBlockedHosts); }
    public int getCustomBlockedCount() { return mCustomBlockedHosts.size(); }

    /**
     * Get category counts for UI display.
     */
    public Map<String, Integer> getCategoryCounts() {
        Map<String, Integer> counts = new HashMap<>();
        counts.put("analytics", ANALYTICS_HOSTS.length);
        counts.put("crash", CRASH_HOSTS.length);
        counts.put("ads", AD_HOSTS.length);
        counts.put("tracking", TRACKING_HOSTS.length);
        counts.put("antiroot", ANTI_ROOT_HOSTS.length);
        counts.put("anticheat", ANTI_CHEAT_HOSTS.length);
        counts.put("telemetry", TELEMETRY_HOSTS.length);
        counts.put("custom", mCustomBlockedHosts.size());
        counts.put("total", mBlockedHosts.size());
        return counts;
    }

    /**
     * Generate bypass status report.
     */
    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Online Bypass Status v0.2.0 ===\n");
        sb.append("Active: ").append(mActive).append("\n");
        sb.append("Total blocked hosts: ").append(mBlockedHosts.size()).append("\n\n");

        Map<String, Integer> counts = getCategoryCounts();
        sb.append("Categories:\n");
        sb.append("  Analytics:    ").append(counts.get("analytics")).append(" hosts\n");
        sb.append("  Crash:        ").append(counts.get("crash")).append(" hosts\n");
        sb.append("  Ads:          ").append(counts.get("ads")).append(" hosts\n");
        sb.append("  Tracking:     ").append(counts.get("tracking")).append(" hosts\n");
        sb.append("  Anti-Root:    ").append(counts.get("antiroot")).append(" hosts\n");
        sb.append("  Anti-Cheat:   ").append(counts.get("anticheat")).append(" hosts\n");
        sb.append("  Telemetry:    ").append(counts.get("telemetry")).append(" hosts\n");
        sb.append("  Custom:       ").append(counts.get("custom")).append(" hosts\n");

        if (!mCustomBlockedHosts.isEmpty()) {
            sb.append("\nCustom blocks:\n");
            for (String h : mCustomBlockedHosts) {
                sb.append("  - ").append(h).append("\n");
            }
        }

        return sb.toString();
    }
}
