package top.niunaijun.blackboxa.view.setting

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.util.Log
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreferenceCompat
import top.niunaijun.blackbox.BlackBoxCore
import top.niunaijun.blackboxa.R
import top.niunaijun.blackboxa.app.AppManager
import top.niunaijun.blackboxa.util.toast
import top.niunaijun.blackboxa.view.gms.GmsManagerActivity
import top.niunaijun.blackbox.core.system.hideroot.HideRootService
import top.niunaijun.blackbox.core.system.hidevpn.HideVpnService
import top.niunaijun.blackbox.core.system.integrity.IntegrityBypassService
import top.niunaijun.blackbox.core.system.bypass.HookDetectionBypassService
import top.niunaijun.blackbox.core.system.bypass.BypassOnlineService
import top.niunaijun.blackbox.core.system.rootmanager.RootManagerService
import top.niunaijun.blackbox.core.system.dumper.AppDumperService
import java.io.File

class SettingFragment : PreferenceFragmentCompat() {

    companion object {
        private const val TAG = "SettingFragment"
        private const val PREFS_NAME = "blackbox_settings"
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.setting, rootKey)

        initGms()
        initTools()
        initRootKernelSettings()
        initSecuritySettings()
        initAdvancedSettings()
        initDumperSettings()
        initSystemSettings()
        initStatusDisplay()
    }

    // ==================== GMS ====================

    private fun initGms() {
        val gmsManagerPreference: Preference = findPreference("gms_manager")!!

        if (BlackBoxCore.get().isSupportGms) {
            gmsManagerPreference.setOnPreferenceClickListener {
                GmsManagerActivity.start(requireContext())
                true
            }
        } else {
            gmsManagerPreference.summary = getString(R.string.no_gms)
            gmsManagerPreference.isEnabled = false
        }
    }

    // ==================== TOOLS ====================

    private fun initTools() {
        // MT Manager - launch installed app
        findPreference<Preference>("mt_manager")?.setOnPreferenceClickListener {
            var launched = false
            val packageNames = listOf(
                "com.moddingx.music",
                "com.internet114.mtmanager",
                "com.bydyxx.mtmanager",
                "mt.manager"
            )
            val activityNames = listOf(
                "com.moddingx.music.MainActivity",
                "com.internet114.mtmanager.MainActivity",
                "mt.manager.Activity"
            )

            for (pkg in packageNames) {
                for (act in activityNames) {
                    try {
                        val intent = Intent()
                        intent.setClassName(pkg, act)
                        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        startActivity(intent)
                        launched = true
                        break
                    } catch (e: Exception) { }
                }
                if (launched) break
            }

            if (!launched) {
                try {
                    val intent = requireContext().packageManager.getLaunchIntentForPackage("com.moddingx.music")
                    if (intent != null) {
                        startActivity(intent)
                        launched = true
                    }
                } catch (e: Exception) { }
            }

            if (!launched) {
                toast("MT Manager not installed. Download from GitHub.")
                try {
                    val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/AlexCui5402/MT-Manager/releases"))
                    startActivity(browserIntent)
                } catch (e: Exception) { }
            }
            true
        }
    }

    // ==================== ROOT & KERNEL ====================

    private fun initRootKernelSettings() {
        Log.d(TAG, "Initializing root/kernel settings...")

        // Root Hide
        initSwitch("root_hide", "Hide Root", "Hide root status from apps") { enabled ->
            Log.i(TAG, "Hide Root: ${if (enabled) "ON" else "OFF"}")
            HideRootService.get().setHideRootEnabled(enabled)
            AppManager.mBlackBoxLoader.invalidHideRoot(enabled)
        }

        // Root Manager - real root access management
        initSwitch("root_manager", "Root Manager", "Manage root access per-app (Magisk/KernelSU style)") { enabled ->
            Log.i(TAG, "Root Manager: ${if (enabled) "ON" else "OFF"}")
            RootManagerService.get().setEnabled(enabled)
            if (enabled) {
                HideRootService.get().setHideRootEnabled(true)
                RootManagerService.get().createFakeSu()
                RootManagerService.get().setMagiskHide(true)
                toast("Root Manager enabled with Magisk Hide")
            } else {
                toast("Root Manager disabled")
            }
        }

        // Zygisk Support
        initSwitch("zygisk_support", "Zygisk Support", "Enable Zygisk injection for modules") { enabled ->
            Log.i(TAG, "Zygisk Support: ${if (enabled) "ON" else "OFF"}")
            RootManagerService.get().setZygiskEnabled(enabled)
            if (enabled) {
                toast("Zygisk enabled - modules can be loaded")
            }
        }

        // LSPosed / Xposed Support
        initSwitch("lsposed_support", "LSPosed / Xposed Support", "Enable LSPosed/Xposed framework") { enabled ->
            Log.i(TAG, "LSPosed Support: ${if (enabled) "ON" else "OFF"}")
            RootManagerService.get().setLSPosedEnabled(enabled)
            if (enabled) {
                toast("LSPosed/Xposed enabled - hook framework active")
            }
        }

        Log.d(TAG, "Root/kernel settings initialized")
    }

    // ==================== SECURITY SETTINGS ====================

    private fun initSecuritySettings() {
        Log.d(TAG, "Initializing security settings...")

        // VPN Hide
        initSwitch("vpn_hide", "Hide VPN", "Hide VPN connections from apps") { enabled ->
            Log.i(TAG, "Hide VPN: ${if (enabled) "ON" else "OFF"}")
            HideVpnService.get().setHideVpnEnabled(enabled)
        }

        // Integrity Bypass
        initSwitch("integrity_bypass", "SafetyNet/Play Integrity Bypass", "Bypass SafetyNet and Play Integrity") { enabled ->
            Log.i(TAG, "Integrity Bypass: ${if (enabled) "ON" else "OFF"}")
            IntegrityBypassService.get().setBypassEnabled(enabled)
        }

        // Hook Detection Bypass
        initSwitch("hook_bypass", "Hook Detection Bypass", "Bypass Frida, Xposed, Substrate detection") { enabled ->
            Log.i(TAG, "Hook Bypass: ${if (enabled) "ON" else "OFF"}")
            HookDetectionBypassService.get().setBypassEnabled(enabled)
        }

        // Frida Hide
        initSwitch("frida_hide", "Hide Frida", "Hide Frida server from detection") { enabled ->
            Log.i(TAG, "Frida Hide: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                HookDetectionBypassService.get().addProtectedPackage("com.frida.server")
                HookDetectionBypassService.get().addProtectedPackage("re.frida.server")
            } else {
                HookDetectionBypassService.get().removeProtectedPackage("com.frida.server")
                HookDetectionBypassService.get().removeProtectedPackage("re.frida.server")
            }
        }

        // Xposed Hide
        initSwitch("xposed_hide", "Hide Xposed", "Hide Xposed framework from detection") { enabled ->
            Log.i(TAG, "Xposed Hide: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                HookDetectionBypassService.get().addProtectedPackage("de.robv.android.xposed.installer")
                HookDetectionBypassService.get().addProtectedPackage("org.meowcat.edxposed.manager")
                HookDetectionBypassService.get().addProtectedPackage("io.github.lsposed.manager")
            } else {
                HookDetectionBypassService.get().removeProtectedPackage("de.robv.android.xposed.installer")
                HookDetectionBypassService.get().removeProtectedPackage("org.meowcat.edxposed.manager")
                HookDetectionBypassService.get().removeProtectedPackage("io.github.lsposed.manager")
            }
        }

        // Online Bypass
        initSwitch("online_bypass", "Online Bypass", "Block anti-cheat/analytics/tracking network requests") { enabled ->
            Log.i(TAG, "Online Bypass: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                BypassOnlineService.get().activate()
                val count = BypassOnlineService.get().blockedCount
                toast("Online bypass enabled - blocking $count hosts")
            } else {
                BypassOnlineService.get().deactivate()
                toast("Online bypass disabled")
            }
        }

        Log.d(TAG, "Security settings initialized")
    }

    // ==================== ADVANCED SETTINGS ====================

    private fun initAdvancedSettings() {
        // Daemon
        invalidHideState {
            val daemonPreference: Preference = findPreference("daemon_enable")!!
            val mDaemonEnable = AppManager.mBlackBoxLoader.daemonEnable()
            daemonPreference.setDefaultValue(mDaemonEnable)
            daemonPreference
        }

        // VPN Network
        invalidHideState {
            val vpnPreference: Preference = findPreference("use_vpn_network")!!
            val mUseVpnNetwork = AppManager.mBlackBoxLoader.useVpnNetwork()
            vpnPreference.setDefaultValue(mUseVpnNetwork)
            vpnPreference
        }

        // Disable Flag Secure
        invalidHideState {
            val disableFlagSecurePreference: Preference = findPreference("disable_flag_secure")!!
            val mDisableFlagSecure = AppManager.mBlackBoxLoader.disableFlagSecure()
            disableFlagSecurePreference.setDefaultValue(mDisableFlagSecure)
            disableFlagSecurePreference
        }

        // Shell Script
        initSwitch("shell_script", "Shell Script Execution", "Enable .sh script execution") { enabled ->
            Log.i(TAG, "Shell Script: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                toast("Shell script execution enabled")
            }
        }

        // Fake Location
        initSwitch("fake_location", "Enhanced Fake Location", "GPS simulation with movement") { enabled ->
            Log.i(TAG, "Fake Location: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                toast("Enhanced fake location enabled")
            }
        }
    }

    // ==================== DUMPER SETTINGS ====================

    private fun initDumperSettings() {
        Log.d(TAG, "Initializing dumper settings...")

        // Enable Dumper
        initSwitch("dumper_enable", "Enable App Dumper", "Enable IL2CPP/DEX/Unity dumping") { enabled ->
            Log.i(TAG, "App Dumper: ${if (enabled) "ON" else "OFF"}")
            AppDumperService.get().setDumpEnabled(enabled)
            if (enabled) {
                toast("App Dumper enabled")
            }
        }

        // Auto Dump (OFF by default)
        initSwitch("auto_dump_enabled", "Auto Dump on Launch", "Auto-dump IL2CPP when launching apps (OFF by default)") { enabled ->
            Log.i(TAG, "Auto Dump: ${if (enabled) "ON" else "OFF"}")
            savePref("auto_dump_enabled", enabled)
            if (enabled) {
                toast("Auto dump enabled - dump will run 3s after app launch")
            } else {
                toast("Auto dump disabled")
            }
        }

        // Dump IL2CPP - triggers manual dump
        findPreference<Preference>("dumper_il2cpp")?.setOnPreferenceClickListener {
            AppDumperService.get().setDumpEnabled(true)
            val lastPkg = getPrefString("last_launched_pkg")
            if (lastPkg.isNotEmpty()) {
                toast("Dumping IL2CPP for $lastPkg...")
                Thread {
                    try {
                        val outputDir = AppDumperService.getDefaultDumpDir(lastPkg) + "/il2cpp"
                        File(outputDir).mkdirs()
                        val result = AppDumperService.get().dumpIL2CPP(lastPkg, outputDir)
                        Log.i(TAG, "Manual IL2CPP dump: success=$result, dir=$outputDir")
                    } catch (e: Exception) {
                        Log.e(TAG, "Manual IL2CPP dump failed: ${e.message}")
                    }
                }.start()
            } else {
                toast("Launch an app first, then come back to dump.")
            }
            true
        }

        // Dump DEX
        findPreference<Preference>("dumper_dex")?.setOnPreferenceClickListener {
            AppDumperService.get().setDumpEnabled(true)
            val lastPkg = getPrefString("last_launched_pkg")
            if (lastPkg.isNotEmpty()) {
                toast("Dumping DEX for $lastPkg...")
                Thread {
                    try {
                        val outputDir = AppDumperService.getDefaultDumpDir(lastPkg) + "/dex"
                        File(outputDir).mkdirs()
                        AppDumperService.get().dumpDEX(lastPkg, outputDir)
                    } catch (e: Exception) {
                        Log.e(TAG, "Manual DEX dump failed: ${e.message}")
                    }
                }.start()
            } else {
                toast("Launch an app first, then come back to dump.")
            }
            true
        }

        // Dump Native SO
        findPreference<Preference>("dumper_native")?.setOnPreferenceClickListener {
            AppDumperService.get().setDumpEnabled(true)
            val lastPkg = getPrefString("last_launched_pkg")
            if (lastPkg.isNotEmpty()) {
                toast("Dumping native libraries for $lastPkg...")
                Thread {
                    try {
                        val outputDir = AppDumperService.getDefaultDumpDir(lastPkg) + "/native"
                        File(outputDir).mkdirs()
                        AppDumperService.get().dumpNativeLibs(lastPkg, outputDir)
                    } catch (e: Exception) {
                        Log.e(TAG, "Manual native dump failed: ${e.message}")
                    }
                }.start()
            } else {
                toast("Launch an app first, then come back to dump.")
            }
            true
        }

        Log.d(TAG, "Dumper settings initialized")
    }

    // ==================== SYSTEM SETTINGS ====================

    private fun initSystemSettings() {
        // View Logs
        findPreference<Preference>("view_logs")?.setOnPreferenceClickListener {
            try {
                val logDir = File("/storage/emulated/0/Download/black/logs")
                if (!logDir.exists()) logDir.mkdirs()
                val intent = Intent(Intent.ACTION_VIEW)
                intent.setDataAndType(Uri.fromFile(logDir), "resource/folder")
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                startActivity(intent)
            } catch (e: Exception) {
                toast("Logs: /storage/emulated/0/Download/black/logs/")
            }
            true
        }

        // Send Logs
        val sendLogsPreference: Preference? = findPreference("send_logs")
        sendLogsPreference?.setOnPreferenceClickListener {
            it.isEnabled = false
            BlackBoxCore.get()
                    .sendLogs(
                            "Manual Log Upload from Settings",
                            true,
                            object : BlackBoxCore.LogSendListener {
                                override fun onSuccess() {
                                    activity?.runOnUiThread { sendLogsPreference.isEnabled = true }
                                }

                                override fun onFailure(error: String?) {
                                    activity?.runOnUiThread { sendLogsPreference.isEnabled = true }
                                }
                            }
                    )
            toast("Sending logs...")
            true
        }
    }

    // ==================== STATUS DISPLAY ====================

    private fun initStatusDisplay() {
        // Show last launched app info
        val lastPkg = getPrefString("last_launched_pkg")
        findPreference<Preference>("dump_status")?.apply {
            if (lastPkg.isNotEmpty()) {
                summary = "Last app: $lastPkg\nTap to open dump folder"
            } else {
                summary = "No app launched yet"
            }
            setOnPreferenceClickListener {
                if (lastPkg.isNotEmpty()) {
                    try {
                        val dumpDir = File(AppDumperService.getDefaultDumpDir(lastPkg))
                        if (dumpDir.exists()) {
                            val intent = Intent(Intent.ACTION_VIEW)
                            intent.setDataAndType(Uri.fromFile(dumpDir), "resource/folder")
                            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            startActivity(intent)
                        } else {
                            toast("No dump yet for $lastPkg")
                        }
                    } catch (e: Exception) {
                        toast("Dump dir: " + AppDumperService.getDefaultDumpDir(lastPkg))
                    }
                } else {
                    toast("Launch an app first")
                }
                true
            }
        }

        // Bypass status
        findPreference<Preference>("bypass_status")?.apply {
            if (BypassOnlineService.get().isActive) {
                val count = BypassOnlineService.get().blockedCount
                summary = "Active - blocking $count hosts"
            } else {
                summary = "Inactive - enable Online Bypass to activate"
            }
            setOnPreferenceClickListener {
                if (BypassOnlineService.get().isActive) {
                    val report = BypassOnlineService.get().generateReport()
                    toast("Online bypass: blocking ${BypassOnlineService.get().blockedCount} hosts")
                } else {
                    toast("Enable Online Bypass in Security settings first")
                }
                true
            }
        }

        // Root Manager status
        findPreference<Preference>("root_status")?.apply {
            if (RootManagerService.get().isEnabled) {
                val permCount = RootManagerService.get().allPermissions.size
                summary = "Active - ${permCount} app(s) managed"
            } else {
                summary = "Inactive - enable Root Manager to activate"
            }
            setOnPreferenceClickListener {
                val report = RootManagerService.get().generateStatusReport()
                toast("Root Manager: ${if (RootManagerService.get().isEnabled) "active" else "inactive"}")
                true
            }
        }
    }

    // ==================== HELPER METHODS ====================

    private fun initSwitch(key: String, title: String, summary: String, onToggle: (Boolean) -> Unit) {
        val pref: SwitchPreferenceCompat = findPreference(key) ?: return

        pref.title = title
        pref.summary = summary

        pref.setOnPreferenceChangeListener { _, newValue ->
            val enabled = newValue as Boolean
            onToggle(enabled)
            toast("${if (enabled) "Enabled" else "Disabled"}: $title")
            true
        }
    }

    private fun invalidHideState(block: () -> Preference) {
        val pref = block()
        pref.setOnPreferenceChangeListener { preference, newValue ->
            val tmpHide = (newValue == true)
            when (preference.key) {
                "root_hide" -> {
                    AppManager.mBlackBoxLoader.invalidHideRoot(tmpHide)
                }
                "daemon_enable" -> {
                    AppManager.mBlackBoxLoader.invalidDaemonEnable(tmpHide)
                }
                "use_vpn_network" -> {
                    AppManager.mBlackBoxLoader.invalidUseVpnNetwork(tmpHide)
                }
                "disable_flag_secure" -> {
                    AppManager.mBlackBoxLoader.invalidDisableFlagSecure(tmpHide)
                }
            }
            toast(R.string.restart_module)
            return@setOnPreferenceChangeListener true
        }
    }

    private fun savePref(key: String, value: Boolean) {
        try {
            val prefs = requireContext().getSharedPreferences(PREFS_NAME, 0)
            prefs.edit().putBoolean(key, value).apply()
        } catch (e: Exception) { }
    }

    private fun getPrefString(key: String): String {
        return try {
            val prefs = requireContext().getSharedPreferences(PREFS_NAME, 0)
            prefs.getString(key, "") ?: ""
        } catch (e: Exception) { "" }
    }
}
