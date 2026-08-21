package top.niunaijun.blackboxa.view.setting

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
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
import top.niunaijun.blackbox.core.system.shell.ShellScriptService
import top.niunaijun.blackbox.core.system.location.EnhancedLocationService
import top.niunaijun.blackbox.core.system.dumper.AppDumperService
import android.util.Log
import java.io.File

class SettingFragment : PreferenceFragmentCompat() {

    companion object {
        private const val TAG = "SettingFragment"
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
                // Try launch by package only
                try {
                    val intent = requireContext().packageManager.getLaunchIntentForPackage("com.moddingx.music")
                    if (intent != null) {
                        startActivity(intent)
                        launched = true
                    }
                } catch (e: Exception) { }
            }
            
            if (!launched) {
                toast("MT Manager not installed. Download from GitHub releases.")
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

        // Root Manager
        initSwitch("root_manager", "Root Manager", "Manage root access per-app (Magisk/KernelSU style)") { enabled ->
            Log.i(TAG, "Root Manager: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                HideRootService.get().setHideRootEnabled(true)
                toast("Root Manager enabled - apps will see non-rooted status by default")
            }
        }

        // Zygisk Support
        initSwitch("zygisk_support", "Zygisk Support", "Enable Zygisk injection for modules") { enabled ->
            Log.i(TAG, "Zygisk Support: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                toast("Zygisk support enabled - module injection will be available")
            }
        }

        // LSPosed / Xposed Support
        initSwitch("lsposed_support", "LSPosed / Xposed Support", "Enable LSPosed/Xposed framework") { enabled ->
            Log.i(TAG, "LSPosed Support: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                toast("LSPosed/Xposed support enabled")
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
        initSwitch("online_bypass", "Online Bypass", "Block anti-cheat/analytics network requests") { enabled ->
            Log.i(TAG, "Online Bypass: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                BypassOnlineService.get().activate()
                toast("Online bypass enabled - blocking ${BypassOnlineService.get().getBlockedCount()} hosts")
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
        initSwitch("shell_script", "Shell Script Execution", "Enable .sh script execution") { _ ->
            Log.d(TAG, "Shell script toggle")
        }

        // Fake Location
        initSwitch("fake_location", "Enhanced Fake Location", "GPS simulation with movement") { _ ->
            Log.d(TAG, "Fake location toggle")
        }
    }

    // ==================== DUMPER SETTINGS ====================

    private fun initDumperSettings() {
        // Enable Dumper
        initSwitch("dumper_enable", "Enable App Dumper", "Enable IL2CPP/DEX/Unity dumping") { enabled ->
            AppDumperService.get().setDumpEnabled(enabled)
        }

        // Auto Dump (OFF by default)
        initSwitch("auto_dump_enabled", "Auto Dump on Launch", "Auto-dump IL2CPP when launching apps (OFF by default to prevent FC)") { enabled ->
            Log.i(TAG, "Auto Dump: ${if (enabled) "ON" else "OFF"}")
            if (enabled) {
                toast("Auto dump enabled - IL2CPP will be dumped when launching apps")
            }
        }

        // Dump IL2CPP
        findPreference<Preference>("dumper_il2cpp")?.setOnPreferenceClickListener {
            toast("IL2CPP dump will be performed when launching an app")
            true
        }

        // Dump DEX
        findPreference<Preference>("dumper_dex")?.setOnPreferenceClickListener {
            toast("DEX dump will be performed when launching an app")
            true
        }

        // Dump Native SO
        findPreference<Preference>("dumper_native")?.setOnPreferenceClickListener {
            toast("Native SO dump will be performed when launching an app")
            true
        }
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
                toast("Logs dir: /storage/emulated/0/Download/black/logs/")
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
            toast("Sending logs... (Check notifications for status)")
            true
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
}
