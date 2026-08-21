package top.niunaijun.blackboxa.view.setting

import android.os.Bundle
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
import top.niunaijun.blackbox.core.system.shell.ShellScriptService
import top.niunaijun.blackbox.core.system.location.EnhancedLocationService
import top.niunaijun.blackbox.core.system.dumper.AppDumperService

class SettingFragment : PreferenceFragmentCompat() {

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.setting, rootKey)

        initGms()
        initSecuritySettings()
        initAdvancedSettings()
        initDumperSettings()
        initSendLogs()
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

    // ==================== SECURITY SETTINGS ====================
    
    private fun initSecuritySettings() {
        // Root Hide
        initSwitch("root_hide", "Hide Root", "Hide root status from apps") { enabled ->
            HideRootService.get().setHideRootEnabled(enabled)
            AppManager.mBlackBoxLoader.invalidHideRoot(enabled)
        }

        // VPN Hide
        initSwitch("vpn_hide", "Hide VPN", "Hide VPN connections from apps") { enabled ->
            HideVpnService.get().setHideVpnEnabled(enabled)
        }

        // Integrity Bypass
        initSwitch("integrity_bypass", "SafetyNet/Play Integrity Bypass", "Bypass SafetyNet and Play Integrity") { enabled ->
            IntegrityBypassService.get().setBypassEnabled(enabled)
        }

        // Hook Detection Bypass
        initSwitch("hook_bypass", "Hook Detection Bypass", "Bypass Frida, Xposed, Substrate detection") { enabled ->
            HookDetectionBypassService.get().setBypassEnabled(enabled)
        }

        // Frida Hide
        initSwitch("frida_hide", "Hide Frida", "Hide Frida server from detection") { enabled ->
            if (enabled) {
                HookDetectionBypassService.get().addProtectedPackage("com.frida.server")
            } else {
                HookDetectionBypassService.get().removeProtectedPackage("com.frida.server")
            }
        }

        // Xposed Hide
        initSwitch("xposed_hide", "Hide Xposed", "Hide Xposed framework from detection") { enabled ->
            if (enabled) {
                HookDetectionBypassService.get().addProtectedPackage("de.robv.android.xposed.installer")
            } else {
                HookDetectionBypassService.get().removeProtectedPackage("de.robv.android.xposed.installer")
            }
        }
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
            // Shell script is always enabled in this version
        }

        // Fake Location
        initSwitch("fake_location", "Enhanced Fake Location", "GPS simulation with movement") { enabled ->
            // Fake location settings
        }
    }

    // ==================== DUMPER SETTINGS ====================
    
    private fun initDumperSettings() {
        // Enable Dumper
        initSwitch("dumper_enable", "Enable App Dumper", "Enable IL2CPP/DEX/Unity dumping") { enabled ->
            AppDumperService.get().setDumpEnabled(enabled)
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

    // ==================== SEND LOGS ====================
    
    private fun initSendLogs() {
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
