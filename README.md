# BlackBox Enhanced v0.0.7

<p align="center">
  <img src="assets/usage.gif" alt="BlackBox Banner" width="100%"/>
</p>

**Enhanced by Panxcz & Freebuff** | Original by ALEX502

BlackBox Enhanced is a powerful virtual engine that allows you to clone and run virtual applications on Android devices without installing APKs. This enhanced edition includes advanced features for privacy, security, automation, and app analysis.

## 🚀 Key Features

### Core Features (Original)
- **Virtual App Cloning**: Run multiple instances of applications
- **Sandboxed Environment**: Isolated process execution
- **No Root Required**: Runs entirely in userspace
- **Multi-Architecture**: Support for 32-bit and 64-bit apps (ARM64, ARMv7, x86)
- **Device Spoofing**: Modify device information for virtual apps
- **Fake Location**: Spoof GPS coordinates

### 🆕 Enhanced Features (by Panxcz & Freebuff)

#### 🖥️ Shell Script Execution (.sh Support)
- Execute shell scripts within the virtual environment
- Run scripts with arguments and environment variables
- Support for .sh, .bash, .zsh files
- Script output streaming and monitoring

#### 🔐 Google Login Support
- Full Google Sign-In integration within virtual apps
- Account management and token handling
- OAuth 2.0 support with token refresh

#### 🔒 Advanced Root Hiding
- Kernel-level root detection bypass
- Magisk, KSU, APatch hiding
- /proc manipulation (mounts, maps, status)
- SELinux enforcing spoof
- Kernel parameter modification

#### 📍 Enhanced Fake Location
- GPS simulation with realistic movement
- Route following with speed control
- Satellite simulation
- Random location generation

#### 🌐 VPN Hiding
- Hide VPN connections from applications
- Bypass VPN detection
- Network interface modification
- DNS server filtering

#### 🛡️ SafetyNet/Play Integrity Bypass
- Bypass SafetyNet attestation
- Bypass Play Integrity checks
- Spoof build properties
- Hide emulator signatures

#### 🔗 Hook Detection Bypass
- Frida detection and hiding
- Xposed detection and hiding
- Substrate detection and hiding
- Memory mapping hiding
- Library filtering

#### 📱 App Dumper (NEW!)
- IL2CPP dump (dump.cs, il2cpp.h)
- Unity game dump (main.h, game.h)
- DEX extraction
- Custom output options
- Summary generation

## 📋 Requirements

- **Android Version**: Android 5.0 (API 21) - Android 17 (API 35)
- **RAM**: 2GB minimum recommended
- **Architecture**: ARMv7a, ARM64-v8a, x86

## 🛠️ Build Instructions

### Prerequisites
- Android Studio (Arctic Fox or newer)
- JDK 21
- Android SDK 35+
- NDK (Version 27.0.12077973)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/Opanxxc/BlackBox-Enhanced.git
cd BlackBox-Enhanced

# Build Debug APK
./gradlew assembleDebug

# Build Release APK
./gradlew assembleRelease
```

## 📱 Download

Download the latest APK from [Releases](https://github.com/Opanxxc/BlackBox-Enhanced/releases/tag/v0.0.7)

## 📚 API Documentation

### App Dumper Service
```kotlin
// Dump IL2CPP data
AppDumperService.get().dumpIL2CPP(packageName, outputDir)

// Dump DEX files
AppDumperService.get().dumpDEX(packageName, outputDir)

// Dump all data
AppDumperService.get().dumpAll(packageName, outputDir)

// Check if app is IL2CPP
val isIL2CPP = AppDumperService.get().isIL2CPPApp(packageName)

// Check if app uses Unity
val isUnity = AppDumperService.get().isUnityApp(packageName)

// Get app dump info
val info = AppDumperService.get().getAppDumpInfo(packageName)
```

### Shell Script Service
```kotlin
// Execute script from file
ShellScriptService.get().executeScript(
    scriptPath, args, envVars, workingDir, callback
)

// Execute script from content
ShellScriptService.get().executeScriptContent(
    scriptContent, scriptName, args, envVars, workingDir, callback
)
```

### Root Hiding Service
```kotlin
// Enable root hiding
HideRootService.get().setHideRootEnabled(true)

// Check kernel root
val hasKernelRoot = HideRootService.get().hasKernelRoot()

// Get modified /proc content
val mounts = HideRootService.get().getModifiedMountsContent()
```

### Hook Detection Bypass
```kotlin
// Check if Frida is installed
val hasFrida = HookDetectionBypassService.get().isFridaInstalled()

// Check if Xposed is installed
val hasXposed = HookDetectionBypassService.get().isXposedInstalled()

// Get modified memory maps
val maps = HookDetectionBypassService.get().getModifiedMapsContent()
```

## 🔍 Troubleshooting

- **App Crashes**: Check logcat for UID mismatches or permission errors
- **Installation Failures**: Verify architecture mismatches or storage permissions
- **Android 15+**: Ensure using the latest build for stricter security policies
- **Dump Failures**: Check if app has IL2CPP or Unity libraries

## 📄 License

Copyright 2022 BlackBox

Licensed under the Apache License, Version 2.0

## 🙏 Credits

- **Original Developer**: ALEX502
- **Enhanced by**: Panxcz & Freebuff
- **Original Framework**: VirtualApp, VirtualAPK
- **Native Hooks**: Dobby, xDL
- **Reflection**: BlackReflection, FreeReflection

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check the documentation above
- Review the troubleshooting section

## 🔗 Links

- **Repository**: https://github.com/Opanxxc/BlackBox-Enhanced
- **Releases**: https://github.com/Opanxxc/BlackBox-Enhanced/releases
- **Issues**: https://github.com/Opanxxc/BlackBox-Enhanced/issues

---

**Made with ❤️ by Panxcz & Freebuff**
