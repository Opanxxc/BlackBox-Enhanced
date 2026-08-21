# BlackBox Enhanced v0.0.8

<p align="center">
  <img src="assets/usage.gif" alt="BlackBox Banner" width="100%"/>
</p>

**Enhanced by Panxcz & Freebuff** | Original by ALEX502

BlackBox Enhanced is a powerful virtual engine with advanced app analysis, security bypass, and dumping capabilities.

## 🚀 Features

### 📱 App Dumper (NEW!)
| Feature | Description |
|---------|-------------|
| **IL2CPP Dump** | dump.cs, il2cpp.h, class/method enumeration |
| **Unity Dump** | main.h, game.h, unity_types.h |
| **DEX Extraction** | APK decompilation support |
| **Native SO Dump** | All .so libraries + analysis |
| **String Dump** | Extract all strings from app |
| **Custom Output** | Configurable dump options |

### 🔐 Security Bypass
| Feature | Description |
|---------|-------------|
| **Root Hiding** | Magisk, KSU, APatch, Kernel-level |
| **Hook Bypass** | Frida, Xposed, Substrate |
| **Integrity Bypass** | SafetyNet, Play Integrity |
| **VPN Hiding** | Hide VPN connections |
| **Memory Hiding** | /proc/maps manipulation |

### 🛠️ Tools
| Feature | Description |
|---------|-------------|
| **Shell Scripts** | Execute .sh files |
| **Google Login** | Account management |
| **Fake Location** | GPS simulation |
| **Device Spoofing** | Modify device info |

## 📱 App Dumper Usage

### Dump IL2CPP
```java
// dump.cs, il2cpp.h, main.h, game.h
AppDumperService.get().dumpIL2CPP(packageName, outputDir);
```

### Dump DEX
```java
// Extract APK for decompilation
AppDumperService.get().dumpDEX(packageName, outputDir);
```

### Dump Native SO
```java
// All .so libraries with analysis
AppDumperService.get().dumpNativeLibs(packageName, outputDir);
```

### Dump Unity
```java
// Unity-specific files
AppDumperService.get().dumpUnity(packageName, outputDir);
```

### Full Dump
```java
// Everything at once
AppDumperService.get().dumpAll(packageName, outputDir);
```

## 📲 Download

[![Download APK](https://img.shields.io/badge/Download-APK-blue?style=for-the-badge)](https://github.com/Opanxxc/BlackBox-Enhanced/releases/tag/v0.0.8)

## 🛠️ Build

```bash
git clone https://github.com/Opanxxc/BlackBox-Enhanced.git
cd BlackBox-Enhanced
./gradlew assembleDebug
```

## 📚 API Reference

### App Dumper
```java
// Check app type
boolean isIL2CPP = AppDumperService.get().isIL2CPPApp(pkg);
boolean isUnity = AppDumperService.get().isUnityApp(pkg);

// Get dump info
AppDumpInfo info = AppDumperService.get().getAppDumpInfo(pkg);

// Get dump result
DumpResult result = AppDumperService.get().getDumpResult(pkg);
```

### Root Hiding
```java
// Enable hiding
HideRootService.get().setHideRootEnabled(true);

// Check kernel root
boolean hasRoot = HideRootService.get().hasKernelRoot();

// Get modified /proc
String mounts = HideRootService.get().getModifiedMountsContent();
```

### Hook Bypass
```java
// Check detection
boolean hasFrida = HookDetectionBypassService.get().isFridaInstalled();
boolean hasXposed = HookDetectionBypassService.get().isXposedInstalled();

// Get modified maps
String maps = HookDetectionBypassService.get().getModifiedMapsContent();
```

## 🔧 Requirements

- Android 5.0 - 17 (API 21-35)
- 2GB RAM minimum
- ARM64/ARMv7/x86

## 🙏 Credits

- **Original**: ALEX502
- **Enhanced by**: Panxcz & Freebuff
- **Framework**: VirtualApp, VirtualAPK
- **Hooks**: Dobby, xDL

## 📄 License

Apache License 2.0

## 🔗 Links

- [GitHub](https://github.com/Opanxxc/BlackBox-Enhanced)
- [Releases](https://github.com/Opanxxc/BlackBox-Enhanced/releases)
- [Issues](https://github.com/Opanxxc/BlackBox-Enhanced/issues)

---

**Made with ❤️ by Panxcz & Freebuff**
