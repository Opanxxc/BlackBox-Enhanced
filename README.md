# BlackBox Enhanced v0.0.10

<p align="center">
  <img src="assets/usage.gif" alt="BlackBox Banner" width="100%"/>
</p>

**Enhanced by Panxcz & Freebuff** | Original by ALEX502

BlackBox Enhanced is a powerful virtual engine with advanced app analysis, security bypass, and dumping capabilities.

## 🚀 What's New in v0.0.10

- ✅ **Default dump output**: `/storage/emulated/0/Download/black/dump/(packagename)`
- ✅ **Persistent signing key** — install-over without losing game data!
- ✅ **Fixed GMS Manager** — no more white screen
- ✅ **Fixed MT Manager** — no more crashes
- ✅ **Immersive fullscreen** — game-like display
- ✅ **Android 5.0 - 17** support

## 📱 Features

### 📱 App Dumper
| Feature | Description |
|---------|-------------|
| **IL2CPP Dump** | dump.cs, il2cpp.h, class/method enumeration |
| **Unity Dump** | main.h, game.h, unity_types.h |
| **DEX Extraction** | APK decompilation support |
| **Native SO Dump** | All .so libraries + analysis |
| **String Dump** | Extract all strings from app |
| **Custom Output** | Default: `/storage/emulated/0/Download/black/dump/(packagename)` |

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

## 📱 App Dumper Output Path

All dump files are saved to:
```
/storage/emulated/0/Download/black/dump/(packagename)/
├── il2cpp/          # IL2CPP dump files
│   ├── dump.cs
│   ├── il2cpp.h
│   ├── main.h
│   ├── game.h
│   └── ...
├── dex/             # DEX extraction
├── native/          # Native SO libraries
├── unity/           # Unity-specific files
└── SUMMARY.txt      # Dump summary
```

### Usage
```java
// Default output path (recommended)
AppDumperService.get().dumpAll(packageName, null);

// Custom output path
AppDumperService.get().dumpAll(packageName, "/custom/path");
```

## 📲 Download

[![Download APK](https://img.shields.io/badge/Download-Universal-APK-blue?style=for-the-badge)](https://github.com/Opanxxc/BlackBox-Enhanced/releases/tag/v0.0.10)

> **Note:** Only universal APK uploaded (works on all architectures)

## 🛠️ Recommended Tools

| Tool | Description | Link |
|------|-------------|------|
| **MT Manager** | APK Editor | [mt2.cn](https://www.mt2.cn/) |
| **NP Manager** | Advanced APK Editor | [npnut.com](https://npnut.com/) |
| **jadx** | Java Decompiler | [GitHub](https://github.com/skylot/jadx) |
| **IDA Pro** | Disassembler | [hex-rays.com](https://www.hex-rays.com/ida-pro/) |
| **radare2** | Reverse Engineering | [rada.re](https://rada.re/) |

## 🏗️ Building

### Prerequisites
- JDK 21
- Android SDK 35
- NDK 27.0.12077973

### Build Commands
```bash
# Debug build
./gradlew assembleDebug

# Release build
./gradlew assembleRelease
```

### Signing
For consistent signing across builds, set GitHub Secrets:
- `RELEASE_KEYSTORE` — Base64 encoded keystore file
- `KEYSTORE_PASSWORD` — Keystore password
- `KEY_ALIAS` — Key alias
- `KEY_PASSWORD` — Key password

To generate and save your keystore:
```bash
# Generate keystore
keytool -genkeypair -v \
  -keystore release.keystore \
  -alias blackbox \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -storepass blackbox123 \
  -keypass blackbox123 \
  -dname "CN=BlackBox Enhanced, OU=Dev, O=BlackBox"

# Encode to base64 for GitHub Secret
base64 -w 0 release.keystore
```

## 🙏 Credits

- **Original**: ALEX502 ([NewBlackbox](https://github.com/ALEX5402/NewBlackbox))
- **Enhanced by**: Panxcz & Freebuff

## 📝 License

This project is for educational purposes only.
