# BlackBox Enhanced

> Android virtual environment with IL2CPP dumper and app isolation.

**Based on [BlackBox by ALEX5402](https://github.com/ALEX5402/NewBlackbox)**  
**Enhanced by Panxcz & Freebuff**

## What This Is

BlackBox Enhanced creates a virtual Android environment where you can run apps in isolation. It includes a dumper that attempts to extract IL2CPP metadata (class names, method names, field names, offsets) from apps that use Unity's IL2CPP backend.

**Important caveats:**
- The IL2CPP dumper works best with apps that have `global-metadata.dat` in their data directory
- Field offsets are approximate (simplified alignment) - not exact struct layouts
- Method RVAs are extracted from metadata tables, not from disassembled code
- The dumper cannot bypass server-side validation or online anti-cheat that phones home to external servers
- This tool is for **educational and research purposes**

## Features

### Virtual Environment
- Run apps in isolated containers (like a sandbox)
- Multi-account support (run same app multiple times)
- Shell script (.sh) execution support

### IL2CPP Dumper (v0.1.3)
- **Real metadata parsing** from `global-metadata.dat` (IL2CPP v24-v29)
- Extracts actual class names, namespaces, field names, method names
- Generates `dump.cs` with real IL2CPP class/method structure
- Computes approximate field offsets within class structs
- Extracts method RVAs and tokens from metadata tables
- Generates `il2cpp.h` / `main.h` / `game.h` / `il2cpp_offsets.h`
- ELF binary analysis of `libil2cpp.so`
- Hex dump and string extraction from native libraries
- Fallback to raw string extraction when metadata parse fails
- DEX file parsing for additional class/method information

### Anti-Detection Bypasses
- Root hiding (Magisk, KSU, APatch)
- Frida/Xposed/Substrate hook detection bypass
- SafetyNet/Play Integrity bypass (MeowBox / YuriKey modes)
- VPN hiding
- Emulator detection bypass
- Online bypass (blocks known anti-cheat/analytics hosts)
- Enhanced fake location with GPS simulation

### Other
- Immersive fullscreen mode (game-like)
- Persistent signing key (install-over without data loss)
- Debug logging throughout
- Android 5.0 - 17 support

## Dump Output

All dumps go to: `/storage/emulated/0/Download/black/dump/(packagename)/`

```
├── il2cpp/
│   ├── dump.cs                ← IL2CPP class/method dump (from metadata)
│   ├── il2cpp_classes.txt     ← Class enumeration (from DEX)
│   ├── il2cpp_methods.txt     ← Method enumeration (from DEX)
│   ├── il2cpp_strings.txt     ← String pool dump (from DEX)
│   ├── il2cpp.h               ← IL2CPP type definitions
│   ├── il2cpp_offsets.h       ← Architecture-specific offsets
│   ├── main.h                 ← App info + memory macros
│   ├── game.h                 ← Unity engine structs
│   ├── libil2cpp.so           ← Native library copy
│   ├── libil2cpp_elf.txt      ← ELF section/symbol analysis
│   ├── libil2cpp_hexdump.txt  ← Hex dump with ASCII
│   ├── libil2cpp_strings.txt  ← Extracted strings with offsets
│   └── global-metadata.dat    ← Metadata copy
├── dex/                       ← Extracted DEX files
├── native/                    ← All .so libraries
├── memory/                    ← Memory region analysis
├── hook/                      ← Hook/classloader dump
└── SUMMARY.txt                ← Dump summary
```

## Building

The project builds via GitHub Actions. APKs are uploaded to the [Releases](https://github.com/Opanxxc/BlackBox-Enhanced/releases) page.

To build locally:
```bash
./gradlew assembleDebug
```

## Requirements

- Android 5.0+ (API 21+)
- The target app must use IL2CPP backend (not Mono) for full dump support

## Known Limitations

- Field offsets are approximate - use Il2CppDumper on a PC for exact offsets
- Cannot dump apps with heavily obfuscated metadata
- Server-side anti-cheat cannot be bypassed from the client
- Some integrity checks (SafetyNet device attestation) may still fail on rooted devices

## Credits

- **Original BlackBox**: [ALEX5402](https://github.com/ALEX5402/NewBlackbox)
- **Enhanced by**: [Panxcz](https://github.com/Opanxxc) & Freebuff
- **IL2CPP format reference**: [Il2CppDumper](https://github.com/Perfare/Il2CppDumper)
- **Version**: 0.1.3

## License

Based on BlackBox by ALEX5402. See original repository for license details.
