# BlackBox Enhanced - Virtual Engine with Advanced Features

<p align="center">
  <img src="assets/usage.gif" alt="BlackBox Banner" width="100%"/>
</p>

BlackBox Enhanced is a powerful virtual engine that allows you to clone and run virtual applications on Android devices without installing APKs. This enhanced edition includes advanced features for privacy, security, and automation.

## 🚀 Key Features

### Core Features (from Original)
- **Virtual App Cloning**: Run multiple instances of applications
- **Sandboxed Environment**: Isolated process execution
- **No Root Required**: Runs entirely in userspace
- **Multi-Architecture**: Support for 32-bit and 64-bit apps (ARM64, ARMv7, x86)
- **Device Spoofing**: Modify device information for virtual apps
- **Fake Location**: Spoof GPS coordinates

### 🆕 New Features

#### 🖥️ Shell Script Execution (.sh Support)
- Execute shell scripts within the virtual environment
- Run scripts with arguments and environment variables
- Support for .sh, .bash, .zsh files
- Script output streaming and monitoring
- Kill running script sessions

```kotlin
// Example: Execute a shell script
ShellScriptService.get().executeScript(
    scriptPath = "/path/to/script.sh",
    args = arrayOf("--verbose", "--output", "result.txt"),
    envVars = mapOf("MY_VAR" to "value"),
    workingDir = "/data/local/tmp",
    callback = object : ShellScriptService.IScriptCallback {
        override fun onOutput(sessionId: Int, line: String) {
            Log.d("Script", line)
        }
        override fun onCompleted(sessionId: Int, exitCode: Int) {
            Log.d("Script", "Completed with exit code: $exitCode")
        }
        override fun onError(sessionId: Int, error: String) {
            Log.e("Script", "Error: $error")
        }
    }
)
```

#### 🔐 Google Login Support
- Full Google Sign-In integration within virtual apps
- Account management and token handling
- OAuth 2.0 support
- Token refresh and validation
- Multiple Google accounts support

```kotlin
// Example: Add Google account
GoogleAuthService.get().addAccount(
    accountName = "user@gmail.com",
    authToken = "ya29...",
    refreshToken = "1//..."
)

// Example: Get auth token
GoogleAuthService.get().getAuthToken(
    accountName = "user@gmail.com",
    authTokenType = "oauth2:https://www.googleapis.com/auth/userinfo.profile",
    callback = object : GoogleAuthService.IAuthTokenCallback {
        override fun onTokenReceived(token: String) {
            Log.d("Auth", "Token: $token")
        }
        override fun onError(error: String) {
            Log.e("Auth", "Error: $error")
        }
    }
)
```

#### 🔒 Hide Root
- Hide root status from applications
- Bypass root detection (Magisk, SuperSU, etc.)
- Hide root-related files and packages
- Simulate non-rooted environment
- Customizable detection bypass

```kotlin
// Example: Enable root hiding
HideRootService.get().setHideRootEnabled(true)

// Example: Add custom root paths to hide
HideRootService.get().addRootPath("/system/app/Superuser.apk")
HideRootService.get().addRootPackage("com.topjohnwu.magisk")
```

#### 📍 Enhanced Fake Location
- GPS simulation with realistic movement
- Route following with speed control
- Satellite simulation
- Random location generation
- Movement patterns and bearing control

```kotlin
// Example: Set fake location
EnhancedLocationService.get().setFakeLocation(
    packageName = "com.example.app",
    latitude = 37.7749,
    longitude = -122.4194,
    accuracy = 10.0f
)

// Example: Start simulation with movement
EnhancedLocationService.get().startSimulation(
    packageName = "com.example.app",
    latitude = 37.7749,
    longitude = -122.4194,
    speed = 1.5f, // meters per second
    bearing = 45.0f // degrees
)

// Example: Follow a route
val route = listOf(
    EnhancedLocationService.LocationConfig().apply {
        latitude = 37.7749; longitude = -122.4194
    },
    EnhancedLocationService.LocationConfig().apply {
        latitude = 37.7849; longitude = -122.4094
    }
)
EnhancedLocationService.get().followRoute(
    packageName = "com.example.app",
    route = route,
    speed = 1.0f,
    callback = object : EnhancedLocationService.IRouteCallback {
        override fun onRouteProgress(packageName: String, currentStep: Int, totalSteps: Int) {
            Log.d("Route", "Step $currentStep/$totalSteps")
        }
        override fun onRouteCompleted(packageName: String) {
            Log.d("Route", "Route completed!")
        }
        override fun onRouteError(packageName: String, error: String) {
            Log.e("Route", "Error: $error")
        }
    }
)
```

#### 🌐 Hide VPN
- Hide VPN connections from applications
- Bypass VPN detection
- Simulate regular network connections
- Hide VPN interfaces and packages
- DNS server filtering

```kotlin
// Example: Enable VPN hiding
HideVpnService.get().setHideVpnEnabled(true)

// Example: Add custom VPN packages to hide
HideVpnService.get().addVpnPackage("com.nordvpn.android")
HideVpnService.get().addVpnInterface("tun0")
```

#### 🛡️ SafetyNet/Play Integrity Bypass
- Bypass SafetyNet attestation
- Bypass Play Integrity checks
- Spoof build properties
- Hide emulator signatures
- Protect banking and payment apps
- Make rooted devices appear legitimate

```kotlin
// Example: Enable integrity bypass
IntegrityBypassService.get().setBypassEnabled(true)

// Example: Check if device passes SafetyNet
val passesSafetyNet = IntegrityBypassService.get().passesSafetyNet()

// Example: Get modified build properties
val properties = IntegrityBypassService.get().getModifiedBuildProperties()

// Example: Check if package needs protection
val needsProtection = IntegrityBypassService.get().isProtectedPackage("com.google.android.gms")
```

## 📋 Requirements

- **Android Version**: Android 5.0 (API 21) or higher
- **RAM**: 2GB minimum recommended
- **Architecture**: ARMv7a, ARM64-v8a, x86

## 🛠️ Build Instructions

### Prerequisites
- Android Studio (Arctic Fox or newer)
- JDK 17
- Android SDK 34+
- NDK (Version 29.0.13846066)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/BlackBox-Enhanced.git
cd BlackBox-Enhanced

# Build Debug APK
./gradlew assembleDebug

# Build Release APK
./gradlew assembleRelease
```

## 🔧 Integration

To use BlackBox Core in your own project, add the AAR dependency:

```gradle
dependencies {
    implementation fileTree(dir: "libs", include = ["*.aar"])
}
```

Refer to `Docs.md` for detailed API documentation.

## 📚 API Documentation

### Shell Script Service
```kotlin
// Execute script from file
val sessionId = ShellScriptService.get().executeScript(
    scriptPath: String,
    args: Array<String>,
    envVars: Map<String, String>,
    workingDir: String,
    callback: IScriptCallback
)

// Execute script from content
val sessionId = ShellScriptService.get().executeScriptContent(
    scriptContent: String,
    scriptName: String,
    args: Array<String>,
    envVars: Map<String, String>,
    workingDir: String,
    callback: IScriptCallback
)

// Kill running session
ShellScriptService.get().killSession(sessionId: Int)

// Check if file is shell script
val isScript = ShellScriptService.get().isShellScript(filePath: String)
```

### Google Auth Service
```kotlin
// Add account
val success = GoogleAuthService.get().addAccount(
    accountName: String,
    authToken: String,
    refreshToken: String?
)

// Remove account
val success = GoogleAuthService.get().removeAccount(accountName: String)

// Get auth token
GoogleAuthService.get().getAuthToken(
    accountName: String,
    authTokenType: String,
    callback: IAuthTokenCallback
)

// Get all accounts
val accounts = GoogleAuthService.get().getAccounts()
```

### Hide Root Service
```kotlin
// Enable/disable root hiding
HideRootService.get().setHideRootEnabled(enabled: Boolean)

// Add custom root paths
HideRootService.get().addRootAppPath(path: String)
HideRootService.get().addRootPath(path: String)
HideRootService.get().addRootPackage(packageName: String)

// Check if path should be hidden
val shouldHide = HideRootService.get().shouldHidePath(path: String)

// Get modified file listing
val files = HideRootService.get().getModifiedFileListing(directory: File)
```

### Enhanced Location Service
```kotlin
// Set fake location
EnhancedLocationService.get().setFakeLocation(
    packageName: String,
    latitude: Double,
    longitude: Double,
    accuracy: Float
)

// Start simulation
EnhancedLocationService.get().startSimulation(
    packageName: String,
    latitude: Double,
    longitude: Double,
    speed: Float,
    bearing: Float
)

// Follow route
EnhancedLocationService.get().followRoute(
    packageName: String,
    route: List<LocationConfig>,
    speed: Float,
    callback: IRouteCallback
)

// Generate random location
val location = EnhancedLocationService.get().generateRandomLocation(
    centerLat: Double,
    centerLon: Double,
    radiusMeters: Double
)
```

### Hide VPN Service
```kotlin
// Enable/disable VPN hiding
HideVpnService.get().setHideVpnEnabled(enabled: Boolean)

// Add custom VPN packages
HideVpnService.get().addVpnPackage(packageName: String)
HideVpnService.get().addVpnInterface(interfaceName: String)

// Check if interface is VPN
val isVpn = HideVpnService.get().isVpnInterface(interfaceName: String)

// Check if VPN is active
val isActive = HideVpnService.get().isVpnActive()

// Get modified network interfaces
val interfaces = HideVpnService.get().getModifiedNetworkInterfaces()
```

### Integrity Bypass Service
```kotlin
// Enable/disable integrity bypass
IntegrityBypassService.get().setBypassEnabled(enabled: Boolean)

// Check if device passes SafetyNet
val passesSafetyNet = IntegrityBypassService.get().passesSafetyNet()

// Check if device passes Play Integrity
val passesPlayIntegrity = IntegrityBypassService.get().passesPlayIntegrity()

// Get modified build properties
val properties = IntegrityBypassService.get().getModifiedBuildProperties()

// Check if package needs protection
val needsProtection = IntegrityBypassService.get().isProtectedPackage(packageName: String)

// Set integrity configuration for package
IntegrityBypassService.get().setIntegrityConfig(
    packageName: String,
    config: IntegrityConfig
)

// Get modified installer package name
val installer = IntegrityBypassService.get().getModifiedInstallerPackageName(packageName: String)

// Check if package is from legitimate source
val isLegitimate = IntegrityBypassService.get().isLegitimateSource(packageName: String)
```

## 🔍 Troubleshooting

- **App Crashes**: Check logcat for UID mismatches or permission errors
- **Installation Failures**: Verify potential architecture mismatches or storage permissions
- **Android 15**: Ensure you are using the latest build which handles stricter security policies
- **Script Execution**: Ensure scripts have proper shebang and permissions
- **Google Login**: Verify OAuth client ID is properly configured
- **Root Detection**: Check if custom root paths need to be added
- **VPN Detection**: Verify VPN interface names are properly configured

## 📄 License

Copyright 2022 BlackBox

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## 🙏 Credits

- **Main Developer**: ALEX502
- **Original Framework**: VirtualApp, VirtualAPK
- **Native Hooks**: Dobby, xDL
- **Reflection**: BlackReflection, FreeReflection
- **Enhanced Features**: [Your Name/Team]

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check the documentation in Docs.md
- Review the troubleshooting section above
