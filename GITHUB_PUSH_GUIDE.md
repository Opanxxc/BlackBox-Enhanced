# GitHub Push Guide - BlackBox Enhanced

## 📋 Prerequisites

Before you begin, make sure you have:
1. GitHub account (https://github.com)
2. Git installed on your computer
3. SSH key configured (recommended) or HTTPS access
4. Android Studio for building the APK

## 🚀 Step-by-Step Instructions

### Step 1: Fork the Repository

1. Go to the original repository: https://github.com/ALEX5402/NewBlackbox
2. Click the "Fork" button in the top right corner
3. Select your GitHub account as the destination
4. Wait for the fork to complete

### Step 2: Clone Your Fork

```bash
# Clone your forked repository
git clone https://github.com/YOUR_USERNAME/NewBlackbox.git
cd NewBlackbox

# Add the original repository as upstream
git remote add upstream https://github.com/ALEX5402/NewBlackbox.git
```

### Step 3: Add Enhanced Features

Copy the enhanced files from this directory to your cloned repository:

```bash
# Copy the enhanced services
cp -r /tmp/NewBlackbox_Enhanced/Bcore/src/main/java/top/niunaijun/blackbox/core/system/shell ./Bcore/src/main/java/top/niunaijun/blackbox/core/system/
cp -r /tmp/NewBlackbox_Enhanced/Bcore/src/main/java/top/niunaijun/blackbox/core/system/auth ./Bcore/src/main/java/top/niunaijun/blackbox/core/system/
cp -r /tmp/NewBlackbox_Enhanced/Bcore/src/main/java/top/niunaijun/blackbox/core/system/hideroot ./Bcore/src/main/java/top/niunaijun/blackbox/core/system/
cp -r /tmp/NewBlackbox_Enhanced/Bcore/src/main/java/top/niunaijun/blackbox/core/system/hidevpn ./Bcore/src/main/java/top/niunaijun/blackbox/core/system/
cp -r /tmp/NewBlackbox_Enhanced/Bcore/src/main/java/top/niunaijun/blackbox/core/system/location/EnhancedLocationService.java ./Bcore/src/main/java/top/niunaijun/blackbox/core/system/location/

# Copy updated BlackBoxSystem.java
cp /tmp/NewBlackbox_Enhanced/Bcore/src/main/java/top/niunaijun/blackbox/core/system/BlackBoxSystem.java ./Bcore/src/main/java/top/niunaijun/blackbox/core/system/

# Copy updated documentation
cp /tmp/NewBlackbox_Enhanced/README.md ./
cp /tmp/NewBlackbox_Enhanced/RELEASE_NOTES.md ./
```

### Step 4: Update BlackBoxSystem.java

The BlackBoxSystem.java has been updated to include the new services. Make sure to replace the original file with the enhanced version.

### Step 5: Commit Changes

```bash
# Add all changes
git add .

# Commit with descriptive message
git commit -m "feat: Add enhanced features

- Shell script execution support (.sh files)
- Google login integration
- Root hiding functionality
- Enhanced fake location with GPS simulation
- VPN hiding from applications

New services:
- ShellScriptService: Execute shell scripts in virtual environment
- GoogleAuthService: Google Sign-In and account management
- HideRootService: Hide root status from apps
- HideVpnService: Hide VPN connections
- EnhancedLocationService: Advanced GPS simulation

This enhances the virtual engine with privacy and automation features."
```

### Step 6: Push to GitHub

```bash
# Push to your fork
git push origin main
```

### Step 7: Create Pull Request (Optional)

If you want to contribute back to the original repository:

1. Go to your fork on GitHub
2. Click "Compare & pull request"
3. Select the original repository as base
4. Add a description of your changes
5. Click "Create pull request"

## 🔧 Building the APK

### Using Android Studio

1. Open Android Studio
2. Click "Open an existing project"
3. Navigate to your cloned repository
4. Select the root folder
5. Wait for Gradle to sync
6. Click "Build" → "Build Bundle(s) / APK(s)" → "Build APK(s)"

### Using Command Line

```bash
# Build Debug APK
./gradlew assembleDebug

# Build Release APK (requires signing configuration)
./gradlew assembleRelease
```

## 📱 Installing the APK

1. Enable "Unknown sources" on your Android device
2. Transfer the APK to your device
3. Open the APK file
4. Follow the installation prompts

## 🔐 Signing the Release APK

For release builds, you need to sign the APK:

### Generate Keystore

```bash
keytool -genkey -v -keystore blackbox-release.keystore -alias blackbox -keyalg RSA -keysize 2048 -validity 10000
```

### Configure Gradle

Create or edit `keystore.properties` in the root directory:

```
storePassword=your_store_password
keyPassword=your_key_password
keyAlias=blackbox
file=blackbox-release.keystore
```

Update `app/build.gradle`:

```gradle
android {
    signingConfigs {
        release {
            if (project.file('keystore.properties').exists()) {
                def keystorePropertiesFile = rootProject.file('keystore.properties')
                def keystoreProperties = new Properties()
                keystoreProperties.load(new FileInputStream(keystorePropertiesFile))
                
                storeFile file(keystoreProperties['file'])
                storePassword keystoreProperties['storePassword']
                keyAlias keystoreProperties['keyAlias']
                keyPassword keystoreProperties['keyPassword']
            }
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.release
        }
    }
}
```

## 🐛 Troubleshooting Build Issues

### Common Issues

1. **Gradle Sync Failed**
   - Check internet connection
   - Verify JDK 17 is installed
   - Clean and rebuild: `./gradlew clean`

2. **NDK Not Found**
   - Install NDK via Android Studio SDK Manager
   - Set NDK path in `local.properties`:
     ```
     ndk.dir=/path/to/ndk
     ```

3. **Missing Dependencies**
   - Run: `./gradlew --refresh-dependencies`
   - Check `settings.gradle` for correct repositories

4. **Compilation Errors**
   - Ensure all new service files are in correct directories
   - Check import statements in BlackBoxSystem.java
   - Verify package names match directory structure

### Clean Build

```bash
# Clean build
./gradlew clean

# Rebuild
./gradlew assembleDebug
```

## 📝 Repository Settings

### Make Repository Public

1. Go to your repository on GitHub
2. Click "Settings" tab
3. Scroll down to "Danger Zone"
4. Click "Change visibility"
5. Select "Public"
6. Confirm the change

### Add Description

1. Go to your repository
2. Click "About" section (right side)
3. Add description: "Enhanced BlackBox virtual engine with shell script support, Google login, root hiding, and advanced location simulation"
4. Add topics: `android`, `virtual-engine`, `privacy`, `root-hiding`, `location-spoofing`

### Add Repository Topics

1. Go to your repository
2. Click the gear icon next to "About"
3. Add topics: `android`, `virtual-engine`, `privacy`, `root-hiding`, `location-spoofing`, `shell-script`, `google-login`

## 🎯 Final Checklist

Before publishing:

- [ ] All new services are properly integrated
- [ ] BlackBoxSystem.java is updated with new service registrations
- [ ] README.md is updated with new features
- [ ] RELEASE_NOTES.md is created
- [ ] Build completes successfully
- [ ] APK installs and runs on device
- [ ] All features work as expected
- [ ] Repository is public
- [ ] Description and topics are added

## 📞 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the README.md for feature documentation
3. Open an issue on GitHub
4. Check Android Studio logs for errors

## 🎉 Congratulations!

You now have a fully enhanced BlackBox virtual engine with:
- ✅ Shell script execution support
- ✅ Google login integration
- ✅ Root hiding functionality
- ✅ Enhanced fake location with GPS simulation
- ✅ VPN hiding from applications

Your repository is now ready to share with the community!
