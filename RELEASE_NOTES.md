# Release Notes - BlackBox Enhanced

## Version 4.1.0 (Latest)

### 🆕 New Features

#### Shell Script Execution (.sh Support)
- Execute shell scripts within the virtual environment
- Run scripts with arguments and environment variables
- Support for .sh, .bash, .zsh files
- Script output streaming and monitoring
- Kill running script sessions
- Automatic script detection and permission handling

#### Google Login Support
- Full Google Sign-In integration within virtual apps
- Account management and token handling
- OAuth 2.0 support with token refresh
- Multiple Google accounts support
- Secure token storage and validation

#### Hide Root
- Hide root status from applications
- Bypass root detection (Magisk, SuperSU, etc.)
- Hide root-related files and packages
- Simulate non-rooted environment
- Customizable detection bypass
- Support for common root detection methods

#### Enhanced Fake Location
- GPS simulation with realistic movement
- Route following with speed control
- Satellite simulation for realistic GPS behavior
- Random location generation within radius
- Movement patterns and bearing control
- Smooth transitions between locations

#### Hide VPN
- Hide VPN connections from applications
- Bypass VPN detection
- Simulate regular network connections
- Hide VPN interfaces and packages
- DNS server filtering
- Network interface modification

### 🔧 Improvements
- Enhanced stability and performance
- Better Android 14+ compatibility
- Improved memory management
- Better error handling and logging
- Enhanced security features

### 🐛 Bug Fixes
- Fixed various crash issues
- Fixed permission handling
- Fixed memory leaks
- Fixed compatibility issues with newer Android versions

## Version 4.0.0

### Initial Enhanced Release
- Base virtual engine features
- Virtual app cloning
- Sandboxed environment
- Multi-architecture support
- Device spoofing
- Basic fake location

## Upgrading from Previous Versions

### From 4.0.0 to 4.1.0
1. Backup your virtual apps and data
2. Uninstall the previous version
3. Install the new version
4. Restore your virtual apps and data

### From 3.x to 4.x
- Major architecture changes
- Complete UI overhaul
- New permission model
- Enhanced security features

## Known Issues
- Some root detection methods may still detect root on certain devices
- Google Sign-In may require additional configuration for some apps
- VPN hiding may not work with all VPN protocols

## Future Plans
- Additional root detection bypass methods
- More Google services integration
- Enhanced route following with speed variation
- GPS satellite constellation simulation
- Network traffic analysis and modification
- Additional privacy features

## Support
For issues and questions:
- Open an issue on GitHub
- Check the documentation in Docs.md
- Review the troubleshooting section in README.md
