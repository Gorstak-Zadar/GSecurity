# 🛡️ GSecurity

A comprehensive Windows security and optimization suite designed to harden your system, protect against malware, optimize network traffic, and enhance gaming performance. GSecurity provides enterprise-grade security tools in an easy-to-use package.

![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=PowerShell&logoColor=white)
![Security](https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Components](#-components)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Component Details](#-component-details)
- [Windows ISO Integration](#-windows-iso-integration)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🎯 Overview

GSecurity is a complete security and optimization solution for Windows systems. It combines multiple security layers, network monitoring, performance optimization, and system hardening into a unified suite. Whether you're securing a personal computer or deploying across an organization, GSecurity provides the tools you need.

### Key Benefits

- 🔒 **Multi-Layer Protection**: Real-time file monitoring, network traffic control, and unsigned binary protection
- 🚀 **Performance Optimization**: Gaming cache system and RAM management
- 🌐 **Network Security**: DNS-over-HTTPS/TLS, firewall management, and traffic monitoring
- 🛡️ **System Hardening**: Service lockdown, privilege management, and security policy enforcement
- 📦 **Easy Deployment**: Can be integrated into Windows installation media

---

## 🧩 Components

GSecurity consists of several specialized modules:

| Component | Description | Status |
|-----------|-------------|--------|
| **Antivirus** | Comprehensive EDR with advanced threat detection | ✅ Active |
| **CleanGuard** | Real-time file protection and malware detection | ✅ Active |
| **GFocus** | Network traffic monitor and firewall rule manager | ✅ Active |
| **SimpleAntivirus** | Unsigned binary detection and protection | ✅ Active |
| **Creds** | Local credential protection and LSASS hardening | ✅ Active |
| **GameCache** | Multi-tier caching system for gaming performance | ✅ Active |
| **Secpol** | Security policy and privilege rights hardening | ✅ Active |
| **RamCleaner** | RAM optimization and memory management | ✅ Active |
| **GSecurity.bat** | Main security script and service management | ✅ Active |
| **DNS Config** | DNS-over-HTTPS/TLS configuration | ✅ Active |

---

## ✨ Features

### 🔐 Security Features

- **Advanced EDR Protection**: Comprehensive endpoint detection and response with 40+ detection modules
- **Real-Time File Monitoring**: Watches for suspicious executables, DLLs, and system files
- **Malware Detection**: Integrates with MalwareBazaar, CIRCL, and Cymru hash lookup services
- **Signature Verification**: Automatically trusts Microsoft-signed binaries
- **Quarantine System**: Isolates suspicious files with backup restoration capability
- **Credential Protection**: LSASS PPL protection, credential caching management, and auditing
- **Threat Detection**: LOLBin detection, process anomalies, AMSI bypass, credential dumps, ransomware, rootkits, and more
- **Network Traffic Control**: Browser-focused traffic monitoring and blocking
- **Firewall Management**: Dynamic rule creation and removal based on user behavior
- **Service Hardening**: Disables unnecessary and potentially dangerous services
- **Privilege Rights**: Restricts network logon and remote access rights

### 🚀 Performance Features

- **Multi-Tier Caching**: RAM and SSD caching for game files
- **LRU Eviction**: Intelligent cache management based on access patterns
- **RAM Optimization**: Continuous standby memory clearing
- **Drive Detection**: Automatic SSD/HDD detection for optimal cache placement

### 🌐 Network Features

- **DNS-over-HTTPS (DoH)**: Encrypted DNS queries via Cloudflare and Google
- **DNS-over-TLS (DoT)**: Additional DNS encryption layer
- **Traffic Monitoring**: Real-time browser connection tracking
- **Smart Blocking**: Blocks suspicious connections while allowing legitimate traffic

### 🎮 Gaming Features

- **Game File Caching**: Automatically caches frequently accessed game files
- **Transparent Access**: Symlink-based caching for seamless operation
- **Performance Boost**: Reduces load times for games on HDDs

---

## 📦 Requirements

- **OS**: Windows 10/11 (some components work on Windows 7/8)
- **Privileges**: Administrator rights required
- **PowerShell**: Version 5.1 or later
- **RAM**: 4GB minimum (8GB+ recommended)
- **Disk Space**: ~500MB for installation + cache space

### Optional Requirements

- **Windows ISO**: For integration into installation media
- **Internet Connection**: For malware hash lookups and DNS configuration

---

## 🚀 Installation

### Method 1: Standard Installation

1. **Clone or download** this repository:
   ```bash
   git clone https://github.com/DumDumTras/GSecurity.git
   cd GSecurity
   ```

2. **Navigate to the scripts directory**:
   ```cmd
   cd Iso\sources\$OEM$\$$\Setup\Scripts\Bin
   ```

3. **Run individual components** (each installs automatically):
   ```powershell
   # Run as Administrator
   .\Antivirus.ps1          # Comprehensive EDR (installs automatically)
   .\CleanGuard.ps1
   .\GFocus.ps1
   .\SimpleAntivirus.ps1
   .\Creds.ps1               # Credential protection
   .\GameCache.ps1
   ```

4. **Run main security script**:
   ```cmd
   GSecurity.bat
   ```

### Method 2: Windows ISO Integration

GSecurity can be integrated into a Windows installation ISO for automated deployment:

1. **Prepare your Windows ISO** (extract or mount)

2. **Copy GSecurity files** to the ISO structure:
   ```
   sources\$OEM$\$$\Setup\Scripts\Bin\
   ```

3. **Configure SetupComplete.cmd** to run GSecurity.bat

4. **Rebuild ISO** using tools like `oscdimg` or `DISM`

See [Windows ISO Integration](#-windows-iso-integration) section for detailed instructions.

---

## 💻 Usage

### Component Management

Each component can be installed, uninstalled, or run manually:

#### CleanGuard

```powershell
# Install (runs automatically on first run)
.\CleanGuard.ps1

# Check status
Get-ScheduledTask -TaskName "CleanGuard"

# View logs
Get-Content "$env:ProgramData\CleanGuard\log.txt"
```

#### GFocus

```powershell
# Install
.\GFocus.ps1 -Install

# Run in monitor mode
.\GFocus.ps1

# Remove blocked rules
.\GFocus.ps1 -RemoveRules

# Uninstall
.\GFocus.ps1 -Uninstall
```

#### SimpleAntivirus

```powershell
# Install
.\SimpleAntivirus.ps1 -Install

# Run manually
.\SimpleAntivirus.ps1

# Uninstall
.\SimpleAntivirus.ps1 -Uninstall
```

#### Antivirus

```powershell
# Install (runs automatically on first run)
.\Antivirus.ps1

# Uninstall
.\Antivirus.ps1 -Uninstall

# View logs
Get-Content "$env:ProgramData\AntivirusProtection\Logs\*.txt"

# Check status
Get-ScheduledTask -TaskName "AntivirusProtection"
```

#### Creds (Credential Protection)

```powershell
# Run as Administrator
.\Creds.ps1
```

This will:
- Enable LSASS Protected Process Light (PPL)
- Clear cached credentials from Credential Manager
- Disable credential caching
- Enable credential access auditing
- **Requires reboot** to apply LSASS PPL changes

#### GameCache

```powershell
# Install
.\GameCache.ps1 -Install

# View cache status
Get-Content "$env:ProgramData\GameCache\cache.log"

# Uninstall
.\GameCache.ps1 -Uninstall
```

### Main Security Script

Run the comprehensive security script:

```cmd
# Run as Administrator
GSecurity.bat
```

This will:
- Apply registry settings
- Disable dangerous services
- Set file permissions
- Install RamCleaner
- Configure security policies
- Restart system (required for some changes)

### DNS Configuration

Configure DNS-over-HTTPS/TLS:

```powershell
.\configure-dns-doh-dot.ps1
```

This sets up:
- Primary DNS: Cloudflare (1.1.1.1)
- Secondary DNS: Google (8.8.8.8)
- DoH/DoT: Enabled automatically

---

## 🔍 Component Details

### Antivirus.ps1

**Purpose**: Comprehensive Endpoint Detection and Response (EDR) system

**Features**:
- **40+ Detection Modules**: Hash detection, LOLBin detection, process anomalies, AMSI bypass, credential dumps, ransomware, rootkits, and more
- **Real-Time Monitoring**: Continuous monitoring of processes, network, registry, services, and file system
- **Advanced Threat Detection**: Code injection, process hollowing, token manipulation, DLL hijacking, fileless malware detection
- **Network Security**: Network anomaly detection, traffic monitoring, DNS exfiltration detection, beacon detection
- **Privacy Protection**: Webcam guardian, clipboard monitoring, password management, keylogger detection
- **Persistence Detection**: WMI persistence, scheduled tasks, registry persistence, service monitoring
- **Quarantine System**: Automatic threat isolation with backup and restore capability
- **Auto-Recovery**: Automatic restart and recovery on failure
- **Managed Jobs**: Efficient background job system for all detection modules
- **Hash Lookups**: Integration with MalwareBazaar, CIRCL, and Cymru APIs

**Installation Path**: `C:\ProgramData\AntivirusProtection\`

**Logs**: `C:\ProgramData\AntivirusProtection\Logs\`

**Quarantine**: `C:\ProgramData\AntivirusProtection\Quarantine\`

**Database**: `C:\ProgramData\AntivirusProtection\Data\`

**Scheduled Task**: `AntivirusProtection`

### CleanGuard.ps1

**Purpose**: Real-time file protection and malware detection

**Features**:
- Monitors `.exe`, `.dll`, `.sys`, `.winmd` files
- Quarantines suspicious files automatically
- Checks against MalwareBazaar and CIRCL databases
- Trusts Microsoft-signed binaries
- Maintains quarantine with restore capability

**Installation Path**: `C:\ProgramData\CleanGuard\`

**Logs**: `C:\ProgramData\CleanGuard\log.txt`

**Quarantine**: `C:\ProgramData\CleanGuard\Quarantine\`

### GFocus.ps1

**Purpose**: Network traffic monitoring and firewall management

**Features**:
- Browser-only monitoring (games unaffected)
- Automatic blocking of suspicious connections
- Smart dependency detection (allows related connections)
- Dynamic firewall rule management
- Address bar inference from browser traffic

**Installation Path**: `C:\ProgramData\GFocus\`

**Note**: Only monitors browser processes, never blocks gaming traffic

### SimpleAntivirus.ps1

**Purpose**: Protection against unsigned binaries

**Features**:
- Watches for new DLL and WINMD files
- Removes permissions from unsigned binaries
- Signature verification
- File system monitoring

**Installation Path**: `C:\ProgramData\SimpleAntivirus\`

### GameCache.ps1

**Purpose**: Multi-tier caching for gaming performance

**Features**:
- RAM cache (2GB default) for small files
- SSD cache (20GB default) for larger files
- LRU eviction algorithm
- Automatic drive detection (SSD/HDD)
- Transparent symlink-based caching

**Installation Path**: `C:\ProgramData\GameCache\`

**Cache Locations**:
- RAM: `%TEMP%\GameCache_RAM\`
- SSD: `[SSD Drive]\GameCache_SSD\`

### Secpol.ps1

**Purpose**: Security policy and privilege rights hardening

**Features**:
- Denies network logon rights
- Restricts remote access
- Hardens user rights
- Applies security policies

**Note**: Requires `secedit` and may require Group Policy Editor

### Creds.ps1

**Purpose**: Local credential protection and LSASS hardening

**Features**:
- **LSASS PPL**: Enables Protected Process Light for LSASS to prevent credential dumping
- **Credential Clearing**: Removes cached credentials from Windows Credential Manager
- **Caching Disabled**: Sets `CachedLogonsCount` to 0 to prevent credential caching
- **Auditing Enabled**: Enables credential validation auditing in Windows Event Log

**Installation**: Standalone script (no installation required)

**Note**: Requires system reboot to apply LSASS PPL changes. Check Event Viewer Security logs for credential access auditing.

### GSecurity.bat

**Purpose**: Main security script and system hardening

**Actions**:
- Applies registry tweaks
- Disables dangerous services (VNC, TeamViewer, AnyDesk, etc.)
- Sets file permissions
- Removes default users
- Installs RamCleaner
- Configures UAC settings
- **Restarts system** (required)

---

## 💿 Windows ISO Integration

GSecurity can be integrated into Windows installation media for automated deployment:

### Step 1: Extract Windows ISO

```cmd
# Mount or extract Windows ISO
# Copy contents to a folder (e.g., C:\WindowsISO)
```

### Step 2: Copy GSecurity Files

```cmd
# Copy the entire GSecurity structure
xcopy /E /I "GSecurity\Iso\sources" "C:\WindowsISO\sources"
```

### Step 3: Configure SetupComplete.cmd

Edit `sources\$OEM$\$$\Setup\Scripts\SetupComplete.cmd`:

```cmd
@echo off
cd /d "%~dp0Bin"
call GSecurity.bat
```

### Step 4: Rebuild ISO

```cmd
# Using oscdimg (Windows ADK)
oscdimg -m -o -u2 -udfver102 -bootdata:2#p0,e,b"C:\WindowsISO\boot\etfsboot.com"#pEF,e,b"C:\WindowsISO\efi\microsoft\boot\efisys.bin" "C:\WindowsISO" "C:\GSecurity-Windows.iso"
```

### Step 5: Test

- Create a VM
- Install Windows from the modified ISO
- Verify GSecurity components are installed

---

## ⚙️ Configuration

### CleanGuard Configuration

Edit `CleanGuard.ps1` to modify:
- File types monitored
- Quarantine location
- Allow-list hashes
- API timeouts

### GFocus Configuration

Edit `GFocus.ps1` to modify:
- Browser process list
- Gaming process list
- Never-block IPs
- Monitoring intervals

### GameCache Configuration

Edit `GameCache.ps1` to modify:
- RAM cache size (default: 2048 MB)
- SSD cache size (default: 20 GB)
- Target file extensions
- Game directory paths
- Monitor interval

### Antivirus Configuration

Edit `Antivirus.ps1` to modify:
- Detection intervals for each module (in `$Script:ManagedJobConfig`)
- Exclusion paths and processes
- Auto-quarantine and auto-kill settings
- Memory usage limits
- Hash lookup API URLs
- Quarantine and log paths

### Creds Configuration

`Creds.ps1` is a standalone script with no configuration file. Modify the script directly to:
- Change credential clearing behavior
- Adjust auditing settings
- Modify LSASS PPL configuration

### RamCleaner Configuration

See [RamCleaner README](../RamCleaner-main/README.md) for configuration options.

---

## 🛠️ Troubleshooting

### Component Not Starting

**Check scheduled task status**:
```powershell
Get-ScheduledTask -TaskName "AntivirusProtection" | Format-List
Get-ScheduledTask -TaskName "CleanGuard" | Format-List
Get-ScheduledTask -TaskName "GFocus" | Format-List
```

**View task history**:
```powershell
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | Where-Object {$_.Message -like "*AntivirusProtection*"}
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | Where-Object {$_.Message -like "*CleanGuard*"}
```

### Antivirus Issues

**Check stability log**:
```powershell
Get-Content "$env:ProgramData\AntivirusProtection\Logs\stability_log.txt"
```

**View detection logs**:
```powershell
Get-ChildItem "$env:ProgramData\AntivirusProtection\Logs\" | Sort-Object LastWriteTime -Descending
```

**Restore from quarantine**:
```powershell
# Check quarantine directory
Get-ChildItem "$env:ProgramData\AntivirusProtection\Quarantine\"
```

### Creds Issues

**Verify LSASS PPL**:
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
# Should return 1 if enabled
```

**Check credential auditing**:
```powershell
auditpol /get /subcategory:"Credential Validation"
```

**View credential events**:
- Open Event Viewer → Windows Logs → Security
- Filter for Event ID 4776 (credential validation)

### CleanGuard Quarantining Legitimate Files

**Restore from quarantine**:
```powershell
# Check last quarantined file
Get-Content "$env:ProgramData\CleanGuard\Quarantine\.last"

# Manual restore: Copy from Backup folder to original location
```

**Add to allow-list**:
Edit `CleanGuard.ps1` and add file hash to `$AllowList` array.

### GFocus Blocking Legitimate Sites

**Remove block rules**:
```powershell
.\GFocus.ps1 -RemoveRules
```

**Allow specific domain**:
```powershell
.\GFocus.ps1 -AllowedDomains "example.com","another.com"
```

### GameCache Not Working

**Check drive detection**:
```powershell
# View cache log
Get-Content "$env:ProgramData\GameCache\cache.log"
```

**Verify permissions**:
- Ensure running as Administrator (required for symlinks)
- Check disk space on cache drives

### DNS Configuration Issues

**Reset DNS**:
```cmd
netsh interface ipv4 set dnsservers name="Ethernet" dhcp
netsh interface ipv6 set dnsservers name="Ethernet" dhcp
```

**Verify DoH/DoT**:
- Open Settings → Network & Internet → DNS
- Check that DNS servers show "On (automatic)"

---

## 🔒 Security Considerations

### Important Warnings

1. **System Restart**: GSecurity.bat and Creds.ps1 will require system restarts
2. **Service Disabling**: Some services are permanently disabled (backup first)
3. **File Quarantine**: Antivirus and CleanGuard may quarantine legitimate files - review logs
4. **Network Blocking**: GFocus may block legitimate connections - use RemoveRules if needed
5. **Privilege Changes**: Secpol makes permanent security policy changes
6. **LSASS PPL**: Creds.ps1 enables LSASS Protected Process Light - may affect some security tools
7. **Credential Caching**: Creds.ps1 disables credential caching - users must be online to log in

### Best Practices

- **Backup First**: Create a system restore point before installation
- **Test in VM**: Test GSecurity in a virtual machine first
- **Review Logs**: Regularly check component logs for issues
- **Update Regularly**: Keep components updated for latest security features
- **Monitor Performance**: Watch for performance impacts and adjust configuration

### Privacy

- **Hash Lookups**: CleanGuard sends file hashes to external services (MalwareBazaar, CIRCL)
- **No Data Collection**: GSecurity does not collect or transmit personal data
- **Local Processing**: All monitoring and blocking happens locally

---

## 📁 File Structure

```
GSecurity/
├── Iso/
│   └── sources/
│       └── $OEM$/
│           └── $$/
│               └── Setup/
│                   └── Scripts/
│                       ├── Bin/
│                       │   ├── Antivirus.ps1
│                       │   ├── CleanGuard.ps1
│                       │   ├── Creds.ps1
│                       │   ├── GFocus.ps1
│                       │   ├── SimpleAntivirus.ps1
│                       │   ├── GameCache.ps1
│                       │   ├── Secpol.ps1
│                       │   ├── GSecurity.bat
│                       │   ├── GSecurity.reg
│                       │   ├── RamCleaner.bat
│                       │   ├── RamCleaner.xml
│                       │   ├── configure-dns-doh-dot.ps1
│                       │   └── EmptyStandbyList.exe
│                       ├── MAS_AIO.cmd
│                       └── SetupComplete.cmd
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Contribution Guidelines

- Follow existing code style
- Add comments for complex logic
- Test thoroughly before submitting
- Update documentation as needed
- Ensure backward compatibility where possible

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**DumDumTras**

- GitHub: [@DumDumTras](https://github.com/DumDumTras)
- Profile: [github.com/DumDumTras](https://github.com/DumDumTras)

---

## 🙏 Acknowledgments

- Windows security community for best practices
- MalwareBazaar and CIRCL for hash lookup services
- Cloudflare and Google for DNS-over-HTTPS/TLS
- All contributors and users of this project

---

## ⚠️ Disclaimer

**USE AT YOUR OWN RISK**

GSecurity performs system-level operations that can significantly alter your Windows configuration. These changes may:

- Disable services permanently
- Modify security policies
- Quarantine files automatically
- Block network connections
- Require system restarts

Always:
- Test in a virtual machine first
- Create system restore points
- Backup important data
- Review logs regularly
- Understand what each component does

The authors and contributors are not responsible for any damage, data loss, or security issues resulting from the use of this software.

---

## 📊 Performance Impact

| Component | CPU Usage | RAM Usage | Disk I/O |
|-----------|-----------|-----------|----------|
| Antivirus | < 5% | ~100-200 MB | Medium |
| CleanGuard | < 1% | ~10-20 MB | Low |
| GFocus | < 2% | ~15-30 MB | Minimal |
| SimpleAntivirus | < 1% | ~5-10 MB | Low |
| GameCache | < 3% | ~20-50 MB | Medium |
| RamCleaner | < 1% | ~2-5 MB | Minimal |

**Total Impact**: Typically < 10% CPU, < 300 MB RAM (with Antivirus active)

---

## 🔄 Updates

Check for updates regularly:
```bash
git pull origin main
```

Or download the latest release from GitHub.

---

**Made with ❤️ for a more secure Windows**
