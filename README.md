<p align="center">
  <img src="https://img.shields.io/badge/🛡️_GSecurity-Windows_Security_Suite-blue?style=for-the-badge&labelColor=0d1117" alt="GSecurity"/>
</p>

<h1 align="center">🛡️ GSecurity</h1>

<p align="center">
  <strong>A comprehensive Windows security hardening and protection suite</strong><br>
  <em>Enterprise-grade security tools • Privacy protection • Automated threat response</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Windows"/>
  <img src="https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=flat-square&logo=powershell&logoColor=white" alt="PowerShell"/>
  <img src="https://img.shields.io/badge/Security-Hardened-red?style=flat-square" alt="Security"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-components">Components</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-windows-iso-integration">ISO Integration</a>
</p>

---

## 🎯 Overview

**GSecurity** is a complete security and privacy solution for Windows systems. It combines multiple protection layers including real-time antivirus, network monitoring, behavioral threat detection, privacy spoofing, vulnerability patching, and system hardening into a unified suite.

### ✨ Key Benefits

| Feature | Description |
|---------|-------------|
| 🔒 **Multi-Layer Protection** | Real-time file monitoring, memory scanning, YARA rules, and threat intelligence |
| 🧠 **Behavioral Analysis** | Detects focus abuse, flash attacks, cursor manipulation, and visual exploits |
| 🕵️ **Privacy Shield** | Identity spoofing and fingerprint randomization to defeat tracking |
| 🩹 **Auto-Patching** | Automatic CISA KEV vulnerability detection and mitigation |
| 🌐 **Network Security** | DNS-over-HTTPS/TLS, browser traffic monitoring, and smart blocking |
| 🔐 **Credential Protection** | Password rotation and security policy hardening |
| 📦 **Easy Deployment** | Can be integrated directly into Windows installation media |

---

## 🧩 Components

GSecurity consists of specialized security modules:

| Component | Description | Type |
|-----------|-------------|------|
| 🦠 **[Antivirus.ps1](#-antivirusps1)** | Comprehensive EDR with real-time protection | Active Protection |
| 🧠 **[NeuroBehaviorMonitor.ps1](#-neurobehaviormonitoryps1)** | Neuro-behavioral threat detection & response | Active Protection |
| 🌐 **[GFocus.ps1](#-gfocusps1)** | Network traffic monitor & firewall manager | Network Security |
| 🕵️ **[PrivacyForgeSpoofing.ps1](#-privacyforgespoofingps1)** | Identity & fingerprint spoofing | Privacy |
| 🩹 **[CVE-MitigationPatcher.ps1](#-cve-mitigationpatcherps1)** | CISA KEV vulnerability auto-patcher | Vulnerability Management |
| 🔑 **[Install-PasswordRotator.ps1](#-install-passwordrotatorps1)** | Automatic password rotation system | Credential Security |
| 🔧 **[Secpol.ps1](#-secpolps1)** | Security policy & privilege hardening | System Hardening |
| 🌍 **[configure-dns-doh-dot.ps1](#-configure-dns-doh-dotps1)** | DNS-over-HTTPS/TLS configuration | Network Security |
| 🛡️ **[GSecurity.bat](#-gsecuritybat)** | Main orchestrator & service hardening | System Hardening |

---

## 🚀 Features

### 🦠 Real-Time Antivirus Protection

- **Hash-Based Detection** — MalwareBazaar, CIRCL, and Cymru threat intelligence
- **YARA Memory Scanning** — Advanced pattern matching in process memory
- **Signature Verification** — Trusts Microsoft-signed binaries automatically
- **Quarantine System** — Isolates threats with backup restoration capability
- **WMI Monitoring** — Real-time process and DLL load interception
- **Behavior Analysis** — Process hollowing, credential access, lateral movement detection
- **C2 Detection** — Identifies and blocks command & control communications

### 🧠 Neuro-Behavioral Protection

- **Focus Abuse Detection** — Stops apps that repeatedly steal window focus
- **Flash Stimulus Protection** — Prevents rapid brightness changes (seizure protection)
- **Topmost Abuse Prevention** — Removes unauthorized always-on-top windows
- **Cursor Jitter Detection** — Identifies and stops cursor manipulation attacks
- **Color Distortion Defense** — Detects screen color inversion/manipulation

### 🕵️ Privacy & Anti-Tracking

- **Identity Rotation** — Generates and rotates fake identity profiles
- **Fingerprint Spoofing** — Randomizes browser fingerprint data
- **Sensor Data Noise** — Spoofs accelerometer, gyroscope, and other sensors
- **Telemetry Confusion** — Generates fake game and software telemetry
- **User Agent Rotation** — Cycles through realistic browser signatures

### 🩹 Vulnerability Management

- **CISA KEV Integration** — Fetches known exploited vulnerabilities catalog
- **Auto-Mitigation** — Applies scriptable fixes for critical CVEs
- **Scheduled Scanning** — Hourly checks for new vulnerabilities
- **Built-in Mitigations** — SMBv1, PrintNightmare, Follina, BlueKeep, and more

### 🌐 Network Security

- **DNS Encryption** — Cloudflare & Google DoH/DoT with automatic upgrade
- **Browser Traffic Monitor** — Tracks and controls browser connections only
- **Smart Blocking** — Blocks suspicious IPs while allowing dependencies
- **Gaming Unaffected** — Never monitors or blocks gaming applications

### 🔐 System Hardening

- **Service Lockdown** — Disables VNC, TeamViewer, AnyDesk, SSH, FTP, etc.
- **Privilege Restriction** — Denies network logon and remote access rights
- **UAC Configuration** — Proper consent prompt behavior
- **DEP Enforcement** — Always-on Data Execution Prevention

---

## 📦 Requirements

| Requirement | Specification |
|-------------|---------------|
| **OS** | Windows 10 / 11 (64-bit) |
| **PowerShell** | Version 5.1 or later |
| **Privileges** | Administrator rights required |
| **RAM** | 4GB minimum (8GB+ recommended) |
| **Disk** | ~100MB for installation |
| **Network** | Internet for threat intelligence updates |

---

## 🚀 Installation

### Method 1: Manual Installation

```powershell
# Clone or download the repository
git clone https://github.com/YourUsername/GSecurity.git
cd GSecurity

# Navigate to scripts directory
cd Iso\sources\$OEM$\$$\Setup\Scripts\Bin

# Run individual components as Administrator
.\Antivirus.ps1                    # 🦠 EDR Protection
.\NeuroBehaviorMonitor.ps1         # 🧠 Behavioral Protection
.\GFocus.ps1                       # 🌐 Network Monitor
.\PrivacyForgeSpoofing.ps1         # 🕵️ Privacy Protection
.\CVE-MitigationPatcher.ps1        # 🩹 Vulnerability Patching
.\Install-PasswordRotator.ps1      # 🔑 Password Rotation
.\configure-dns-doh-dot.ps1        # 🌍 Secure DNS
.\Secpol.ps1                       # 🔧 Policy Hardening
```

### Method 2: Full Suite Installation

```cmd
# Run as Administrator
GSecurity.bat
```

> ⚠️ **Note:** GSecurity.bat will restart your system after applying changes.

### Method 3: Windows ISO Integration

See [Windows ISO Integration](#-windows-iso-integration) for automated deployment.

---

## 💻 Usage

### 🦠 Antivirus.ps1

**Comprehensive Endpoint Detection & Response**

```powershell
# Install and run (auto-installs as scheduled task)
.\Antivirus.ps1

# View logs
Get-Content "C:\ProgramData\Antivirus\av.log"

# Check quarantine
Get-ChildItem "C:\ProgramData\Antivirus\Quarantine"
```

**Features:**
- 🔍 Real-time file system monitoring
- 🧬 Memory scanning with YARA rules
- 🌐 Threat intelligence from MalwareBazaar, CIRCL, Cymru
- ⚡ WMI-based process/DLL interception
- 🚫 Automatic quarantine and process termination
- 📊 Persistence and fileless malware detection

---

### 🧠 NeuroBehaviorMonitor.ps1

**Neuro-Behavioral Threat Detection & Active Response**

```powershell
# Full response mode (default) - minimize, remove flags, kill threats
.\NeuroBehaviorMonitor.ps1

# Moderate mode - no process killing
.\NeuroBehaviorMonitor.ps1 -ResponseLevel Moderate

# Alert only - logging without action
.\NeuroBehaviorMonitor.ps1 -ResponseLevel AlertOnly

# Custom tick interval
.\NeuroBehaviorMonitor.ps1 -TickIntervalSeconds 2
```

**Response Levels:**
| Level | Actions |
|-------|---------|
| 🔴 **Full** | Minimize + Remove flags + Kill process |
| 🟡 **Moderate** | Minimize + Remove flags (no kills) |
| ⚪ **AlertOnly** | Log only, no action taken |

---

### 🌐 GFocus.ps1

**Network Traffic Monitor & Smart Firewall**

```powershell
# Start monitoring (browsers only)
.\GFocus.ps1

# Allow specific domains
.\GFocus.ps1 -AllowedDomains "example.com","trusted.org"

# Remove all block rules
.\GFocus.ps1 -RemoveRules
```

**Key Features:**
- 🎮 **Gaming Safe** — Never monitors or blocks games
- 🌐 **Browser Only** — Targets browser processes exclusively
- 🔗 **Smart Dependencies** — Auto-allows related connections
- ♻️ **Dynamic Rules** — Removes blocks when user navigates to site

---

### 🕵️ PrivacyForgeSpoofing.ps1

**Identity & Fingerprint Spoofing**

```powershell
# Start privacy protection (runs continuously)
.\PrivacyForgeSpoofing.ps1
```

**Spoofing Capabilities:**
- 👤 Fake identity generation (name, email, location)
- 🖥️ User agent and screen resolution rotation
- 🎮 Game telemetry spoofing
- 📱 Sensor data randomization
- 🔄 Automatic identity rotation (hourly or threshold-based)

---

### 🩹 CVE-MitigationPatcher.ps1

**CISA KEV Vulnerability Auto-Patcher**

```powershell
# Apply mitigations (default)
.\CVE-MitigationPatcher.ps1

# Preview only (dry run)
.\CVE-MitigationPatcher.ps1 -DryRun

# Report only (list CVEs without action)
.\CVE-MitigationPatcher.ps1 -ReportOnly

# Filter by vendor
.\CVE-MitigationPatcher.ps1 -FilterVendor "Microsoft"

# Install as scheduled task (hourly)
.\CVE-MitigationPatcher.ps1 -RegisterSchedule

# Uninstall scheduled task
.\CVE-MitigationPatcher.ps1 -UnregisterSchedule
```

**Built-in Mitigations:**
| CVE | Vulnerability | Mitigation |
|-----|---------------|------------|
| CVE-2017-0144 | EternalBlue | Disable SMBv1 |
| CVE-2020-0796 | SMBGhost | Disable SMBv3 Compression |
| CVE-2019-0708 | BlueKeep | Enable RDP NLA |
| CVE-2021-34527 | PrintNightmare | Disable Print Spooler |
| CVE-2022-30190 | Follina | Block MSDT Protocol |
| CVE-2024-38063 | IPv6 RCE | Disable IPv6 |

---

### 🔑 Install-PasswordRotator.ps1

**Automatic Password Rotation System**

```powershell
# Install (one-shot, run as Administrator)
.\Install-PasswordRotator.ps1

# Uninstall
.\Install-PasswordRotator.ps1 Uninstall
```

**How it Works:**
1. 🔓 Sets current user password to blank on install
2. ⏰ After logon, waits 60 seconds then sets random 24-char password
3. 🔄 Rotates to new random password every 10 minutes
4. 🔓 Resets password to blank on logoff
5. 🛡️ Protects against password-based attacks while logged in

---

### 🌍 configure-dns-doh-dot.ps1

**Secure DNS Configuration**

```powershell
# Configure DoH/DoT (run as Administrator)
.\configure-dns-doh-dot.ps1
```

**Configuration:**
| Type | Primary (Cloudflare) | Secondary (Google) |
|------|---------------------|-------------------|
| IPv4 | 1.1.1.1 | 8.8.8.8 |
| IPv6 | 2606:4700:4700::1111 | 2001:4860:4860::8888 |
| DoH | ✅ Enabled | ✅ Enabled |
| DoT | ✅ Enabled | ✅ Enabled |

---

### 🔧 Secpol.ps1

**Security Policy Hardening**

```powershell
# Apply privilege restrictions
.\Secpol.ps1
```

**Restrictions Applied:**
- 🚫 Deny network logon for authenticated users
- 🚫 Deny remote interactive logon
- 🚫 Clear remote shutdown privileges
- 🚫 Clear remote logon rights

---

### 🛡️ GSecurity.bat

**Main Security Orchestrator**

```cmd
# Run full system hardening (requires restart)
GSecurity.bat
```

**Actions Performed:**
- 📝 Applies registry security tweaks
- 🛑 Disables dangerous services (VNC, TeamViewer, AnyDesk, SSH, FTP, etc.)
- 🔐 Sets file permissions on critical system files
- 👤 Removes default user accounts
- ⚙️ Configures UAC behavior
- 💻 Enables DEP (Data Execution Prevention)
- 🔄 Restarts system to apply changes

---

## 💿 Windows ISO Integration

GSecurity can be integrated into Windows installation media for automated deployment:

### Step 1: Prepare Windows ISO

```cmd
# Mount or extract Windows ISO to a folder (e.g., C:\WindowsISO)
```

### Step 2: Copy GSecurity Files

```cmd
xcopy /E /I "GSecurity\Iso\sources" "C:\WindowsISO\sources"
```

### Step 3: Rebuild ISO

```cmd
# Using oscdimg from Windows ADK
oscdimg -m -o -u2 -udfver102 ^
  -bootdata:2#p0,e,b"C:\WindowsISO\boot\etfsboot.com"#pEF,e,b"C:\WindowsISO\efi\microsoft\boot\efisys.bin" ^
  "C:\WindowsISO" "C:\GSecurity-Windows.iso"
```

### Step 4: Test

1. Create a VM
2. Install Windows from the modified ISO
3. GSecurity runs automatically on first logon

---

## 📁 File Structure

```
GSecurity/
├── 📄 README.md
└── 📁 Iso/
    ├── 📄 autounattend.xml          # Unattended Windows installation
    ├── 📄 Autorun.inf
    └── 📁 sources/
        └── 📁 $OEM$/
            ├── 📁 $$/Setup/Scripts/
            │   ├── 📄 SetupComplete.cmd    # Post-install trigger
            │   └── 📁 Bin/
            │       ├── 🦠 Antivirus.ps1
            │       ├── 🧠 NeuroBehaviorMonitor.ps1
            │       ├── 🌐 GFocus.ps1
            │       ├── 🕵️ PrivacyForgeSpoofing.ps1
            │       ├── 🩹 CVE-MitigationPatcher.ps1
            │       ├── 🔑 Install-PasswordRotator.ps1
            │       ├── 🔧 Secpol.ps1
            │       ├── 🌍 configure-dns-doh-dot.ps1
            │       ├── 🛡️ GSecurity.bat
            │       ├── 📄 GSecurity.reg
            │       ├── 📄 Antivirus.xml
            │       ├── 📄 Antivirus.cmd
            │       └── 📄 GFocusRulesRemover.ps1
            └── 📁 $1/
                ├── 📄 autoexec.bat
                ├── 📄 config.sys
                └── 📁 users/Default/Desktop/Extras/
```

---

## ⚠️ Security Considerations

### 🔴 Important Warnings

| Warning | Description |
|---------|-------------|
| 🔄 **Restart Required** | GSecurity.bat and some mitigations require system restart |
| 🛑 **Service Changes** | Some services are permanently disabled |
| 📦 **File Quarantine** | Antivirus may quarantine legitimate files — review logs |
| 🌐 **Network Blocking** | GFocus may block connections — use `-RemoveRules` if needed |
| 🔐 **Policy Changes** | Secpol makes permanent security policy changes |
| 🔑 **Password Rotation** | PasswordRotator changes user passwords automatically |

### ✅ Best Practices

1. 💾 **Backup First** — Create a system restore point before installation
2. 🖥️ **Test in VM** — Test GSecurity in a virtual machine first
3. 📋 **Review Logs** — Regularly check component logs for issues
4. 🔄 **Update Regularly** — Keep components updated for latest security
5. ⚡ **Monitor Performance** — Watch for performance impacts

### 🔒 Privacy

- **Hash Lookups** — File hashes are sent to external threat intelligence services
- **No Data Collection** — GSecurity does not collect or transmit personal data
- **Local Processing** — All monitoring and blocking happens locally

---

## 📊 Performance Impact

| Component | CPU | RAM | Disk I/O |
|-----------|-----|-----|----------|
| 🦠 Antivirus | < 5% | ~50-100 MB | Medium |
| 🧠 NeuroBehaviorMonitor | < 2% | ~20-30 MB | Low |
| 🌐 GFocus | < 2% | ~15-25 MB | Minimal |
| 🕵️ PrivacyForgeSpoofing | < 1% | ~10-20 MB | Minimal |
| 🩹 CVE-MitigationPatcher | < 1%* | ~10 MB | Low |

*\*Runs hourly when scheduled*

**Total Impact:** Typically < 10% CPU, < 200 MB RAM

---

## 🛠️ Troubleshooting

### Component Not Starting

```powershell
# Check scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like "*Antivirus*" -or $_.TaskName -like "*CVE*" }

# View task history
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | 
    Where-Object { $_.Message -like "*Antivirus*" } | 
    Select-Object -First 10
```

### Antivirus Issues

```powershell
# Check logs
Get-Content "C:\ProgramData\Antivirus\av.log" -Tail 50

# View blocked files
Get-Content "C:\ProgramData\Antivirus\blocked.log"

# Check quarantine
Get-ChildItem "C:\ProgramData\Antivirus\Quarantine"
```

### GFocus Blocking Legitimate Sites

```powershell
# Remove all block rules
.\GFocus.ps1 -RemoveRules

# Or allow specific domains
.\GFocus.ps1 -AllowedDomains "example.com"
```

### DNS Configuration Issues

```cmd
# Reset DNS to DHCP
netsh interface ipv4 set dnsservers name="Ethernet" dhcp
netsh interface ipv6 set dnsservers name="Ethernet" dhcp

# Verify configuration
ipconfig /all | findstr "DNS"
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. 🍴 Fork the repository
2. 🌿 Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. 💾 Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. 📤 Push to the branch (`git push origin feature/AmazingFeature`)
5. 🔀 Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Gorstak**

- 🌐 Discord: [discord.gg/65sZs7aJQP](https://discord.gg/65sZs7aJQP)

---

## 🙏 Acknowledgments

- 🦠 [MalwareBazaar](https://bazaar.abuse.ch/) — Threat intelligence
- 🔍 [CIRCL](https://www.circl.lu/) — Hash lookup services
- 🇺🇸 [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Vulnerability catalog
- 🌐 [Cloudflare](https://cloudflare.com/) & [Google](https://google.com/) — DNS services
- 🎯 [YARA](https://virustotal.github.io/yara/) — Pattern matching engine
- ❤️ All contributors and users of this project

---

<p align="center">
  <strong>Made with ❤️ for a more secure Windows</strong>
</p>

<p align="center">
  <sub>⚠️ USE AT YOUR OWN RISK — Always test in a virtual machine first</sub>
</p>
