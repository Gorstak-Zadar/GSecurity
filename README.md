<p align="center">
  <img src="https://img.shields.io/badge/🛡️_GSecurity-Windows_Security_Suite-blue?style=for-the-badge&labelColor=0d1117" alt="GSecurity"/>
</p>

<h1 align="center">🛡️ GSecurity</h1>

<p align="center">
  <strong>A comprehensive Windows security hardening and protection suite</strong><br>
  <em>Enterprise-grade EDR • 95+ Security Modules • Automated Threat Response</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Windows"/>
  <img src="https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=flat-square&logo=powershell&logoColor=white" alt="PowerShell"/>
  <img src="https://img.shields.io/badge/Modules-95+-red?style=flat-square" alt="Modules"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-security-modules">Security Modules</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-windows-iso-integration">ISO Integration</a>
</p>

---

## 🎯 Overview

**GSecurity** is a complete endpoint detection and response (EDR) solution for Windows systems. It combines 95+ security modules into a single unified PowerShell engine, providing **active threat mitigation** - not just detection, but automatic quarantine, process termination, network blocking, and system remediation. Features include real-time antivirus protection, network monitoring, behavioral threat detection, privacy spoofing, vulnerability patching, PUA/PUP detection, heuristic analysis, and comprehensive system hardening.

### ✨ Key Benefits

| Feature | Description |
|---------|-------------|
| ⚔️ **Active Threat Mitigation** | Automatic quarantine, process termination, network blocking, and system remediation |
| 🔒 **Multi-Layer Protection** | Real-time file monitoring, memory scanning, YARA rules, and threat intelligence |
| 🧠 **Behavioral Analysis** | Detects focus abuse, flash attacks, cursor manipulation, and visual exploits |
| 🕵️ **Privacy Shield** | Identity spoofing and fingerprint randomization to defeat tracking |
| 🩹 **Auto-Patching** | Automatic CISA KEV vulnerability detection and mitigation |
| 🌐 **Network Security** | DNS-over-HTTPS/TLS, browser traffic monitoring, firewall blocking |
| 🔐 **Credential Protection** | LSASS protection, credential dump blocking, and security policy hardening |
| 🎯 **MITRE ATT&CK** | Detection and response mapped to MITRE ATT&CK framework |
| 🔍 **Heuristic Analysis** | Akinator engine with intelligent threat scoring and behavioral patterns |
| 🚫 **PUA/PUP Removal** | Auto-kills crypto miners, removes adware, resets browser hijacks |
| ⚡ **Performance Optimized** | CPU throttling, parallel scanning, and intelligent caching |
| 📦 **Easy Deployment** | Can be integrated directly into Windows installation media |

---

## 🧩 Architecture

GSecurity uses a modular architecture where all security features are integrated into a single powerful PowerShell engine:

| Component | Description |
|-----------|-------------|
| 🦠 **Antivirus.ps1** | The main EDR engine with 95+ integrated security modules |
| 🛡️ **GSecurity.bat** | Orchestrator that applies registry hardening and triggers setup |
| 📝 **GSecurity.reg** | Comprehensive registry security tweaks |
| ⚙️ **Antivirus.cmd** | Installer that deploys files and creates scheduled tasks |
| 📋 **Antivirus.xml** | Scheduled task configuration for persistence |

---

## 🚀 Security Modules

GSecurity includes 95+ integrated security modules organized by category:

### 🦠 Threat Detection & Response

| Module | Description | Interval |
|--------|-------------|----------|
| Hash Detection | MalwareBazaar, CIRCL, Cymru threat intelligence | 15s |
| YARA Detection | Advanced pattern matching in process memory | 120s |
| Tiny Threat Scan | Quick scan for suspicious unsigned DLLs | 20s |
| Advanced Threat Detection | Deep analysis of process behavior | 20s |
| File Entropy Detection | Detects packed/encrypted malware | 120s |
| Attack Tools Detection | Identifies known hacking tools | 30s |
| Ransomware Detection | Monitors for encryption behavior | 15s |
| Akinator Heuristic Scan | AI-like threat scoring with behavioral patterns | 120s |
| Threat Response Engine | Automated response to detected threats | 10s |
| Parallel Scan | Multi-threaded file scanning for performance | 300s |

### 🚫 PUA/PUP Detection

| Module | Description | Interval |
|--------|-------------|----------|
| PUA Detection | Potentially Unwanted Applications (RATs, miners) | 180s |
| PUP Detection | Potentially Unwanted Programs (toolbars, adware) | 180s |
| PUM Detection | Potentially Unwanted Modifications (hijacked settings) | 180s |
| Phantom Process Killer | Terminates hidden/orphaned malicious processes | 30s |
| WMI Phone Home Detection | Detects WMI-based telemetry abuse | 30s |

### 🧠 Behavioral Analysis

| Module | Description | Interval |
|--------|-------------|----------|
| Neuro Behavior Monitor | Focus abuse, flash attacks, cursor manipulation | 15s |
| Process Anomaly Detection | Unusual process behavior patterns | 15s |
| Process Hollowing Detection | Detects code injection via hollowing | 30s |
| Suspicious Parent-Child Detection | Abnormal process relationships | 45s |
| LOLBin Detection | Living-off-the-land binary abuse | 15s |
| AMSI Bypass Detection | PowerShell/script evasion attempts | 15s |
| Keylogger Hook Detection | Detects keyboard hook injection | 60s |

### 🔐 Credential & Access Security

| Module | Description | Interval |
|--------|-------------|----------|
| Credential Dump Detection | Mimikatz, LSASS access monitoring | 15s |
| Credential Protection | Protects stored credentials | 300s |
| Password Management | Secure password handling | 120s |
| Token Manipulation Detection | Privilege escalation attempts | 60s |

### 🌐 Network Security

| Module | Description | Interval |
|--------|-------------|----------|
| GFocus | Browser traffic monitor & smart firewall | 2s |
| Secure DNS Monitoring | DoH/DoT configuration enforcement | 300s |
| Network Anomaly Detection | Unusual network patterns | 30s |
| Network Traffic Monitoring | Connection analysis | 45s |
| DNS Exfiltration Detection | Data exfil via DNS queries | 30s |
| Beacon Detection | C2 beacon pattern recognition | 60s |
| C2 Block (GRules) | Command & control blocking | 3600s |
| App Phone Home Blocker | Blocks unwanted telemetry | 5s |

### 🕵️ Privacy Protection

| Module | Description | Interval |
|--------|-------------|----------|
| Privacy Forge Spoofing | Identity & fingerprint rotation | 60s |
| Clipboard Monitoring | Sensitive data protection | 30s |
| Webcam Guardian | Camera access monitoring | 5s |
| Microphone Guardian | Mic access monitoring | 5s |
| Screen Recording Protection | Prevents unauthorized capture | 10s |

### 💾 Persistence & Evasion Detection

| Module | Description | Interval |
|--------|-------------|----------|
| WMI Persistence Detection | WMI subscription abuse | 120s |
| Scheduled Task Detection | Malicious task creation | 120s |
| Registry Persistence Detection | Run key monitoring | 120s |
| Startup Persistence Detection | Autorun locations | 120s |
| COM Monitoring | COM object hijacking | 120s |
| Service Monitoring | Malicious service detection | 60s |

### 🔧 Code Injection Detection

| Module | Description | Interval |
|--------|-------------|----------|
| Code Injection Detection | General injection techniques | 30s |
| DLL Hijacking Detection | DLL search order abuse | 90s |
| Reflective DLL Injection Detection | Memory-only DLL loading | 30s |
| Fileless Detection | Memory-resident malware | 20s |
| Unsigned DLL Remover | Removes suspicious DLLs | 300s |
| ELF DLL Unloader | Foreign binary detection | 10s |

### 🛡️ System Protection

| Module | Description | Interval |
|--------|-------------|----------|
| Rootkit Detection | Hidden process/driver detection | 180s |
| Driver Watcher | Malicious driver monitoring | 60s |
| BCD Security | Boot configuration protection | 300s |
| File Integrity Monitor | Critical file changes | 300s |
| Shadow Copy Monitoring | VSS manipulation detection | 30s |
| Firewall Rule Monitoring | Unauthorized rule changes | 120s |
| ASR Rules | Attack Surface Reduction | 86400s |
| SFC Disinfection Scan | System File Checker integrity restoration | 300s |
| Database Integrity Check | Validates security database integrity (HMAC) | 300s |
| Cache Maintenance | Optimizes detection cache performance | 600s |

### 🩹 Vulnerability Management

| Module | Description | Interval |
|--------|-------------|----------|
| CVE Mitigation Patcher | CISA KEV auto-patching | 3600s |
| Local Proxy Detection | Malicious proxy detection | 60s |
| HID Macro Guard | USB attack prevention | 60s |

### 🎮 Device & Media Protection

| Module | Description | Interval |
|--------|-------------|----------|
| USB Monitoring | Removable media threats | 20s |
| Mobile Device Monitoring | Phone/tablet connections | 15s |
| Audio Output Monitor | Sound device protection | 10s |
| Wallpaper Protection | Desktop tampering | 30s |
| System Sound Protection | Sound scheme changes | 60s |
| Sleep Disruption Protection | Power state manipulation | 60s |

### 📊 Monitoring & Intelligence

| Module | Description | Interval |
|--------|-------------|----------|
| Event Log Monitoring | Security event analysis | 60s |
| Named Pipe Monitoring | IPC attack detection | 45s |
| Browser Extension Monitoring | Malicious extensions | 300s |
| MITRE Mapping | ATT&CK framework correlation | 300s |
| Script Content Scan | Malicious script detection | 120s |
| Script Host Detection | Suspicious script execution | 60s |
| Process Auditing | Comprehensive process logging | 86400s |
| Security Report | Generates comprehensive security reports | 3600s |
| IDS Detection | Intrusion Detection System alerts | 60s |
| Honeypot Monitoring | Decoy file/folder access detection | 30s |

### 🔒 System Hardening (via GSecurity.bat)

- **Service Lockdown** — Disables VNC, TeamViewer, AnyDesk, SSH, FTP, Telnet, WinRM, etc.
- **File Permission Hardening** — Restricts access to critical system files
- **UAC Configuration** — Proper consent prompt behavior
- **DEP Enforcement** — Always-on Data Execution Prevention
- **Account Cleanup** — Removes default/unused accounts

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

# Run the EDR engine directly (all 95+ modules included)
powershell -ExecutionPolicy Bypass -File .\Antivirus.ps1
```

### Method 2: Full Suite Installation (Recommended)

```cmd
# Navigate to the Scripts folder and run as Administrator
cd Iso\sources\$OEM$\$$\Setup\Scripts\Bin
Antivirus.cmd
```

This will:
1. Copy all files to `C:\ProgramData\Antivirus\`
2. Create a scheduled task for persistence
3. Apply file permission hardening
4. Disable dangerous services
5. Enable DEP (Data Execution Prevention)
6. Restart the system

> ⚠️ **Note:** The installer will restart your system after applying changes.

### Method 3: Windows ISO Integration

See [Windows ISO Integration](#-windows-iso-integration) for automated deployment during Windows installation.

---

## 💻 Usage

### 🦠 Antivirus.ps1 — The Main EDR Engine

**Comprehensive Endpoint Detection & Response with 95+ Integrated Modules**

```powershell
# Run the EDR engine (starts all security modules)
powershell -ExecutionPolicy Bypass -File .\Antivirus.ps1

# View main logs
Get-Content "C:\ProgramData\Antivirus\Logs\av.log" -Tail 100

# Check quarantine folder
Get-ChildItem "C:\ProgramData\Antivirus\Quarantine"

# View stability logs
Get-Content "C:\ProgramData\Antivirus\Logs\stability_log.txt"
```

**Key Configuration Options** (in script header):

```powershell
$Config = @{
    # Core Settings
    AutoKillThreats = $true       # Automatically terminate malicious processes
    AutoQuarantine = $true        # Automatically quarantine threats
    MaxMemoryUsageMB = 500        # Memory usage limit
    EnableUnsignedDLLScanner = $true  # Scan for suspicious unsigned DLLs
    
    # Database & Cache
    MaxDatabaseEntries = 50000    # Maximum hash database entries
    DatabaseCleanupDays = 30      # Days before old entries are cleaned
    MaxCacheSize = 10000          # Maximum cache entries
    
    # Performance
    MaxParallelThreads = 8        # Threads for parallel scanning
    EnableCPUThrottling = $true   # Enable CPU usage throttling
    CPUThrottleThreshold = 85     # Throttle when CPU exceeds this %
    
    # PUA/PUP Response
    AutoKillPUA = $false          # Auto-kill potentially unwanted apps
    AutoKillCryptoMiners = $true  # Auto-kill crypto miners
    
    # Heuristic Analysis (Akinator)
    AkinatorEnabled = $true       # Enable heuristic scanning
    AkinatorMaliciousThreshold = 15   # Score threshold for malicious
    AkinatorQuarantineThreshold = 25  # Score threshold for quarantine
    
    # Threat Response
    ThreatResponseEnabled = $true     # Enable automated response
    SuspendOnMediumThreat = $true     # Suspend processes on medium threats
    KillOnHighThreat = $true          # Kill processes on high threats
}
```

**Reactive Threat Response:**

GSecurity implements **active threat mitigation**, not just detection and logging. When threats are detected, the following actions are taken automatically:

| Threat Type | Reactive Actions |
|-------------|------------------|
| **Malicious Files** | Quarantine file, terminate using processes, block hash |
| **Crypto Miners** | Kill process, quarantine executable, log to threat DB |
| **Rogue Security** | Kill process, quarantine, add to response queue |
| **Ransomware** | Kill process, block file operations, alert user |
| **Fileless Malware** | Terminate PowerShell/WMI process, log encoded command |
| **Network Threats** | Block IP via firewall, terminate suspicious connection |
| **LOLBin Abuse** | Kill process, log command line for investigation |
| **Credential Dumping** | Kill process, protect LSASS, block access |
| **PUA/PUP** | Kill process, remove startup entries, reset browser hijacks |
| **WMI Persistence** | Remove malicious WMI filters/consumers/bindings |
| **Scheduled Task Malware** | Disable and remove malicious scheduled tasks |
| **Suspicious Drivers** | Disable driver, add to threat queue |
| **Clipboard Data Theft** | Clear clipboard containing critical sensitive data |

**Module Timing Configuration:**

All 95+ modules run on configurable intervals. Key intervals include:

| Module Category | Default Interval |
|-----------------|------------------|
| Real-time protection (GFocus, Subliminal) | 2-5 seconds |
| Threat detection (Hash, YARA, Ransomware) | 15-30 seconds |
| Behavioral analysis (Process, Network) | 15-60 seconds |
| PUA/PUP detection | 30-180 seconds |
| System monitoring (Services, Firewall) | 60-120 seconds |
| Heuristic analysis (Akinator) | 120 seconds |
| Heavy scans (Rootkit, File Integrity, SFC) | 180-300 seconds |
| Maintenance (Cache, Database, Parallel) | 300-600 seconds |
| Reports & scheduled tasks (CVE, Auditing) | 3600-86400 seconds |

---

### 🛡️ GSecurity.bat — Registry Hardening

**Applies comprehensive registry security tweaks**

```cmd
# Navigate to Scripts folder
cd Iso\sources\$OEM$\$$\Setup\Scripts

# Run registry hardening (requires Admin)
GSecurity.bat
```

This imports all `.reg` files from the `Bin` folder to apply security tweaks.

---

### ⚙️ Antivirus.cmd — Full Installation

**Complete deployment with scheduled task and system hardening**

```cmd
# Run as Administrator
Antivirus.cmd
```

**What it does:**

1. **Deploys Files** — Copies all components to `C:\ProgramData\Antivirus\`
2. **Creates Scheduled Task** — Registers persistent task via `Antivirus.xml`
3. **Hardens File Permissions:**
   - `useroobe.dll` — Reset and restrict inheritance
   - `consent.exe` — Console logon only
   - `winmm.dll` — Console logon only
   - User desktops — Owner-only access
4. **Disables Dangerous Services:**

| Service | Description |
|---------|-------------|
| VNC, TeamViewer, AnyDesk, Radmin, LogMeIn | Remote access |
| OpenSSH, sshd | SSH servers |
| FileZilla Server, vsftpd, ftpsvc | FTP servers |
| TelnetServer | Telnet |
| WinRM | Windows Remote Management |
| RemoteRegistry | Remote registry access |
| SNMP | Network management |
| SsdpSrv, upnphost | UPnP services |
| seclogon | Secondary logon |
| LanmanWorkstation, LanmanServer | SMB services |

5. **Configures UAC** — Sets proper consent behavior
6. **Enables DEP** — `bcdedit /set nx AlwaysOn`
7. **Cleanup** — Removes `defaultuser0` account
8. **Restarts** — Applies changes with system restart

---

### 📊 Log Locations

| Log | Path | Description |
|-----|------|-------------|
| Main Log | `C:\ProgramData\Antivirus\Logs\av.log` | All detections and actions |
| Stability | `C:\ProgramData\Antivirus\Logs\stability_log.txt` | Module health tracking |
| Quarantine | `C:\ProgramData\Antivirus\Quarantine\` | Isolated threats |
| Hash Database | `C:\ProgramData\Antivirus\Data\known_files.db` | Cached file verdicts |
| Whitelist | `C:\ProgramData\Antivirus\Data\whitelist.json` | Allowed files/paths |
| DB Integrity | `C:\ProgramData\Antivirus\Data\db_integrity.hmac` | Database integrity HMAC |
| Reports | `C:\ProgramData\Antivirus\Reports\` | Security reports (hourly) |

---

### 🔧 CVE Mitigations (Built-in)

The CVE Mitigation Patcher module includes protections for:

| CVE | Vulnerability | Mitigation |
|-----|---------------|------------|
| CVE-2017-0144 | EternalBlue (SMBv1) | Disable SMBv1 |
| CVE-2020-0796 | SMBGhost | Disable SMBv3 Compression |
| CVE-2019-0708 | BlueKeep (RDP) | Enable NLA |
| CVE-2021-34527 | PrintNightmare | Disable Print Spooler |
| CVE-2022-30190 | Follina (MSDT) | Block Protocol Handler |
| CVE-2024-38063 | IPv6 RCE | Disable IPv6 |

---

### 🌐 Secure DNS Configuration

The Secure DNS module configures:

| Provider | IPv4 | IPv6 | DoH/DoT |
|----------|------|------|---------|
| Cloudflare (Primary) | 1.1.1.1 | 2606:4700:4700::1111 | ✅ |
| Google (Secondary) | 8.8.8.8 | 2001:4860:4860::8888 | ✅ |

---

## 💿 Windows ISO Integration

GSecurity can be integrated into Windows installation media for fully automated deployment:

### How It Works

The `autounattend.xml` configures:
- Unattended Windows installation (no user prompts)
- Automatic local admin account creation
- First logon command that triggers GSecurity setup
- Regional settings (customizable)

### Step 1: Prepare Windows ISO

```cmd
# Mount or extract Windows ISO to a folder
# Example: C:\WindowsISO
```

### Step 2: Copy GSecurity Files

```cmd
# Copy the entire Iso folder contents
xcopy /E /I "GSecurity\Iso\*" "C:\WindowsISO\"
```

This copies:
- `autounattend.xml` → Root of ISO (triggers unattended install)
- `sources\$OEM$\` → OEM preinstallation folder (runs on first logon)

### Step 3: Customize (Optional)

Edit `autounattend.xml` to change:
- `InputLocale` / `UserLocale` — Regional settings
- `TimeZone` — System timezone
- `ComputerName` — Default PC name
- `Username` — Admin account name

### Step 4: Rebuild ISO

```cmd
# Using oscdimg from Windows ADK
oscdimg -m -o -u2 -udfver102 ^
  -bootdata:2#p0,e,b"C:\WindowsISO\boot\etfsboot.com"#pEF,e,b"C:\WindowsISO\efi\microsoft\boot\efisys.bin" ^
  "C:\WindowsISO" "C:\GSecurity-Windows.iso"
```

### Step 5: Test in VM

1. Create a new VM (Hyper-V, VMware, VirtualBox)
2. Boot from the modified ISO
3. Windows installs automatically
4. On first logon, GSecurity deploys and hardens the system
5. System restarts with full protection active

### Deployment Flow

```
Windows Install → First Logon → GSecurity.bat → Antivirus.cmd → Restart → Protected
```

---

## 📁 File Structure

```
GSecurity/
├── 📄 README.md
└── 📁 Iso/
    ├── 📄 autounattend.xml          # Unattended Windows installation config
    ├── 📄 Autorun.inf               # ISO autorun configuration
    └── 📁 sources/
        └── 📁 $OEM$/
            ├── 📁 $$/Setup/Scripts/
            │   ├── 📄 SetupComplete.cmd    # Post-install trigger
            │   └── 📁 Bin/
            │       ├── 🦠 Antivirus.ps1    # Main EDR engine (95+ modules)
            │       ├── 🛡️ GSecurity.bat    # Registry hardening orchestrator
            │       ├── ⚙️ Antivirus.cmd    # Installer & system hardening
            │       ├── 📝 GSecurity.reg    # Security registry tweaks
            │       └── 📋 Antivirus.xml    # Scheduled task definition
            └── 📁 $1/
                ├── 📄 autoexec.bat
                ├── 📄 config.sys
                └── 📁 users/Default/Desktop/Extras/
                    └── 📁 Bookmarks/
                        └── 📄 bookmarks.html
```

### Installed File Locations

After installation, files are deployed to:

```
C:\ProgramData\Antivirus/
├── 📁 Logs/
│   ├── 📄 av.log                    # Main detection log
│   └── 📄 stability_log.txt         # Module health log
├── 📁 Quarantine/                   # Isolated threats
├── 📁 Data/
│   ├── 📄 known_files.db            # Hash verdict cache (50k max entries)
│   ├── 📄 whitelist.json            # Allowed files/paths
│   └── 📄 db_integrity.hmac         # Database integrity HMAC
├── 📁 Reports/                      # Security reports (hourly, 30-day retention)
├── 🦠 Antivirus.ps1                 # Main EDR engine (95+ modules)
├── ⚙️ Antivirus.cmd                 # Installer script
├── 📋 Antivirus.xml                 # Scheduled task
└── 📝 GSecurity.reg                 # Registry tweaks
```

---

## ⚠️ Security Considerations

### 🔴 Important Warnings

| Warning | Description |
|---------|-------------|
| 🔄 **Restart Required** | Installation requires system restart to apply all changes |
| 🛑 **Service Changes** | Remote access services (VNC, TeamViewer, SSH, etc.) are permanently disabled |
| 📦 **File Quarantine** | EDR may quarantine legitimate files — review logs regularly |
| 🌐 **Network Blocking** | GFocus module may block browser connections |
| 🔐 **Permission Changes** | Critical system files have permissions hardened |
| 🛡️ **SMB Disabled** | LanmanWorkstation/Server disabled (may affect network shares) |
| 🚫 **PUA Detection** | May flag legitimate remote access tools (TeamViewer, AnyDesk, etc.) |
| ⛏️ **Crypto Miner Auto-Kill** | Crypto miners are terminated automatically by default |

### ✅ Best Practices

1. 💾 **Backup First** — Create a system restore point before installation
2. 🖥️ **Test in VM** — Test GSecurity in a virtual machine first
3. 📋 **Review Logs** — Regularly check `C:\ProgramData\Antivirus\Logs\`
4. 📝 **Whitelist Legitimate Files** — Add false positives to `whitelist.json`
5. ⚡ **Monitor Performance** — Watch for performance impacts
6. 🔄 **Update Threat Intel** — Hash database updates automatically via API calls

### 🔒 Privacy

| Aspect | Details |
|--------|---------|
| **Hash Lookups** | SHA256 hashes sent to MalwareBazaar, CIRCL, Cymru for threat intel |
| **No PII Transmission** | Only file hashes are sent, never file contents or personal data |
| **Local Processing** | All behavioral analysis, monitoring, and blocking happens locally |
| **Privacy Spoofing** | PrivacyForge module generates fake identities to protect real data |
| **DNS Encryption** | All DNS queries encrypted via DoH/DoT |
| **Intelligent Caching** | Hash verdicts cached locally to minimize external API calls |
| **Rate Limiting** | API calls throttled (100ms delay) to prevent fingerprinting |

---

## 📊 Performance Impact

Since all modules are integrated into a single engine, resources are shared efficiently:

| Metric | Idle | Active Scan | Peak |
|--------|------|-------------|------|
| **CPU** | < 2% | 5-10% | < 15%* |
| **RAM** | ~100 MB | ~200 MB | < 500 MB** |
| **Disk I/O** | Minimal | Medium | Medium |

*\*CPU throttling automatically activates above 85% (configurable)*
*\*\*Configurable via `MaxMemoryUsageMB` setting*

**Performance Optimizations:**

- **CPU Throttling** — Automatically pauses scans when CPU exceeds threshold
- **Parallel Scanning** — Multi-threaded file scanning (up to 8 threads)
- **Intelligent Caching** — LRU cache with 10,000 entries to avoid redundant API calls
- **Rate-Limited APIs** — 100ms delay between threat intel API calls
- **Cache Maintenance** — Automatic cleanup of stale cache entries

**Module Scheduling:**

- High-frequency modules (2-5s): GFocus, device guardians, subliminal detection
- Medium-frequency (15-60s): Threat detection, behavioral analysis, PUA/PUP
- Low-frequency (120-300s): Deep scans, integrity checks, heuristics
- Maintenance (300-600s): Cache cleanup, database integrity, parallel scans
- Scheduled (3600s+): CVE patching, reports, auditing

The staggered intervals ensure consistent performance without CPU spikes.

---

## 🛠️ Troubleshooting

### EDR Not Starting

```powershell
# Check if scheduled task exists
Get-ScheduledTask | Where-Object { $_.TaskName -like "*Antivirus*" }

# View task status
Get-ScheduledTask -TaskName "Antivirus" | Get-ScheduledTaskInfo

# View task history
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | 
    Where-Object { $_.Message -like "*Antivirus*" } | 
    Select-Object -First 10

# Manually start the task
Start-ScheduledTask -TaskName "Antivirus"
```

### Checking Logs

```powershell
# View recent detections
Get-Content "C:\ProgramData\Antivirus\Logs\av.log" -Tail 100

# View module stability
Get-Content "C:\ProgramData\Antivirus\Logs\stability_log.txt" -Tail 50

# Check quarantine
Get-ChildItem "C:\ProgramData\Antivirus\Quarantine" -Recurse

# View hash database stats
(Get-Content "C:\ProgramData\Antivirus\Data\known_files.db").Count
```

### False Positives

```powershell
# Add file to whitelist
$whitelist = Get-Content "C:\ProgramData\Antivirus\Data\whitelist.json" | ConvertFrom-Json
$whitelist += @{ Path = "C:\Path\To\File.exe"; Reason = "False positive" }
$whitelist | ConvertTo-Json | Set-Content "C:\ProgramData\Antivirus\Data\whitelist.json"
```

### Network Issues (GFocus Module)

```powershell
# Remove firewall rules created by GFocus
Get-NetFirewallRule -DisplayName "*GFocus*" | Remove-NetFirewallRule

# Or disable the GFocus module by editing interval to very high value
# In Antivirus.ps1: GFocusIntervalSeconds = 999999
```

### DNS Configuration Issues

```cmd
# Reset DNS to DHCP
netsh interface ipv4 set dnsservers name="Ethernet" dhcp
netsh interface ipv6 set dnsservers name="Ethernet" dhcp

# Flush DNS cache
ipconfig /flushdns

# Verify configuration
ipconfig /all | findstr "DNS"
```

### PUA/PUP False Positives

```powershell
# Disable auto-kill for PUA (keeps detection but won't terminate)
# Edit Antivirus.ps1 and set:
# AutoKillPUA = $false

# Whitelist a specific application
$whitelist = Get-Content "C:\ProgramData\Antivirus\Data\whitelist.json" | ConvertFrom-Json
$whitelist.Processes += @{ Name = "myapp.exe"; Reason = "Legitimate tool" }
$whitelist | ConvertTo-Json -Depth 3 | Set-Content "C:\ProgramData\Antivirus\Data\whitelist.json"
```

### Performance Issues (CPU Throttling)

```powershell
# Adjust CPU throttling threshold (default 85%)
# Edit Antivirus.ps1 and modify:
# CPUThrottleThreshold = 90    # Higher = less throttling
# CPUThrottleDelayMs = 1000    # Lower = shorter pauses

# Disable CPU throttling entirely (not recommended)
# EnableCPUThrottling = $false
```

### Heuristic Analysis (Akinator) Tuning

```powershell
# Adjust sensitivity thresholds
# Edit Antivirus.ps1:
# AkinatorMaliciousThreshold = 20   # Higher = fewer detections
# AkinatorQuarantineThreshold = 30  # Higher = fewer auto-quarantines

# Disable heuristic scanning entirely
# AkinatorEnabled = $false
```

### Uninstalling GSecurity

```powershell
# Remove scheduled task
Unregister-ScheduledTask -TaskName "Antivirus" -Confirm:$false

# Stop any running instances
Get-Process -Name "powershell" | Where-Object { 
    $_.CommandLine -like "*Antivirus.ps1*" 
} | Stop-Process -Force

# Remove installation folder
Remove-Item -Path "C:\ProgramData\Antivirus" -Recurse -Force

# Remove firewall rules
Get-NetFirewallRule -DisplayName "*GFocus*" | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName "*GSecurity*" | Remove-NetFirewallRule
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

- 🦠 [MalwareBazaar](https://bazaar.abuse.ch/) — Malware sample threat intelligence
- 🔍 [CIRCL](https://www.circl.lu/) — Hash lookup services
- 🔎 [Team Cymru](https://www.team-cymru.com/) — Malware hash reputation
- 🇺🇸 [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known exploited vulnerabilities catalog
- 🌐 [Cloudflare](https://cloudflare.com/) & [Google](https://google.com/) — Secure DNS services
- 🎯 [YARA](https://virustotal.github.io/yara/) — Pattern matching engine
- 🛡️ [MITRE ATT&CK](https://attack.mitre.org/) — Threat framework mapping
- ❤️ All contributors and users of this project

---

<p align="center">
  <strong>Made with ❤️ for a more secure Windows</strong>
</p>

<p align="center">
  <sub>⚠️ USE AT YOUR OWN RISK — Always test in a virtual machine first</sub>
</p>
