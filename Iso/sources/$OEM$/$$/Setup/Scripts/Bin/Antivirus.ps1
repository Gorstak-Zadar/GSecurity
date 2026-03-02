# Antivirus.ps1
# Author: Gorstak

# ========================= CONFIGURATION =========================
$Config = @{
    # Paths
    BaseDirectory           = "C:\ProgramData\Antivirus"
    QuarantineDirectory     = "C:\ProgramData\Antivirus\Quarantine"
    BackupDirectory         = "C:\ProgramData\Antivirus\Backup"
    LogFile                 = "C:\ProgramData\Antivirus\av.log"
    BlockedLogFile          = "C:\ProgramData\Antivirus\blocked.log"
    DatabaseFile            = "C:\ProgramData\Antivirus\known_files.db"
    
    # Memory & Performance Settings (OPTIMIZED TO REDUCE RAM)
    MaxDatabaseEntries      = 50000          # Limit cache size
    MaxLogSizeMB            = 10             # Rotate logs at 10MB
    MemoryScanIntervalSec   = 8              # Scan memory every 8s (was 15s)
    MemoryScanMaxSizeMB     = 150            # Only scan processes UNDER 150MB (small = suspicious)
    ProcessTimeoutSeconds   = 30             # Kill stuck operations
    DatabaseCleanupDays     = 30             # Remove entries older than 30 days
    
    # Feature Flags
    EnableMemoryScanning    = $true
    EnableRealtimeMonitor   = $true
    EnableThreatIntel       = $true
    EnableAlerts            = $true
    AutoQuarantine          = $true
    
    # API Configuration
    MalwareBazaarApiKey     = ""             # Optional API key
    CirclHashLookupUrl      = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl             = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl     = "https://mb-api.abuse.ch/api/v1/"
    
    # Threat Detection Thresholds
    CymruDetectionThreshold = 60             # Require 60% AV detection
    SuspiciousFileSizeKB    = 3072           # 3MB max for suspicious DLLs
}

# Behavior monitoring settings
$BehaviorConfig = @{
    EnableBehaviorKill      = $true
    EnableAutoBlockC2       = $true
    DeepScanIntervalHours   = 6
    ThreatIntelUpdateDays   = 7
}

# KeyScrambler anti-keylogger settings
$KeyScramblerConfig = @{
    EnableKeyScrambler      = $false          # Disabled by default - can interfere with typing
    FloodChance             = 0.5             # Probability of injecting fake keystrokes
    BeforeKeyChance         = 0.75            # Probability of injecting before real key
    AfterKeyChance          = 0.75            # Probability of injecting after real key
    MinFakeChars            = 1               # Minimum fake characters per injection
    MaxFakeChars            = 6               # Maximum fake characters per injection
}

# ========================= INITIALIZATION =========================
$RulesDirectory = Join-Path $Config.BaseDirectory "rules"
$KnownFilesCache = @{}

# Check admin privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Allowed system accounts
$AllowedSIDs = @(
    'S-1-2-0',   # Console user
    'S-1-5-20'   # Network Service
)

# High-risk paths where unsigned DLLs are suspicious
$RiskyPaths = @(
    '\temp\', '\downloads\', '\appdata\local\temp\', '\public\', '\windows\temp\',
    '\appdata\roaming\', '\desktop\'
)

# Comprehensive monitored file extensions (200+ extensions)
$MonitoredExtensions = @(
    # Executables and core system files
    '.exe', '.dll', '.sys', '.ocx', '.scr', '.com', '.cpl', '.msi', '.drv', '.winmd',
    
    # Scripts
    '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.jse', '.wsf', '.wsh', '.psc1',
    
    # Archives and compressed files
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.bzip', '.bzip2', '.xz', '.tgz',
    '.tbz', '.taz', '.tpz', '.z', '.lzh', '.lha', '.arc', '.arj', '.cab', '.iso', '.img',
    
    # Office documents
    '.doc', '.docx', '.docm', '.docb', '.dot', '.dotx', '.dotm', '.xls', '.xlsx', '.xlsm',
    '.xlsb', '.xlt', '.xltx', '.xltm', '.xlam', '.xla', '.xlm', '.xll', '.xlw', '.ppt',
    '.pptx', '.pptm', '.pps', '.ppsx', '.ppsm', '.pot', '.potx', '.potm', '.ppa', '.ppam',
    '.rtf', '.odt', '.ods',
    
    # Database files
    '.mdb', '.accdb', '.accde', '.accda', '.accdr', '.accdt', '.accdu', '.mde', '.mda',
    '.mdn', '.mdt', '.mdw', '.mdf', '.ldb', '.laccdb',
    
    # Web and markup
    '.htm', '.html', '.mht', '.mhtml', '.xml', '.xsl', '.xps', '.svg',
    
    # Development and programming
    '.c', '.h', '.cpp', '.py', '.py3', '.pyc', '.pyo', '.pyw', '.pyx', '.pyz', '.pyzw',
    '.rb', '.pl', '.perl', '.java', '.class', '.jar', '.war',
    
    # Configuration and registry
    '.reg', '.inf', '.ini', '.cfg', '.config', '.manifest', '.setting', '.pol',
    
    # Shortcuts and links
    '.lnk', '.url', '.website', '.webloc', '.desktop', '.desklink',
    
    # Windows specific
    '.gadget', '.appref-ms', '.application', '.vbp', '.vb', '.bas', '.prg', '.pif',
    '.scf', '.sct', '.shb', '.shs', '.vxd', '.hlp', '.chm', '.hta',
    
    # Installers and packages
    '.msp', '.mst', '.msu', '.pkg', '.deb', '.rpm',
    
    # Media that can contain scripts
    '.swf',
    
    # Virtual disks
    '.vhd', '.vhdx', '.vmdk', '.vdi',
    
    # Mac specific
    '.dmg', '.app', '.command', '.terminal', '.tool',
    
    # Linux executables
    '.elf', '.bin', '.run', '.sh', '.ksh', '.csh',
    
    # Mobile apps
    '.apk', '.ipa', '.xap',
    
    # Browser extensions
    '.crx', '.xpi',
    
    # Certificate and encryption
    '.cer', '.crt', '.der', '.pfx', '.p12', '.pem',
    
    # Email
    '.eml', '.msg', '.pst', '.ost',
    
    # Other potentially dangerous
    '.ace', '.air', '.ax', '.cnv', '.cpl', '.diagcab', '.drv', '.fon', '.grp',
    '.hlp', '.hpj', '.inf', '.ins', '.isp', '.its', '.job', '.jse', '.lib', '.library-ms',
    '.local', '.mad', '.maf', '.mag', '.mam', '.manifest', '.map', '.mapimail', '.mas',
    '.mat', '.mau', '.mav', '.maw', '.may', '.mcf', '.mcl', '.mhtml', '.mmc', '.mof',
    '.msc', '.msh', '.msh1', '.msh2', '.msh1xml', '.msh2xml', '.mshxml', '.msp', '.mui',
    '.mydocs', '.nls', '.nsh', '.ntfs', '.ocx', '.ops', '.osd', '.pa', '.pcd', '.pif',
    '.plg', '.prf', '.printerexport', '.prn', '.ps1xml', '.ps2', '.ps2xml', '.psc1',
    '.psc2', '.psd1', '.psm1', '.pst', '.pstreg', '.reg', '.rgs', '.scr', '.sct',
    '.search-ms', '.searchconnector-ms', '.settingcontent-ms', '.shb', '.shs', '.slk',
    '.sldm', '.sldx', '.spl', '.stm', '.sys', '.theme', '.themepack', '.tmp', '.tsp',
    '.url', '.vbe', '.vbs', '.vsmacros', '.vss', '.vst', '.vsw', '.was', '.wbk', '.webpnp',
    '.website', '.wiz', '.wll', '.wpk', '.ws', '.wsc', '.wsf', '.wsh', '.xbap', '.xip',
    '.xla', '.xlam', '.xld', '.xldm', '.xll', '.xlm', '.xnk', '.xrm-ms', '.zoo'
)

# Protected processes that should never be killed
$ProtectedProcesses = @(
    'System', 'Idle', 'Registry', 'smss', 'csrss', 'wininit', 'services', 'lsass',
    'svchost', 'winlogon', 'explorer', 'dwm', 'SearchUI', 'SearchIndexer', 'fontdrvhost',
    'RuntimeBroker', 'sihost', 'taskhostw'
)

# Evil strings for in-memory detection
$EvilStrings = @(
    'mimikatz', 'sekurlsa::', 'kerberos::', 'lsadump::', 'wdigest', 'tspkg',
    'http-beacon', 'https-beacon', 'cobaltstrike', 'sleepmask', 'reflective',
    'amsi.dll', 'AmsiScanBuffer', 'EtwEventWrite', 'MiniDumpWriteDump',
    'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'ReflectiveLoader', 'sharpchrome', 'rubeus', 'safetykatz', 'sharphound',
    'invoke-mimikatz', 'invoke-bloodhound', 'powersploit', 'empire'
)

# ========================= CREATE DIRECTORIES =========================
New-Item -ItemType Directory -Path $Config.BaseDirectory, $Config.QuarantineDirectory, $Config.BackupDirectory, $RulesDirectory -Force -ErrorAction SilentlyContinue | Out-Null

# ========================= LOGGING FUNCTIONS =========================
function Write-Log {
    param([string]$Message)
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "$timestamp | $Message"
    
    try {
        $logLine | Out-File -FilePath $Config.LogFile -Append -Encoding UTF8
    } catch {
        Write-Host "[LOG ERROR] $_"
    }
    
    Write-Host $logLine
    
    # Log rotation
    if (Test-Path $Config.LogFile) {
        $logSize = (Get-Item $Config.LogFile -ErrorAction SilentlyContinue).Length
        if ($logSize -ge ($Config.MaxLogSizeMB * 1MB)) {
            $archiveName = "$($Config.BaseDirectory)\av_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            try {
                Rename-Item -Path $Config.LogFile -NewName $archiveName -ErrorAction SilentlyContinue
                Write-Host "Log rotated to: $archiveName"
            } catch {}
        }
    }
}

Write-Log "=== Clean Antivirus Starting ==="
Write-Log "Admin: $IsAdmin | User: $env:USERNAME | SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# ========================= DATABASE MANAGEMENT =========================
function Load-Database {
    if (Test-Path $Config.DatabaseFile) {
        try {
            $lines = Get-Content $Config.DatabaseFile -ErrorAction Stop
            $count = 0
            
            foreach ($line in $lines) {
                if ($line -match '^([0-9a-f]{64}),(true|false),(.+)$') {
                    $hash = $matches[1]
                    $safe = [bool]::Parse($matches[2])
                    $timestamp = $matches[3]
                    
                    # Skip entries older than cleanup threshold
                    try {
                        $entryDate = [datetime]::Parse($timestamp)
                        if ($entryDate -lt (Get-Date).AddDays(-$Config.DatabaseCleanupDays)) {
                            continue
                        }
                    } catch {}
                    
                    $KnownFilesCache[$hash] = $safe
                    $count++
                    
                    # Enforce max database size
                    if ($count -ge $Config.MaxDatabaseEntries) {
                        break
                    }
                }
            }
            
            Write-Log "Loaded $count entries from database (cleaned old entries)"
        } catch {
            Write-Log "Failed to load database: $_"
            $KnownFilesCache.Clear()
        }
    } else {
        New-Item -Path $Config.DatabaseFile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Created new database file"
    }
}

function Save-ToDatabase {
    param(
        [string]$Hash,
        [bool]$IsSafe
    )
    
    if (-not $Hash) { return }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$Hash,$IsSafe,$timestamp"
    
    try {
        $entry | Out-File -FilePath $Config.DatabaseFile -Append -Encoding UTF8
        $KnownFilesCache[$Hash] = $IsSafe
    } catch {
        Write-Log "Failed to save to database: $_"
    }
    
    # Trigger garbage collection if cache is too large
    if ($KnownFilesCache.Count -gt $Config.MaxDatabaseEntries) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

Load-Database

# ========================= FILE EXCLUSIONS =========================
function Test-ShouldExclude {
    param([string]$FilePath)
    
    $lower = $FilePath.ToLower()
    
    # Exclude system assemblies and framework files
    if ($lower -like '*\assembly\*') { return $true }
    if ($lower -like '*\winsxs\*') { return $true }
    if ($lower -like '*\microsoft.net\*') { return $true }
    
    # Exclude Windows system config
    if ($lower -like '*\windows\system32\config\*') { return $true }
    
    # Exclude IME files
    if ($lower -like '*ctfmon*' -or $lower -like '*msctf.dll' -or $lower -like '*msutb.dll') {
        return $true
    }
    
    return $false
}

# ========================= HASH CALCULATION =========================
function Get-FileHashSafe {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return $null }
    
    try {
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        return $hash.ToLower()
    } catch {
        return $null
    }
}

function Get-FileSignatureInfo {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return $null }
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $hash = Get-FileHashSafe -FilePath $FilePath
        
        return [PSCustomObject]@{
            Hash          = $hash
            Status        = $signature.Status
            StatusMessage = $signature.StatusMessage
            SignerName    = $signature.SignerCertificate.Subject
        }
    } catch {
        return $null
    }
}

# ========================= HASH LOOKUP SERVICES =========================
function Test-CirclHashLookup {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $url = "$($Config.CirclHashLookupUrl)/$SHA256"
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 8 -ErrorAction Stop
        
        if ($response) {
            Write-Log "CIRCL known-good match: $SHA256"
            return $true
        }
    } catch {
        # Not found or error - return false
    }
    
    return $false
}

function Test-CymruMalwareHash {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $url = "$($Config.CymruApiUrl)/$SHA256"
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 8 -ErrorAction Stop
        
        if ($response.detections -ge $Config.CymruDetectionThreshold) {
            Write-Log "CYMRU malware match: $SHA256 (detections: $($response.detections))"
            return $true
        }
    } catch {
        # Not found or error
    }
    
    return $false
}

function Test-MalwareBazaarHash {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $body = @{
            query = 'get_info'
            hash = $SHA256
        }
        
        if ($Config.MalwareBazaarApiKey) {
            $body.api_key = $Config.MalwareBazaarApiKey
        }
        
        $response = Invoke-RestMethod -Uri $Config.MalwareBazaarApiUrl -Method Post -Body $body -TimeoutSec 10 -ErrorAction Stop
        
        if ($response.query_status -eq 'ok' -or ($response.data -and $response.data.Count -gt 0)) {
            Write-Log "MalwareBazaar match: $SHA256"
            return $true
        }
    } catch {
        # Not found or error
    }
    
    return $false
}

# ========================= SUSPICIOUS FILE DETECTION =========================
function Test-SuspiciousUnsignedDll {
    param([string]$FilePath)
    
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($extension -notin @('.dll', '.winmd')) {
        return $false
    }
    
    # Check if signed
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($signature.Status -eq 'Valid') {
            return $false
        }
    } catch {
        # Assume unsigned if error
    }
    
    # Check file size and location
    $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
    if (-not $fileInfo) { return $false }
    
    $fileSizeKB = $fileInfo.Length / 1KB
    $pathLower = $FilePath.ToLower()
    $fileName = $fileInfo.Name.ToLower()
    
    # Check if in risky path and small size
    foreach ($riskyPath in $RiskyPaths) {
        if ($pathLower -like "*$riskyPath*" -and $fileSizeKB -lt $Config.SuspiciousFileSizeKB) {
            return $true
        }
    }
    
    # Check for suspicious AppData roaming DLL
    if ($pathLower -like '*\appdata\roaming\*' -and $fileSizeKB -lt 800 -and $fileName -match '^[a-z0-9]{4,12}\.(dll|winmd)$') {
        return $true
    }
    
    return $false
}

# ========================= FILE LOCKING UTILITIES =========================
function Test-FileLocked {
    param([string]$FilePath)
    
    try {
        $stream = [IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

function Stop-ProcessesUsingFile {
    param([string]$FilePath)
    
    $fileName = [IO.Path]::GetFileName($FilePath)
    
    try {
        Get-Process | Where-Object {
            try {
                $_.Modules.FileName -contains $FilePath
            } catch {
                $false
            }
        } | ForEach-Object {
            if ($ProtectedProcesses -notcontains $_.Name) {
                Write-Log "Stopping process $($_.Name) (PID: $($_.Id)) using file: $FilePath"
                try {
                    $_.CloseMainWindow() | Out-Null
                    Start-Sleep -Milliseconds 500
                    
                    if (-not $_.HasExited) {
                        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }
        }
    } catch {
        # Try taskkill as fallback
        try {
            taskkill /F /FI "MODULES eq $fileName" 2>&1 | Out-Null
        } catch {}
    }
}

function Set-FileOwnership {
    param([string]$FilePath)
    
    try {
        takeown /F $FilePath /A 2>&1 | Out-Null
        icacls $FilePath /reset 2>&1 | Out-Null
        icacls $FilePath /grant "Administrators:F" /inheritance:d 2>&1 | Out-Null
        Write-Log "Set ownership and permissions for: $FilePath"
        return $true
    } catch {
        Write-Log "Failed to set ownership: $_"
        return $false
    }
}

# ========================= QUARANTINE FUNCTIONS =========================
function Move-ToQuarantine {
    param(
        [string]$FilePath,
        [string]$Reason
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Log "Cannot quarantine - file not found: $FilePath"
        return
    }
    
    # Release file if locked
    if (Test-FileLocked -FilePath $FilePath) {
        Stop-ProcessesUsingFile -FilePath $FilePath
        Start-Sleep -Milliseconds 500
    }
    
    $fileName = [IO.Path]::GetFileName($FilePath)
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupPath = Join-Path $Config.BackupDirectory "${fileName}_${timestamp}.bak"
    $quarantinePath = Join-Path $Config.QuarantineDirectory "${fileName}_${timestamp}"
    
    try {
        # Create backup
        Copy-Item -Path $FilePath -Destination $backupPath -Force -ErrorAction Stop
        
        # Move to quarantine
        Move-Item -Path $FilePath -Destination $quarantinePath -Force -ErrorAction Stop
        
        Write-Log "QUARANTINED [$Reason]: $FilePath -> $quarantinePath"
        Send-ThreatAlert -Severity "HIGH" -Message "File quarantined: $Reason" -Details $FilePath
    } catch {
        Write-Log "Quarantine failed for $FilePath : $_"
        
        # Try with ownership change
        if (Set-FileOwnership -FilePath $FilePath) {
            try {
                Copy-Item -Path $FilePath -Destination $backupPath -Force -ErrorAction Stop
                Move-Item -Path $FilePath -Destination $quarantinePath -Force -ErrorAction Stop
                Write-Log "QUARANTINED (after ownership fix) [$Reason]: $FilePath"
            } catch {
                Write-Log "Quarantine still failed after ownership fix: $_"
            }
        }
    }
}

function Block-FileExecution {
    param(
        [string]$FilePath,
        [int]$ProcessId,
        [string]$Type
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $blockEntry = "$timestamp | BLOCKED $Type | $FilePath | PID $ProcessId"
    
    try {
        $blockEntry | Out-File -FilePath $Config.BlockedLogFile -Append -Encoding UTF8
    } catch {}
    
    Write-Log "BLOCKED $Type | $FilePath | PID $ProcessId"
    
    # Kill the process
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process -and ($ProtectedProcesses -notcontains $process.ProcessName)) {
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
            Write-Log "Killed process PID $ProcessId"
        }
    } catch {}
    
    # Quarantine the file
    if (Test-Path $FilePath) {
        Move-ToQuarantine -FilePath $FilePath -Reason "Real-time $Type block"
    }
}

# ========================= THREAT PROCESS TERMINATION =========================
function Stop-ThreatProcess {
    param(
        [int]$ProcessId,
        [string]$ProcessName
    )
    
    if ($ProtectedProcesses -contains $ProcessName) {
        Write-Log "Cannot terminate protected process: $ProcessName (PID: $ProcessId)"
        return $false
    }
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process) {
            Stop-Process -Id $ProcessId -Force -ErrorAction Stop
            Write-Log "Terminated threat process: $ProcessName (PID: $ProcessId)"
            return $true
        }
    } catch {
        Write-Log "Failed to terminate process $ProcessName (PID: $ProcessId): $_"
    }
    
    return $false
}

# ========================= CACHED PROCESS LIST =========================
function Get-CachedProcessList {
    try {
        return Get-Process -ErrorAction SilentlyContinue
    } catch {
        return @()
    }
}

# ========================= ALERTING SYSTEM =========================
$global:EmailConfig = $null
$global:WebhookUrl = $null

function Send-ThreatAlert {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$Details
    )
    
    if (-not $Config.EnableAlerts) { return }
    
    $severityUpper = $Severity.ToUpper()
    
    # Determine event log entry type
    $entryType = switch ($severityUpper) {
        "CRITICAL" { [System.Diagnostics.EventLogEntryType]::Error }
        "HIGH"     { [System.Diagnostics.EventLogEntryType]::Warning }
        "MEDIUM"   { [System.Diagnostics.EventLogEntryType]::Warning }
        default    { [System.Diagnostics.EventLogEntryType]::Information }
    }
    
    # Write to Windows Event Log
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("Antivirus")) {
            New-EventLog -LogName Application -Source "Antivirus" -ErrorAction SilentlyContinue
        }
        
        Write-EventLog -LogName Application -Source "Antivirus" `
            -EventId 1001 -Message "$Message - $Details" `
            -EntryType $entryType -ErrorAction SilentlyContinue
    } catch {}
    
    # Send email if configured
    if ($global:EmailConfig) {
        try {
            Send-MailMessage @global:EmailConfig `
                -Subject "[$severityUpper] Antivirus Alert" `
                -Body "$Message`n`nDetails: $Details" `
                -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Email alert failed: $_"
        }
    }
    
    # Send webhook if configured
    if ($global:WebhookUrl) {
        try {
            $payload = @{
                severity  = $severityUpper
                message   = $Message
                details   = $Details
                timestamp = Get-Date -Format 'o'
                hostname  = $env:COMPUTERNAME
            } | ConvertTo-Json
            
            Invoke-WebRequest -Uri $global:WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Log "Webhook alert failed: $_"
        }
    }
}

# ========================= THREAT INTELLIGENCE UPDATES =========================
function Update-ThreatIntelligence {
    if (-not $Config.EnableThreatIntel) { return }
    
    Write-Log "Updating threat intelligence feeds..."
    
    $yaraRules = @(
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_campaign_uac.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_malware_set.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/Malware.yar"
    )
    
    $hashLists = @(
        "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latest-hashes.txt"
    )
    
    foreach ($url in $yaraRules) {
        $fileName = Split-Path $url -Leaf
        $outputPath = Join-Path $RulesDirectory $fileName
        
        try {
            Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            Write-Log "Downloaded YARA rule: $fileName"
        } catch {
            Write-Log "Failed to download YARA rule $fileName : $_"
        }
    }
    
    foreach ($url in $hashLists) {
        $fileName = Split-Path $url -Leaf
        $outputPath = Join-Path $Config.BaseDirectory $fileName
        
        try {
            Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            Write-Log "Downloaded hash list: $fileName"
        } catch {
            Write-Log "Failed to download hash list $fileName : $_"
        }
    }
}

# ========================= MAIN THREAT ANALYSIS ENGINE =========================
function Invoke-ThreatAnalysis {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath -PathType Leaf)) { return }
    if (Test-ShouldExclude -FilePath $FilePath) { return }
    
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($extension -notin $MonitoredExtensions) { return }
    
    # Calculate hash
    $fileHash = Get-FileHashSafe -FilePath $FilePath
    if (-not $fileHash) { return }
    
    # Check cache
    if ($KnownFilesCache.ContainsKey($fileHash)) {
        if (-not $KnownFilesCache[$fileHash]) {
            # Known bad file
            Move-ToQuarantine -FilePath $FilePath -Reason "Previously identified threat"
        }
        return
    }
    
    # Check CIRCL for known-good
    if (Test-CirclHashLookup -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $true
        Write-Log "ALLOWED (CIRCL known-good): $FilePath"
        return
    }
    
    # Check Cymru for known-bad
    if (Test-CymruMalwareHash -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "Cymru MHR malware match (>=$($Config.CymruDetectionThreshold)% detection)"
        return
    }
    
    # Check MalwareBazaar
    if (Test-MalwareBazaarHash -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "MalwareBazaar malware match"
        return
    }
    
    # Check for suspicious unsigned DLL
    if (Test-SuspiciousUnsignedDll -FilePath $FilePath) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "Suspicious unsigned DLL/WINMD in risky location"
        return
    }
    
    # Check digital signature
    $signatureInfo = Get-FileSignatureInfo -FilePath $FilePath
    if ($signatureInfo) {
        $isSafe = ($signatureInfo.Status -eq 'Valid')
        Save-ToDatabase -Hash $fileHash -IsSafe $isSafe
        
        if ($isSafe) {
            Write-Log "ALLOWED (digitally signed): $FilePath"
        } else {
            Write-Log "ALLOWED (unsigned but no threat indicators): $FilePath"
        }
    }
}

# ========================= MEMORY SCANNING =========================
function Start-MemoryScanner {
    if (-not $Config.EnableMemoryScanning) {
        Write-Log "Memory scanning is disabled in configuration"
        return
    }
    
    Write-Log "Starting optimized memory scanner (interval: $($Config.MemoryScanIntervalSec)s, max size: $($Config.MemoryScanMaxSizeMB)MB)"
    
    Start-Job -ScriptBlock {
        $config = $using:Config
        $protected = $using:ProtectedProcesses
        $evilStrings = $using:EvilStrings
        $logFile = Join-Path $config.BaseDirectory "memory_hits.log"
        
        while ($true) {
            Start-Sleep -Seconds $config.MemoryScanIntervalSec
            
            # Only scan small processes (potential malware)
            $maxBytes = $config.MemoryScanMaxSizeMB * 1MB
            
            Get-Process | Where-Object {
                $_.WorkingSet64 -lt $maxBytes -and $protected -notcontains $_.Name
            } | ForEach-Object {
                $process = $_
                $suspicious = $false
                $reasons = @()
                
                # Check for reflective loading / process hollowing
                try {
                    if (-not $process.Path -or $process.Path -eq '') {
                        $suspicious = $true
                        $reasons += "NoPath"
                    }
                } catch {}
                
                # Check for empty modules
                try {
                    $emptyModules = $process.Modules | Where-Object {
                        $_.FileName -eq '' -or $_.ModuleName -eq ''
                    }
                    
                    if ($emptyModules) {
                        $suspicious = $true
                        $reasons += "EmptyModule"
                    }
                } catch {}
                
                # Check for evil strings in module names
                try {
                    foreach ($module in $process.Modules) {
                        foreach ($evilString in $evilStrings) {
                            if ($module.ModuleName -match $evilString -or ($module.FileName -and $module.FileName -match $evilString)) {
                                $suspicious = $true
                                $reasons += "EvilString($evilString)"
                                break
                            }
                        }
                        if ($suspicious) { break }
                    }
                } catch {}
                
                # If suspicious, log and kill
                if ($suspicious) {
                    $reasonString = $reasons -join '; '
                    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | MEMORY HIT [$reasonString] -> $($process.Name) (PID: $($process.Id)) Path: '$($process.Path)' WS: $([math]::Round($process.WorkingSet64/1MB, 2))MB"
                    
                    try {
                        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                    } catch {}
                    
                    # Kill the suspicious process
                    try {
                        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
            }
            
            # Periodic garbage collection to manage memory
            if ((Get-Random -Minimum 1 -Maximum 10) -eq 1) {
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
            }
        }
    } | Out-Null
}

# ========================= YARA MEMORY SCANNER =========================
function Start-YaraMemoryScanner {
    param(
        [string]$BaseDir = $Config.BaseDirectory
    )

    $yaraExe     = Join-Path $BaseDir "yara64.exe"
    $yaraRuleMem = Join-Path $BaseDir "mem.yar"

    Write-Log "Initializing YARA components..."

    if (-not (Test-Path $yaraExe)) {
        Write-Log "yara64.exe not found - attempting download"

        try {
            $releaseUrl = "https://api.github.com/repos/VirusTotal/yara/releases/latest"
            $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{"Accept"="application/vnd.github.v3+json"} -TimeoutSec 12

            $asset = $release.assets | Where-Object { $_.name -match 'yara.*win64\.zip' } | Select-Object -First 1

            if ($asset) {
                $zipUrl = $asset.browser_download_url
                $tempZip = Join-Path $BaseDir "yara-latest-win64.zip"

                Write-Log "Downloading YARA from: $zipUrl"
                Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip -TimeoutSec 30 -UseBasicParsing

                Expand-Archive -Path $tempZip -DestinationPath $BaseDir -Force

                Get-ChildItem $BaseDir -Filter "*yara*64.exe" | ForEach-Object {
                    if ($_.Name -ne "yara64.exe") {
                        Rename-Item $_.FullName (Join-Path $BaseDir "yara64.exe") -Force -ErrorAction SilentlyContinue
                    }
                }

                Remove-Item $tempZip -Force -ErrorAction SilentlyContinue

                if (Test-Path $yaraExe) {
                    Write-Log "Successfully downloaded and extracted yara64.exe"
                } else {
                    Write-Log "ERROR: yara64.exe still not found after extraction"
                }
            } else {
                Write-Log "Could not find win64 zip asset in latest release"
            }
        }
        catch {
            Write-Log "Failed to auto-download YARA: $_"
            Write-Log "You must manually place yara64.exe into $BaseDir"
            Write-Log "Download from: https://github.com/VirusTotal/yara/releases/latest"
        }
    }
    else {
        Write-Log "yara64.exe already exists"
    }

    if (-not (Test-Path $yaraRuleMem)) {
        Write-Log "Downloading memory YARA rules..."

        $ruleUrls = @(
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/generic_anomalies.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar"
        )

        $combinedRules = @()

        foreach ($url in $ruleUrls) {
            try {
                $content = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 12 | Select-Object -ExpandProperty Content
                $combinedRules += $content
                Write-Log "Downloaded rule set: $(Split-Path $url -Leaf)"
            }
            catch {
                Write-Log "Failed to download $url : $_"
            }
        }

        if ($combinedRules.Count -gt 0) {
            $combinedRules -join "`n`n" | Out-File -FilePath $yaraRuleMem -Encoding utf8 -Force
            Write-Log "Created combined memory rule file: $yaraRuleMem"
        }
        else {
            Write-Log "No memory rules could be downloaded"
        }
    }
    else {
        Write-Log "Memory YARA rules already exist"
    }

    if (Test-Path $yaraExe) {
        Write-Log "YARA setup complete - ready to use"
        
        Write-Log "Starting YARA memory scanner"
        
        Start-Job -ScriptBlock {
            param($yaraExePath, $yaraRulePath, $protectedProcs, $configData)
            
            $logFile = Join-Path $configData.BaseDirectory "yara_memory_hits.log"
            
            while ($true) {
                Start-Sleep -Seconds $configData.MemoryScanIntervalSec
                
                Get-Process | Where-Object {
                    $_.WorkingSet64 -gt 100MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp'
                } | ForEach-Object {
                    $process = $_
                    
                    try {
                        $result = & $yaraExePath -w $yaraRulePath -p $process.Id 2>$null
                        
                        if ($LASTEXITCODE -eq 0 -and $result) {
                            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | YARA HIT -> $($process.Name) (PID: $($process.Id))"
                            
                            try {
                                $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                            } catch {}
                            
                            if ($protectedProcs -notcontains $process.Name) {
                                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                            }
                        }
                    } catch {}
                }
            }
        } -ArgumentList $yaraExe, $yaraRuleMem, $ProtectedProcesses, $Config | Out-Null
        
        return $true
    }
    else {
        Write-Log "YARA executable missing - memory YARA scanning will be DISABLED"
        return $false
    }
}

# ========================= FILELESS MALWARE DETECTION =========================
function Find-FilelessIndicators {
    $detections = @()
    
    # Check for PowerShell without file
    try {
        $suspiciousPowerShell = Get-Process -Name powershell, pwsh -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -match 'encodedcommand|enc|iex|invoke-expression'
        }
        
        if ($suspiciousPowerShell) {
            $detections += [PSCustomObject]@{
                Type    = "FilelessPowerShell"
                Details = $suspiciousPowerShell | Select-Object Name, Id, MainWindowTitle
            }
            Write-Log "Fileless indicator detected: PowerShell without file"
        }
    } catch {}
    
    # Check WMI event subscriptions
    try {
        $wmiEvents = Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Query -match 'powershell|vbscript|javascript' }
        
        if ($wmiEvents) {
            $detections += [PSCustomObject]@{
                Type    = "WMIEventSubscription"
                Details = $wmiEvents | Select-Object Name, Query
            }
            Write-Log "Fileless indicator detected: WMI event subscriptions"
        }
    } catch {}
    
    # Check registry Run keys for scripts
    try {
        $registryKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        )
        
        foreach ($key in $registryKeys) {
            if (Test-Path $key) {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                
                if ($props) {
                    $props.PSObject.Properties | Where-Object {
                        $_.MemberType -eq 'NoteProperty' -and $_.Value -match 'powershell.*-enc|mshta|regsvr32.*scrobj'
                    } | ForEach-Object {
                        $detections += [PSCustomObject]@{
                            Type    = "RegistryScript"
                            Details = "$key -> $($_.Name): $($_.Value)"
                        }
                        Write-Log "Fileless indicator detected: Registry script in $key"
                    }
                }
            }
        }
    } catch {}
    
    return $detections
}

# ========================= PERSISTENCE DETECTION =========================
function Find-PersistenceMechanisms {
    $suspiciousItems = @()
    
    $locations = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'C:\Windows\System32\Tasks',
        'C:\Windows\Tasks',
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
    )
    
    foreach ($location in $locations) {
        try {
            if ($location -match '^HK') {
                # Registry location
                if (Test-Path $location) {
                    $props = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    
                    if ($props) {
                        $props.PSObject.Properties | Where-Object {
                            $_.MemberType -eq 'NoteProperty' -and $_.Value -match '\.(exe|dll|ps1|vbs|js|bat|cmd)$'
                        } | ForEach-Object {
                            $suspiciousItems += [PSCustomObject]@{
                                Location = $location
                                Name     = $_.Name
                                Value    = $_.Value
                                Type     = 'Registry'
                            }
                        }
                    }
                }
            } else {
                # File system location
                if (Test-Path $location) {
                    Get-ChildItem -Path $location -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -match '\.(exe|dll|lnk|ps1|vbs|js|bat|cmd)$' } |
                        ForEach-Object {
                            $suspiciousItems += [PSCustomObject]@{
                                Location = $location
                                Name     = $_.Name
                                Value    = $_.FullName
                                Type     = 'FileSystem'
                            }
                        }
                }
            }
        } catch {
            Write-Log "Error checking persistence location $location : $_"
        }
    }
    
    return $suspiciousItems
}

# ========================= BEHAVIOR ANALYSIS =========================
function Test-ProcessHollowing {
    param($Process)
    
    try {
        $processPath = $Process.Path
        if (-not $processPath) { return $false }
        
        $modules = $Process.Modules
        if ($modules -and $modules.Count -gt 0) {
            return ($modules[0].FileName -ne $processPath)
        }
    } catch {}
    
    return $false
}

function Test-CredentialAccessBehavior {
    param($Process)
    
    try {
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)" -ErrorAction SilentlyContinue).CommandLine
        
        if ($commandLine -match 'mimikatz|procdump|sekurlsa|lsadump|credential|password') {
            return $true
        }
    } catch {}
    
    if ($Process.ProcessName -match 'vaultcmd|cred') {
        return $true
    }
    
    return $false
}

function Test-LateralMovementBehavior {
    param($Process)
    
    try {
        $connections = Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue
        
        $externalConnections = $connections | Where-Object {
            $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)|^(::1|fe80:)' -and
            $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::'
        }
        
        return (($externalConnections | Measure-Object).Count -gt 10)
    } catch {}
    
    return $false
}

function Test-C2Communication {
    param($Connection)
    
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 8443, 9001, 1337, 31337)
    
    if ($Connection.RemotePort -in $suspiciousPorts) {
        try {
            $hostname = [System.Net.Dns]::GetHostEntry($Connection.RemoteAddress).HostName
            
            $c2Domains = @('pastebin', 'ddns.net', 'no-ip.org', 'duckdns.org', 'bit.ly', 'tinyurl')
            
            foreach ($domain in $c2Domains) {
                if ($hostname -like "*$domain*") {
                    return $true
                }
            }
        } catch {}
    }
    
    return $false
}

# ========================= PROCESS AND NETWORK SCANNING =========================
function Invoke-ProcessAndNetworkScan {
    # Scan running processes
    Get-Process | ForEach-Object {
        $process = $_
        
        # Analyze executable if path exists
        try {
            $exePath = $process.MainModule.FileName
            if ($exePath -and (Test-Path $exePath)) {
                Invoke-ThreatAnalysis -FilePath $exePath
            }
        } catch {}
        
        # Behavior analysis
        if ($BehaviorConfig.EnableBehaviorKill -and ($ProtectedProcesses -notcontains $process.Name)) {
            try {
                if (Test-ProcessHollowing -Process $process) {
                    Write-Log "BEHAVIOR: Process hollowing detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "HIGH" -Message "Process hollowing detected" -Details "$($process.Name) PID: $($process.Id)"
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                }
                elseif (Test-CredentialAccessBehavior -Process $process) {
                    Write-Log "BEHAVIOR: Credential access detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "HIGH" -Message "Credential access behavior" -Details "$($process.Name) PID: $($process.Id)"
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                }
                elseif (Test-LateralMovementBehavior -Process $process) {
                    Write-Log "BEHAVIOR: Lateral movement detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "MEDIUM" -Message "Lateral movement behavior" -Details "$($process.Name) PID: $($process.Id)"
                }
            } catch {}
        }
    }
    
    # Scan network connections
    if ($BehaviorConfig.EnableAutoBlockC2) {
        Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $_.State -in @('Established', 'Listen')
        } | ForEach-Object {
            $connection = $_
            
            try {
                $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
                
                if ($process -and (Test-C2Communication -Connection $connection)) {
                    Write-Log "NETWORK: Suspicious C2 connection - $($process.Name) (PID: $($process.Id)) -> $($connection.RemoteAddress):$($connection.RemotePort)"
                    Send-ThreatAlert -Severity "HIGH" -Message "C2 communication detected" -Details "$($process.Name) -> $($connection.RemoteAddress):$($connection.RemotePort)"
                    
                    if ($ProtectedProcesses -notcontains $process.Name) {
                        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    }
                    
                    # Block the IP with firewall rule
                    try {
                        $ruleName = "Block_C2_$($connection.RemoteAddress)"
                        New-NetFirewallRule -DisplayName $ruleName `
                            -Direction Outbound `
                            -Protocol TCP `
                            -RemoteAddress $connection.RemoteAddress `
                            -Action Block `
                            -Enabled True `
                            -ErrorAction SilentlyContinue | Out-Null
                        
                        Write-Log "Created firewall rule to block: $($connection.RemoteAddress)"
                    } catch {}
                }
            } catch {}
        }
    }
}

# ========================= INITIAL SCAN =========================
Write-Log "Performing initial scan of high-risk folders"

$highRiskFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp"
)

foreach ($folder in $highRiskFolders) {
    if (Test-Path $folder) {
        Write-Log "Scanning: $folder"
        Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Invoke-ThreatAnalysis -FilePath $_.FullName
        }
    }
}

# ========================= REAL-TIME FILE MONITORING =========================
if ($Config.EnableRealtimeMonitor) {
    Write-Log "Setting up real-time file monitoring"
    
    foreach ($folder in $highRiskFolders) {
        if (-not (Test-Path $folder)) { continue }
        
        try {
            $watcher = New-Object IO.FileSystemWatcher $folder, '*.*' -Property @{
                IncludeSubdirectories = $true
                NotifyFilter          = [IO.NotifyFilters]'FileName, LastWrite'
            }
            
            Register-ObjectEvent $watcher Created -Action {
                $filePath = $Event.SourceEventArgs.FullPath
                $extension = [IO.Path]::GetExtension($filePath).ToLower()
                
                if ($MonitoredExtensions -contains $extension) {
                    Start-Sleep -Milliseconds 800
                    Invoke-ThreatAnalysis -FilePath $filePath
                }
            } | Out-Null
            
            $watcher.EnableRaisingEvents = $true
            Write-Log "File watcher active for: $folder"
        } catch {
            Write-Log "Failed to create file watcher for $folder : $_"
        }
    }
}

# ========================= WMI REAL-TIME EXECUTION HOOKS =========================
Write-Log "Registering WMI real-time execution monitors"

try {
    Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
        $event = $Event.SourceEventArgs.NewEvent
        $filePath = $event.ProcessName
        $processId = $event.ProcessId
        
        try {
            $ownerSid = (Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue | 
                Invoke-CimMethod -MethodName GetOwnerSid).Sid
        } catch {
            $ownerSid = "Unknown"
        }
        
        # Quick allow for trusted SIDs with valid signatures
        if ($AllowedSIDs -contains $ownerSid) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
                if ($signature.Status -eq 'Valid') {
                    return
                }
            } catch {}
        }
        
        Block-FileExecution -FilePath $filePath -ProcessId $processId -Type "EXE"
    } | Out-Null
    
    Write-Log "WMI process start monitor registered"
} catch {
    Write-Log "Failed to register WMI process start monitor: $_"
}

try {
    Register-WmiEvent -Query "SELECT * FROM Win32_ModuleLoadTrace" -Action {
        $event = $Event.SourceEventArgs.NewEvent
        $filePath = $event.ImageName
        $processId = $event.ProcessId
        
        if (-not (Test-Path $filePath)) { return }
        
        try {
            $ownerSid = (Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue | 
                Invoke-CimMethod -MethodName GetOwnerSid).Sid
        } catch {
            $ownerSid = "Unknown"
        }
        
        # Quick allow for trusted SIDs with valid signatures
        if ($AllowedSIDs -contains $ownerSid) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
                if ($signature.Status -eq 'Valid') {
                    return
                }
            } catch {}
        }
        
        Block-FileExecution -FilePath $filePath -ProcessId $processId -Type "DLL"
    } | Out-Null
    
    Write-Log "WMI module load monitor registered"
} catch {
    Write-Log "Failed to register WMI module load monitor: $_"
}

# ========================= START BACKGROUND TASKS =========================

# Start memory scanner
if ($Config.EnableMemoryScanning) {
    Start-MemoryScanner
    Start-YaraMemoryScanner
}

# Start threat intelligence updater and deep scanner
if ($IsAdmin -and $Config.EnableThreatIntel) {
    $lastUpdateFile = Join-Path $Config.BaseDirectory "last_update.txt"
    $currentTime = Get-Date
    $shouldUpdate = $false
    
    if (-not (Test-Path $lastUpdateFile)) {
        $shouldUpdate = $true
    } else {
        try {
            $lastUpdate = (Get-Item $lastUpdateFile).LastWriteTime
            if ($lastUpdate -lt $currentTime.AddDays(-$BehaviorConfig.ThreatIntelUpdateDays)) {
                $shouldUpdate = $true
            }
        } catch {
            $shouldUpdate = $true
        }
    }
    
    if ($shouldUpdate) {
        Update-ThreatIntelligence
        $currentTime | Out-File -FilePath $lastUpdateFile
    }
    
    # Start deep scan scheduled task (runs in main loop instead of separate job for function access)
    $Script:LastDeepScan = Get-Date
    $Script:DeepScanIntervalSeconds = 60 * 60 * $BehaviorConfig.DeepScanIntervalHours
    
    Write-Log "Deep scanner initialized (interval: $($BehaviorConfig.DeepScanIntervalHours) hours)"
}

function Invoke-ScheduledDeepScan {
    if (-not $Script:LastDeepScan) { return }
    
    $timeSinceLastScan = (Get-Date) - $Script:LastDeepScan
    if ($timeSinceLastScan.TotalSeconds -lt $Script:DeepScanIntervalSeconds) { return }
    
    $Script:LastDeepScan = Get-Date
    Write-Log "Running scheduled deep scan..."
    
    # Persistence scan
    try {
        $persistence = Find-PersistenceMechanisms
        if ($persistence -and $persistence.Count -gt 0) {
            $outputFile = Join-Path $Config.BaseDirectory "persistence_scan.csv"
            $persistence | Export-Csv -Path $outputFile -NoTypeInformation
            Write-Log "Persistence scan found $($persistence.Count) items -> $outputFile"
            Send-ThreatAlert -Severity "MEDIUM" -Message "Persistence mechanisms detected" -Details "Found $($persistence.Count) items"
        }
    } catch {
        Write-Log "Persistence scan error: $_"
    }
    
    # Fileless malware scan
    try {
        $fileless = Find-FilelessIndicators
        if ($fileless -and $fileless.Count -gt 0) {
            $outputFile = Join-Path $Config.BaseDirectory "fileless_detections.xml"
            $fileless | Export-Clixml -Path $outputFile
            Write-Log "Fileless indicators found: $($fileless.Count) -> $outputFile"
            Send-ThreatAlert -Severity "HIGH" -Message "Fileless malware indicators" -Details "Found $($fileless.Count) indicators"
        }
    } catch {
        Write-Log "Fileless scan error: $_"
    }
}

function Invoke-ShadowProxyCaptureDetection {
    # Niche detection: Identifies processes loading a suspicious COMBINATION of:
    # - COM proxy/stub DLLs (system communication hooks)
    # - Media capture DLLs (camera/mic access)
    # - User management DLLs (account/credential access)
    #
    # Individually these are legitimate Windows components.
    # Combined in a non-system process = potential surveillance malware
    
    $suspiciousModules = @{
        # COM Proxy/Stub - inter-process communication hooks
        ProxyStub = @('npmproxy.dll', 'onecoreapiproxystub.dll', 'onecoreuapcommonproxystub.dll', 
                      'onecorecommonproxystub.dll', 'usermgrproxy.dll', 'edaboradutilsproxy.dll')
        # Media capture - camera/microphone access
        MediaCapture = @('mfcaptureengine.dll', 'mfplat.dll', 'mfsensorgroup.dll', 
                         'windows.media.capture.dll', 'frameserver.dll', 'frameservermonitor.dll')
        # User/credential management
        UserMgmt = @('usermgrcli.dll', 'usermgrproxy.dll', 'credprovs.dll', 'authui.dll')
        # Network interception
        NetIntercept = @('winhttp.dll', 'wininet.dll', 'urlmon.dll', 'rasapi32.dll')
    }
    
    # Known legitimate processes that may load these combinations
    $whitelistedProcesses = @(
        'svchost', 'explorer', 'dwm', 'sihost', 'taskhostw', 'runtimebroker',
        'searchhost', 'startmenuexperiencehost', 'shellexperiencehost',
        'systemsettings', 'applicationframehost', 'textinputhost',
        'securityhealthservice', 'msmpeng', 'nissrv',
        'teams', 'zoom', 'skype', 'discord', 'slack',  # Communication apps
        'brave', 'chrome', 'firefox', 'msedge', 'opera'  # Browsers
    )
    
    foreach ($proc in (Get-CachedProcessList)) {
        if ($proc.Id -eq $PID) { continue }
        
        $procNameLower = $proc.ProcessName.ToLower()
        if ($procNameLower -in $whitelistedProcesses) { continue }
        
        try {
            $loadedModules = $proc.Modules | ForEach-Object { $_.ModuleName.ToLower() }
            if (-not $loadedModules) { continue }
            
            # Count how many categories of suspicious modules are loaded
            $categories = @{
                ProxyStub = $false
                MediaCapture = $false
                UserMgmt = $false
                NetIntercept = $false
            }
            
            foreach ($mod in $loadedModules) {
                if ($suspiciousModules.ProxyStub -contains $mod) { $categories.ProxyStub = $true }
                if ($suspiciousModules.MediaCapture -contains $mod) { $categories.MediaCapture = $true }
                if ($suspiciousModules.UserMgmt -contains $mod) { $categories.UserMgmt = $true }
                if ($suspiciousModules.NetIntercept -contains $mod) { $categories.NetIntercept = $true }
            }
            
            $loadedCategories = ($categories.Values | Where-Object { $_ -eq $true }).Count
            
            # Alert if process loads 3+ categories (proxy + capture + something else)
            if ($loadedCategories -ge 3) {
                # Additional checks to reduce false positives
                $isSigned = $false
                $isFromSafeLocation = $false
                
                if ($proc.Path) {
                    $sig = Get-AuthenticodeSignature $proc.Path -EA 0
                    $isSigned = $sig.Status -eq 'Valid'
                    $isFromSafeLocation = $proc.Path -match '^C:\\Windows\\|^C:\\Program Files'
                }
                
                # Only alert for unsigned or suspiciously located processes
                if (-not $isSigned -or -not $isFromSafeLocation) {
                    $loadedCats = @()
                    if ($categories.ProxyStub) { $loadedCats += "ProxyStub" }
                    if ($categories.MediaCapture) { $loadedCats += "MediaCapture" }
                    if ($categories.UserMgmt) { $loadedCats += "UserMgmt" }
                    if ($categories.NetIntercept) { $loadedCats += "NetIntercept" }
                    
                    Write-Log "SHADOW PROXY-CAPTURE DETECTED: $($proc.ProcessName) (PID: $($proc.Id))"
                    Write-Log "  -> Path: $($proc.Path)"
                    Write-Log "  -> Loaded categories: $($loadedCats -join ', ')"
                    Write-Log "  -> Signed: $isSigned | SafeLocation: $isFromSafeLocation"
                    Send-ThreatAlert -Severity "CRITICAL" -Message "Suspicious module combination detected" -Details "$($proc.ProcessName) loaded: $($loadedCats -join ', ')"
                    
                    # Kill if unsigned AND from suspicious location
                    if (-not $isSigned -and -not $isFromSafeLocation) {
                        Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName
                    }
                }
            }
        } catch {}
    }
}

# ===================== KeyScrambler Anti-Keylogger Protection =====================

$KeyScramblerSource = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class KeyScrambler
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT
    {
        public uint type;
        public INPUTUNION u;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP   = 0x0002;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool GetMessage(out MSG msg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll")] private static extern IntPtr GetMessageExtraInfo();
    [DllImport("user32.dll")] private static extern short GetKeyState(int nVirtKey);
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string lpModuleName);

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int x; public int y; }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    private static IntPtr _hookID = IntPtr.Zero;
    private static LowLevelKeyboardProc _proc;
    private static Random _rnd = new Random();
    
    private static double _floodChance = 0.5;
    private static double _beforeKeyChance = 0.75;
    private static double _afterKeyChance = 0.75;
    private static int _minFakeChars = 1;
    private static int _maxFakeChars = 6;

    public static void Configure(double floodChance, double beforeChance, double afterChance, int minChars, int maxChars)
    {
        _floodChance = floodChance;
        _beforeKeyChance = beforeChance;
        _afterKeyChance = afterChance;
        _minFakeChars = minChars;
        _maxFakeChars = maxChars;
    }

    public static void Start()
    {
        if (_hookID != IntPtr.Zero) return;

        _proc = HookCallback;
        _hookID = SetWindowsHookEx(WH_KEYBOARD_LL,
            Marshal.GetFunctionPointerForDelegate(_proc),
            GetModuleHandle(null), 0);

        if (_hookID == IntPtr.Zero)
            throw new Exception("KeyScrambler hook failed: " + Marshal.GetLastWin32Error());

        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    public static void Stop()
    {
        if (_hookID != IntPtr.Zero)
        {
            UnhookWindowsHookEx(_hookID);
            _hookID = IntPtr.Zero;
        }
    }

    public static bool IsRunning()
    {
        return _hookID != IntPtr.Zero;
    }

    private static bool ModifiersDown()
    {
        return (GetKeyState(0x10) & 0x8000) != 0 ||  // Shift
               (GetKeyState(0x11) & 0x8000) != 0 ||  // Ctrl
               (GetKeyState(0x12) & 0x8000) != 0;    // Alt
    }

    private static void InjectFakeChar(char c)
    {
        var inputs = new INPUT[2];

        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki.wVk = 0;
        inputs[0].u.ki.wScan = (ushort)c;
        inputs[0].u.ki.dwFlags = KEYEVENTF_UNICODE;
        inputs[0].u.ki.dwExtraInfo = GetMessageExtraInfo();

        inputs[1] = inputs[0];
        inputs[1].u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;

        SendInput(2, inputs, Marshal.SizeOf(typeof(INPUT)));
        Thread.Sleep(_rnd.Next(1, 7));
    }

    private static void Flood()
    {
        if (_rnd.NextDouble() < _floodChance) return;
        int count = _rnd.Next(_minFakeChars, _maxFakeChars + 1);
        for (int i = 0; i < count; i++)
            InjectFakeChar((char)_rnd.Next('A', 'Z' + 1));
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            KBDLLHOOKSTRUCT k = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));

            if ((k.flags & 0x10) != 0) return CallNextHookEx(_hookID, nCode, wParam, lParam);
            if (ModifiersDown()) return CallNextHookEx(_hookID, nCode, wParam, lParam);

            if (k.vkCode >= 65 && k.vkCode <= 90)
            {
                if (_rnd.NextDouble() < _beforeKeyChance) Flood();
                var ret = CallNextHookEx(_hookID, nCode, wParam, lParam);
                if (_rnd.NextDouble() < _afterKeyChance) Flood();
                return ret;
            }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }
}
"@

$Script:KeyScramblerRunspace = $null
$Script:KeyScramblerPowerShell = $null

function Start-KeyScrambler {
    if (-not $KeyScramblerConfig.EnableKeyScrambler) {
        Write-Log "KeyScrambler is disabled in configuration"
        return
    }
    
    Write-Log "Initializing KeyScrambler anti-keylogger protection..."
    
    try {
        if (-not ([System.Management.Automation.PSTypeName]'KeyScrambler').Type) {
            Add-Type -TypeDefinition $KeyScramblerSource -Language CSharp -ErrorAction Stop
            Write-Log "KeyScrambler compiled successfully"
        }
        
        [KeyScrambler]::Configure(
            $KeyScramblerConfig.FloodChance,
            $KeyScramblerConfig.BeforeKeyChance,
            $KeyScramblerConfig.AfterKeyChance,
            $KeyScramblerConfig.MinFakeChars,
            $KeyScramblerConfig.MaxFakeChars
        )
        
        # Use runspace (thread) instead of job (separate process)
        $Script:KeyScramblerRunspace = [runspacefactory]::CreateRunspace()
        $Script:KeyScramblerRunspace.ApartmentState = "STA"
        $Script:KeyScramblerRunspace.ThreadOptions = "ReuseThread"
        $Script:KeyScramblerRunspace.Open()
        
        $Script:KeyScramblerPowerShell = [powershell]::Create()
        $Script:KeyScramblerPowerShell.Runspace = $Script:KeyScramblerRunspace
        
        $null = $Script:KeyScramblerPowerShell.AddScript({
            param($Source, $FloodChance, $BeforeChance, $AfterChance, $MinChars, $MaxChars)
            Add-Type -TypeDefinition $Source -Language CSharp -ErrorAction Stop
            [KeyScrambler]::Configure($FloodChance, $BeforeChance, $AfterChance, $MinChars, $MaxChars)
            [KeyScrambler]::Start()
        }).AddArgument($KeyScramblerSource).AddArgument($KeyScramblerConfig.FloodChance).AddArgument($KeyScramblerConfig.BeforeKeyChance).AddArgument($KeyScramblerConfig.AfterKeyChance).AddArgument($KeyScramblerConfig.MinFakeChars).AddArgument($KeyScramblerConfig.MaxFakeChars)
        
        $null = $Script:KeyScramblerPowerShell.BeginInvoke()
        
        Write-Log "KeyScrambler ACTIVE - anti-keylogger protection enabled (runspace thread)"
        Write-Log "  -> You see only your real typing"
        Write-Log "  -> Keyloggers receive garbage mixed with your keystrokes"
    }
    catch {
        Write-Log "KeyScrambler initialization failed: $_"
    }
}

function Stop-KeyScrambler {
    try {
        if ($Script:KeyScramblerPowerShell) {
            $Script:KeyScramblerPowerShell.Stop()
            $Script:KeyScramblerPowerShell.Dispose()
            $Script:KeyScramblerPowerShell = $null
        }
        if ($Script:KeyScramblerRunspace) {
            $Script:KeyScramblerRunspace.Close()
            $Script:KeyScramblerRunspace.Dispose()
            $Script:KeyScramblerRunspace = $null
        }
        Write-Log "KeyScrambler stopped"
    } catch {}
}

# ===================== Niche/Specialized Detection Functions =====================

# NeuroBehaviorMonitor state variables
$Script:NBM_LastRun = [DateTime]::MinValue
$Script:NBM_TickInterval = 2
$Script:NBM_FocusHistory = @{}
$Script:NBM_LastBrightness = -1
$Script:NBM_FlashScore = 0
$Script:NBM_LastCursorPos = @{X=0; Y=0}
$Script:NBM_CursorFirstSeen = [DateTime]::MinValue
$Script:NBM_CursorJitterCount = 0
$Script:NBM_LastAvgR = -1
$Script:NBM_LastAvgG = -1
$Script:NBM_LastAvgB = -1
$Script:NBM_DistortScore = 0
$Script:NBM_TopmostAllowlist = @("explorer", "taskmgr", "devenv", "code", "chrome", "firefox", "msedge")
$Script:NBM_Reported = @{}

function Test-NBMShouldReport {
    param([string]$Key)
    if ($Script:NBM_Reported.ContainsKey($Key)) { return $false }
    $Script:NBM_Reported[$Key] = [DateTime]::UtcNow
    return $true
}

function Invoke-NeuroBehaviorMonitor {
    $now = Get-Date
    if ($Script:NBM_LastRun -ne [DateTime]::MinValue -and ($now - $Script:NBM_LastRun).TotalSeconds -lt $Script:NBM_TickInterval) { return }
    $Script:NBM_LastRun = $now
    
    try {
        Add-Type -AssemblyName System.Windows.Forms -EA 0
        Add-Type -AssemblyName System.Drawing -EA 0
        
        if (-not ([System.Management.Automation.PSTypeName]'NeuroWin32').Type) {
            Add-Type @"
using System;
using System.Runtime.InteropServices;
public class NeuroWin32 {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_TOPMOST = 0x00000008;
}
"@ -EA 0
        }
        
        $hWnd = [NeuroWin32]::GetForegroundWindow()
        if ($hWnd -eq [IntPtr]::Zero) { return }
        $fpid = 0
        [NeuroWin32]::GetWindowThreadProcessId($hWnd, [ref]$fpid) | Out-Null
        if ($fpid -eq 0 -or $fpid -eq $PID) { return }
        
        $proc = Get-Process -Id $fpid -EA 0
        $procName = if ($proc) { $proc.ProcessName } else { "unknown" }
        
        # Screen sample for flash/color detection
        $bmp = [System.Drawing.Bitmap]::new(64,64)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen(0,0,0,0,$bmp.Size)
        $g.Dispose()
        
        $sumBright = 0; $sumR = 0; $sumG = 0; $sumB = 0; $samples = 0
        for ($x=0; $x -lt 64; $x+=4) {
            for ($y=0; $y -lt 64; $y+=4) {
                $c = $bmp.GetPixel($x,$y)
                $sumR += $c.R; $sumG += $c.G; $sumB += $c.B
                $sumBright += $c.R + $c.G + $c.B
                $samples++
            }
        }
        $bmp.Dispose()
        $n = [Math]::Max(1, $samples)
        $avgR = $sumR/$n; $avgG = $sumG/$n; $avgB = $sumB/$n
        
        # Focus steal detection
        if (-not $Script:NBM_FocusHistory.ContainsKey($fpid)) { $Script:NBM_FocusHistory[$fpid] = @{Count=0; FirstSeen=[DateTime]::UtcNow} }
        $fe = $Script:NBM_FocusHistory[$fpid]
        $fe.Count++
        $elapsed = ([DateTime]::UtcNow - $fe.FirstSeen).TotalSeconds
        if ($elapsed -gt 10) { $fe.Count = 1; $fe.FirstSeen = [DateTime]::UtcNow }
        if ($elapsed -lt 10 -and $fe.Count -gt 8) {
            if (Test-NBMShouldReport -Key "Focus:$procName") {
                Write-Log "NeuroBehavior: Focus abuse by $procName"
                Send-ThreatAlert -Severity "MEDIUM" -Message "Focus abuse detected" -Details $procName
            }
            $fe.Count = 0
        }
        $Script:NBM_FocusHistory[$fpid] = $fe
        
        # Flash detection
        if ($Script:NBM_LastBrightness -ge 0) {
            $delta = [Math]::Abs($sumBright - $Script:NBM_LastBrightness)
            if ($delta -gt 40000) { $Script:NBM_FlashScore++ } else { $Script:NBM_FlashScore = [Math]::Max(0, $Script:NBM_FlashScore - 1) }
            if ($Script:NBM_FlashScore -ge 6) {
                if (Test-NBMShouldReport -Key "Flash:$procName") {
                    Write-Log "NeuroBehavior: Flash stimulus from $procName"
                    Send-ThreatAlert -Severity "HIGH" -Message "Flash stimulus detected" -Details $procName
                    Stop-ThreatProcess -ProcessId $fpid -ProcessName $procName
                }
                $Script:NBM_FlashScore = 0
            }
        }
        $Script:NBM_LastBrightness = $sumBright
        
        # Topmost abuse
        $exStyle = [NeuroWin32]::GetWindowLong($hWnd, [NeuroWin32]::GWL_EXSTYLE)
        if (([int]$exStyle -band [NeuroWin32]::WS_EX_TOPMOST) -ne 0 -and $Script:NBM_TopmostAllowlist -notcontains $procName.ToLower()) {
            if (Test-NBMShouldReport -Key "Topmost:$procName") {
                Write-Log "NeuroBehavior: Topmost abuse by $procName"
            }
        }
        
        # Color distortion
        if ($Script:NBM_LastAvgR -ge 0) {
            $dR = [Math]::Abs($avgR - $Script:NBM_LastAvgR)
            $dG = [Math]::Abs($avgG - $Script:NBM_LastAvgG)
            $dB = [Math]::Abs($avgB - $Script:NBM_LastAvgB)
            $maxD = [Math]::Max($dR, [Math]::Max($dG, $dB))
            if ($maxD -gt 70) { $Script:NBM_DistortScore++ } else { $Script:NBM_DistortScore = [Math]::Max(0, $Script:NBM_DistortScore - 1) }
            if ($Script:NBM_DistortScore -ge 5) {
                if (Test-NBMShouldReport -Key "Distort:$procName") {
                    Write-Log "NeuroBehavior: Screen distortion by $procName"
                }
                $Script:NBM_DistortScore = 0
            }
        }
        $Script:NBM_LastAvgR = $avgR; $Script:NBM_LastAvgG = $avgG; $Script:NBM_LastAvgB = $avgB
    } catch {}
}

# PrivacyForge - Identity spoofing
$Script:PrivacyForgeIdentity = $null
$Script:PrivacyForgeDataCollected = 0
$Script:PrivacyForgeLastRotation = Get-Date

function Invoke-PrivacyForgeGenerateIdentity {
    $firstNames = @("John", "Jane", "Michael", "Sarah", "David", "Emily", "James", "Jessica")
    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis")
    $domains = @("gmail.com", "yahoo.com", "outlook.com", "protonmail.com")
    $userAgents = @(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    )
    
    $firstName = Get-Random -InputObject $firstNames
    $lastName = Get-Random -InputObject $lastNames
    
    return @{
        name = "$firstName $lastName"
        email = "$firstName$lastName$(Get-Random -Min 100 -Max 9999)@$(Get-Random -InputObject $domains)"
        user_agent = Get-Random -InputObject $userAgents
        device_id = [Guid]::NewGuid().ToString()
        mac_address = "{0:X2}-{1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}" -f (1..6 | ForEach-Object { Get-Random -Min 0 -Max 256 })
    }
}

function Invoke-PrivacyForgeSpoofing {
    try {
        $timeSinceRotation = (Get-Date) - $Script:PrivacyForgeLastRotation
        $shouldRotate = ($timeSinceRotation.TotalSeconds -ge 3600) -or ($Script:PrivacyForgeDataCollected -ge 50) -or (-not $Script:PrivacyForgeIdentity)
        
        if ($shouldRotate) {
            $Script:PrivacyForgeIdentity = Invoke-PrivacyForgeGenerateIdentity
            $Script:PrivacyForgeDataCollected = 0
            $Script:PrivacyForgeLastRotation = Get-Date
            Write-Log "PrivacyForge: Identity rotated - $($Script:PrivacyForgeIdentity.name)"
        }
        
        $Script:PrivacyForgeDataCollected += Get-Random -Min 1 -Max 5
    } catch {}
}


# ========================= MAIN MONITORING LOOP =========================
Write-Log "All monitoring systems active"
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Clean Antivirus is now running" -ForegroundColor Green
Write-Host "Press [Ctrl+C] to stop" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Green

try {
    while ($true) {
        try {
            Invoke-ProcessAndNetworkScan
            Invoke-ScheduledDeepScan
            Write-Log "Periodic scan cycle completed"
        } catch {
            Write-Log "Scan cycle error: $_"
        }
        
        Start-Sleep -Seconds 30
    }
} catch {
    Write-Log "Main loop terminated: $($_.Exception.Message)"
    Write-Host "`nAntivirus stopped. Check log file: $($Config.LogFile)" -ForegroundColor Red
}