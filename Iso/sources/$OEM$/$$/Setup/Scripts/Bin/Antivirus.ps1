# Antivirus.ps1
# Author: Gorstak

$Config = @{
    BaseDirectory           = "C:\ProgramData\Antivirus"
    QuarantineDirectory     = "C:\ProgramData\Antivirus\Quarantine"
    BackupDirectory         = "C:\ProgramData\Antivirus\Backup"
    LogFile                 = "C:\ProgramData\Antivirus\av.log"
    BlockedLogFile          = "C:\ProgramData\Antivirus\blocked.log"
    DatabaseFile            = "C:\ProgramData\Antivirus\known_files.db"
    
    MaxDatabaseEntries      = 50000
    MaxLogSizeMB            = 10
    MemoryScanIntervalSec   = 8
    MemoryScanMaxSizeMB     = 150
    ProcessTimeoutSeconds   = 30
    DatabaseCleanupDays     = 30
    
    EnableMemoryScanning    = $true
    EnableRealtimeMonitor   = $true
    EnableThreatIntel       = $true
    EnableAlerts            = $true
    AutoQuarantine          = $true
    
    MalwareBazaarApiKey     = ""
    CirclHashLookupUrl      = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl             = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl     = "https://mb-api.abuse.ch/api/v1/"
    
    CymruDetectionThreshold = 60
    SuspiciousFileSizeKB    = 3072
}

$BehaviorConfig = @{
    EnableBehaviorKill      = $true
    EnableAutoBlockC2       = $true
    DeepScanIntervalHours   = 6
    ThreatIntelUpdateDays   = 7
}

$KeyScramblerConfig = @{
    EnableKeyScrambler      = $true
    FloodChance             = 0.5
    BeforeKeyChance         = 0.75
    AfterKeyChance          = 0.75
    MinFakeChars            = 1
    MaxFakeChars            = 6
}

$RulesDirectory = Join-Path $Config.BaseDirectory "rules"
$KnownFilesCache = @{}

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

$AllowedSIDs = @('S-1-2-0', 'S-1-5-20')

$RiskyPaths = @('\temp\', '\downloads\', '\appdata\local\temp\', '\public\', '\windows\temp\', '\appdata\roaming\', '\desktop\')

# Monitor only specific extensions
$MonitoredExtensions = @('.com', '.exe', '.exif', '.dll', '.winmd')

# Executable extensions for special handling
$ExecutableExtensions = @(
    '.exe', '.dll', '.sys', '.ocx', '.scr', '.com', '.cpl', '.msi', '.drv', '.winmd',
    '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.jse', '.wsf', '.wsh', '.psc1',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.bzip', '.bzip2', '.xz', '.tgz',
    '.tbz', '.taz', '.tpz', '.z', '.lzh', '.lha', '.arc', '.arj', '.cab', '.iso', '.img',
    '.doc', '.docx', '.docm', '.docb', '.dot', '.dotx', '.dotm', '.xls', '.xlsx', '.xlsm',
    '.xlsb', '.xlt', '.xltx', '.xltm', '.xlam', '.xla', '.xlm', '.xll', '.xlw', '.ppt',
    '.pptx', '.pptm', '.pps', '.ppsx', '.ppsm', '.pot', '.potx', '.potm', '.ppa', '.ppam',
    '.rtf', '.odt', '.ods', '.mdb', '.accdb', '.accde', '.accda', '.accdr', '.accdt',
    '.htm', '.html', '.mht', '.mhtml', '.xml', '.xsl', '.xps', '.svg',
    '.reg', '.inf', '.ini', '.cfg', '.config', '.manifest', '.lnk', '.url',
    '.chm', '.hta', '.msp', '.msu', '.apk', '.crx', '.xpi', '.eml', '.msg'
)

$ProtectedProcesses = @(
    'System', 'Idle', 'Registry', 'smss', 'csrss', 'wininit', 'services', 'lsass',
    'svchost', 'winlogon', 'explorer', 'dwm', 'SearchUI', 'SearchIndexer', 'fontdrvhost',
    'RuntimeBroker', 'sihost', 'taskhostw'
)

$EvilStrings = @(
    'mimikatz', 'sekurlsa::', 'kerberos::', 'lsadump::', 'wdigest', 'tspkg',
    'http-beacon', 'https-beacon', 'cobaltstrike', 'sleepmask', 'reflective',
    'ReflectiveLoader', 'sharpchrome', 'rubeus', 'safetykatz', 'sharphound',
    'invoke-mimikatz', 'invoke-bloodhound', 'powersploit', 'empire'
)
# Note: Removed 'amsi.dll', 'AmsiScanBuffer', 'EtwEventWrite', 'MiniDumpWriteDump',
# 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread' - these are legitimate
# Windows APIs/DLLs that many normal programs use. Flagging them causes false positives.

New-Item -ItemType Directory -Path $Config.BaseDirectory, $Config.QuarantineDirectory, $Config.BackupDirectory, $RulesDirectory -Force -ErrorAction SilentlyContinue | Out-Null

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
    
    if (Test-Path $Config.LogFile) {
        $logSize = (Get-Item $Config.LogFile -ErrorAction SilentlyContinue).Length
        if ($logSize -ge ($Config.MaxLogSizeMB * 1MB)) {
            $archiveName = "$($Config.BaseDirectory)\av_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            try {
                Rename-Item -Path $Config.LogFile -NewName $archiveName -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

Write-Log "=== Antivirus Starting ==="
Write-Log "Admin: $IsAdmin | User: $env:USERNAME | SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

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
                    
                    try {
                        $entryDate = [datetime]::Parse($timestamp)
                        if ($entryDate -lt (Get-Date).AddDays(-$Config.DatabaseCleanupDays)) {
                            continue
                        }
                    } catch {}
                    
                    $KnownFilesCache[$hash] = $safe
                    $count++
                    
                    if ($count -ge $Config.MaxDatabaseEntries) {
                        break
                    }
                }
            }
            
            Write-Log "Loaded $count entries from database"
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
    
    if ($KnownFilesCache.Count -gt $Config.MaxDatabaseEntries) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

Load-Database

function Test-ShouldExclude {
    param([string]$FilePath)
    
    $lower = $FilePath.ToLower()
    
    # Exclude antivirus's own folder to prevent self-quarantine
    $avFolderLower = $Config.BaseDirectory.ToLower()
    if ($lower -like "$avFolderLower\*" -or $lower -eq $avFolderLower) { return $true }
    
    if ($lower -like '*\assembly\*') { return $true }
    if ($lower -like '*\winsxs\*') { return $true }
    if ($lower -like '*\microsoft.net\*') { return $true }
    if ($lower -like '*\windows\system32\config\*') { return $true }
    if ($lower -like '*ctfmon*' -or $lower -like '*msctf.dll' -or $lower -like '*msutb.dll') {
        return $true
    }
    
    return $false
}

function Get-FileHashSafe {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return $null }
    
    try {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
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
    } catch {}
    
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
    } catch {}
    
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
    } catch {}
    
    return $false
}

function Test-SuspiciousUnsignedDll {
    param([string]$FilePath)
    
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($extension -notin @('.dll', '.winmd')) { return $false }
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($signature.Status -eq 'Valid') { return $false }
    } catch {}
    
    $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
    if (-not $fileInfo) { return $false }
    
    $fileSizeKB = $fileInfo.Length / 1KB
    $pathLower = $FilePath.ToLower()
    
    foreach ($riskyPath in $RiskyPaths) {
        if ($pathLower -like "*$riskyPath*" -and $fileSizeKB -lt $Config.SuspiciousFileSizeKB) {
            return $true
        }
    }
    
    if ($pathLower -like '*\appdata\roaming\*' -and $fileSizeKB -lt 800 -and $fileInfo.Name -match '^[a-z0-9]{4,12}\.(dll|winmd)$') {
        return $true
    }
    
    return $false
}

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

function Move-ToQuarantine {
    param(
        [string]$FilePath,
        [string]$Reason
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Log "Cannot quarantine - file not found: $FilePath"
        return
    }
    
    if (Test-FileLocked -FilePath $FilePath) {
        Stop-ProcessesUsingFile -FilePath $FilePath
        Start-Sleep -Milliseconds 500
    }
    
    $fileName = [IO.Path]::GetFileName($FilePath)
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupPath = Join-Path $Config.BackupDirectory "${fileName}_${timestamp}.bak"
    $quarantinePath = Join-Path $Config.QuarantineDirectory "${fileName}_${timestamp}"
    
    try {
        Copy-Item -Path $FilePath -Destination $backupPath -Force -ErrorAction Stop
        Move-Item -Path $FilePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "QUARANTINED [$Reason]: $FilePath -> $quarantinePath"
        Send-ThreatAlert -Severity "HIGH" -Message "File quarantined: $Reason" -Details $FilePath
    } catch {
        Write-Log "Quarantine failed for $FilePath : $_"
        
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
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process -and ($ProtectedProcesses -notcontains $process.ProcessName)) {
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
            Write-Log "Killed process PID $ProcessId"
        }
    } catch {}
    
    if (Test-Path $FilePath) {
        Move-ToQuarantine -FilePath $FilePath -Reason "Real-time $Type block"
    }
}

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
    
    $entryType = switch ($severityUpper) {
        "CRITICAL" { [System.Diagnostics.EventLogEntryType]::Error }
        "HIGH"     { [System.Diagnostics.EventLogEntryType]::Warning }
        "MEDIUM"   { [System.Diagnostics.EventLogEntryType]::Warning }
        default    { [System.Diagnostics.EventLogEntryType]::Information }
    }
    
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("Antivirus")) {
            New-EventLog -LogName Application -Source "Antivirus" -ErrorAction SilentlyContinue
        }
        
        Write-EventLog -LogName Application -Source "Antivirus" `
            -EventId 1001 -Message "$Message - $Details" `
            -EntryType $entryType -ErrorAction SilentlyContinue
    } catch {}
    
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

function Invoke-ThreatAnalysis {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath -PathType Leaf)) { return }
    if (Test-ShouldExclude -FilePath $FilePath) { return }
    
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($MonitoredExtensions -notcontains $extension) { return }
    
    $fileHash = Get-FileHashSafe -FilePath $FilePath
    if (-not $fileHash) { return }
    
    if ($KnownFilesCache.ContainsKey($fileHash)) {
        if (-not $KnownFilesCache[$fileHash]) {
            Move-ToQuarantine -FilePath $FilePath -Reason "Previously identified threat"
        }
        return
    }
    
    if (Test-CirclHashLookup -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $true
        Write-Log "ALLOWED (CIRCL known-good): $FilePath"
        return
    }
    
    if (Test-CymruMalwareHash -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "Cymru MHR malware match (>=$($Config.CymruDetectionThreshold)% detection)"
        return
    }
    
    if (Test-MalwareBazaarHash -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "MalwareBazaar malware match"
        return
    }
    
    if (Test-SuspiciousUnsignedDll -FilePath $FilePath) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "Suspicious unsigned DLL/WINMD in risky location"
        return
    }
    
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

function Initialize-Yara {
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
        return $true
    }
    else {
        Write-Log "YARA executable missing - memory YARA scanning will be DISABLED"
        return $false
    }
}

$yaraReady = Initialize-Yara

function Invoke-MemoryScan {
    if (-not $Config.EnableMemoryScanning) { return }
    
    $maxBytes = $Config.MemoryScanMaxSizeMB * 1MB
    $logFile = Join-Path $Config.BaseDirectory "memory_hits.log"
    
    Get-Process -EA 0 | Where-Object {
        $_.WorkingSet64 -lt $maxBytes -and $ProtectedProcesses -notcontains $_.Name
    } | ForEach-Object {
        $process = $_
        $suspicious = $false
        $reasons = @()
        
        try {
            if (-not $process.Path -or $process.Path -eq '') {
                $suspicious = $true
                $reasons += "NoPath"
            }
        } catch {}
        
        try {
            $emptyModules = $process.Modules | Where-Object {
                $_.FileName -eq '' -or $_.ModuleName -eq ''
            }
            if ($emptyModules) {
                $suspicious = $true
                $reasons += "EmptyModule"
            }
        } catch {}
        
        try {
            foreach ($module in $process.Modules) {
                foreach ($evilString in $EvilStrings) {
                    if ($module.ModuleName -match $evilString -or ($module.FileName -and $module.FileName -match $evilString)) {
                        $suspicious = $true
                        $reasons += "EvilString($evilString)"
                        break
                    }
                }
                if ($suspicious) { break }
            }
        } catch {}
        
        if ($suspicious) {
            $reasonString = $reasons -join '; '
            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | MEMORY HIT [$reasonString] -> $($process.Name) (PID: $($process.Id)) Path: '$($process.Path)' WS: $([math]::Round($process.WorkingSet64/1MB, 2))MB"
            Write-Log "MEMORY: $reasonString -> $($process.Name) (PID: $($process.Id))"
            try { $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 } catch {}
            try { Stop-Process -Id $process.Id -Force -EA 0 } catch {}
        }
    }
}

function Invoke-YaraMemoryScan {
    $yaraExePath = Join-Path $Config.BaseDirectory "yara64.exe"
    $yaraRulePath = Join-Path $Config.BaseDirectory "mem.yar"
    
    if (-not (Test-Path $yaraExePath) -or -not (Test-Path $yaraRulePath)) { return }
    
    $logFile = Join-Path $Config.BaseDirectory "yara_memory_hits.log"
    
    Get-Process -EA 0 | Where-Object {
        $_.WorkingSet64 -gt 100MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp'
    } | ForEach-Object {
        $process = $_
        
        try {
            $result = & $yaraExePath -w $yaraRulePath -p $process.Id 2>$null
            
            if ($LASTEXITCODE -eq 0 -and $result) {
                $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | YARA HIT -> $($process.Name) (PID: $($process.Id))"
                Write-Log "YARA: Hit on $($process.Name) (PID: $($process.Id))"
                try { $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 } catch {}
                
                if ($ProtectedProcesses -notcontains $process.Name) {
                    Stop-Process -Id $process.Id -Force -EA 0
                }
            }
        } catch {}
    }
}

function Find-FilelessIndicators {
    $detections = @()
    
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

function Invoke-ProcessAndNetworkScan {
    Get-Process | ForEach-Object {
        $process = $_
        
        try {
            $exePath = $process.MainModule.FileName
            if ($exePath -and (Test-Path $exePath)) {
                Invoke-ThreatAnalysis -FilePath $exePath
            }
        } catch {}
        
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
            } catch {            }
        }
    }
}

# ===================== Additional Detection Functions =====================

function Stop-ThreatProcess {
    param([int]$ProcessId, [string]$ProcessName)
    
    if ($ProcessId -eq $PID) { return }
    if ($ProtectedProcesses -contains $ProcessName -or $ProtectedProcesses -contains ($ProcessName -replace '\.exe$','')) { return }
    
    try {
        $proc = Get-Process -Id $ProcessId -EA 0
        if ($proc.Path -like 'C:\Windows\*' -or $proc.Path -like 'C:\Program Files*') { return }
        
        Stop-Process -Id $ProcessId -Force -EA 0
        Write-Log "Terminated threat: $ProcessName (PID: $ProcessId)"
    } catch {}
}

function Invoke-LOLBinDetection {
    # Living Off the Land Binaries - legitimate Windows tools abused by attackers
    # Extended patterns based on LOLBAS project (https://lolbas-project.github.io/)
    $LOLBins = @{
        "certutil"   = "-decode|-urlcache|-verifyctl|-encode|-ping|-f\s+http"
        "bitsadmin"  = "transfer|addfile|/download|/create|/addfile|/SetNotifyCmdLine"
        "mshta"      = "http://|https://|javascript:|vbscript:|about:"
        "regsvr32"   = "scrobj\.dll|/s|/n|/u|/i:http|/i:ftp"
        "rundll32"   = "javascript:|http://|shell32\.dll,Control_RunDLL|advpack\.dll|ieadvpack\.dll|zipfldr\.dll"
        "wmic"       = "process call create|/node:|format:.*http|xsl:http|/format:"
        "powershell" = "-enc\s|-encodedcommand|downloadstring|iex\s|invoke-expression|-nop|-w\s*hidden|bypass|-ep\s+bypass|webclient|Net\.WebClient|bitstransfer"
        "msiexec"    = "/quiet|/q.*http|/i\s+http|/i\s+\\\\|/y\s+|/y.*\.dll|/z.*\.dll"
        "cscript"    = "http://|https://|//e:jscript|//e:vbscript"
        "wscript"    = "http://|https://|//e:jscript|//e:vbscript"
        "cmd"        = "/c.*powershell.*-enc|/c.*certutil.*-urlcache|/c.*bitsadmin.*transfer"
        "forfiles"   = "/c.*cmd|/c.*powershell"
        "pcalua"     = "-a.*\.exe|-a.*\.dll|-a.*http"
        "msconfig"   = "-5|/auto"
        "msbuild"    = "\.csproj|\.xml|/p:.*http"
        "installutil"= "/logfile=|/LogToConsole=false"
        "regasm"     = "/u\s+"
        "regsvcs"    = "/u\s+"
        "cmstp"      = "/ni|/s|/au|\.inf"
        "dnscmd"     = "/config|/enumrecords"
        "eudcedit"   = ".*"
        "eventvwr"   = ".*"
        "expand"     = "-f:.*\.dll|-f:.*\.exe|http://|https://"
        "extrac32"   = "/y|/c|\.cab"
        "findstr"    = "/s.*password|/s.*credential"
        "ftp"        = "-s:"
        "gpscript"   = "/startup|/logon"
        "hh"         = "http://|https://|\.chm"
        "ieexec"     = "http://|https://"
        "infdefaultinstall" = ".*\.inf"
        "makecab"    = "/d.*cmd|/d.*powershell"
        "mavinject"  = "/injectrunning"
        "mftrace"    = ".*\.dll"
        "microsoft.workflow.compiler" = ".*\.xml"
        "mmc"        = "-a.*\.msc|\.msc.*http"
        "msdeploy"   = "-source:.*-dest:"
        "msdt"       = "PCWDiagnostic|/id"
        "netsh"      = "add helper|trace start"
        "odbcconf"   = "/a.*regsvr|/f.*\.rsp"
        "pcwrun"     = ".*\.exe"
        "presentationhost" = ".*\.xbap|.*\.xaml"
        "print"      = "/d:.*\.exe|/d:.*\.dll"
        "psr"        = "/start|/gui 0"
        "rasautou"   = "-a.*-e"
        "rdrleakdiag"= "/fullmemdmp"
        "reg"        = "export.*sam|export.*security|save.*sam|save.*security|add.*Run"
        "regedit"    = "/s.*\.reg|/e.*\.reg"
        "replace"    = "/a.*\.exe|/a.*\.dll"
        "rpcping"    = "-u.*-a.*-f"
        "runscripthelper" = "surfacecheck"
        "sc"         = "create.*binpath|config.*binpath"
        "schtasks"   = "/create.*/tr.*powershell|/create.*/tr.*cmd|/create.*/tr.*http"
        "scriptrunner" = "-appvscript"
        "syncappvpublishingserver" = ".*powershell|.*\;"
        "tttracer"   = "-dumpfull"
        "verclsid"   = "/c|/s"
        "wab"        = ".*"
        "winrm"      = "invoke|create.*powershell"
        "xwizard"    = "runwizard|/extract"
    }
    
    foreach ($proc in Get-WmiObject Win32_Process -EA 0) {
        if ($proc.ProcessId -eq $PID -or -not $proc.CommandLine) { continue }
        
        $name = $proc.Name -replace '\.exe$',''
        $cmd = $proc.CommandLine.ToLower()
        
        foreach ($lolbin in $LOLBins.Keys) {
            if ($name -eq $lolbin -and $cmd -match $LOLBins[$lolbin]) {
                Write-Log "LOLBin attack: $($proc.Name) PID:$($proc.ProcessId)"
                Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
                break
            }
        }
    }
}

function Invoke-ProcessAnomalyDetection {
    $systemBinaries = @("svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe")
    $officeApps = "winword|excel|powerpnt|outlook|msaccess"
    $scriptEngines = "powershell|cmd|wscript|cscript|mshta"
    
    foreach ($proc in Get-WmiObject Win32_Process -EA 0) {
        if ($proc.ProcessId -eq $PID) { continue }
        
        $cmd = $proc.CommandLine
        $path = $proc.ExecutablePath
        $parent = Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -EA 0
        
        # Office apps spawning script engines (macro attack)
        if ($parent.Name -match $officeApps -and $proc.Name -match $scriptEngines) {
            Write-Log "Macro attack: $($parent.Name) spawned $($proc.Name)"
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
            continue
        }
        
        # System binaries from wrong location
        if ($proc.Name -in $systemBinaries -and $path -and $path -notmatch "Windows\\System32") {
            Write-Log "Masquerading: Fake $($proc.Name) at $path"
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
            continue
        }
        
        # Suspicious command line patterns
        if ($cmd -and ($cmd -match "-enc\s.*bypass" -or $cmd -match "DownloadString|DownloadFile" -or $cmd -match "FromBase64String.*Invoke")) {
            Write-Log "Suspicious process: $($proc.Name)"
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
        }
    }
}

function Invoke-AMSIBypassDetection {
    $pattern = "AmsiScanBuffer|amsiInitFailed|AmsiUtils|AmsiContext|Patch.*Amsi|Disable.*Amsi|bypass.*amsi"
    
    foreach ($proc in Get-CimInstance Win32_Process -EA 0) {
        if ($proc.ProcessId -eq $PID -or $proc.Name -notmatch "powershell|pwsh|wscript|cscript") { continue }
        
        $cmd = $proc.CommandLine
        if (-not $cmd) { continue }
        
        if ($cmd -match $pattern) {
            Write-Log "AMSI bypass attempt: $($proc.Name) PID:$($proc.ProcessId)"
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
            continue
        }
        
        # Check encoded commands
        if ($cmd -match "-enc\s+([A-Za-z0-9+/=]+)") {
            try {
                $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
                if ($decoded -match $pattern) {
                    Write-Log "Encoded AMSI bypass: $($proc.Name)"
                    Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
                }
            } catch {}
        }
    }
}

function Invoke-CredentialDumpDetection {
    $toolPattern = "mimikatz|sekurlsa|pwdump|gsecdump|procdump|nanodump|lsassy|lazagne|hashdump"
    $lsassProc = Get-Process lsass -EA 0
    
    foreach ($proc in Get-WmiObject Win32_Process -EA 0) {
        if ($proc.ProcessId -eq $PID) { continue }
        
        $cmd = $proc.CommandLine
        $name = $proc.Name
        
        # Known tools
        if ($name -match $toolPattern -or $cmd -match $toolPattern) {
            Write-Log "Credential tool: $name"
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $name
            continue
        }
        
        # LSASS access
        if ($lsassProc -and $cmd -match "lsass" -and $proc.ProcessId -ne $lsassProc.Id) {
            Write-Log "LSASS access: $name"
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $name
            continue
        }
        
        # Memory/registry dumps
        if ($cmd -match "MiniDump|comsvcs\.dll.*#24|reg\s+(save|export).*(sam|security|system)") {
            Write-Log "Credential dump: $name"
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $name
        }
    }
}

function Invoke-WMIPersistenceDetection {
    try {
        $ns = "root\subscription"
        $filters = Get-CimInstance -Namespace $ns -ClassName __EventFilter -EA 0
        $consumers = Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -EA 0
        $bindings = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -EA 0
        
        foreach ($filter in $filters) {
            if ($filter.Name -match "microsoft|SCM Event") { continue }
            if ($filter.Query -match "ProcessStartTrace|powershell|cmd") {
                Write-Log "Malicious WMI filter: $($filter.Name)"
                Send-ThreatAlert -Severity "HIGH" -Message "WMI persistence detected" -Details $filter.Name
                $bindings | Where-Object { $_.Filter -like "*$($filter.Name)*" } | ForEach-Object { Remove-CimInstance $_ -EA 0 }
                Remove-CimInstance $filter -EA 0
            }
        }
        
        foreach ($consumer in $consumers) {
            if ($consumer.CommandLineTemplate -match "powershell|cmd|-enc|http") {
                Write-Log "Malicious WMI consumer: $($consumer.Name)"
                Send-ThreatAlert -Severity "HIGH" -Message "WMI persistence detected" -Details $consumer.Name
                $bindings | Where-Object { $_.Consumer -like "*$($consumer.Name)*" } | ForEach-Object { Remove-CimInstance $_ -EA 0 }
                Remove-CimInstance $consumer -EA 0
            }
        }
    } catch {}
}

function Invoke-ScheduledTaskDetection {
    $whitelist = @("Antivirus", "GoogleUpdate", "MicrosoftEdge", "OneDrive", "Adobe")
    $badExes = "powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin"
    $badArgs = "-enc|http://|https://|bypass|hidden|downloadstring"
    
    try {
        foreach ($task in Get-ScheduledTask -EA 0 | Where-Object { $_.State -eq "Ready" -and $_.TaskPath -notmatch "\\Microsoft\\" }) {
            if ($whitelist | Where-Object { $task.TaskName -match $_ }) { continue }
            
            $exe = $task.Actions[0].Execute
            $args = $task.Actions[0].Arguments
            
            if ($exe -match $badExes -and $args -match $badArgs) {
                Write-Log "Malicious task: $($task.TaskName)"
                Send-ThreatAlert -Severity "HIGH" -Message "Malicious scheduled task" -Details $task.TaskName
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -EA 0
            }
        }
    } catch {}
}

function Invoke-RegistryPersistenceDetection {
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $badPattern = "powershell.*-enc|cmd.*/c.*powershell|http://|https://|wscript|cscript|mshta"
    
    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        try {
            $props = Get-ItemProperty -Path $key -EA 0
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match "^PS" -or -not $prop.Value) { continue }
                
                if ($prop.Value -match $badPattern) {
                    Write-Log "Registry persistence: $key\$($prop.Name)"
                    Send-ThreatAlert -Severity "HIGH" -Message "Registry persistence" -Details "$key\$($prop.Name)"
                    
                    # Try to quarantine the executable
                    $exePath = ($prop.Value -split ' ')[0] -replace '"',''
                    if ($exePath -and (Test-Path $exePath) -and $exePath -notmatch "Windows|Program Files") {
                        Move-ToQuarantine -FilePath $exePath -Reason "Registry persistence executable"
                    }
                    
                    if ($key -like "HKCU:*") {
                        Remove-ItemProperty -Path $key -Name $prop.Name -EA 0
                    }
                }
            }
        } catch {}
    }
}

function Invoke-DLLHijackingDetection {
    $badLocations = "\\Temp\\|\\Downloads\\|\\Desktop\\|\\AppData\\"
    
    foreach ($proc in Get-Process -EA 0) {
        if ($proc.Id -eq $PID) { continue }
        try {
            foreach ($mod in $proc.Modules) {
                if ($mod.FileName -match $badLocations -and $mod.FileName -like "*.dll") {
                    $sig = Get-AuthenticodeSignature $mod.FileName -EA 0
                    if ($sig.Status -ne "Valid") {
                        Write-Log "Suspicious DLL: $($proc.ProcessName) loaded $($mod.FileName)"
                        Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName
                        break
                    }
                }
            }
        } catch {}
    }
}

function Invoke-TokenManipulationDetection {
    foreach ($proc in Get-Process -EA 0 | Where-Object { $_.Path }) {
        try {
            $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -EA 0).GetOwner()
            if ($owner.Domain -eq "NT AUTHORITY" -and $proc.Path -notmatch "^C:\\Windows") {
                Write-Log "Token manipulation: $($proc.ProcessName) as SYSTEM from $($proc.Path)"
                Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName
            }
        } catch {}
    }
}

function Invoke-ProcessHollowingDetection {
    # System processes and their legitimate locations
    $systemProcsSystem32 = @("svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "wininit.exe")
    $systemProcsWindows = @("explorer.exe")  # explorer.exe is in C:\Windows, not System32
    
    foreach ($proc in Get-CimInstance Win32_Process -EA 0) {
        if ($proc.ProcessId -eq $PID) { continue }
        try {
            $procObj = Get-Process -Id $proc.ProcessId -EA 0
            
            # Path mismatch
            if ($procObj.Path -and $proc.ExecutablePath -and $procObj.Path -ne $proc.ExecutablePath) {
                Write-Log "Process hollowing: $($proc.Name)"
                Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
                continue
            }
            
            # System32 processes from wrong location
            if ($proc.Name -in $systemProcsSystem32 -and $proc.ExecutablePath -and $proc.ExecutablePath -notmatch "Windows\\System32") {
                Write-Log "Fake system process: $($proc.Name) at $($proc.ExecutablePath)"
                Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
            }
            
            # Windows folder processes from wrong location
            if ($proc.Name -in $systemProcsWindows -and $proc.ExecutablePath -and $proc.ExecutablePath -notmatch "^C:\\Windows\\[^\\]+$") {
                Write-Log "Fake system process: $($proc.Name) at $($proc.ExecutablePath)"
                Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
            }
        } catch {}
    }
}

function Invoke-RansomwareDetection {
    $encryptedExts = @(".encrypted", ".locked", ".crypto", ".crypt", ".locky", ".cerber", ".zepto")
    $shadowDelete = "vssadmin.*delete|wbadmin.*delete|shadowcopy.*delete|recoveryenabled.*no"
    
    # Check shadow deletion commands
    foreach ($proc in Get-WmiObject Win32_Process -EA 0) {
        if ($proc.ProcessId -eq $PID) { continue }
        if ($proc.CommandLine -match $shadowDelete) {
            Write-Log "Ransomware (shadow delete): $($proc.Name)"
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
        }
    }
    
    # Check recently encrypted files
    $userDirs = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")
    $recentEncrypted = 0
    
    foreach ($dir in $userDirs) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem $dir -Recurse -File -EA 0 | Where-Object { (Get-Date) - $_.LastWriteTime -lt [TimeSpan]::FromMinutes(5) } | ForEach-Object {
            if ($encryptedExts -contains $_.Extension.ToLower()) { $recentEncrypted++ }
            if ($_.Name -match "readme|decrypt|how_to|ransom") { Write-Log "Ransom note: $($_.FullName)" }
        }
    }
    
    if ($recentEncrypted -gt 10) {
        Write-Log "RANSOMWARE ALERT: $recentEncrypted files encrypted!"
        Send-ThreatAlert -Severity "CRITICAL" -Message "Ransomware detected" -Details "$recentEncrypted files encrypted"
    }
}

function Invoke-NetworkAnomalyDetection {
    $badPorts = @(4444, 5555, 31337, 6666, 12345, 54321)
    $scriptProcs = "cmd|powershell|wscript|cscript|mshta|rundll32"
    
    Get-NetTCPConnection -State Established -EA 0 | Where-Object { $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.)" } | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -EA 0
        $ip = $_.RemoteAddress
        $port = $_.RemotePort
        
        $isThreat = ($port -in $badPorts) -or ($proc.ProcessName -match $scriptProcs) -or ($proc.Path -and $proc.Path -notmatch "Windows|Program Files")
        
        if ($isThreat) {
            Write-Log "Network threat: $($proc.ProcessName) -> $ip`:$port"
            $ruleName = "AV_Block_$ip"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -EA 0)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress $ip -Action Block -EA 0 | Out-Null
            }
            if ($proc.ProcessName -match $scriptProcs) {
                Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName
            }
        }
    }
}

# ===================== Advanced Abuse Detection Functions =====================

function Invoke-CameraMicAccessDetection {
    # Detects suspicious processes accessing camera/microphone via Media Foundation
    # MFCaptureEngine.dll is legitimately used by apps for camera/mic access
    # But malware can abuse this for surveillance
    
    $whitelistedApps = @(
        'brave', 'chrome', 'firefox', 'msedge', 'opera',  # Browsers
        'teams', 'zoom', 'skype', 'discord', 'slack',     # Communication apps
        'obs64', 'obs32', 'streamlabs',                   # Streaming
        'WindowsCamera', 'Camera',                         # Windows Camera
        'SecurityHealthService', 'MsMpEng'                # Windows Security
    )
    
    foreach ($proc in Get-Process -EA 0) {
        if ($proc.Id -eq $PID) { continue }
        try {
            $loadedMF = $proc.Modules | Where-Object { $_.ModuleName -match 'MFCaptureEngine|mfplat|mf\.dll' }
            if (-not $loadedMF) { continue }
            
            $procName = $proc.ProcessName.ToLower()
            $isWhitelisted = $whitelistedApps | Where-Object { $procName -like "*$_*" }
            
            if (-not $isWhitelisted) {
                # Check if the process is signed
                $sig = Get-AuthenticodeSignature $proc.Path -EA 0
                $isSigned = $sig.Status -eq 'Valid'
                
                # Check if from suspicious location
                $isSuspiciousPath = $proc.Path -match '\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp\\'
                
                # Check if has no visible window (hidden process)
                $hasWindow = $proc.MainWindowHandle -ne [IntPtr]::Zero
                
                if (-not $isSigned -or $isSuspiciousPath -or -not $hasWindow) {
                    Write-Log "CAMERA/MIC ACCESS ALERT: $($proc.ProcessName) (PID:$($proc.Id)) accessing media capture"
                    Write-Log "  -> Path: $($proc.Path)"
                    Write-Log "  -> Signed: $isSigned | SuspiciousPath: $isSuspiciousPath | HasWindow: $hasWindow"
                    Send-ThreatAlert -Severity "HIGH" -Message "Suspicious camera/mic access" -Details "$($proc.ProcessName) at $($proc.Path)"
                    
                    if (-not $isSigned -and $isSuspiciousPath) {
                        Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName
                    }
                }
            }
        } catch {}
    }
}

function Invoke-COMHijackingDetection {
    # Detects COM object hijacking where malware registers fake COM objects in HKCU
    # that shadow legitimate HKLM entries, causing legitimate processes to load malicious DLLs
    
    $suspiciousPaths = @('\\Temp\\', '\\Downloads\\', '\\AppData\\Local\\Temp\\', '\\Desktop\\', '\\Public\\')
    
    try {
        # Get all HKCU COM registrations
        $hkcuClsids = Get-ChildItem "HKCU:\Software\Classes\CLSID" -EA 0
        
        foreach ($clsid in $hkcuClsids) {
            $clsidName = $clsid.PSChildName
            $inprocServer = Get-ItemProperty "$($clsid.PSPath)\InprocServer32" -EA 0
            
            if (-not $inprocServer) { continue }
            
            $dllPath = $inprocServer.'(default)'
            if (-not $dllPath) { continue }
            
            # Check if this CLSID also exists in HKLM (shadowing)
            $hklmExists = Test-Path "HKLM:\Software\Classes\CLSID\$clsidName"
            
            # Check if DLL path is suspicious
            $isSuspiciousPath = $false
            foreach ($badPath in $suspiciousPaths) {
                if ($dllPath -match [regex]::Escape($badPath)) {
                    $isSuspiciousPath = $true
                    break
                }
            }
            
            # Check if DLL is signed
            $isSigned = $false
            if (Test-Path $dllPath) {
                $sig = Get-AuthenticodeSignature $dllPath -EA 0
                $isSigned = $sig.Status -eq 'Valid'
            }
            
            if ($hklmExists -and ($isSuspiciousPath -or -not $isSigned)) {
                Write-Log "COM HIJACKING DETECTED: $clsidName"
                Write-Log "  -> DLL: $dllPath"
                Write-Log "  -> Shadows HKLM: $hklmExists | Suspicious Path: $isSuspiciousPath | Signed: $isSigned"
                Send-ThreatAlert -Severity "CRITICAL" -Message "COM hijacking detected" -Details "CLSID: $clsidName -> $dllPath"
                
                # Quarantine the malicious DLL
                if (Test-Path $dllPath) {
                    Move-ToQuarantine -FilePath $dllPath -Reason "COM hijacking payload"
                }
                
                # Remove the HKCU registration
                Remove-Item -Path $clsid.PSPath -Recurse -Force -EA 0
                Write-Log "  -> Removed malicious HKCU COM registration"
            }
        }
    } catch {
        Write-Log "COM hijacking detection error: $_"
    }
}

function Invoke-ProxySettingsAbuseDetection {
    # Detects malware modifying proxy settings to intercept browser traffic (MITM)
    # Monitors Internet Settings registry keys for unauthorized changes
    
    $proxyKeys = @{
        'ProxyEnable' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        'ProxyServer' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        'AutoConfigURL' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'  # WPAD
    }
    
    # Known legitimate proxy patterns (corporate, VPN, etc.)
    $legitimateProxies = @(
        'localhost', '127.0.0.1', '*.internal', '*.corp'
    )
    
    try {
        $settings = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA 0
        
        # Check if proxy is enabled
        if ($settings.ProxyEnable -eq 1) {
            $proxyServer = $settings.ProxyServer
            $autoConfigUrl = $settings.AutoConfigURL
            
            $isLegitimate = $false
            foreach ($legit in $legitimateProxies) {
                if ($proxyServer -like $legit) {
                    $isLegitimate = $true
                    break
                }
            }
            
            # Suspicious indicators
            $isSuspicious = $false
            $reason = ""
            
            # Check for external proxy pointing to unknown addresses
            if ($proxyServer -and -not $isLegitimate) {
                if ($proxyServer -match '^\d+\.\d+\.\d+\.\d+:\d+$') {
                    # Raw IP address proxy - suspicious
                    $isSuspicious = $true
                    $reason = "Raw IP proxy: $proxyServer"
                }
            }
            
            # Check for WPAD pointing to suspicious URLs
            if ($autoConfigUrl) {
                if ($autoConfigUrl -match 'http://' -and $autoConfigUrl -notmatch 'wpad\.|\.internal|\.corp|\.local') {
                    $isSuspicious = $true
                    $reason = "Suspicious WPAD URL: $autoConfigUrl"
                }
            }
            
            if ($isSuspicious) {
                Write-Log "PROXY ABUSE DETECTED: $reason"
                Send-ThreatAlert -Severity "HIGH" -Message "Proxy settings tampered" -Details $reason
                
                # Log but don't auto-remediate (might break legitimate corporate setups)
                Write-Log "  -> Review manually: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
            }
        }
        
        # Also check for WinHTTP proxy (system-wide)
        $winhttp = netsh winhttp show proxy 2>$null
        if ($winhttp -match 'Proxy Server.*:\s+(\S+)') {
            $systemProxy = $Matches[1]
            if ($systemProxy -ne 'Direct access' -and $systemProxy -match '^\d+\.\d+\.\d+\.\d+:\d+$') {
                Write-Log "SYSTEM PROXY DETECTED: $systemProxy (WinHTTP)"
                Write-Log "  -> May be legitimate corporate proxy, review manually"
            }
        }
    } catch {
        Write-Log "Proxy detection error: $_"
    }
}

function Invoke-DLLSearchOrderHijacking {
    # Detects DLL search order hijacking where known Windows DLL names
    # are placed in application directories to be loaded instead of System32 versions
    
    # Common DLLs that are targets for search order hijacking
    $targetDLLs = @(
        'version.dll', 'winmm.dll', 'dwmapi.dll', 'uxtheme.dll', 'samcli.dll',
        'propsys.dll', 'ntmarta.dll', 'secur32.dll', 'userenv.dll', 'profapi.dll',
        'cryptsp.dll', 'rsaenh.dll', 'gpapi.dll', 'dpapi.dll', 'mpr.dll',
        'shfolder.dll', 'cabinet.dll', 'linkinfo.dll', 'ntshrui.dll', 'srvcli.dll',
        'cscapi.dll', 'netutils.dll', 'dbghelp.dll', 'dbgcore.dll', 'fltlib.dll',
        'wldap32.dll', 'crypt32.dll', 'msasn1.dll', 'imagehlp.dll', 'wintrust.dll'
    )
    
    foreach ($proc in Get-Process -EA 0) {
        if ($proc.Id -eq $PID) { continue }
        try {
            foreach ($mod in $proc.Modules) {
                $modName = $mod.ModuleName.ToLower()
                $modPath = $mod.FileName.ToLower()
                
                # Check if this is a known target DLL
                if ($modName -in $targetDLLs) {
                    # Check if it's loaded from non-System32 location
                    $isFromSystem32 = $modPath -match 'windows\\system32\\' -or $modPath -match 'windows\\syswow64\\'
                    
                    if (-not $isFromSystem32) {
                        # Verify signature
                        $sig = Get-AuthenticodeSignature $mod.FileName -EA 0
                        $isSigned = $sig.Status -eq 'Valid'
                        $isMicrosoft = $sig.SignerCertificate.Subject -match 'Microsoft'
                        
                        if (-not $isSigned -or -not $isMicrosoft) {
                            Write-Log "DLL SEARCH ORDER HIJACK: $($proc.ProcessName) loaded $modName from $($mod.FileName)"
                            Write-Log "  -> Expected: C:\\Windows\\System32\\$modName"
                            Write-Log "  -> Signed: $isSigned | Microsoft: $isMicrosoft"
                            Send-ThreatAlert -Severity "CRITICAL" -Message "DLL hijacking detected" -Details "$($proc.ProcessName) loaded fake $modName"
                            
                            # Stop the affected process
                            Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName
                            
                            # Quarantine the malicious DLL
                            Move-ToQuarantine -FilePath $mod.FileName -Reason "DLL search order hijack"
                            break
                        }
                    }
                }
            }
        } catch {}
    }
}

function Invoke-ProxywareDetection {
    # Detects proxyware/bandwidth hijacking malware like Honeygain, Peer2Profit, etc.
    # These monetize victim's internet connection without consent
    
    $proxywareIndicators = @{
        Processes = @('honeygain', 'peer2profit', 'packetstream', 'traffmonetizer', 'iproyal', 'pawns', 'earnapp', 'nanowire', 'spider')
        Domains = @('honeygain.com', 'peer2profit.com', 'packetstream.io', 'traffmonetizer.com', 'iproyal.com', 'pawns.app', 'earnapp.com')
        Services = @('HoneygainService', 'Peer2ProfitService', 'PacketStreamService')
    }
    
    # Check running processes
    foreach ($indicator in $proxywareIndicators.Processes) {
        $found = Get-Process -EA 0 | Where-Object { $_.ProcessName -like "*$indicator*" }
        if ($found) {
            foreach ($proc in $found) {
                Write-Log "PROXYWARE DETECTED: $($proc.ProcessName) (PID: $($proc.Id))"
                Send-ThreatAlert -Severity "HIGH" -Message "Proxyware detected" -Details $proc.ProcessName
                Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName
            }
        }
    }
    
    # Check services
    foreach ($svcName in $proxywareIndicators.Services) {
        $svc = Get-Service -Name $svcName -EA 0
        if ($svc) {
            Write-Log "PROXYWARE SERVICE: $($svc.Name) ($($svc.Status))"
            Stop-Service -Name $svcName -Force -EA 0
            Set-Service -Name $svcName -StartupType Disabled -EA 0
        }
    }
    
    # Check installed programs
    $installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA 0
    foreach ($indicator in $proxywareIndicators.Processes) {
        $found = $installed | Where-Object { $_.DisplayName -like "*$indicator*" }
        if ($found) {
            Write-Log "PROXYWARE INSTALLED: $($found.DisplayName)"
            Send-ThreatAlert -Severity "HIGH" -Message "Proxyware installed" -Details $found.DisplayName
        }
    }
    
    # Check startup entries
    $startupPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $startupPaths) {
        if (-not (Test-Path $path)) { continue }
        $props = Get-ItemProperty -Path $path -EA 0
        foreach ($indicator in $proxywareIndicators.Processes) {
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Value -like "*$indicator*") {
                    Write-Log "PROXYWARE STARTUP: $($prop.Name) -> $($prop.Value)"
                    Remove-ItemProperty -Path $path -Name $prop.Name -EA 0
                }
            }
        }
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
    
    foreach ($proc in Get-Process -EA 0) {
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

# ELF DLL Unloader
$Script:ElfDLLProcessed = @{}

function Invoke-ElfDLLUnloader {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'DLLUnloaderLite').Type) {
            Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DLLUnloaderLite {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);
    [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
"@ -EA 0
        }
        
        # This function was intended to detect malicious ELF binaries loaded as DLLs
        # but the pattern '*_elf.dll' incorrectly matches legitimate browser DLLs like chrome_elf.dll
        # DISABLED: This function causes browser instability by unloading chrome_elf.dll
        # TODO: Rewrite to detect actual Linux ELF binaries, not DLLs with 'elf' in the name
        return
    } catch {}
}

# Rootkit Detection (simplified)
function Invoke-RootkitDetection {
    try {
        # Hidden process detection
        $procList = Get-Process | Select-Object -ExpandProperty Id
        $perfProcs = Get-Counter "\Process(*)\ID Process" -EA 0 | Select-Object -ExpandProperty CounterSamples | 
            Where-Object { $_.CookedValue -gt 0 } | ForEach-Object { [int]$_.CookedValue }
        
        $hidden = $perfProcs | Where-Object { $_ -notin $procList }
        foreach ($pid in $hidden) {
            Write-Log "ROOTKIT: Hidden process PID $pid"
            Send-ThreatAlert -Severity "CRITICAL" -Message "Hidden process detected" -Details "PID: $pid"
        }
        
        # Suspicious drivers
        Get-WindowsDriver -Online -EA 0 | Where-Object { $_.ProviderName -notmatch "Microsoft" -and $_.ClassName -eq "System" } | ForEach-Object {
            $driverPath = $_.OriginalFileName
            if ($driverPath -and (Test-Path $driverPath)) {
                $sig = Get-AuthenticodeSignature $driverPath -EA 0
                if ($sig.Status -ne "Valid") {
                    Write-Log "ROOTKIT: Unsigned driver $($_.DriverName)"
                    Send-ThreatAlert -Severity "HIGH" -Message "Suspicious driver" -Details $_.DriverName
                }
            }
        }
        
        # Suspicious modules in system processes
        @("lsass", "csrss", "winlogon", "services") | ForEach-Object {
            $proc = Get-Process -Name $_ -EA 0
            if ($proc) {
                $proc.Modules | Where-Object { $_.FileName -notmatch "^C:\\Windows" } | ForEach-Object {
                    Write-Log "ROOTKIT: Suspicious module $($_.ModuleName) in $($proc.ProcessName)"
                }
            }
        }
    } catch {}
}

# Attack Tools Detection
function Invoke-AttackToolsDetection {
    $attackTools = @(
        "mimikatz", "sekurlsa", "lazagne", "procdump", "pwdump", "gsecdump",
        "hydra", "hashcat", "john", "ncrack", "medusa",
        "metasploit", "msfconsole", "msfvenom", "cobaltstrike", "beacon",
        "bloodhound", "sharphound", "empire", "powersploit",
        "nmap", "masscan", "sqlmap", "burpsuite",
        "xmrig", "ccminer", "minerd"
    )
    $pattern = $attackTools -join "|"
    
    foreach ($proc in Get-WmiObject Win32_Process -EA 0) {
        $name = $proc.Name.ToLower()
        $cmd = if ($proc.CommandLine) { $proc.CommandLine.ToLower() } else { "" }
        $path = if ($proc.ExecutablePath) { $proc.ExecutablePath.ToLower() } else { "" }
        
        if ($name -match $pattern -or $cmd -match $pattern -or $path -match $pattern) {
            Write-Log "Attack tool: $($proc.Name)"
            Send-ThreatAlert -Severity "CRITICAL" -Message "Attack tool detected" -Details $proc.Name
            Stop-ThreatProcess -ProcessId $proc.ProcessId -ProcessName $proc.Name
            
            if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                Move-ToQuarantine -FilePath $proc.ExecutablePath -Reason "Attack tool"
            }
        }
    }
}

# Beacon Detection
function Invoke-BeaconDetection {
    $connections = Get-NetTCPConnection -State Established -EA 0 | Where-Object { 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.)" 
    } | Select-Object -First 200
    
    $groups = $connections | Group-Object OwningProcess, RemoteAddress
    
    foreach ($g in $groups) {
        if ($g.Count -lt 3) { continue }
        
        $procId = ($g.Name -split ',')[0].Trim()
        $ip = ($g.Name -split ',')[1].Trim()
        $proc = Get-Process -Id $procId -EA 0
        
        if ($proc -and $g.Count -gt 5) {
            Write-Log "Beacon pattern: $($proc.ProcessName) -> $ip ($($g.Count) connections)"
            Send-ThreatAlert -Severity "HIGH" -Message "Beacon detected" -Details "$($proc.ProcessName) -> $ip"
            
            # Block IP
            $rule = "AV_Beacon_$ip"
            if (-not (Get-NetFirewallRule -DisplayName $rule -EA 0)) {
                New-NetFirewallRule -DisplayName $rule -Direction Outbound -RemoteAddress $ip -Action Block -EA 0 | Out-Null
            }
            
            Stop-ThreatProcess -ProcessId $proc.Id -ProcessName $proc.ProcessName
        }
    }
}

# USB Monitoring
$Script:KnownUSBDevices = @{}

function Invoke-USBMonitoring {
    try {
        $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" -EA 0
        
        foreach ($drive in $drives) {
            $id = $drive.DeviceID
            if ($Script:KnownUSBDevices.ContainsKey($id)) { continue }
            
            $Script:KnownUSBDevices[$id] = Get-Date
            Write-Log "USB: New device $id"
            
            # Scan for autorun and suspicious files
            $autorun = Join-Path $id "autorun.inf"
            if (Test-Path $autorun) {
                Write-Log "USB: Autorun detected on $id"
                Remove-Item $autorun -Force -EA 0
            }
            
            Get-ChildItem "$id\" -Include *.exe,*.dll,*.scr,*.bat,*.vbs,*.ps1 -Recurse -EA 0 | ForEach-Object {
                $sig = Get-AuthenticodeSignature $_.FullName -EA 0
                if ($sig.Status -ne "Valid") {
                    Write-Log "USB: Unsigned executable $($_.FullName)"
                    Move-ToQuarantine -FilePath $_.FullName -Reason "Unsigned USB executable"
                }
            }
        }
    } catch {}
}

# GFocus - User-initiated connection whitelist firewall
# Browsers: whitelist based on address bar + 30 sec grace for dependencies
# Other apps: only allowed connections when they have foreground focus

$Script:GFocus_BrowserAllowedIPs = @{}      # IP -> expiry time (browser whitelist)
$Script:GFocus_BrowserBlockedIPs = @{}      # IP -> rule name (browser blocks)
$Script:GFocus_AppBlockedProcs = @{}        # ProcessId -> @{RuleName; IPs} (app blocks)
$Script:GFocus_LastAddressBar = ""
$Script:GFocus_LastForegroundPid = 0
$Script:GFocus_GracePeriod = 30
$Script:GFocus_Browsers = "chrome|msedge|firefox|brave|opera|iexplore|vivaldi|waterfox"
$Script:GFocus_ControlledApps = "powershell|pwsh|cmd|WindowsTerminal|python|node|curl|wget|git|ssh|telnet|ftp|wscript|cscript|mshta"

function Invoke-GFocus {
    try {
        if (-not ([System.Management.Automation.PSTypeName]'GFocusUI').Type) {
            Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class GFocusUI {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
}
"@ -EA 0
        }
        
        Add-Type -AssemblyName UIAutomationClient -EA 0
        Add-Type -AssemblyName UIAutomationTypes -EA 0
        
        $hWnd = [GFocusUI]::GetForegroundWindow()
        $fgPid = 0
        [GFocusUI]::GetWindowThreadProcessId($hWnd, [ref]$fgPid) | Out-Null
        if ($fgPid -eq 0) { return }
        
        $fgProc = Get-Process -Id $fgPid -EA 0
        if (-not $fgProc) { return }
        
        $now = Get-Date
        $isBrowser = $fgProc.ProcessName -match $Script:GFocus_Browsers
        $isControlledApp = $fgProc.ProcessName -match $Script:GFocus_ControlledApps
        
        # ==================== BROWSER ADDRESS BAR DETECTION ====================
        # Only read address bar when browser is in foreground
        if ($isBrowser) {
            # Detect if browser just regained focus (was doing something else before)
            $lastWasBrowser = $false
            try {
                $lastProc = Get-Process -Id $Script:GFocus_LastForegroundPid -EA 0
                if ($lastProc -and $lastProc.ProcessName -match $Script:GFocus_Browsers) {
                    $lastWasBrowser = $true
                }
            } catch {}
            $browserRegainedFocus = (-not $lastWasBrowser -and $Script:GFocus_LastForegroundPid -ne 0)
            
            $userInput = $null
            
            # Get address bar content
            try {
                $auto = [System.Windows.Automation.AutomationElement]::FromHandle($hWnd)
                $editCondition = [System.Windows.Automation.PropertyCondition]::new(
                    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                    [System.Windows.Automation.ControlType]::Edit
                )
                $edits = $auto.FindAll([System.Windows.Automation.TreeScope]::Descendants, $editCondition)
                
                foreach ($edit in $edits) {
                    try {
                        $valuePattern = $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
                        $value = $valuePattern.Current.Value
                        if ($value -match "^https?://|^www\.|^\w+\.\w+") {
                            $userInput = $value
                            break
                        }
                    } catch {}
                }
            } catch {}
            
            # When browser regains focus, unblock ALL previously blocked browser IPs
            # (Discord/etc use many IPs - CDNs, APIs, WebSockets - not just the main hostname)
            if ($browserRegainedFocus -and $Script:GFocus_BrowserBlockedIPs.Count -gt 0) {
                Write-Log "GFocus: Browser regained focus - unblocking all $($Script:GFocus_BrowserBlockedIPs.Count) blocked IPs"
                foreach ($ip in @($Script:GFocus_BrowserBlockedIPs.Keys)) {
                    $ruleName = $Script:GFocus_BrowserBlockedIPs[$ip]
                    Remove-NetFirewallRule -DisplayName $ruleName -EA 0
                    $Script:GFocus_BrowserAllowedIPs[$ip] = $now.AddSeconds($Script:GFocus_GracePeriod)
                    Write-Log "GFocus: Unblocked $ip (browser regained focus)"
                }
                $Script:GFocus_BrowserBlockedIPs.Clear()
            }
            
            # Process new navigation (URL changed)
            $shouldProcess = $userInput -and ($userInput -ne $Script:GFocus_LastAddressBar)
            
            if ($shouldProcess) {
                $Script:GFocus_LastAddressBar = $userInput
                
                $hostname = $null
                if ($userInput -match "https?://([^/:]+)") { $hostname = $Matches[1] }
                elseif ($userInput -match "^www\.([^/:]+)") { $hostname = "www." + $Matches[1] }
                elseif ($userInput -match "^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}") { $hostname = $Matches[0] }
                
                if ($hostname) {
                    Write-Log "GFocus: Browser navigated to $hostname"
                    
                    try {
                        $ips = [System.Net.Dns]::GetHostAddresses($hostname) | ForEach-Object { $_.IPAddressToString }
                        $expiry = $now.AddSeconds($Script:GFocus_GracePeriod)
                        
                        foreach ($ip in $ips) {
                            $Script:GFocus_BrowserAllowedIPs[$ip] = $expiry
                        }
                    } catch {}
                }
            }
        }
        
        # ==================== BROWSER CONNECTION MONITORING ====================
        # Always monitor ALL browser processes (they spawn multiple child processes)
        $browserProcs = Get-Process -EA 0 | Where-Object { $_.ProcessName -match $Script:GFocus_Browsers } | Select-Object -ExpandProperty Id
        $browserConns = Get-NetTCPConnection -State Established -EA 0 | Where-Object { $_.OwningProcess -in $browserProcs }
        
        foreach ($conn in $browserConns) {
            $ip = $conn.RemoteAddress
            if ($ip -match "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1|fe80)") { continue }
            
            if ($Script:GFocus_BrowserAllowedIPs.ContainsKey($ip)) {
                $Script:GFocus_BrowserAllowedIPs[$ip] = $now.AddSeconds($Script:GFocus_GracePeriod)
            } elseif (-not $Script:GFocus_BrowserBlockedIPs.ContainsKey($ip)) {
                # Block non-user-initiated browser connection
                $ruleName = "GFocus_Browser_$($ip -replace '[.:]','_')"
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress $ip -Action Block -EA 0 | Out-Null
                $Script:GFocus_BrowserBlockedIPs[$ip] = $ruleName
                Write-Log "GFocus: Blocked browser connection to $ip (not user-initiated)"
            }
        }
        
        # Cleanup expired browser IPs
        $expired = @($Script:GFocus_BrowserAllowedIPs.Keys | Where-Object { $Script:GFocus_BrowserAllowedIPs[$_] -lt $now })
        foreach ($ip in $expired) { $Script:GFocus_BrowserAllowedIPs.Remove($ip) }
        
        # ==================== CONTROLLED APP HANDLING ====================
        # Apps like PowerShell only get network access when in foreground
        
        # Get all controlled app processes
        $controlledProcs = Get-Process -EA 0 | Where-Object { $_.ProcessName -match $Script:GFocus_ControlledApps }
        
        foreach ($appProc in $controlledProcs) {
            $appPid = $appProc.Id
            $appName = $appProc.ProcessName
            $hasForeground = ($appPid -eq $fgPid)
            
            # Get this app's connections
            $appConns = Get-NetTCPConnection -State Established -EA 0 | Where-Object { $_.OwningProcess -eq $appPid }
            $appIPs = @($appConns | ForEach-Object { $_.RemoteAddress } | Where-Object { $_ -notmatch "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1|fe80)" } | Select-Object -Unique)
            
            if ($hasForeground) {
                # App has foreground - allow its connections, remove any blocks
                if ($Script:GFocus_AppBlockedProcs.ContainsKey($appPid)) {
                    $blockInfo = $Script:GFocus_AppBlockedProcs[$appPid]
                    foreach ($ruleName in $blockInfo.RuleNames) {
                        Remove-NetFirewallRule -DisplayName $ruleName -EA 0
                    }
                    $Script:GFocus_AppBlockedProcs.Remove($appPid)
                    Write-Log "GFocus: $appName gained foreground - unblocked connections"
                }
            } else {
                # App lost foreground - block its external connections
                if ($appIPs.Count -gt 0 -and -not $Script:GFocus_AppBlockedProcs.ContainsKey($appPid)) {
                    $ruleNames = @()
                    foreach ($ip in $appIPs) {
                        $ruleName = "GFocus_App_${appName}_$($ip -replace '[.:]','_')"
                        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress $ip -Action Block -EA 0 | Out-Null
                        $ruleNames += $ruleName
                    }
                    $Script:GFocus_AppBlockedProcs[$appPid] = @{ RuleNames = $ruleNames; IPs = $appIPs }
                    Write-Log "GFocus: $appName lost foreground - blocked $($appIPs.Count) connection(s)"
                }
            }
        }
        
        # Cleanup rules for processes that no longer exist
        $deadPids = @($Script:GFocus_AppBlockedProcs.Keys | Where-Object { -not (Get-Process -Id $_ -EA 0) })
        foreach ($deadPid in $deadPids) {
            $blockInfo = $Script:GFocus_AppBlockedProcs[$deadPid]
            foreach ($ruleName in $blockInfo.RuleNames) {
                Remove-NetFirewallRule -DisplayName $ruleName -EA 0
            }
            $Script:GFocus_AppBlockedProcs.Remove($deadPid)
        }
        
        $Script:GFocus_LastForegroundPid = $fgPid
        
    } catch {}
}

# Script Content Scanner
function Invoke-ScriptContentScan {
    $badPatterns = @(
        "Invoke-Mimikatz", "Invoke-BloodHound", "Invoke-Kerberoast",
        "AmsiScanBuffer", "amsiInitFailed", "VirtualAlloc.*PAGE_EXECUTE",
        "CreateRemoteThread", "WriteProcessMemory", "ReflectiveLoader"
    )
    $pattern = $badPatterns -join "|"
    
    $scriptDirs = @("$env:TEMP", "$env:APPDATA", "$env:USERPROFILE\Downloads")
    
    foreach ($dir in $scriptDirs) {
        if (-not (Test-Path $dir)) { continue }
        
        Get-ChildItem $dir -Include *.ps1,*.vbs,*.js,*.bat,*.cmd -Recurse -EA 0 | ForEach-Object {
            try {
                $content = Get-Content $_.FullName -Raw -EA 0
                if ($content -match $pattern) {
                    Write-Log "Malicious script: $($_.FullName)"
                    Move-ToQuarantine -FilePath $_.FullName -Reason "Malicious script content"
                }
            } catch {}
        }
    }
}

# Startup Persistence Detection
function Invoke-StartupPersistenceDetection {
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($path in $startupPaths) {
        if (-not (Test-Path $path)) { continue }
        
        Get-ChildItem $path -EA 0 | ForEach-Object {
            $file = $_
            if ($file.Extension -match "\.(exe|dll|vbs|js|bat|cmd|ps1|scr)$") {
                $targetPath = if ($file.Extension -eq ".lnk") {
                    $shell = New-Object -ComObject WScript.Shell
                    $shell.CreateShortcut($file.FullName).TargetPath
                } else { $file.FullName }
                
                if ($targetPath -and (Test-Path $targetPath)) {
                    $sig = Get-AuthenticodeSignature $targetPath -EA 0
                    if ($sig.Status -ne "Valid") {
                        Write-Log "Startup persistence: Unsigned $($file.Name)"
                        Move-ToQuarantine -FilePath $file.FullName -Reason "Unsigned startup item"
                    }
                }
            }
        }
    }
}

# Driver Watcher
function Invoke-DriverWatcher {
    $badDriverNames = @("bfs", "unionfs", "rootkit", "stealth", "hide")
    $pattern = $badDriverNames -join "|"
    
    Get-WindowsDriver -Online -EA 0 | Where-Object { $_.DriverName -match $pattern } | ForEach-Object {
        Write-Log "Suspicious driver: $($_.DriverName)"
        Send-ThreatAlert -Severity "HIGH" -Message "Suspicious driver" -Details $_.DriverName
        
        # Try to stop and disable
        try {
            Stop-Service -Name $_.DriverName -Force -EA 0
            Set-Service -Name $_.DriverName -StartupType Disabled -EA 0
            Write-Log "Driver disabled: $($_.DriverName)"
        } catch {}
    }
}

Write-Log "Performing full system scan - all drives, all folders, monitored extensions only"

# Suspicious extensions (subset for double-extension detection)
$suspiciousExtensions = @('.com', '.exe', '.exif', '.dll', '.winmd')

# Function to detect multiple/suspicious extensions (e.g., file.pdf.exe, file.dll.exe.dll)
function Test-SuspiciousExtension {
    param([string]$FileName)
    
    # Check for multiple extensions
    $parts = $FileName -split '\.'
    if ($parts.Count -gt 2) {
        # Has multiple extensions - check if any are executable
        for ($i = 1; $i -lt $parts.Count - 1; $i++) {
            $ext = ".$($parts[$i])".ToLower()
            if ($suspiciousExtensions -contains $ext) {
                return $true  # Hidden executable extension
            }
        }
    }
    
    # Check for unicode tricks or excessive spaces
    if ($FileName -match '\s{2,}\.' -or $FileName -match '[\u200B-\u200D\uFEFF]') {
        return $true
    }
    
    return $false
}

# Get ALL drives - local, removable, and network
$allDrives = Get-WmiObject Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object {
    $_.DriveType -in @(2, 3, 4)  # 2=Removable, 3=Local, 4=Network
} | Select-Object -ExpandProperty DeviceID

Write-Log "Found drives to scan: $($allDrives -join ', ')"

foreach ($drive in $allDrives) {
    Write-Log "Scanning drive: $drive"
    
    try {
        # Scan only files with monitored extensions
        Get-ChildItem -Path "$drive\" -Recurse -File -ErrorAction SilentlyContinue | 
            Where-Object { $MonitoredExtensions -contains $_.Extension.ToLower() } | ForEach-Object {
            $file = $_
            $fileName = $file.Name
            $filePath = $file.FullName
            $ext = $file.Extension.ToLower()
            
            # Skip Windows core system files to avoid breaking the OS
            if ($filePath -match "\\Windows\\System32\\|\\Windows\\SysWOW64\\|\\Windows\\WinSxS\\|\\Windows\\assembly\\") {
                # But still check for suspicious names even in system folders
                if (Test-SuspiciousExtension -FileName $fileName) {
                    Write-Log "SUSPICIOUS: Multiple extension in system folder: $filePath"
                    Send-ThreatAlert -Severity "CRITICAL" -Message "Suspicious file in system folder" -Details $filePath
                }
                return
            }
            
            # Check for multiple/suspicious extensions (e.g., pdf.exe, doc.scr)
            if (Test-SuspiciousExtension -FileName $fileName) {
                Write-Log "THREAT: Multiple/suspicious extension detected: $filePath"
                Send-ThreatAlert -Severity "HIGH" -Message "Suspicious multiple extension" -Details $filePath
                Move-ToQuarantine -FilePath $filePath -Reason "Multiple/suspicious extension: $fileName"
                return
            }
            
            # Full threat analysis for ALL files
            Invoke-ThreatAnalysis -FilePath $filePath
            
            # Check for unsigned DLLs
            if ($ext -in @('.dll', '.winmd')) {
                try {
                    $sig = Get-AuthenticodeSignature $filePath -ErrorAction SilentlyContinue
                    if ($sig.Status -ne 'Valid') {
                        Write-Log "Unsigned DLL: $filePath"
                        Move-ToQuarantine -FilePath $filePath -Reason "Unsigned DLL"
                    }
                } catch {}
            }
        }
    } catch {
        Write-Log "Error scanning drive $drive : $_"
    }
}

Write-Log "Full system scan completed"

# Monitor ALL accessible drives for real-time protection
$monitorFolders = @()
foreach ($drive in $allDrives) {
    $monitorFolders += "$drive\"
}

if ($Config.EnableRealtimeMonitor) {
    Write-Log "Setting up real-time file monitoring"
    
    foreach ($folder in $monitorFolders) {
        if (-not (Test-Path $folder)) { continue }
        
        try {
            $watcher = New-Object IO.FileSystemWatcher $folder, '*.*' -Property @{
                IncludeSubdirectories = $true
                NotifyFilter          = [IO.NotifyFilters]'FileName, LastWrite'
            }
            
            Register-ObjectEvent $watcher Created -Action {
                $filePath = $Event.SourceEventArgs.FullPath
                $ext = [IO.Path]::GetExtension($filePath).ToLower()
                if ($using:MonitoredExtensions -contains $ext) {
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

if ($Config.EnableMemoryScanning) {
    Write-Log "Memory scanning enabled (runs in main loop)"
}

if ($KeyScramblerConfig.EnableKeyScrambler) {
    Start-KeyScrambler
}

$Script:LastDeepScan = [DateTime]::MinValue

function Invoke-DeepScan {
    if (-not $IsAdmin -or -not $Config.EnableThreatIntel) { return }
    
    $now = Get-Date
    $intervalSeconds = 60 * 60 * $BehaviorConfig.DeepScanIntervalHours
    
    if ($Script:LastDeepScan -ne [DateTime]::MinValue -and ($now - $Script:LastDeepScan).TotalSeconds -lt $intervalSeconds) {
        return
    }
    
    $Script:LastDeepScan = $now
    Write-Log "Running deep scan..."
    
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
    
    Write-Log "Deep scanner initialized (runs every $($BehaviorConfig.DeepScanIntervalHours) hours)"
}

Write-Log "All monitoring systems active"
Write-Host "`nAntivirus is now running" -ForegroundColor Green
Write-Host "Press [Ctrl+C] to stop" -ForegroundColor Yellow

try {
    while ($true) {
        try {
            # Core threat detection
            Invoke-ProcessAndNetworkScan
            Start-Sleep -Seconds 5
            
            Invoke-LOLBinDetection
            Start-Sleep -Seconds 5
            
            Invoke-ProcessAnomalyDetection
            Start-Sleep -Seconds 5
            
            Invoke-AMSIBypassDetection
            Start-Sleep -Seconds 5
            
            Invoke-CredentialDumpDetection
            Start-Sleep -Seconds 5
            
            Invoke-RansomwareDetection
            Start-Sleep -Seconds 5
            
            Invoke-ProcessHollowingDetection
            Start-Sleep -Seconds 5
            
            Invoke-NetworkAnomalyDetection
            Start-Sleep -Seconds 5
            
            Invoke-DLLHijackingDetection
            Start-Sleep -Seconds 5
            
            Invoke-TokenManipulationDetection
            Start-Sleep -Seconds 5
            
            Invoke-WMIPersistenceDetection
            Start-Sleep -Seconds 5
            
            Invoke-ScheduledTaskDetection
            Start-Sleep -Seconds 5
            
            Invoke-RegistryPersistenceDetection
            Start-Sleep -Seconds 5
            
            # Niche/specialized detections
            Invoke-NeuroBehaviorMonitor
            Start-Sleep -Seconds 5
            
            Invoke-PrivacyForgeSpoofing
            Start-Sleep -Seconds 5
            
            Invoke-ElfDLLUnloader
            Start-Sleep -Seconds 5
            
            Invoke-RootkitDetection
            Start-Sleep -Seconds 5
            
            Invoke-AttackToolsDetection
            Start-Sleep -Seconds 5
            
            Invoke-BeaconDetection
            Start-Sleep -Seconds 5
            
            Invoke-USBMonitoring
            Start-Sleep -Seconds 5
            
            Invoke-GFocus
            Start-Sleep -Seconds 5
            
            Invoke-ScriptContentScan
            Start-Sleep -Seconds 5
            
            Invoke-StartupPersistenceDetection
            Start-Sleep -Seconds 5
            
            Invoke-DriverWatcher
            Start-Sleep -Seconds 5
            
            # Advanced abuse detection (new)
            Invoke-CameraMicAccessDetection
            Start-Sleep -Seconds 5
            
            Invoke-COMHijackingDetection
            Start-Sleep -Seconds 5
            
            Invoke-ProxySettingsAbuseDetection
            Start-Sleep -Seconds 5
            
            Invoke-DLLSearchOrderHijacking
            Start-Sleep -Seconds 5
            
            Invoke-ProxywareDetection
            Start-Sleep -Seconds 5
            
            Invoke-ShadowProxyCaptureDetection
            Start-Sleep -Seconds 5
            
            # Memory scanning (previously in separate jobs)
            Invoke-MemoryScan
            Start-Sleep -Seconds 5
            
            Invoke-YaraMemoryScan
            Start-Sleep -Seconds 5
            
            # Deep scan (runs periodically based on interval)
            Invoke-DeepScan
            Start-Sleep -Seconds 5
            
            Write-Log "Scan cycle completed"
        } catch {
            Write-Log "Scan cycle error: $_"
        }
    }
} catch {
    Write-Log "Main loop terminated: $($_.Exception.Message)"
    Write-Host "`nAntivirus stopped. Check log file: $($Config.LogFile)" -ForegroundColor Red
}