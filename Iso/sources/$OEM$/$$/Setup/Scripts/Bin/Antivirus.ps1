# Ultimate Antivirus by Gorstak - Extended EDR Version
# Combines hash lookups, memory scanning, real-time monitoring, smart DLL blocking
# + behavior monitoring, persistence & fileless detection, threat intel updates, alerting
$Base = "C:\ProgramData\Antivirus"
$Quarantine = Join-Path $Base "Quarantine"
$Backup = Join-Path $Base "Backup"
$LogFile = Join-Path $Base "antivirus.log"
$BlockedLog = Join-Path $Base "blocked.log"
$Database = Join-Path $Base "scanned_files.txt"
$RulesDir = Join-Path $Base "rules"
$scannedFiles = @{}
# Task configuration
$taskName = "UltimateAntivirusStartup"
$taskDescription = "Ultimate Antivirus - Runs at user logon with admin privileges"
$scriptDir = "C:\Windows\Setup\Scripts\Bin"
$scriptPath = "$scriptDir\Antivirus.ps1"
# Config / feature flags
$DeepScanHours = 6
$ThreatIntelDays = 7
$BehaviorKillEnabled = $true
$AutoBlockC2 = $true
# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
# Allowed system accounts
$AllowedSIDs = @(
    'S-1-2-0', # Console user
    'S-1-5-20' # Network Service
)
# Optional MalwareBazaar API key
$MalwareBazaarAuthKey = ""
# Free public hash lookup endpoints
$CirclLookupBase = "https://hashlookup.circl.lu/lookup/sha256"
$CymruMHR = "https://api.malwarehash.cymru.com/v1/hash"
# High-risk paths where unsigned DLLs are suspicious
$RiskyPaths = @(
    '\temp\','\downloads\','\appdata\local\temp\','\public\','\windows\temp\',
    '\appdata\roaming\','\desktop\'
)
# Comprehensive list of monitored extensions
$MonitoredExtensions = @(
    # Standard executable and script extensions
    '.exe','.dll','.sys','.ocx','.scr','.com','.cpl','.msi','.drv','.winmd',
    '.ps1','.bat','.cmd','.vbs','.js','.hta','.jse','.wsf','.wsh','.psc1',
   
    # Extended list (unchanged from original)
    '.zoo','.zlo','.zfsendtotarget','.z','.xz','.xsl','.xps','.xpi','.xnk','.xml',
    '.xlw','.xltx','.xltm','.xlt','.xlsx','.xlsm','.xlsb','.xls','.xlm','.xll',
    '.xld','.xlc','.xlb','.xlam','.xla','.xip','.xbap','.xar','.wwl','.wsc',
    '.ws','.wll','.wiz','.website','.webpnp','.webloc','.wbk','.was','.vxd',
    '.vsw','.vst','.vss','.vsmacros','.vhdx','.vhd','.vbp','.vb','.url','.tz',
    '.txz','.tsp','.tpz','.tool','.tmp','.tlb','.theme','.tgz','.terminal',
    '.term','.tbz','.taz','.tar','.swf','.stm','.spl','.slk','.sldx',
    '.sldm','.sit','.shs','.shb','.settingcontent-ms','.search-ms','.searchconnector-ms',
    '.sea','.sct','.scf','.rtf','.rqy','.rpy','.rev','.reg','.rb',
    '.rar','.r09','.r08','.r07','.r06','.r05','.r04','.r03','.r02','.r01',
    '.r00','.pyzw','.pyz','.pyx','.pywz','.pyw','.pyt','.pyp','.pyo','.pyi',
    '.pyde','.pyd','.pyc','.py3','.py','.pxd','.pstreg','.pst','.psdm1','.psd1',
    '.prn','.printerexport','.prg','.prf','.pptx','.pptm','.ppt','.ppsx','.ppsm',
    '.pps','.ppam','.ppa','.potx','.potm','.pot','.plg','.pl','.pkg','.pif',
    '.pi','.perl','.pcd','.pa','.osd','.oqy','.ops','.one','.ods',
    '.ntfs','.nsh','.nls','.mydocs','.mui','.msu','.mst','.msp','.mshxml',
    '.msh2xml','.msh2','.msh1xml','.msh1','.msh','.mof','.mmc','.mhtml','.mht',
    '.mdz','.mdw','.mdt','.mdn','.mdf','.mde','.mdb','.mda','.mcl','.mcf',
    '.may','.maw','.mav','.mau','.mat','.mas','.mar','.maq','.mapimail',
    '.manifest','.mam','.mag','.maf','.mad','.lzh','.local','.library-ms',
    '.lha','.ldb','.laccdb','.ksh','.job','.jnlp','.jar','.its','.isp','.iso',
    '.iqy','.ins','.ini','.inf','.img','.ime','.ie','.hwp','.htt','.htm',
    '.htc','.hpj','.hlp','.hex','.gz','.grp','.glk','.gadget',
    '.fxp','.fon','.fat','.elf','.ecf','.dqy','.dotx','.dotm',
    '.dot','.docm','.docb','.doc','.dmg','.dir','.dif','.diagcab',
    '.desktop','.desklink','.der','.dcr','.db','.csv','.csh','.crx','.crt',
    '.crazy','.cpx','.command','.cnt','.cnv','.clb',
    '.class','.cla','.chm','.chi','.cfg','.cer','.cdb','.cab','.bzip2','.bzip',
    '.bz2','.bz','.bas','.ax','.asx','.aspx','.asp','.asa','.arj',
    '.arc','.appref-ms','.application','.app','.air','.adp','.adn','.ade',
    '.ad','.acm','.accdu','.accdt','.accdr','.accde','.accda','.c','.h'
)
# Protected processes we never kill
$ProtectedProcessNames = @('System','lsass','wininit','winlogon','csrss','services','smss',
                           'Registry','svchost','explorer','dwm','SearchUI','SearchIndexer','Idle')
# Create folders
New-Item -ItemType Directory -Path $Base,$Quarantine,$Backup,$RulesDir -Force | Out-Null
# ------------------------- Logging with Rotation -------------------------
function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding ASCII
    Write-Host $line
   
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$Base\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $LogFile -NewName $archiveName -ErrorAction SilentlyContinue
    }
}
Log "=== Ultimate Antivirus starting ==="
Log "Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
# ------------------------- Setup & Task Registration -------------------------
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Log "Set execution policy to Bypass"
}
if ($isAdmin) {
    if (-not (Test-Path $scriptDir)) {
        New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath -ErrorAction SilentlyContinue).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue).LastWriteTime) {
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction SilentlyContinue
        Log "Updated script to: $scriptPath"
    }
   
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $existingTask) {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction SilentlyContinue
        Log "Scheduled task registered as SYSTEM"
    }
}
# ------------------------- Database Management -------------------------
if (Test-Path $Database) {
    try {
        $scannedFiles.Clear()
        $lines = Get-Content $Database -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                $scannedFiles[$matches[1]] = [bool]::Parse($matches[2])
            }
        }
        Log "Loaded $($scannedFiles.Count) entries from database"
    } catch {
        Log "Failed to load database: $($_.Exception.Message)"
        $scannedFiles.Clear()
    }
} else {
    New-Item -Path $Database -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
    Log "Created new database"
}
# ------------------------- File Exclusions -------------------------
function Should-ExcludeFile {
    param ([string]$filePath)
    $lowerPath = $filePath.ToLower()
   
    if ($lowerPath -like "*\assembly\*") { return $true }
    if ($lowerPath -like "*ctfmon*" -or $lowerPath -like "*msctf.dll" -or $lowerPath -like "*msutb.dll") { return $true }
    if ($lowerPath -like "*\windows\system32\config\*") { return $true }
    if ($lowerPath -like "*\winsxs\*") { return $true }
    if ($lowerPath -like "*\microsoft.net\*") { return $true }
   
    return $false
}
# ------------------------- Fast Signature + CIRCL Check -------------------------
function Test-FastAllow($filePath) {
    if (-not (Test-Path $filePath)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature $filePath -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return $true }
    } catch {}
    try {
        $hash = (Get-FileHash $filePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        $r = Invoke-RestMethod "$CirclLookupBase/$hash" -TimeoutSec 4 -ErrorAction SilentlyContinue
        if ($r) { return $true }
    } catch {}
    return $false
}
# ------------------------- Hash Computation -------------------------
function Compute-Hash($path) {
    try {
        return (Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    } catch {
        return $null
    }
}
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        return $null
    }
}
# ------------------------- Hash Lookup Services -------------------------
function Query-CIRCL($sha256) {
    try {
        $resp = Invoke-RestMethod "$CirclLookupBase/$sha256" -TimeoutSec 8 -ErrorAction Stop
        return ($resp -and ($resp | ConvertTo-Json -Depth 3).Length -gt 10)
    } catch { return $false }
}
function Query-CymruMHR($sha256) {
    try {
        $resp = Invoke-RestMethod "$CymruMHR/$sha256" -TimeoutSec 8 -ErrorAction Stop
        return ($resp.detections -and $resp.detections -ge 60)
    } catch { return $false }
}
function Query-MalwareBazaar($sha256) {
    if (-not $sha256) { return $false }
    $body = @{ query = 'get_info'; sha256_hash = $sha256 }
    if ($MalwareBazaarAuthKey) { $body.api_key = $MalwareBazaarAuthKey }
    try {
        $resp = Invoke-RestMethod "https://mb-api.abuse.ch/api/v1/" -Method Post -Body $body -TimeoutSec 10
        return ($resp.query_status -eq 'ok' -or ($resp.data -and $resp.data.Count -gt 0))
    } catch { return $false }
}
# ------------------------- Smart Unsigned DLL/WINMD Blocking -------------------------
function Is-SuspiciousUnsignedDll($file) {
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin @('.dll','.winmd')) { return $false }
    try {
        $sig = Get-AuthenticodeSignature $file -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return $false }
    } catch { return $false }
    $size = (Get-Item $file -ErrorAction SilentlyContinue).Length
    $pathLower = $file.ToLower()
    $name = [IO.Path]::GetFileName($file).ToLower()
    foreach ($rp in $RiskyPaths) {
        if ($pathLower -like "*$rp*" -and $size -lt 3MB) { return $true }
    }
    if ($pathLower -like "*\appdata\roaming\*" -and $size -lt 800KB -and $name -match '^[a-z0-9]{4,12}\.(dll|winmd)$') {
        return $true
    }
   
    return $false
}
# ------------------------- File Lock Handling -------------------------
function Is-Locked($file) {
    try {
        [IO.File]::Open($file,'Open','ReadWrite','None').Close()
        return $false
    } catch {
        return $true
    }
}
function Try-ReleaseFile($file) {
    $holders = Get-Process | Where-Object {
        try { $_.Modules.FileName -contains $file } catch { $false }
    } | Select-Object -Unique
    foreach ($p in $holders) {
        if ($ProtectedProcessNames -contains $p.Name) { continue }
        try { $p.CloseMainWindow(); Start-Sleep -Milliseconds 600 } catch {}
        if (!$p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    return -not (Is-Locked $file)
}
# ------------------------- Ownership & Permissions -------------------------
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A 2>&1 | Out-Null
        icacls $filePath /reset 2>&1 | Out-Null
        icacls $filePath /grant "Administrators:F" /inheritance:d 2>&1 | Out-Null
        Log "Set ownership/permissions: $filePath"
        return $true
    } catch {
        return $false
    }
}
# ------------------------- Process Termination -------------------------
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object {
            try { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) } catch { $false }
        }
        foreach ($process in $processes) {
            if ($ProtectedProcessNames -contains $process.Name) { continue }
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
        }
    } catch {
        try {
            taskkill /F /FI "MODULES eq $(Split-Path $filePath -Leaf)" 2>&1 | Out-Null
        } catch {}
    }
}
# ------------------------- Quarantine -------------------------
function Do-Quarantine($file, $reason) {
    if (-not (Test-Path $file)) { return }
   
    if (Is-Locked $file) {
        Try-ReleaseFile $file | Out-Null
    }
    $name = [IO.Path]::GetFileName($file)
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak = Join-Path $Backup ("$name`_$ts.bak")
    $q = Join-Path $Quarantine ("$name`_$ts")
    try {
        Copy-Item $file $bak -Force -ErrorAction Stop
        Move-Item $file $q -Force -ErrorAction Stop
        Log "QUARANTINED [$reason]: $file → $q"
    } catch {
        Log "QUARANTINE FAILED [$reason]: $file - $_"
        if (Set-FileOwnershipAndPermissions $file) {
            try {
                Copy-Item $file $bak -Force -ErrorAction Stop
                Move-Item $file $q -Force -ErrorAction Stop
                Log "QUARANTINED (after permission fix) [$reason]: $file"
            } catch {
                Log "QUARANTINE STILL FAILED: $_"
            }
        }
    }
}
function Deny-Execution($file,$pid,$type) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | BLOCKED $type | $file | PID $pid" | Out-File $BlockedLog -Append
    Log "BLOCKED $type | $file | PID $pid"
   
    try {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc -and ($ProtectedProcessNames -notcontains $proc.ProcessName)) {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
    } catch {}
   
    if (Test-Path $file) {
        Do-Quarantine $file "Real-time $type block"
    }
}
# ------------------------- Threat Intel Update -------------------------
function Update-ThreatIntelligence {
    param([string]$BasePath = $Base)
   
    $yaraRules = @(
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_campaign_uac.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_malware_set.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/Malware.yar"
    )
   
    $hashLists = @(
        "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latest-hashes.txt"
    )
   
    Log "Updating threat intelligence..."
   
    foreach ($url in $yaraRules) {
        $fileName = Split-Path $url -Leaf
        $output = Join-Path $RulesDir $fileName
        try {
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -TimeoutSec 15
            Log "Downloaded YARA rule: $fileName"
        } catch {
            Log "Failed to download ${fileName}: $_"
        }
    }
    foreach ($url in $hashLists) {
        $fileName = Split-Path $url -Leaf
        $output = Join-Path $BasePath $fileName
        try {
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -TimeoutSec 15
            Log "Downloaded hash list: $fileName"
        } catch {
            Log "Failed to download hash list ${fileName}: $_"
        }
    }
}
# ------------------------- Alerting & Reporting -------------------------
$global:EmailConfig = $null
$global:WebhookUrl = $null
function Send-Alert {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$Details
    )
    $sevUpper = $Severity.ToUpper()
    $entryType = [System.Diagnostics.EventLogEntryType]::Information
    switch ($sevUpper) {
        "CRITICAL" { $entryType = [System.Diagnostics.EventLogEntryType]::Error }
        "HIGH" { $entryType = [System.Diagnostics.EventLogEntryType]::Warning }
        "MEDIUM" { $entryType = [System.Diagnostics.EventLogEntryType]::Warning }
        default { $entryType = [System.Diagnostics.EventLogEntryType]::Information }
    }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("UltimateAntivirus")) {
            New-EventLog -LogName Application -Source "UltimateAntivirus" -ErrorAction SilentlyContinue
        }
    } catch {}
    try {
        Write-EventLog -LogName Application -Source "UltimateAntivirus" `
            -EventId 1001 -Message "$Message - $Details" `
            -EntryType $entryType -ErrorAction SilentlyContinue
    } catch {}
    if ($global:EmailConfig) {
        try {
            Send-MailMessage @global:EmailConfig `
                -Subject "[$sevUpper] Antivirus Alert" `
                -Body "$Message`n`nDetails: $Details" -ErrorAction SilentlyContinue
        } catch { Log "Email alert failed: $_" }
    }
    if ($global:WebhookUrl) {
        try {
            $payload = @{
                text = "[$sevUpper] $Message"
                details = $Details
                timestamp = Get-Date -Format "o"
            } | ConvertTo-Json
            Invoke-WebRequest -Uri $global:WebhookUrl -Method Post -Body $payload -ErrorAction SilentlyContinue
        } catch { Log "Webhook alert failed: $_" }
    }
}
# ------------------------- Main Decision Engine -------------------------
function Decide-And-Act($file) {
    if (-not (Test-Path $file -PathType Leaf)) { return }
    if (Should-ExcludeFile $file) { return }
   
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin $MonitoredExtensions) { return }
    $sha256 = Compute-Hash $file
    if (-not $sha256) { return }
    if ($scannedFiles.ContainsKey($sha256)) {
        if (-not $scannedFiles[$sha256]) {
            Do-Quarantine $file "Previously identified threat"
        }
        return
    }
    if (Query-CIRCL($sha256)) {
        $scannedFiles[$sha256] = $true
        "$sha256,true" | Out-File -FilePath $Database -Append -Encoding UTF8
        Log "ALLOWED (CIRCL trusted): $file"
        return
    }
    if (Query-CymruMHR($sha256)) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "Cymru MHR match (≥60% AVs)"
        Send-Alert -Severity "HIGH" -Message "Known malware detected" -Details $file
        return
    }
   
    if (Query-MalwareBazaar($sha256)) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "MalwareBazaar match"
        Send-Alert -Severity "HIGH" -Message "MalwareBazaar match" -Details $file
        return
    }
    if (Is-SuspiciousUnsignedDll $file) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "Suspicious unsigned DLL/WINMD in risky location"
        Send-Alert -Severity "MEDIUM" -Message "Suspicious unsigned DLL blocked" -Details $file
        return
    }
    $fileHash = Calculate-FileHash $file
    if ($fileHash) {
        $isValid = $fileHash.Status -eq "Valid"
        $scannedFiles[$sha256] = $isValid
        "$sha256,$isValid" | Out-File -FilePath $Database -Append -Encoding UTF8
       
        if ($isValid) {
            Log "ALLOWED (signed): $file"
        } else {
            Log "ALLOWED (clean but unsigned): $file"
        }
    }
}
# ------------------------- Memory Scanner -------------------------
function Start-MemoryScanner {
    $yaraExe = "$Base\yara64.exe"
    $yaraRule = "$Base\mem.yar"
    if (Test-Path $yaraExe) {
        if (-not (Test-Path $yaraRule)) {
            try {
                Invoke-WebRequest "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/memory.yar" -OutFile $yaraRule -UseBasicParsing -TimeoutSec 10
            } catch {}
        }
        Log "[+] Full YARA memory scanner active"
        Start-Job -ScriptBlock {
            $exe = $using:yaraExe; $rule = $using:yaraRule; $log = "$using:Base\memory_hits.log"
            while ($true) {
                Start-Sleep -MilliSeconds 10
                Get-Process | Where-Object {
                    $_.WorkingSet64 -gt 150MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp'
                } | ForEach-Object {
                    & $exe -w $rule -p $_.Id 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        "$(Get-Date) | YARA HIT → $($_.Name) ($($_.Id))" | Out-File $log -Append
                        if ($using:ProtectedProcessNames -notcontains $_.Name) {
                            Stop-Process $_.Id -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        } | Out-Null
        return
    }
    Log "[+] PowerShell memory scanner active"
    Start-Job -ScriptBlock {
        $log = "$using:Base\ps_memory_hits.log"
        $EvilStrings = @(
            'mimikatz','sekurlsa::','kerberos::','lsadump::','wdigest','tspkg',
            'http-beacon','https-beacon','cobaltstrike','sleepmask','reflective',
            'amsi.dll','AmsiScanBuffer','EtwEventWrite','MiniDumpWriteDump',
            'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
            'ReflectiveLoader','sharpchrome','rubeus','safetykatz','sharphound'
        )
        while ($true) {
            Start-Sleep -MilliSeconds 10
            Get-Process | Where-Object {
                $_.WorkingSet64 -gt 100MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp|excel|word|outlook'
            } | ForEach-Object {
                $hit = $false
                try {
                    $_.Modules | ForEach-Object {
                        if ($EvilStrings | Where-Object { $_.ModuleName -match $_ -or $_.FileName -match $_ }) {
                            $hit = $true
                        }
                    }
                } catch {}
                if ($hit) {
                    "$(Get-Date) | PS MEMORY HIT → $($_.Name) ($($_.Id))" | Out-File $log -Append
                    if ($using:ProtectedProcessNames -notcontains $_.Name) {
                        Stop-Process $_.Id -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    } | Out-Null
}
Log "[+] Starting reflective payload detector"
Start-Job -ScriptBlock {
    $log = "$using:Base\manual_map_hits.log"
    while ($true) {
        Start-Sleep -MilliSeconds 10
        Get-Process | Where-Object { $_.WorkingSet64 -gt 40MB } | ForEach-Object {
            $p = $_
            $sus = $false
            if (-not $p.Path -or $p.Path -eq '' -or $p.Path -match '\$Unknown\$') { $sus = $true }
            if ($p.Modules | Where-Object { $_.FileName -eq '' -or $_.ModuleName -eq '' }) { $sus = $true }
            if ($sus) {
                "$([DateTime]::Now) | REFLECTIVE PAYLOAD → $($p.Name) ($($p.Id)) Path='$($p.Path)'" | Out-File $log -Append
                if ($using:ProtectedProcessNames -notcontains $p.Name) {
                    Stop-Process $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
} | Out-Null
# ------------------------- Behavior / Fileless / Persistence -------------------------
function Detect-FilelessMalware {
    $detections = @()
    try {
        $ps = Get-Process -Name powershell -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -match "encodedcommand|enc|iex|invoke-expression" -or
            ($_.Modules | Where-Object { $_.ModuleName -eq "" -or $_.FileName -eq "" })
        }
        if ($ps) {
            $detections += [PSCustomObject]@{
                Indicator = "PowerShellWithoutFile"
                Details = $ps | Select-Object Name,Id,MainWindowTitle
            }
            Log "Fileless indicator: PowerShellWithoutFile"
        }
    } catch {}
    try {
        $wmi = Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue |
               Where-Object { $_.Query -match "powershell|vbscript|javascript" }
        if ($wmi) {
            $detections += [PSCustomObject]@{
                Indicator = "WMIEventSubscriptions"
                Details = $wmi | Select-Object Name,Query
            }
            Log "Fileless indicator: WMIEventSubscriptions"
        }
    } catch {}
    try {
        $keys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        foreach ($key in $keys) {
            if (Test-Path $key) {
                Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | ForEach-Object {
                        $val = $_.Value
                        if ($val -and $val -match "powershell.*-enc|mshta|regsvr32.*scrobj") {
                            $detections += [PSCustomObject]@{
                                Indicator = "RegistryScripts"
                                Details = "$key -> $($_.Name)"
                            }
                            Log "Fileless indicator: RegistryScripts at $key"
                        }
                    }
                }
            }
        }
    } catch {}
    return $detections
}
function Find-PersistenceMechanisms {
    $persistenceLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "C:\Windows\System32\Tasks",
        "C:\Windows\Tasks",
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Google\Chrome\User Data\Default\Extensions",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\extensions"
    )
   
    $suspiciousEntries = @()
   
    foreach ($location in $persistenceLocations) {
        try {
            if ($location -match "^HK") {
                Get-Item $location -ErrorAction SilentlyContinue |
                    Get-ItemProperty -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $props = $_ | Get-Member -MemberType NoteProperty
                        foreach ($prop in $props) {
                            $value = $_.$($prop.Name)
                            if ($value -and $value -match "\.(exe|dll|ps1|vbs|js|bat|cmd)$") {
                                $suspiciousEntries += [PSCustomObject]@{
                                    Location = $location
                                    Name = $prop.Name
                                    Value = $value
                                    Type = "Registry"
                                }
                            }
                        }
                    }
            } elseif (Test-Path $location) {
                Get-ChildItem $location -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -match '\.(exe|dll|lnk|ps1|vbs|js)$' } |
                    ForEach-Object {
                        $suspiciousEntries += [PSCustomObject]@{
                            Location = $location
                            Name = $_.Name
                            Value = $_.FullName
                            Type = "FileSystem"
                        }
                    }
            }
        } catch {
            Log "Error checking persistence location $location : $_"
        }
    }
   
    return $suspiciousEntries
}
# ------------------------- Behavior + Network Heuristics -------------------------
function Test-ProcessHollowing {
    param($Process)
    try {
        $procPath = $Process.Path
    } catch { return $false }
    try {
        $image = Get-Process -Id $Process.Id -Module -ErrorAction SilentlyContinue
    } catch { $image = $null }
    if ($image -and $procPath -and $image.Modules.Count -gt 0) {
        return ($image.Modules[0].FileName -ne $procPath)
    }
    return $false
}
function Test-CredentialAccess {
    param($Process)
    try {
        $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)").CommandLine
    } catch { $cmdline = "" }
    if ($cmdline -match "mimikatz|procdump|sekurlsa|lsadump") { return $true }
    if ($Process.ProcessName -match "vaultcmd|cred") { return $true }
    return $false
}
function Test-LateralMovement {
    param($Process)
    try {
        $connections = Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue
    } catch { return $false }
    $remoteIPs = $connections | Where-Object {
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" -and
        $_.RemoteAddress -ne "0.0.0.0"
    }
    return (($remoteIPs | Measure-Object).Count -gt 5)
}
function Check-NetworkC2 {
    param($Connection)
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 8443, 9001, 1337, 31337)
    $knownC2Servers = @(
        "pastebin.com", "github.io", "bit.ly", "tinyurl.com",
        ".*\.ddns\.net$", ".*\.no-ip\.org$", ".*\.duckdns\.org$"
    )
    if ($Connection.RemotePort -notin $suspiciousPorts) { return $false }
    try {
        $dnsName = [System.Net.Dns]::GetHostEntry($Connection.RemoteAddress).HostName
    } catch { $dnsName = "" }
    foreach ($pattern in $knownC2Servers) {
        if ($dnsName -match $pattern) { return $true }
    }
    return $false
}
# ------------------------- Process + Network Scanner -------------------------
function Scan-ProcessesAndNetwork() {
    Get-Process | ForEach-Object {
        $p = $_
        try {
            $exe = $p.MainModule.FileName
        } catch { $exe = $null }
        if ($exe -and (Test-Path $exe)) {
            Decide-And-Act $exe
        }
        # Lightweight behavior checks
        if ($BehaviorKillEnabled -and ($ProtectedProcessNames -notcontains $p.Name)) {
            try {
                if (Test-ProcessHollowing -Process $p) {
                    Log "BEHAVIOR: Process hollowing suspected: $($p.Name) PID $($p.Id)"
                    Send-Alert -Severity "HIGH" -Message "Process hollowing" -Details "$($p.Name) PID $($p.Id)"
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                } elseif (Test-CredentialAccess -Process $p) {
                    Log "BEHAVIOR: Credential-access tool suspected: $($p.Name) PID $($p.Id)"
                    Send-Alert -Severity "HIGH" -Message "Credential access behavior" -Details "$($p.Name) PID $($p.Id)"
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                } elseif (Test-LateralMovement -Process $p) {
                    Log "BEHAVIOR: Lateral movement suspected: $($p.Name) PID $($p.Id)"
                    Send-Alert -Severity "MEDIUM" -Message "Lateral movement behavior" -Details "$($p.Name) PID $($p.Id)"
                }
            } catch {}
        }
    }
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Established','Listen' } | ForEach-Object {
        $conn = $_
        try {
            $p = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        } catch { $p = $null }
        if ($p) {
            try {
                $exe = $p.MainModule.FileName
                if ($exe) { Decide-And-Act $exe }
            } catch {}
            if ($AutoBlockC2 -and (Check-NetworkC2 -Connection $conn)) {
                Log "NETWORK: Suspicious C2 pattern from $($p.Name) PID $($p.Id) to $($conn.RemoteAddress):$($conn.RemotePort)"
                Send-Alert -Severity "HIGH" -Message "Suspicious C2 connection" -Details "$($p.Name) PID $($p.Id) $($conn.RemoteAddress):$($conn.RemotePort)"
                if ($ProtectedProcessNames -notcontains $p.Name) {
                    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
                }
                try {
                    New-NetFirewallRule -DisplayName "Block C2 $($conn.RemoteAddress)" `
                        -Direction Outbound -Protocol TCP `
                        -RemoteAddress $conn.RemoteAddress `
                        -Action Block -Enabled True -ErrorAction SilentlyContinue | Out-Null
                } catch {}
            }
        }
    }
}
# ------------------------- Initial Scan -------------------------
Log "Performing initial scan of high-risk folders"
@("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Decide-And-Act $_.FullName
        }
    }
}
# ------------------------- Simple & Safe Real-Time Monitoring -------------------------
$WatchFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "C:\Windows\Temp"
)
$global:FileWatchers = @()
$global:FileEventSubs = @()
# One single action used by ALL watchers → no memory leak
$SafeAction = {
    $path = $Event.SourceEventArgs.FullPath
    $ext = [IO.Path]::GetExtension($path).ToLower()
    if ($MonitoredExtensions -contains $ext) {
        Start-Sleep -Milliseconds 800
        Decide-And-Act $path
    }
}
foreach ($folder in $WatchFolders) {
    if (-not (Test-Path $folder)) { continue }
   
    $watcher = New-Object IO.FileSystemWatcher $folder, "*.*"
    $watcher.IncludeSubdirectories = $true
    $watcher.NotifyFilter = 'FileName, LastWrite'
   
    # Use the SAME action every time
$createdSub = Register-ObjectEvent $watcher Created -Action $SafeAction
$changedSub = Register-ObjectEvent $watcher Changed -Action $SafeAction
$global:FileEventSubs += $createdSub, $changedSub
$global:FileWatchers += $watcher
   
    $watcher.EnableRaisingEvents = $true
}
Log "Real-time monitoring started — safe and low-memory version active!"
# ------------------------- Cleanup Function (Call on exit or manually) -------------------------
function Stop-RealTimeMonitoring {
    Log "Stopping real-time file monitoring and releasing resources..."
    foreach ($sub in $global:FileEventSubs) {
        try {
            Unregister-Event -SubscriptionId $sub.Id -ErrorAction SilentlyContinue
        } catch {}
    }
    foreach ($watcher in $global:FileWatchers) {
        try {
            $watcher.EnableRaisingEvents = $false
            $watcher.Dispose()
        } catch {}
    }
    $global:FileWatchers = @()
    $global:FileEventSubs = @()
   
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
   
    Log "File watchers cleaned up and memory released."
}
# Register cleanup when PowerShell exits (e.g., script stopped or system shutdown)
$null = Register-EngineEvent PowerShell.Exiting -Action {
    Stop-RealTimeMonitoring
}
# ------------------------- Start the Monitoring -------------------------
Start-RealTimeMonitoring
Log "Real-time file watchers active and optimized."
# ------------------------- WMI Real-time Execution Hooks -------------------------
Log "Registering WMI real-time execution monitors"
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $e = $Event.SourceEventArgs.NewEvent
    $Path = $e.ProcessName
    $PID = $e.ProcessId
    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }
    if ($AllowedSIDs -contains $OwnerSID) {
        if (Test-FastAllow $Path) { return }
    }
    Deny-Execution $Path $PID "EXE"
} | Out-Null
Register-WmiEvent -Query "SELECT * FROM Win32_ModuleLoadTrace" -Action {
    $e = $Event.SourceEventArgs.NewEvent
    $Path = $e.ImageName
    $PID = $e.ProcessId
    if (-not (Test-Path $Path)) { return }
    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }
    if ($AllowedSIDs -contains $OwnerSID) {
        if (Test-FastAllow $Path) { return }
    }
    Deny-Execution $Path $PID "DLL"
} | Out-Null
# ------------------------- Start Memory Scanners -------------------------
Start-MemoryScanner
# ------------------------- Threat Intel + Deep Scan Scheduler -------------------------
if ($isAdmin) {
    $lastUpdateFile = Join-Path $Base "last_update.txt"
    $now = Get-Date
    $doUpdate = $false
    if (-not (Test-Path $lastUpdateFile)) {
        $doUpdate = $true
    } else {
        try {
            $last = (Get-Item $lastUpdateFile).LastWriteTime
            if ($last -lt $now.AddDays(-$ThreatIntelDays)) { $doUpdate = $true }
        } catch { $doUpdate = $true }
    }
    if ($doUpdate) {
        Update-ThreatIntelligence
        $now | Out-File $lastUpdateFile
    }
    Start-Job -ScriptBlock {
        $base = $using:Base
        $deepHours = $using:DeepScanHours
        while ($true) {
            Start-Sleep -Seconds (60 * 60 * $deepHours)
            try {
                $persistence = Find-PersistenceMechanisms
                if ($persistence -and $persistence.Count -gt 0) {
                    $csv = Join-Path $base "persistence_scan.csv"
                    $persistence | Export-Csv $csv -NoTypeInformation
                    Log "Persistence scan found $($persistence.Count) entries -> $csv"
                    Send-Alert -Severity "MEDIUM" -Message "Persistence mechanisms detected" -Details "Count: $($persistence.Count)"
                }
            } catch {
                Log "Persistence scan error: $_"
            }
            try {
                $fileless = Detect-FilelessMalware
                if ($fileless -and $fileless.Count -gt 0) {
                    $xml = Join-Path $base "fileless_detections.xml"
                    $fileless | Export-Clixml $xml
                    Log "Fileless malware indicators detected -> $xml"
                    Send-Alert -Severity "HIGH" -Message "Fileless indicators detected" -Details "Count: $($fileless.Count)"
                }
            } catch {
                Log "Fileless scan error: $_"
            }
        }
    } | Out-Null
}
# ------------------------- Main Monitoring Loop -------------------------
Log "All monitoring systems active. Starting main loop..."
Write-Host "Ultimate Antivirus running. Press [Ctrl] + [C] to stop."
try {
    while ($true) {
        try {
            Scan-ProcessesAndNetwork
            Log "Periodic scan completed"
        } catch {
            Log "Scan loop error: $_"
        }
        Start-Sleep -Seconds 30
    }
} catch {
    Log "Main loop crashed: $($_.Exception.Message)"
    Write-Host "Script crashed. Check $LogFile for details."
}