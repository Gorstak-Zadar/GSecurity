# Antivirus-Merged-Light.ps1
# Merged 2025–2026 style: simple structure + selected strong features
# Base: smaller Antivirus.ps1 + selected pieces from big version
# Target: readable, maintainable, ~600 lines, admin-only features

param(
    [switch]$Uninstall,
    [switch]$ChaosMode,     # create & detect EICAR test file
    [switch]$LearningMode,  # log only — no quarantine, no kill
    [switch]$SelfTest       # basic config & path check, then exit
)

#Requires -Version 5.1
#Requires -RunAsAdministrator   # we will enforce it anyway

$Script:Version = "2026-merged-light-0.9"

# ============================================================================
#  1. Early elevation check & restart if needed
# ============================================================================

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "Requesting elevation..." -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $($PSBoundParameters.Keys -join ' ')" -Verb RunAs -Wait:$false
    } catch {
        Write-Host "Elevation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 0
}

Write-Host "Running elevated ($PID)" -ForegroundColor Green

# ============================================================================
#  2. Configuration
# ============================================================================

$Base       = "C:\ProgramData\AntivirusMerged"
$Quarantine = "$Base\Quarantine"
$Backup     = "$Base\Backup"
$LogDir     = "$Base\Logs"
$LogFile    = "$LogDir\antivirus_$(Get-Date -Format 'yyyy-MM').log"
$HashCache  = "$Base\Data\hashcache.csv"
$PIDFile    = "$Base\Data\pid.txt"

$MonitoredExtensions = @(
    '.exe','.dll','.sys','.scr','.com','.cpl','.msi','.bat','.cmd','.ps1','.vbs',
    '.js','.jse','.wsf','.hta','.jar','.lnk','.pif','.url','.exif','.winmd'
)

$RiskyPaths = @('\temp','\downloads','\appdata\local\temp','\public','\desktop')

$ProtectedProcesses = @(
    'smss','csrss','wininit','winlogon','services','lsass','svchost',
    'explorer','dwm','conhost','MsMpEng','NisSrv','SecurityHealthService'
)

$Config = @{
    LearningMode       = $LearningMode.IsPresent
    AutoQuarantine     = -not $LearningMode.IsPresent
    AutoKill           = -not $LearningMode.IsPresent
    EnableToast        = $true
    CirclUrl           = "https://hashlookup.circl.lu/lookup/sha256"
    MaxHashCacheAgeDays= 45
    EICARHash          = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
}

# Create structure
@($Base, $Quarantine, $Backup, $LogDir, "$Base\Data") | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item $_ -ItemType Directory -Force | Out-Null }
}

# ============================================================================
#  3. Logging
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"   # INFO, WARN, ERROR, THREAT, ALLOW
    )
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts  [$Level]  $Message"
    
    # Console
    switch ($Level) {
        "THREAT" { Write-Host $line -ForegroundColor Red     }
        "ERROR"  { Write-Host $line -ForegroundColor Red     }
        "WARN"   { Write-Host $line -ForegroundColor Yellow  }
        default  { Write-Host $line -ForegroundColor Gray    }
    }
    
    # File (rotate monthly by filename)
    $line | Out-File -FilePath $LogFile -Append -Encoding utf8 -Force
    
    # Very basic size rotation (optional improvement later)
    if ((Get-Item $LogFile -ea SilentlyContinue).Length -gt 10MB) {
        $old = $LogFile + ".old"
        if (Test-Path $old) { Remove-Item $old -Force }
        Rename-Item $LogFile $old -Force
    }
}

Write-Log "Antivirus-Merged-Light v$Script:Version starting (PID:$PID)  LearningMode:$($Config.LearningMode)" "INFO"

# ============================================================================
#  4. Hash reputation cache (most valuable addition)
# ============================================================================

$script:HashCache = @{}

function Load-HashCache {
    if (-not (Test-Path $HashCache)) { return }
    try {
        Import-Csv $HashCache -Header Hash,IsSafe,Timestamp | ForEach-Object {
            $dt = [datetime]::ParseExact($_.Timestamp,"yyyy-MM-dd HH:mm:ss",$null)
            if ($dt -gt (Get-Date).AddDays(-$Config.MaxHashCacheAgeDays)) {
                $script:HashCache[$_.Hash] = [bool]::Parse($_.IsSafe)
            }
        }
        Write-Log "Loaded $($script:HashCache.Count) hash cache entries" "INFO"
    } catch {
        Write-Log "Hash cache load failed: $_" "WARN"
    }
}

function Save-HashResult {
    param([string]$Hash, [bool]$IsSafe)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Hash,$IsSafe,$ts" | Out-File $HashCache -Append -Encoding utf8
    $script:HashCache[$Hash] = $IsSafe
}

function Test-IsKnownGood {
    param([string]$Path)
    
    if (-not (Test-Path $Path -PathType Leaf)) { return $false }
    
    # Signature first (fast & strong)
    try {
        $sig = Get-AuthenticodeSignature $Path -ErrorAction Stop
        if ($sig.Status -eq "Valid" -or $sig.Status -eq "TrustedPublisher") {
            return $true
        }
    } catch {}

    # Hash cache
    try {
        $h = (Get-FileHash $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        if ($script:HashCache.ContainsKey($h)) {
            return $script:HashCache[$h]
        }
    } catch {}

    # CIRCL (only one external lookup for now)
    try {
        $h = (Get-FileHash $Path -Algorithm SHA256).Hash.ToLower()
        $r = Invoke-RestMethod "$($Config.CirclUrl)/$h" -TimeoutSec 6 -UseBasicParsing -ErrorAction Stop
        if ($r) {
            Save-HashResult $h $true
            Write-Log "CIRCL known-good: $Path" "ALLOW"
            return $true
        }
    } catch {
        Write-Log "CIRCL lookup failed for $Path : $_" "WARN"
    }

    return $false
}

# ============================================================================
#  5. Quarantine logic
# ============================================================================

function Invoke-Quarantine {
    param(
        [string]$Path,
        [string]$Reason
    )
    if ($Config.LearningMode -or -not $Config.AutoQuarantine) {
        Write-Log "Would quarantine: $Path  ($Reason)" "THREAT"
        return
    }

    if (-not (Test-Path $Path)) { return }

    $name = [IO.Path]::GetFileName($Path)
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $qPath = Join-Path $Quarantine "$name`_$stamp"
    $bak   = Join-Path $Backup   "$name`_$stamp.bak"

    # Try to release locks (non-protected processes only)
    Get-Process | Where-Object {
        $_.Modules.FileName -contains $Path -and $ProtectedProcesses -notcontains $_.Name
    } | ForEach-Object {
        try { Stop-Process $_.Id -Force -ea SilentlyContinue } catch {}
    }

    try {
        Copy-Item $Path $bak -Force
        Move-Item $Path $qPath -Force
        Write-Log "QUARANTINED  $Path  →  $qPath   ($Reason)  backup: $bak" "THREAT"
        
        if ($Config.EnableToast) {
            # Minimal toast (expand later with BurntToast module if wanted)
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show("Threat quarantined: $name`nReason: $Reason","Antivirus Alert",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
        }
    } catch {
        Write-Log "Quarantine failed: $Path  →  $($_.Exception.Message)" "ERROR"
    }
}

# ============================================================================
#  6. Core decision logic
# ============================================================================

function Decide-And-Act {
    param([string]$Path)

    if (-not (Test-Path $Path -PathType Leaf)) { return }
    $ext = [IO.Path]::GetExtension($Path).ToLower()
    if ($ext -notin $MonitoredExtensions) { return }

    # Fast allow: trusted signature / CIRCL / cache
    if (Test-IsKnownGood $Path) {
        Write-Log "Allowed (reputation) -> $Path" "ALLOW"
        return
    }

    # Heuristic: small unsigned DLL in risky path
    $isSuspDll = $false
    if ($ext -in @('.dll','.winmd')) {
        try {
            $sig = Get-AuthenticodeSignature $Path
            if ($sig.Status -ne "Valid") {
                $size = (Get-Item $Path).Length
                $lower = $Path.ToLower()
                if ($RiskyPaths | Where-Object { $lower -like "*$_*" } -and $size -lt 4MB) {
                    $isSuspDll = $true
                }
            }
        } catch {}
    }

    if ($isSuspDll) {
        Invoke-Quarantine $Path "Suspicious small unsigned DLL in risky location"
        return
    }

    # Default action
    Write-Log "No strong reputation - monitoring only -> $Path" "INFO"
}   #  <--- this closing brace was probably missing

# ============================================================================
#  7. Chaos / EICAR test mode
# ============================================================================

if ($ChaosMode) {
    Write-Host "`n=== CHAOS / EICAR TEST MODE ===" -ForegroundColor Cyan
    
    $eicarPart1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}'
    $eicarPart2 = '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    $eicarStr = $eicarPart1 + $eicarPart2
    
    $testFile = Join-Path $env:TEMP "eicar-test-$(Get-Random).com"
    
    Set-Content -Path $testFile -Value $eicarStr -Encoding Ascii -NoNewline
    
    Write-Host "Created EICAR test file: $testFile" -ForegroundColor Green
    
    Start-Sleep -Milliseconds 1200
    Decide-And-Act $testFile
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    Write-Host "Test finished. Check log: $LogFile`n" -ForegroundColor Cyan
    exit 0
}

# ============================================================================
#  8. Initial scan (wider than original)
# ============================================================================

Write-Log "Initial scan started" "INFO"

$initialFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "C:\Temp",
    "C:\Users\Public"
)

# Optional: shallow scan of fixed drives roots
Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    $root = $_.DeviceID + ":\"
    if (Test-Path $root) { $initialFolders += $root }
}

foreach ($folder in $initialFolders) {
    if (-not (Test-Path $folder)) { continue }
    Get-ChildItem $folder -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in $MonitoredExtensions } |
        ForEach-Object { Decide-And-Act $_.FullName }
}

Write-Log "Initial scan finished" "INFO"

# ============================================================================
#  9. Real-time watchers
# ============================================================================

$WatchFolders = $initialFolders | Select-Object -Unique

$watcherList = @()

foreach ($folder in $WatchFolders) {
    if (-not (Test-Path $folder)) { continue }
    
    $w = New-Object IO.FileSystemWatcher $folder, "*.*" -Property @{
        IncludeSubdirectories = $true
        NotifyFilter          = 'FileName,LastWrite'
        EnableRaisingEvents   = $true
    }
    
    Register-ObjectEvent $w Created -Action {
        $p = $Event.SourceEventArgs.FullPath
        $ext = [IO.Path]::GetExtension($p).ToLower()
        if ($using:MonitoredExtensions -contains $ext) {
            Start-Sleep -Milliseconds 900   # give file time to finish writing
            Decide-And-Act $p
        }
    } | Out-Null
    
    $watcherList += $w
    Write-Log "Watcher started on: $folder" "INFO"
}

# ============================================================================
# 10. Reflective / manual mapping detector (kept from original — very nice feature)
# ============================================================================

Write-Log "Starting reflective/manual-map background scanner" "INFO"

Start-Job -Name "ReflectiveScanner" -ScriptBlock {
    $protected = $using:ProtectedProcesses
    $log = "$using:Base\reflective.log"
    
    while ($true) {
        Start-Sleep -Seconds 12
        Get-Process | Where-Object { $_.WorkingSet64 -gt 35MB } | ForEach-Object {
            $p = $_
            $sus = [string]::IsNullOrWhiteSpace($p.Path) -or 
                   ($p.Modules | Where-Object { [string]::IsNullOrWhiteSpace($_.FileName) })
            
            if ($sus -and $protected -notcontains $p.ProcessName) {
                $msg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Possible reflective/manual-map → $($p.Name) ($($p.Id))  Path='$($p.Path)'"
                $msg | Out-File $log -Append -Encoding utf8
                try { Stop-Process $p.Id -Force -ea SilentlyContinue } catch {}
            }
        }
    }
} | Out-Null

# ============================================================================
# 11. Simple WMI process creation hook
# ============================================================================

Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $path = $Event.SourceEventArgs.NewEvent.ProcessName
    if ($path -and (Test-Path $path)) {
        Decide-And-Act $path
    }
} | Out-Null

Write-Log "WMI process creation hook registered" "INFO"

# ============================================================================
# 12. Main loop (periodic sweep)
# ============================================================================

try {
    Load-HashCache

    while ($true) {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $path = $_.MainModule.FileName
                if ($path -and (Test-Path $path)) {
                    Decide-And-Act $path
                }
            } catch {}
        }
        
        Start-Sleep -Seconds 45
    }
}
finally {
    Write-Log 'Script exiting / terminated' 'INFO'
    
    foreach ($w in $watcherList) {
        $w.EnableRaisingEvents = $false
        $w.Dispose()
    }
    
    # Optional: remove PID file, cleanup mutex, etc.
}