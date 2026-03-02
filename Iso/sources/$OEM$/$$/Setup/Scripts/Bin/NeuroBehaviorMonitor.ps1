# NeuroBehaviorMonitor.ps1
# Detects psychological manipulation techniques: focus abuse, flash attacks, topmost abuse, screen distortion
# Author: Gorstak

param(
    [switch]$RunOnce,
    [int]$IntervalSeconds = 2
)

# ========================= CONFIGURATION =========================
$Script:NBM_TickInterval = $IntervalSeconds
$Script:NBM_FocusHistory = @{}
$Script:NBM_LastBrightness = -1
$Script:NBM_FlashScore = 0
$Script:NBM_LastAvgR = -1
$Script:NBM_LastAvgG = -1
$Script:NBM_LastAvgB = -1
$Script:NBM_DistortScore = 0
$Script:NBM_TopmostAllowlist = @(
    'explorer', 'taskmgr', 'devenv', 'code', 'chrome', 'firefox', 'msedge',
    'powershell', 'pwsh', 'windowsterminal', 'cmd'
)
$Script:NBM_Reported = @{}
$Script:LogFile = "C:\ProgramData\Antivirus\neurobehavior.log"

# ========================= LOGGING =========================
function Write-NBMLog {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "$timestamp | $Message"
    
    try {
        $logLine | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8
    } catch {}
    
    Write-Host $logLine
}

# ========================= WIN32 API =========================
function Initialize-NeuroWin32 {
    if (-not ([System.Management.Automation.PSTypeName]'NeuroWin32').Type) {
        $source = @'
using System;
using System.Runtime.InteropServices;

public class NeuroWin32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    
    [DllImport("user32.dll")]
    public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_TOPMOST = 0x00000008;
}
'@
        try {
            Add-Type -TypeDefinition $source -ErrorAction Stop
            Write-NBMLog "NeuroWin32 API initialized"
            return $true
        } catch {
            Write-NBMLog "Failed to initialize NeuroWin32: $_"
            return $false
        }
    }
    return $true
}

# ========================= HELPER FUNCTIONS =========================
function Test-ShouldReport {
    param([string]$Key)
    if ($Script:NBM_Reported.ContainsKey($Key)) { return $false }
    $Script:NBM_Reported[$Key] = [DateTime]::UtcNow
    return $true
}

function Send-NBMAlert {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$ProcessName
    )
    
    Write-NBMLog "[$Severity] $Message - Process: $ProcessName"
    
    # Write to Windows Event Log
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('NeuroBehaviorMonitor')) {
            New-EventLog -LogName Application -Source 'NeuroBehaviorMonitor' -ErrorAction SilentlyContinue
        }
        
        $entryType = switch ($Severity) {
            'CRITICAL' { [System.Diagnostics.EventLogEntryType]::Error }
            'HIGH' { [System.Diagnostics.EventLogEntryType]::Warning }
            default { [System.Diagnostics.EventLogEntryType]::Information }
        }
        
        Write-EventLog -LogName Application -Source 'NeuroBehaviorMonitor' `
            -EventId 2001 -Message "$Message - $ProcessName" `
            -EntryType $entryType -ErrorAction SilentlyContinue
    } catch {}
}

function Stop-ThreatProcess {
    param(
        [int]$ProcessId,
        [string]$ProcessName
    )
    
    $protected = @('System', 'lsass', 'csrss', 'wininit', 'winlogon', 'services', 'smss', 'svchost', 'explorer', 'dwm')
    
    if ($protected -contains $ProcessName) {
        Write-NBMLog "Cannot terminate protected process: $ProcessName (PID: $ProcessId)"
        return $false
    }
    
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-NBMLog "Terminated threat process: $ProcessName (PID: $ProcessId)"
        return $true
    } catch {
        Write-NBMLog "Failed to terminate $ProcessName (PID: $ProcessId): $_"
        return $false
    }
}

# ========================= MAIN DETECTION FUNCTION =========================
function Invoke-NeuroBehaviorMonitor {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        
        # Get foreground window
        $hWnd = [NeuroWin32]::GetForegroundWindow()
        if ($hWnd -eq [IntPtr]::Zero) { return }
        
        $fpid = 0
        [NeuroWin32]::GetWindowThreadProcessId($hWnd, [ref]$fpid) | Out-Null
        if ($fpid -eq 0 -or $fpid -eq $PID) { return }
        
        $proc = Get-Process -Id $fpid -ErrorAction SilentlyContinue
        $procName = if ($proc) { $proc.ProcessName } else { 'unknown' }
        
        # Screen sample for flash/color detection
        $bmp = [System.Drawing.Bitmap]::new(64, 64)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
        $g.Dispose()
        
        $sumBright = 0; $sumR = 0; $sumG = 0; $sumB = 0; $samples = 0
        for ($x = 0; $x -lt 64; $x += 4) {
            for ($y = 0; $y -lt 64; $y += 4) {
                $c = $bmp.GetPixel($x, $y)
                $sumR += $c.R; $sumG += $c.G; $sumB += $c.B
                $sumBright += $c.R + $c.G + $c.B
                $samples++
            }
        }
        $bmp.Dispose()
        
        $n = [Math]::Max(1, $samples)
        $avgR = $sumR / $n
        $avgG = $sumG / $n
        $avgB = $sumB / $n
        
        # ----- DETECTION 1: Focus Steal -----
        if (-not $Script:NBM_FocusHistory.ContainsKey($fpid)) {
            $Script:NBM_FocusHistory[$fpid] = @{ Count = 0; FirstSeen = [DateTime]::UtcNow }
        }
        
        $fe = $Script:NBM_FocusHistory[$fpid]
        $fe.Count++
        $elapsed = ([DateTime]::UtcNow - $fe.FirstSeen).TotalSeconds
        
        if ($elapsed -gt 10) {
            $fe.Count = 1
            $fe.FirstSeen = [DateTime]::UtcNow
        }
        
        if ($elapsed -lt 10 -and $fe.Count -gt 8) {
            if (Test-ShouldReport -Key "Focus:$procName") {
                Send-NBMAlert -Severity 'MEDIUM' -Message 'Focus abuse detected' -ProcessName $procName
            }
            $fe.Count = 0
        }
        $Script:NBM_FocusHistory[$fpid] = $fe
        
        # ----- DETECTION 2: Flash Attack -----
        if ($Script:NBM_LastBrightness -ge 0) {
            $delta = [Math]::Abs($sumBright - $Script:NBM_LastBrightness)
            
            if ($delta -gt 40000) {
                $Script:NBM_FlashScore++
            } else {
                $Script:NBM_FlashScore = [Math]::Max(0, $Script:NBM_FlashScore - 1)
            }
            
            if ($Script:NBM_FlashScore -ge 6) {
                if (Test-ShouldReport -Key "Flash:$procName") {
                    Send-NBMAlert -Severity 'HIGH' -Message 'Flash stimulus detected' -ProcessName $procName
                    Stop-ThreatProcess -ProcessId $fpid -ProcessName $procName
                }
                $Script:NBM_FlashScore = 0
            }
        }
        $Script:NBM_LastBrightness = $sumBright
        
        # ----- DETECTION 3: Topmost Abuse -----
        $exStyle = [NeuroWin32]::GetWindowLong($hWnd, [NeuroWin32]::GWL_EXSTYLE)
        $isTopmost = ([int]$exStyle -band [NeuroWin32]::WS_EX_TOPMOST) -ne 0
        
        if ($isTopmost -and $Script:NBM_TopmostAllowlist -notcontains $procName.ToLower()) {
            if (Test-ShouldReport -Key "Topmost:$procName") {
                Send-NBMAlert -Severity 'LOW' -Message 'Topmost window abuse detected' -ProcessName $procName
            }
        }
        
        # ----- DETECTION 4: Color Distortion -----
        if ($Script:NBM_LastAvgR -ge 0) {
            $dR = [Math]::Abs($avgR - $Script:NBM_LastAvgR)
            $dG = [Math]::Abs($avgG - $Script:NBM_LastAvgG)
            $dB = [Math]::Abs($avgB - $Script:NBM_LastAvgB)
            $maxD = [Math]::Max($dR, [Math]::Max($dG, $dB))
            
            if ($maxD -gt 70) {
                $Script:NBM_DistortScore++
            } else {
                $Script:NBM_DistortScore = [Math]::Max(0, $Script:NBM_DistortScore - 1)
            }
            
            if ($Script:NBM_DistortScore -ge 5) {
                if (Test-ShouldReport -Key "Distort:$procName") {
                    Send-NBMAlert -Severity 'MEDIUM' -Message 'Screen color distortion detected' -ProcessName $procName
                }
                $Script:NBM_DistortScore = 0
            }
        }
        
        $Script:NBM_LastAvgR = $avgR
        $Script:NBM_LastAvgG = $avgG
        $Script:NBM_LastAvgB = $avgB
        
    } catch {
        Write-NBMLog "Detection error: $_"
    }
}

# ========================= MAIN EXECUTION =========================
Write-NBMLog "=== NeuroBehaviorMonitor Starting ==="
Write-NBMLog "Interval: ${Script:NBM_TickInterval}s | RunOnce: $RunOnce"

# Initialize Win32 API
if (-not (Initialize-NeuroWin32)) {
    Write-NBMLog "Failed to initialize - exiting"
    exit 1
}

if ($RunOnce) {
    Invoke-NeuroBehaviorMonitor
    Write-NBMLog "Single scan completed"
} else {
    Write-Host "NeuroBehaviorMonitor running. Press [Ctrl]+[C] to stop." -ForegroundColor Green
    
    try {
        while ($true) {
            Invoke-NeuroBehaviorMonitor
            Start-Sleep -Seconds $Script:NBM_TickInterval
        }
    } catch {
        Write-NBMLog "Monitor stopped: $_"
    }
}
