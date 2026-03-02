#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detects potential surveillance malware by identifying suspicious DLL loading patterns.

.DESCRIPTION
    Identifies processes loading a suspicious combination of COM proxy/stub DLLs,
    media capture DLLs, and user management DLLs. Individually these are legitimate
    Windows components, but combined in a non-system process may indicate surveillance malware.

.EXAMPLE
    .\Invoke-ShadowProxyCaptureDetection.ps1
#>

$script:LogFile = Join-Path $PSScriptRoot "ShadowProxyDetection_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Write-Host $logEntry
    Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Get-CachedProcessList {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne 0 }
}

function Send-ThreatAlert {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$Details
    )
    Write-Log "[$Severity ALERT] $Message"
    Write-Log "  Details: $Details"
    
    # Windows toast notification (optional, won't fail if unavailable)
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
        $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
        $text = $xml.GetElementsByTagName("text")
        $text[0].AppendChild($xml.CreateTextNode("Security Alert: $Severity")) | Out-Null
        $text[1].AppendChild($xml.CreateTextNode($Message)) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Shadow Proxy Detection").Show($toast)
    } catch {}
}

function Stop-ThreatProcess {
    param(
        [int]$ProcessId,
        [string]$ProcessName
    )
    Write-Log "TERMINATING THREAT: $ProcessName (PID: $ProcessId)"
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-Log "  -> Process terminated successfully"
    } catch {
        Write-Log "  -> Failed to terminate: $_"
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

# Run the detection
Write-Log "=== Shadow Proxy-Capture Detection Started ==="
Write-Log "Log file: $script:LogFile"
Invoke-ShadowProxyCaptureDetection
Write-Log "=== Detection Complete ==="
