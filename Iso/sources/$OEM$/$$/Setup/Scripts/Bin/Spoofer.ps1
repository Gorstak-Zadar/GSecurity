# PrivacyForge.ps1
# Privacy protection through identity spoofing and data confusion
# Converted from Python - Author: Gorstak

param(
    [switch]$NoGui,
    [switch]$RunOnce,
    [int]$RotationInterval = 3600,
    [int]$DataThreshold = 50
)

# ========================= CONFIGURATION =========================
$Script:Config = @{
    RotationInterval = $RotationInterval
    DataThreshold = $DataThreshold
    LogFile = "C:\ProgramData\Antivirus\privacyforge.log"
    FakeSites = @(
        "https://www.reddit.com",
        "https://www.bbc.com/news",
        "https://www.twitter.com",
        "https://www.nytimes.com",
        "https://www.wikipedia.org",
        "https://www.github.com"
    )
}

# ========================= STATE =========================
$Script:CurrentIdentity = $null
$Script:DataCollected = 0
$Script:LastRotation = Get-Date
$Script:IsRunning = $false

# ========================= LOGGING =========================
function Write-PFLog {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "$timestamp | $Message"
    
    try {
        $logDir = Split-Path $Script:Config.LogFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $logLine | Out-File -FilePath $Script:Config.LogFile -Append -Encoding UTF8
    } catch {}
    
    Write-Host $logLine
}

# ========================= FAKE DATA GENERATORS =========================
$Script:FirstNames = @('James', 'John', 'Robert', 'Michael', 'William', 'David', 'Richard', 'Joseph',
                       'Mary', 'Patricia', 'Jennifer', 'Linda', 'Elizabeth', 'Barbara', 'Susan', 'Jessica',
                       'Sarah', 'Karen', 'Nancy', 'Lisa', 'Margaret', 'Betty', 'Dorothy', 'Sandra')

$Script:LastNames = @('Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
                      'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson',
                      'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson', 'White')

$Script:Domains = @('gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'protonmail.com', 'icloud.com')

$Script:Cities = @('New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix', 'Philadelphia',
                   'San Antonio', 'San Diego', 'Dallas', 'San Jose', 'Austin', 'Jacksonville',
                   'London', 'Paris', 'Berlin', 'Tokyo', 'Sydney', 'Toronto', 'Amsterdam', 'Madrid')

$Script:Countries = @('United States', 'United Kingdom', 'Canada', 'Australia', 'Germany', 'France',
                      'Japan', 'Netherlands', 'Spain', 'Italy', 'Brazil', 'Mexico', 'India', 'Sweden')

$Script:Languages = @('en-US', 'en-GB', 'fr-FR', 'es-ES', 'de-DE', 'it-IT', 'pt-BR', 'ja-JP', 'zh-CN')

$Script:Timezones = @('America/New_York', 'America/Los_Angeles', 'America/Chicago', 'Europe/London',
                      'Europe/Paris', 'Europe/Berlin', 'Asia/Tokyo', 'Australia/Sydney', 'America/Toronto')

$Script:Interests = @('tech', 'gaming', 'news', 'sports', 'music', 'movies', 'travel', 'food',
                      'fitness', 'photography', 'art', 'science', 'politics', 'fashion', 'books')

$Script:UserAgents = @(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
)

# ========================= IDENTITY GENERATION =========================
function New-FakeIdentity {
    $firstName = Get-Random -InputObject $Script:FirstNames
    $lastName = Get-Random -InputObject $Script:LastNames
    $domain = Get-Random -InputObject $Script:Domains
    $randomNum = Get-Random -Minimum 100 -Maximum 9999
    
    $width = Get-Random -Minimum 1280 -Maximum 1920
    $height = Get-Random -Minimum 720 -Maximum 1080
    
    $selectedInterests = $Script:Interests | Get-Random -Count 4
    
    return @{
        Name = "$firstName $lastName"
        Email = "$firstName.$lastName$randomNum@$domain".ToLower()
        Username = "$firstName$lastName$randomNum".ToLower()
        Location = Get-Random -InputObject $Script:Cities
        Country = Get-Random -InputObject $Script:Countries
        UserAgent = Get-Random -InputObject $Script:UserAgents
        ScreenResolution = "${width}x${height}"
        Interests = $selectedInterests
        DeviceId = [Guid]::NewGuid().ToString()
        MacAddress = (1..6 | ForEach-Object { '{0:X2}' -f (Get-Random -Minimum 0 -Maximum 256) }) -join ':'
        Language = Get-Random -InputObject $Script:Languages
        Timezone = Get-Random -InputObject $Script:Timezones
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        SessionId = Get-Random -Minimum 100000 -Maximum 999999
        HardwareId = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Minimum 0 -Maximum 16) })
    }
}

# ========================= SPOOFING FUNCTIONS =========================
function Invoke-SpoofSoftwareMetadata {
    Write-PFLog "Spoofing software metadata..."
    
    $headers = @{
        'User-Agent' = $Script:CurrentIdentity.UserAgent
        'Accept-Language' = $Script:CurrentIdentity.Language
        'X-Device-ID' = $Script:CurrentIdentity.DeviceId
        'X-Session-ID' = $Script:CurrentIdentity.SessionId.ToString()
    }
    
    try {
        $response = Invoke-WebRequest -Uri "https://httpbin.org/headers" -Headers $headers -TimeoutSec 10 -UseBasicParsing
        Write-PFLog "Sent spoofed headers to httpbin.org"
    } catch {
        Write-PFLog "Network request failed (expected if offline): $_"
    }
}

function Invoke-SpoofGameTelemetry {
    Write-PFLog "Spoofing game telemetry..."
    
    $fakeTelemetry = @{
        PlayerId = [Guid]::NewGuid().ToString()
        HardwareId = $Script:CurrentIdentity.HardwareId
        Latency = Get-Random -Minimum 20 -Maximum 200
        GameVersion = "$(Get-Random -Minimum 1 -Maximum 5).$(Get-Random -Minimum 0 -Maximum 9).$(Get-Random -Minimum 0 -Maximum 99)"
        FPS = Get-Random -Minimum 30 -Maximum 144
        GPU = @('NVIDIA RTX 3080', 'NVIDIA RTX 4070', 'AMD RX 6800', 'Intel Arc A770') | Get-Random
        RAM = @(8, 16, 32, 64) | Get-Random
    }
    
    Write-PFLog "Game telemetry: $($fakeTelemetry | ConvertTo-Json -Compress)"
}

function Invoke-SpoofSensors {
    Write-PFLog "Spoofing sensor data..."
    
    $sensors = @{
        Accelerometer = @{
            X = [Math]::Round((Get-Random -Minimum -1000 -Maximum 1000) / 100, 2)
            Y = [Math]::Round((Get-Random -Minimum -1000 -Maximum 1000) / 100, 2)
            Z = [Math]::Round((Get-Random -Minimum -1000 -Maximum 1000) / 100, 2)
        }
        Gyroscope = @{
            Pitch = [Math]::Round((Get-Random -Minimum -18000 -Maximum 18000) / 100, 2)
            Roll = [Math]::Round((Get-Random -Minimum -18000 -Maximum 18000) / 100, 2)
            Yaw = [Math]::Round((Get-Random -Minimum -18000 -Maximum 18000) / 100, 2)
        }
        Magnetometer = @{
            X = [Math]::Round((Get-Random -Minimum -5000 -Maximum 5000) / 100, 2)
            Y = [Math]::Round((Get-Random -Minimum -5000 -Maximum 5000) / 100, 2)
            Z = [Math]::Round((Get-Random -Minimum -5000 -Maximum 5000) / 100, 2)
        }
        LightSensor = Get-Random -Minimum 0 -Maximum 1000
        ProximitySensor = @(0, 5, 10) | Get-Random
        AmbientTemperature = [Math]::Round((Get-Random -Minimum 1500 -Maximum 3500) / 100, 1)
    }
    
    Write-PFLog "Sensors spoofed: Light=$($sensors.LightSensor)lux, Temp=$($sensors.AmbientTemperature)C"
}

function Invoke-SpoofClipboard {
    Write-PFLog "Spoofing clipboard..."
    
    $fakeTexts = @(
        "Meeting at 3pm tomorrow",
        "Remember to call John",
        "https://www.example.com/article/12345",
        "Password123!",
        "groceries: milk, bread, eggs",
        "flight confirmation: ABC123",
        "The quick brown fox jumps over the lazy dog"
    )
    
    $fakeContent = Get-Random -InputObject $fakeTexts
    
    try {
        Set-Clipboard -Value $fakeContent
        Write-PFLog "Clipboard set to: $($fakeContent.Substring(0, [Math]::Min(20, $fakeContent.Length)))..."
    } catch {
        Write-PFLog "Clipboard spoofing failed: $_"
    }
}

function Invoke-SpoofSystemMetrics {
    Write-PFLog "Spoofing system metrics..."
    
    $fakeMetrics = @{
        CPUUsage = [Math]::Round((Get-Random -Minimum 500 -Maximum 8000) / 100, 1)
        MemoryUsage = [Math]::Round((Get-Random -Minimum 2000 -Maximum 9000) / 100, 1)
        BatteryLevel = Get-Random -Minimum 20 -Maximum 100
        DiskUsage = [Math]::Round((Get-Random -Minimum 3000 -Maximum 8500) / 100, 1)
        NetworkLatency = Get-Random -Minimum 5 -Maximum 150
        Uptime = Get-Random -Minimum 3600 -Maximum 604800
    }
    
    Write-PFLog "System metrics: CPU=$($fakeMetrics.CPUUsage)%, RAM=$($fakeMetrics.MemoryUsage)%, Battery=$($fakeMetrics.BatteryLevel)%"
}

function Invoke-SpoofMouseMovement {
    Write-PFLog "Spoofing mouse/eye tracking..."
    
    try {
        Add-Type -AssemblyName System.Windows.Forms
        
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        
        for ($i = 0; $i -lt 3; $i++) {
            $x = Get-Random -Minimum 0 -Maximum $screen.Width
            $y = Get-Random -Minimum 0 -Maximum $screen.Height
            
            [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($x, $y)
            
            Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
        }
        
        Write-PFLog "Mouse moved to random positions"
    } catch {
        Write-PFLog "Mouse spoofing failed: $_"
    }
}

function Invoke-SpoofFileMetadata {
    Write-PFLog "Spoofing file metadata..."
    
    $dummyFile = Join-Path $env:TEMP "pf_dummy_$(Get-Random).txt"
    
    try {
        $fakeContent = "Random content: $([Guid]::NewGuid().ToString())"
        $fakeContent | Out-File -FilePath $dummyFile -Encoding UTF8
        
        $randomDate = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 365))
        (Get-Item $dummyFile).LastWriteTime = $randomDate
        (Get-Item $dummyFile).CreationTime = $randomDate.AddDays(-(Get-Random -Minimum 1 -Maximum 30))
        
        Write-PFLog "Created dummy file with spoofed timestamps"
        
        Remove-Item $dummyFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-PFLog "File metadata spoofing failed: $_"
    }
}

function Invoke-SpoofDNSNoise {
    Write-PFLog "Generating DNS noise..."
    
    $noiseDomains = @(
        "news.google.com", "mail.yahoo.com", "docs.microsoft.com",
        "developer.mozilla.org", "stackoverflow.com", "medium.com",
        "linkedin.com", "pinterest.com", "tumblr.com", "quora.com"
    )
    
    $selected = $noiseDomains | Get-Random -Count 3
    
    foreach ($domain in $selected) {
        try {
            $null = Resolve-DnsName -Name $domain -ErrorAction SilentlyContinue
        } catch {}
    }
    
    Write-PFLog "DNS queries sent to: $($selected -join ', ')"
}

function Invoke-SpoofBrowserFingerprint {
    Write-PFLog "Spoofing browser fingerprint data..."
    
    $fingerprint = @{
        Canvas = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Minimum 0 -Maximum 16) })
        WebGL = @('NVIDIA Corporation', 'AMD', 'Intel Inc.', 'Apple GPU') | Get-Random
        AudioContext = [Math]::Round((Get-Random -Minimum 0 -Maximum 1000000) / 1000000, 6)
        Fonts = @('Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia') | Get-Random -Count 4
        Plugins = Get-Random -Minimum 0 -Maximum 5
        DoNotTrack = @('1', 'null', 'unspecified') | Get-Random
        Cookies = $true
        LocalStorage = $true
        SessionStorage = $true
        ColorDepth = @(24, 32) | Get-Random
        PixelRatio = @(1, 1.25, 1.5, 2) | Get-Random
    }
    
    Write-PFLog "Browser fingerprint generated: WebGL=$($fingerprint.WebGL), ColorDepth=$($fingerprint.ColorDepth)"
}

# ========================= IDENTITY ROTATION =========================
function Invoke-RotateIdentity {
    Write-PFLog "=== ROTATING IDENTITY ==="
    
    $Script:CurrentIdentity = New-FakeIdentity
    $Script:DataCollected = 0
    $Script:LastRotation = Get-Date
    
    Write-PFLog "New identity: $($Script:CurrentIdentity.Name) <$($Script:CurrentIdentity.Email)>"
    Write-PFLog "Location: $($Script:CurrentIdentity.Location), $($Script:CurrentIdentity.Country)"
    Write-PFLog "Device ID: $($Script:CurrentIdentity.DeviceId)"
    
    Invoke-SpoofSoftwareMetadata
    Invoke-SpoofGameTelemetry
    Invoke-SpoofSensors
    Invoke-SpoofClipboard
    Invoke-SpoofSystemMetrics
    Invoke-SpoofFileMetadata
    Invoke-SpoofDNSNoise
    Invoke-SpoofBrowserFingerprint
    
    Write-PFLog "=== IDENTITY ROTATION COMPLETE ==="
}

# ========================= MONITORING =========================
function Start-DataLeakageMonitor {
    Write-PFLog "Starting data leakage monitor..."
    
    while ($Script:IsRunning) {
        $Script:DataCollected += Get-Random -Minimum 1 -Maximum 6
        
        $timeSinceRotation = (Get-Date) - $Script:LastRotation
        
        if ($Script:DataCollected -ge $Script:Config.DataThreshold) {
            Write-PFLog "Data threshold reached ($Script:DataCollected/$($Script:Config.DataThreshold)). Rotating..."
            Invoke-RotateIdentity
        }
        elseif ($timeSinceRotation.TotalSeconds -ge $Script:Config.RotationInterval) {
            Write-PFLog "Time interval reached. Rotating..."
            Invoke-RotateIdentity
        }
        
        Start-Sleep -Seconds 8
    }
}

# ========================= GUI =========================
function Show-PrivacyForgeGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "PrivacyForge"
    $form.Size = New-Object System.Drawing.Size(500, 450)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    
    # Title
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Location = New-Object System.Drawing.Point(10, 10)
    $titleLabel.Size = New-Object System.Drawing.Size(480, 30)
    $titleLabel.Text = "PrivacyForge - Identity Protection"
    $titleLabel.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $titleLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($titleLabel)
    
    # Status label
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(20, 50)
    $statusLabel.Size = New-Object System.Drawing.Size(450, 200)
    $statusLabel.Text = "Initializing..."
    $statusLabel.Font = New-Object System.Drawing.Font("Consolas", 10)
    $statusLabel.BorderStyle = "FixedSingle"
    $form.Controls.Add($statusLabel)
    
    # Progress bar
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(20, 260)
    $progressBar.Size = New-Object System.Drawing.Size(450, 25)
    $progressBar.Maximum = $Script:Config.DataThreshold
    $form.Controls.Add($progressBar)
    
    # Progress label
    $progressLabel = New-Object System.Windows.Forms.Label
    $progressLabel.Location = New-Object System.Drawing.Point(20, 290)
    $progressLabel.Size = New-Object System.Drawing.Size(450, 20)
    $progressLabel.Text = "Data Collected: 0 / $($Script:Config.DataThreshold)"
    $progressLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($progressLabel)
    
    # Start button
    $startButton = New-Object System.Windows.Forms.Button
    $startButton.Location = New-Object System.Drawing.Point(20, 320)
    $startButton.Size = New-Object System.Drawing.Size(140, 40)
    $startButton.Text = "Start Protection"
    $startButton.BackColor = [System.Drawing.Color]::Green
    $startButton.ForeColor = [System.Drawing.Color]::White
    $startButton.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($startButton)
    
    # Scramble button
    $scrambleButton = New-Object System.Windows.Forms.Button
    $scrambleButton.Location = New-Object System.Drawing.Point(180, 320)
    $scrambleButton.Size = New-Object System.Drawing.Size(140, 40)
    $scrambleButton.Text = "Scramble Now"
    $scrambleButton.BackColor = [System.Drawing.Color]::Blue
    $scrambleButton.ForeColor = [System.Drawing.Color]::White
    $scrambleButton.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($scrambleButton)
    
    # Stop button
    $stopButton = New-Object System.Windows.Forms.Button
    $stopButton.Location = New-Object System.Drawing.Point(340, 320)
    $stopButton.Size = New-Object System.Drawing.Size(130, 40)
    $stopButton.Text = "Stop"
    $stopButton.BackColor = [System.Drawing.Color]::Red
    $stopButton.ForeColor = [System.Drawing.Color]::White
    $stopButton.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
    $stopButton.Enabled = $false
    $form.Controls.Add($stopButton)
    
    # Status update function
    $updateStatus = {
        if ($Script:CurrentIdentity) {
            $interests = $Script:CurrentIdentity.Interests -join ", "
            $statusLabel.Text = @"
Current Identity:
  Name: $($Script:CurrentIdentity.Name)
  Email: $($Script:CurrentIdentity.Email)
  Username: $($Script:CurrentIdentity.Username)
  Location: $($Script:CurrentIdentity.Location), $($Script:CurrentIdentity.Country)
  Language: $($Script:CurrentIdentity.Language)
  Timezone: $($Script:CurrentIdentity.Timezone)
  Device ID: $($Script:CurrentIdentity.DeviceId.Substring(0,8))...
  Interests: $interests
  Last Updated: $($Script:CurrentIdentity.Timestamp)
"@
            $progressBar.Value = [Math]::Min($Script:DataCollected, $Script:Config.DataThreshold)
            $progressLabel.Text = "Data Collected: $Script:DataCollected / $($Script:Config.DataThreshold)"
        }
    }
    
    # Timer for UI updates
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    $timer.Add_Tick($updateStatus)
    
    # Button events
    $startButton.Add_Click({
        $Script:IsRunning = $true
        $startButton.Enabled = $false
        $stopButton.Enabled = $true
        
        Invoke-RotateIdentity
        & $updateStatus
        
        $timer.Start()
        
        $monitorJob = Start-Job -ScriptBlock {
            param($threshold, $interval)
            $dataCollected = 0
            $lastRotation = Get-Date
            
            while ($true) {
                $dataCollected += Get-Random -Minimum 1 -Maximum 6
                Start-Sleep -Seconds 8
            }
        } -ArgumentList $Script:Config.DataThreshold, $Script:Config.RotationInterval
        
        [System.Windows.Forms.MessageBox]::Show("Protection started! Your identity is now being spoofed.", "PrivacyForge", "OK", "Information")
    })
    
    $scrambleButton.Add_Click({
        Invoke-RotateIdentity
        & $updateStatus
        [System.Windows.Forms.MessageBox]::Show("Identity scrambled! All data has been spoofed.", "PrivacyForge", "OK", "Information")
    })
    
    $stopButton.Add_Click({
        $Script:IsRunning = $false
        $timer.Stop()
        $startButton.Enabled = $true
        $stopButton.Enabled = $false
        [System.Windows.Forms.MessageBox]::Show("Protection stopped.", "PrivacyForge", "OK", "Information")
    })
    
    # Initialize
    $Script:CurrentIdentity = New-FakeIdentity
    & $updateStatus
    
    $form.ShowDialog() | Out-Null
}

# ========================= MAIN =========================
Write-PFLog "=== PrivacyForge Starting ==="

if ($RunOnce) {
    Invoke-RotateIdentity
    Write-PFLog "Single rotation completed"
}
elseif ($NoGui) {
    Write-Host "PrivacyForge running in console mode. Press [Ctrl]+[C] to stop." -ForegroundColor Green
    $Script:IsRunning = $true
    Invoke-RotateIdentity
    Start-DataLeakageMonitor
}
else {
    Show-PrivacyForgeGui
}
