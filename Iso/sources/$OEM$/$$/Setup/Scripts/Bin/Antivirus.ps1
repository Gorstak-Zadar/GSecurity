# Antivirus.ps1
# Author: Gorstak

#Requires -RunAsAdministrator
param([string]$Path='',[int]$IntervalMinutes=60) # 0=one-shot, no guard
$Path=if($Path){[System.IO.Path]::GetFullPath($Path)}else{(Get-Location).Path}
$Base=[System.IO.Path]::GetFullPath("$env:LOCALAPPDATA\Antivirus")
$YaraUrl="https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip"
$RulesUrl="https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
$VcRedistUrl="https://aka.ms/vc14/vc_redist.x64.exe"
$Ext='*.exe','*.msi','*.dll','*.ocx','*.winmd','*.ps1','*.vbs','*.js','*.bat','*.cmd'
$Cache="$Base\av.csv"; $HashCache="$Base\hashes.csv"

function Ensure-Setup {
    $yaraExe=(Get-ChildItem $Base -Recurse -Filter yara64.exe -EA 0|Select -First 1).FullName
    if(!$yaraExe){
        Write-Host "Downloading Yara..."
        $z="$env:TEMP\yara.zip"; Invoke-WebRequest $YaraUrl -OutFile $z -UseBasicParsing
        Expand-Archive $z -DestinationPath $Base -Force
        if(Test-Path "$Base\yara-4.5.5-2368-win64"){Rename-Item "$Base\yara-4.5.5-2368-win64" yara}
        Remove-Item $z -Force -EA 0
    }
    $yaraExe=(Get-ChildItem $Base -Recurse -Filter yara64.exe -EA 0|Select -First 1).FullName
    if($yaraExe){
        $yaraDir=[System.IO.Path]::GetDirectoryName($yaraExe)
        $vcruntime="$yaraDir\vcruntime140.dll"
        if(!(Test-Path $vcruntime)){
            $bundled="$PSScriptRoot\vcruntime140.dll"
            $sysDll="$env:SystemRoot\System32\vcruntime140.dll"
            if(Test-Path $bundled){Copy-Item $bundled $vcruntime -Force; Write-Host "Using bundled vcruntime140.dll"}
            elseif(Test-Path $sysDll){Copy-Item $sysDll $vcruntime -Force; Write-Host "Copied vcruntime140.dll from System32"}
            else{
                Write-Host "Downloading and installing Visual C++ Redistributable..."
                $vcExe="$env:TEMP\vc_redist.x64.exe"
                try{
                    Invoke-WebRequest $VcRedistUrl -OutFile $vcExe -UseBasicParsing
                    Start-Process -FilePath $vcExe -ArgumentList "/install","/quiet","/norestart" -Wait
                    if(Test-Path $sysDll){Copy-Item $sysDll $vcruntime -Force; Write-Host "Installed VC++ Redist and copied vcruntime140.dll"}
                }catch{Write-Host "Failed to install VC++ Redist: $_" -ForegroundColor Yellow}
                Remove-Item $vcExe -Force -EA 0
            }
        }
    }
    if(!(Test-Path "$Base\rules\index.yar")){
        Write-Host "Downloading Yara-Rules..."
        $z="$env:TEMP\rules.zip"; Invoke-WebRequest $RulesUrl -OutFile $z -UseBasicParsing
        Expand-Archive $z -DestinationPath $Base -Force; Rename-Item "$Base\rules-master" rules; Remove-Item $z -Force
    }
}

function Test-Hash {
    param($h)
    if(!$h){return 'unknown'}
    $r=$script:H[$h]; if($r){return $r}
    try{(Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha1/$h" -EA Stop)|Out-Null; $r='good'}catch{
        try{Resolve-DnsName "$h.malware.hash.cymru.com" -EA Stop|Out-Null; $r='bad'}catch{$r='unknown'}
    }
    "$h,$r"|Add-Content $HashCache; $script:H[$h]=$r; return $r
}

function Invoke-Scan {
    param([string]$p)
    $yaraExe=(Get-ChildItem $Base -Recurse -Filter yara64.exe -EA 0|Select -First 1).FullName
    $files=Get-ChildItem $p -Recurse -Include $Ext -ErrorAction SilentlyContinue
    foreach($f in $files){
        try{$h=(Get-FileHash $f.FullName -A SHA1 -EA Stop).Hash}catch{continue}
        if(!$h){continue}
        $r=Test-Hash $h
        if($r -eq'bad'){Write-Host "MALWARE (hash): $($f.FullName)" -ForegroundColor Red; continue}
        if($yaraExe){$y=& $yaraExe -r "$Base\rules" $f.FullName 2>$null}
        if($y){Write-Host "MALWARE (yara): $($f.FullName)`n$y" -ForegroundColor Red}
    }
}

# Main
New-Item $Base -ItemType Directory -Force|Out-Null
if(!(Test-Path $Cache)){"Path,Hash,Result"|Out-File $Cache}
$script:H=@{}; if(Test-Path $HashCache){Get-Content $HashCache|%{$a=$_.Split(',');if($a.Count -ge 2){$script:H[$a[0]]=$a[1]}}}
Ensure-Setup

if($IntervalMinutes -le 0){Invoke-Scan $Path; exit}
$exts=@('.exe','.msi','.dll','.ocx','.winmd','.ps1','.vbs','.js','.bat','.cmd')
Unregister-Event -SourceIdentifier ProcessStart -ErrorAction SilentlyContinue
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier ProcessStart -Action {
    $e=$Event.SourceEventArgs.NewEvent; $pid=$e.ProcessID
    try{
        $p=Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -EA 0
        if(!$p.ExecutablePath){return}; $path=$p.ExecutablePath
        if($path -like "*\Antivirus*" -or $path -like "*\yara*"){return}
        $ext=[System.IO.Path]::GetExtension($path).ToLower()
        if($ext -notin $Event.MessageData.exts){return}
        if(!(Test-Path $path)){return}
        $h=(Get-FileHash $path -A SHA1 -EA 0).Hash; if(!$h){return}
        $r=$null; $c=Get-Content $Event.MessageData.cache -EA 0
        foreach($l in $c){$a=$l.Split(',');if($a[0]-eq$h){$r=$a[1];break}}
        if(!$r){try{(Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha1/$h" -EA Stop)|Out-Null; $r='good'}catch{try{Resolve-DnsName "$h.malware.hash.cymru.com" -EA Stop|Out-Null; $r='bad'}catch{$r='unknown'}; "$h,$r"|Add-Content $Event.MessageData.cache}}
        if($r -eq'bad'){Stop-Process -Id $pid -Force -EA 0; Write-Host "KILLED (malware): $path" -ForegroundColor Red}
    }catch{}
} -MessageData @{cache=$HashCache;exts=$exts}|Out-Null
Write-Host "Guard active - killing malware on launch"
while($true){
    Write-Host "Scanning $Path at $(Get-Date)"; Invoke-Scan $Path; Write-Host "Next scan in $IntervalMinutes min"
    Start-Sleep -Seconds ($IntervalMinutes*60)
}
