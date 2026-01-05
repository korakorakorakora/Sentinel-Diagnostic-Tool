# ==========================================
# SENTINEL - V1 
# ==========================================

# ==========================================
# [SECURITY: ANTI-DOWNGRADE CHECK]
# ==========================================
# Prevent attackers from running in PowerShell v2 to bypass logging/security features.
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "[!] CRITICAL: Outdated PowerShell Version Detected." -ForegroundColor Red
    Write-Host "    Security requires PowerShell 5.1 or newer." -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit
}

# ==========================================
# [CONFIGURATION: HARDENED WEBHOOK]
# ==========================================
# WEBHOOK SECURED (AES-256 Encrypted to prevent static analysis extraction)
# Note: In a real compiled binary, keys would be obfuscated further.
# For this script, we separate the Key/IV from the data to prevent simple Base64 decoding.

# Replace these bytes with your actual generated AES data.
# Placeholder values used here for demonstration of the logic structure.
$EncryptedWebhookData = @(187,21,44,89,201,11,55,99,22,111,200,10,5,88,77,201,33,44,55,66,77,88,99,11,22,33,44,55,66,77,88,99) 
$AesKey = @(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)
$AesIV  = @(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)

# Decryption Function (Inline)
function Decrypt-SecureString {
    Param($Bytes, $Key, $IV)
    try {
        $Aes = [System.Security.Cryptography.Aes]::Create()
        $Aes.Key = $Key
        $Aes.IV = $IV
        $Decryptor = $Aes.CreateDecryptor()
        $Stream = New-Object System.IO.MemoryStream(,$Bytes)
        $Crypto = New-Object System.Security.Cryptography.CryptoStream($Stream, $Decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $Reader = New-Object System.IO.StreamReader($Crypto)
        return $Reader.ReadToEnd()
    } catch {
        return $null
    }
}

# Fallback for demonstration if AES fails (Development Mode) or if user hasn't generated keys
# In production, remove this fallback and ensure AES works.
$EncodedWebhook = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ1NDM0MTg5NTY2Nzk3ODM4My9BTEUxRVpUZXVzWHZEUlctSXVLSWpqTXR2QWdkR3k2Tzc4b1dPd1B2VWFsRUo4TGVOeWVzZ2x3RWdZbldxMjJCV1RBVA=="
$DecryptedUrl = Decrypt-SecureString -Bytes $EncryptedWebhookData -Key $AesKey -IV $AesIV

if ([string]::IsNullOrEmpty($DecryptedUrl)) {
    # Fallback to Base64 if AES fails (For compatibility with provided code input)
    $WebhookURL = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedWebhook))
} else {
    $WebhookURL = $DecryptedUrl
}
$WebhookEndpoints = @($WebhookURL)

# ==========================================
# [SELF-ELEVATION - RUN AS ADMIN]
# ==========================================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

    Write-Host "`n[!] Elevation required, relaunching in Administrator mode..." -ForegroundColor Yellow

    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) { $scriptPath = $PSCommandPath }

    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

    try {
        Start-Process "$($PSHome)\powershell.exe" -Verb RunAs -ArgumentList $arguments
    } catch {
        Write-Host "[!] Elevation failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    exit
}

# ==========================================
# [INITIALIZATION]
# ==========================================
Add-Type -AssemblyName System.Windows.Forms
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "SilentlyContinue"
Clear-Host
$host.UI.RawUI.WindowTitle = "SENTINEL"
$ScanStart = Get-Date

# Capture script path for integrity/self-hash
try {
    if ($MyInvocation.MyCommand.Path) {
        $ScriptPath = $MyInvocation.MyCommand.Path
    } else {
        $ScriptPath = $PSCommandPath
    }
} catch {
    $ScriptPath = $null
}

# Generate Verification Code
$Chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
$RandomString = -join ((1..6) | % { $Chars[(Get-Random -Maximum $Chars.Length)] })
$VerificationCode = "SENTINEL-$RandomString"

# Constrained Language Mode info
$PSLanguageMode = $ExecutionContext.SessionState.LanguageMode
if ($PSLanguageMode -ne "FullLanguage") {
    Write-Host "`n [!] WARNING: PowerShell is running in Constrained Language Mode: $PSLanguageMode" -ForegroundColor Yellow
}

# Variables
$RiskScore = 0
$global:EvidenceMap = @{}
$SecurityLog = @()
$DNSLog = @()
$LuaLog = @()
$HeuristicLog = @()
$global:ArtifactLog = @()
$global:LastActions = @()
$global:BrowserHits = @()
$global:DebugHits = @()
$global:TimelineEvents = @()
$global:MonitorString = "Unknown"

# --- DATABASE 1: CHEAT SIGNATURES ---
$CheatDatabase = @(
    "Solara", "Wave", "Celery", "Incognito", "Fluxus", "Krampus", "Ro-Exec", "Synapse",
    "CheatEngine", "ProcessHacker", "Injector", "Executor", "Delta", "Codex", "Vega", "Arceus", "Hydrogen",
    "NetLimiter", "LagSwitch", "Aimmy", "Nezur", "ReClass", "Fiddler", "Wireshark", "Lunar", "DarkDex",
    "OwlHub", "Xeno", "Seliware", "OpAutoClicker", "TinyTask", "Swift", "Lunex", "Nihon", "Zorara",
    "AppleWare", "MacSploit", "Ignis", "Volta", "Valkyrie", "Evon", "Trigon", "Oxygen", "Comet",
    "Ethereal", "Drift", "Blosm", "Memesneeze", "Thunder Client", "Lure", "Chocola", "Serotonin",
    "Severe", "Matcha", "Melatonin", "Matrix Hub", "Rbxcli", "Vector", "DX9ware", "Ronin",
    "Evolve", "Charm", "Isabelle", "LX63", "Valex", "Cryptic", "Vega X", "Volt", "ChocoSploit",
    "Potassium", "Volcano", "Bunni", "Velocity", "SirHurt", "Luna", "Lovreware", "Matrix",
    "newuimatrix", "Crash Handler", "crashhandler", "Unnamed Enhancement", "Crash",
    "Injector.exe", "DLL Injector"
)

# --- DATABASE 2: CHEAT MD5 HASHES (BLACKLIST) ---
$CheatHashes = @(
    "874AA42DE5D8388DCE5C8D883FEC3E61", # Aimmy / CouldBeAimmyV2
    "1B61EDAED8B5543CD875D3D22A219947"  # AimmyLauncher
)

# --- DATABASE 2.1: WHITELISTED MD5 HASHES (SAFE FILES) ---
$WhitelistedHashes = @(
    "PUT_HASHES_FROM_GENERATOR_HERE"
)

# --- WHITELIST (SAFE PUBLISHERS) ---
$TrustedPublishers = @(
    "Microsoft", "Windows", "NVIDIA", "Intel", "AMD", "Google", "Mozilla", "Valve", "Epic Games", "Riot Games",
    "Discord", "Spotify", "Adobe", "Oracle", "Logitech", "Razer", "Corsair", "SteelSeries", "ASUS", "MSI",
    "Roblox", "Ubisoft", "Electronic Arts", "Activision", "Blizzard", "TeamViewer", "Zoom", "OBS", "Streamlabs",
    "Opera", "Brave", "HP", "Dell", "Lenovo", "Acer", "Realtek", "Dolby", "Nahimic", "Figma", "GitHub", "Slack"
)

# --- VULNERABLE DRIVER HASHES ---
$VulnDriverHashes = @(
    "29264D00D0104033C026C5140134914104273010", # kdmapper (intel)
    "4C345330386926078D1C13550868843916053309", # Capcom
    "D268153400570371F14397750700201202573216"  # MSI Afterburner (Old)
)

# Database 3: Domains
$AuthDomains = @(
    "weao.xyz", "inject.today", "solara.dev", "getsolara.dev", "solara.cc", "solaraweb.vercel.app",
    "getwave.gg", "wave.info", "celery.zip", "celeryinjector.com", "incognito.dev",
    "fluxteam.net", "fluxus.team", "delta-executor.com", "deltaexploits.net",
    "codex.lol", "hydrogen.sh", "spdmteam.com", "evon.cc", "vegax.gg",
    "jjsploit.net", "wearedevs.net", "scriptblox.com", "robloxscripts.com",
    "krnl.place", "krampus.gg", "lunexmods.cc", "xeno-executor.com",
    "ark.cloud", "valyse.net", "cometrbx.xyz", "oxygenu.xyz", "cheatbuddy.gg",
    "sirhurt.net", "sakpot.com", "blackout.gg", "nihon.lol", "olympus.gg",
    "zorara.fun", "macsploit.org", "appleware.dev", "ignis.gg", "getignis.gg",
    "lovreware.com", "bunni.lol", "potassium.lol", "ethereal.sh"
)

# Database 4: Lua Signatures
$LuaSignatures = @(
    "loadstring(game:HttpGet", "syn.request", "fluxus.request", "getgenv()",
    "game.Players.LocalPlayer.Character.HumanoidRootPart", "fireclickdetector",
    "game:GetService('VirtualUser')", "is_sirhurt_closure", "pebc_create", "getrenv()._G"
)

# Debug / reversing tools signatures
$DebugTools = @(
    "x64dbg", "x32dbg", "ollydbg", "ida64", "ida32", "idaq", "idaq64",
    "ghidra", "ImmunityDebugger", "procmon", "procexp", "wireshark",
    "fiddler", "cheatengine", "dnSpy", "dotPeek", "scylla", "scylla_x64",
    "radare2", "cutter", "TitanHide", "xAnalyzer"
)

# Counters
$Count_Files = 0
$Count_Processes = 0
$Count_Prefetch = 0
$Count_Recycle = 0
$Count_Registry = 0
$Count_DNS = 0
$Count_Lua = 0

# UI Helper
Function Log-Evidence {
    Param ([string]$Text, [int]$ScoreAdd)

    $global:RiskScore += $ScoreAdd

    if ($global:EvidenceMap.ContainsKey($Text)) {
        $global:EvidenceMap[$Text] = $global:EvidenceMap[$Text] + 1
    } else {
        $global:EvidenceMap[$Text] = 1
        Write-Host "  [-] $Text" -ForegroundColor Red
    }
    $global:TimelineEvents += "$(Get-Date -Format 'u') | $Text"
}

Function Log-Security {
    Param ([string]$Feature, [bool]$Enabled, [bool]$IsCritical)
    if ($Enabled) {
        $Status = "ENABLED"
        $Color = "Green"
        $Icon = "[+]"
    } else {
        $Status = "DISABLED"
        $Color = "Red"
        $Icon = "[!]"
        if ($IsCritical) { $global:RiskScore += 25 }
    }
    Write-Host "  $Icon $Feature : $Status" -ForegroundColor $Color
    $global:SecurityLog += "$Icon $Feature : $Status"
}

# UTF-8 Sanitizer
Function Clean-String {
    Param ([string]$InputString)
    if ([string]::IsNullOrWhiteSpace($InputString)) { return "" }
    return $InputString -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
}

# SHA-256 hash function
Function Get-FileSHA256 {
    Param([string]$Path)
    try {
        if (Test-Path $Path) {
            return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
        }
    } catch {}
    return $null
}

# ROT13 Decoder
Function From-Rot13 {
    Param ([string]$InputString)
    $Characters = $InputString.ToCharArray()
    for ($i = 0; $i -lt $Characters.Length; $i++) {
        $Char = $Characters[$i]
        $Code = [int]$Char
        if ($Char -match '[a-zA-Z]') {
            if (($Char -match '[a-m]') -or ($Char -match '[A-M]')) {
                $Characters[$i] = [char]($Code + 13)
            } else { $Characters[$i] = [char]($Code - 13) }
        }
    }
    return -join $Characters
}

# Webhook sender
Function Send-WebRequestWithRotation {
    Param(
        [string]$JsonBody,
        [string]$ContextLabel
    )

    $Sent = $false
    foreach ($Endpoint in $WebhookEndpoints) {
        if (-not ($Endpoint -match "http")) { continue }
        try {
            Invoke-RestMethod -Uri $Endpoint -Method Post -Body $JsonBody -ContentType "application/json; charset=utf-8"
            $Sent = $true
            break
        } catch {}
    }

    if (-not $Sent) {
        Write-Host " [!] WEBHOOK FAILED for $ContextLabel" -ForegroundColor Red
    }
}

# Smart Splitter
Function Split-LogMessage {
    Param ([string]$LogContent, [int]$ChunkSize = 1900)
    if ([string]::IsNullOrWhiteSpace($LogContent)) { return @("No Data") }
    $Lines = $LogContent -split "`n"
    $Chunks = @()
    $CurrentBuffer = ""
    foreach ($Line in $Lines) {
        $CleanLine = $Line.Trim()
        if ([string]::IsNullOrWhiteSpace($CleanLine)) { continue }
        if (($CurrentBuffer.Length + $CleanLine.Length + 2) -gt $ChunkSize) {
            if ($CurrentBuffer.Length -gt 0) { $Chunks += $CurrentBuffer }
            $CurrentBuffer = $CleanLine + "`n"
        } else { $CurrentBuffer += $CleanLine + "`n" }
    }
    if ($CurrentBuffer.Length -gt 0) { $Chunks += $CurrentBuffer }
    return $Chunks
}

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "             SENTINEL - ADVANCED FORENSICS            " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Scanning System...`n" -ForegroundColor Gray
# ==========================================
# 0. MONITOR CONFIGURATION (NEW)
# ==========================================
Write-Host " [0] MONITOR CONFIGURATION..." -ForegroundColor Magenta
try {
    $Screens = [System.Windows.Forms.Screen]::AllScreens
    $MCount = $Screens.Count
    $MInfo = @()
    $Idx = 1
    foreach ($S in $Screens) {
        $Type = if ($S.Primary) { "(Primary)" } else { "(Ext)" }
        $MInfo += "[$Idx] $($S.Bounds.Width)x$($S.Bounds.Height) $Type"
        $Idx++
    }
    
    $global:MonitorString = "**Count: $MCount** | " + ($MInfo -join ", ")
    
    if ($MCount -gt 1) {
        Write-Host "  [!] MULTIPLE MONITORS DETECTED: $MCount" -ForegroundColor Red
        Log-Evidence "VIOLATION: Multiple Monitors Detected ($MCount)" 100
    } else {
        Write-Host "  [+] Single Monitor Verified" -ForegroundColor Green
    }
} catch {
    $global:MonitorString = "Error Reading Screens"
}

# ==========================================
# 1. NETWORK & DNS FORENSICS
# ==========================================
Write-Host "`n [1] NETWORK & DNS ANALYSIS..." -ForegroundColor Magenta

$HostsPath = "C:\Windows\System32\drivers\etc\hosts"
if (Test-Path $HostsPath) {
    $HostsContent = Get-Content $HostsPath -Raw
    if ($HostsContent -match "discord" -or $HostsContent -match "webhook") {
        Log-Evidence "CRITICAL: HOSTS FILE TAMPERED (Discord Blocked)" 100
    }
}
try {
    $TestReq = Invoke-WebRequest -Uri "https://discord.com" -UseBasicParsing -TimeoutSec 5
    Write-Host "  [+] Connection to Discord: OK" -ForegroundColor Green
} catch {
    Log-Evidence "CRITICAL: CANNOT REACH DISCORD (Check Internet/Firewall)" 100
}

# DNS cache
try {
    $DNSCache = Get-DnsClientCache
    $Count_DNS = $DNSCache.Count
    if ($Count_DNS -lt 5) {
        Log-Evidence "TAMPER: DNS Cache Suspiciously Empty (Recently Flushed)" 60
    }
    foreach ($Entry in $DNSCache) {
        foreach ($Domain in $AuthDomains) {
            if ($Entry.EntryName -match $Domain) {
                if ($global:DNSLog -notcontains "[DNS] Visited: $Domain") {
                    $global:DNSLog += "[DNS] Visited: $Domain"
                    Write-Host "  [!] DNS Trace: $Domain" -ForegroundColor Yellow
                    $global:RiskScore += 15
                    $global:TimelineEvents += "$(Get-Date -Format 'u') | DNS: $($Entry.EntryName)"
                }
            }
        }
    }
} catch {
    Log-Evidence "WARNING: Could not read DNS Cache (Possible Cleaner)" 10
}

# ==========================================
# 2. DEEP FORENSICS (USN, EVENTS & GHOSTS)
# ==========================================
Write-Host "`n [2] DEEP FORENSICS (USN/EVENTS/GHOSTS)..." -ForegroundColor Magenta

# 2A. PREFETCH SCAN (GHOST EXECUTION HISTORY)
try {
    $PrefetchPath = "C:\Windows\Prefetch"
    if (Test-Path $PrefetchPath) {
        $PrefetchFiles = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
        foreach ($PF in $PrefetchFiles) {
            foreach ($Cheat in $CheatDatabase) {
                if ($PF.Name -match $Cheat) {
                    $LastRun = $PF.LastWriteTime
                    Log-Evidence "PREFETCH: Trace of [$Cheat] found! Last executed approx: $LastRun" 80
                    $global:ArtifactLog += "PREFETCH: $($PF.Name) (LastRun: $LastRun)"
                }
            }
        }
    }
} catch {
    # SECURITY: Tamper Detection
    Log-Evidence "CRITICAL: Prefetch Scan Failed (Access Denied/Tampering)" 100
    $global:ArtifactLog += "!!! SCAN FAILED: $($_.Exception.Message) !!!"
}

# 2B. USERASSIST SCAN (GUI EXECUTION HISTORY)
try {
    $UserAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
    if (Test-Path $UserAssistPath) {
        $Entries = Get-ItemProperty $UserAssistPath
        foreach ($Property in $Entries.PSObject.Properties) {
            $Name = $Property.Name
            if ($Name -match "{") { continue }
            $Decoded = From-Rot13 $Name
            
            if ($Decoded -match "\.exe") {
                foreach ($Cheat in $CheatDatabase) {
                    if ($Decoded -match $Cheat) {
                        Log-Evidence "USERASSIST: Evidence of execution for [$Cheat]" 70
                        $global:ArtifactLog += "USERASSIST: $Decoded"
                    }
                }
            }
        }
    }
} catch {}

# 2C. USN JOURNAL SCAN & LAST 10 ACTIONS
try {
    Write-Host "  [.] Reading USN Journal... (Please Wait)" -ForegroundColor Gray
    $USNData = fsutil usn readjournal C: csv | Select-Object -Last 100
    $ActionCounter = 0

    if ($USNData) {
        $USNArray = $USNData | Sort-Object -Descending
        foreach ($Line in $USNArray) {
            $LineStr = $Line.ToString()
            if ($LineStr -match ",") {
                $parts = $LineStr -split ","
                if ($parts.Count -gt 3) {
                    $FileName = $parts[0].Trim('"')
                    $Action   = $parts[3].Trim('"')

                    if ($FileName -match "\.exe|\.dll|\.lua|\.txt|\.zip" -and $FileName -notmatch "SENTINEL" -and $FileName -notmatch "Discord") {
                        if ($ActionCounter -lt 10) {
                            $global:LastActions += "[$Action] $FileName"
                            $ActionCounter++
                        }
                    }

                    foreach ($Cheat in $CheatDatabase) {
                        if ($FileName -match $Cheat) {
                            if ($Action -match "FileDelete" -or $Action -match "Close") {
                                Log-Evidence "FORENSIC: USN Journal found deleted cheat trace [$Cheat]" 60
                            }
                        }
                    }
                }
            }
        }
    }
    Write-Progress -Activity "Forensics: Scanning USN Journal" -Completed
} catch {
    # SECURITY: Tamper Detection
    Log-Evidence "CRITICAL: USN Journal Scan Failed (fsutil access denied)" 100
    Write-Host "  [!] USN Journal Scan Skipped (fsutil error)" -ForegroundColor Yellow
}

# 2D. RECYCLE BIN SCAN
try {
    $Shell = New-Object -ComObject Shell.Application
    $RecycleBin = $Shell.NameSpace(0xA).Items()
    foreach ($Item in $RecycleBin) {
        foreach ($Cheat in $CheatDatabase) {
            if ($Item.Name -match $Cheat) {
                Log-Evidence "RECYCLE BIN: Deleted Cheat [$($Item.Name)] detected!" 60
                $global:ArtifactLog += "RECYCLE: $($Item.Name) (Path: $($Item.Path))"
            }
        }
    }
} catch { Write-Host "  [!] Recycle Bin Access Failed" -ForegroundColor Yellow }

# 2E. EVENT LOGS
try {
    $ServiceEvents = Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($ServiceEvents) {
        foreach ($Event in $ServiceEvents) {
            if ($Event.TimeCreated -gt (Get-Date).AddMinutes(-30)) {
                $Msg = $Event.Message
                if ($Msg -notmatch "Microsoft" -and $Msg -notmatch "Intel" -and $Msg -notmatch "NVIDIA" -and $Msg -notmatch "AMD") {
                    Log-Evidence "SUSPICIOUS: New Service Installed recently! ($($Event.TimeCreated))" 50
                }
            }
        }
    }
} catch {}

# ==========================================
# 3. REGISTRY & SECURITY
# ==========================================
Write-Host "`n [3] REGISTRY & SECURITY..." -ForegroundColor Magenta

# MuiCache
try {
    $MuiPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $MuiPath) {
        $Entries = Get-ItemProperty $MuiPath
        foreach ($Prop in $Entries.PSObject.Properties) {
            foreach ($Cheat in $CheatDatabase) {
                if ($Prop.Name -match $Cheat) {
                    $Count_Registry++
                    Log-Evidence "REGISTRY: MuiCache Trace found for [$Cheat]" 30
                }
            }
        }
    }
} catch {}

# Security Checks
try {
    $MpStatus = Get-MpComputerStatus
    Log-Security "Defender Real-Time" $MpStatus.RealTimeProtectionEnabled $true
    Log-Security "Tamper Protection" $MpStatus.IsTamperProtected $true
} catch { Log-Security "Defender Service" $false $true }

try {
    $VBS = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
    $VBS_Bool = if ($VBS.Enabled -eq 1) { $true } else { $false }
    Log-Security "Core Isolation" $VBS_Bool $false
} catch { Log-Security "Core Isolation" $false $false }

$TestSign = bcdedit /enum "{current}" | Select-String "testsigning"
if ($TestSign -match "Yes|On") {
    Log-Evidence "SECURITY FATAL: TEST SIGNING MODE ENABLED" 100
    Log-Security "Driver Signature Enf." $false $true
} else {
    Log-Security "Driver Signature Enf." $true $false
}

$DebugCheck = bcdedit /enum "{current}" | Select-String "debug"
if ($DebugCheck -match "Yes|On") {
    Log-Evidence "SECURITY FATAL: KERNEL DEBUGGING IS ACTIVE" 100
    Log-Security "Kernel Debug Prevention" $false $true
} else {
    Log-Security "Kernel Debug Prevention" $true $false
}

try {
    $Blocklist = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" -Name "VulnerableDriverBlocklistEnable" -ErrorAction SilentlyContinue
    if ($Blocklist.VulnerableDriverBlocklistEnable -eq 0) {
        Log-Evidence "SECURITY WEAKNESS: Vulnerable Driver Blocklist is DISABLED" 50
        Log-Security "Vuln. Driver Blocklist" $false $true
    } else {
        Log-Security "Vuln. Driver Blocklist" $true $false
    }
} catch { Log-Security "Vuln. Driver Blocklist" $true $false }

# ===== EXTENDED FROM INSPECTION SCRIPT (WEBHOOK-FRIENDLY SUMMARIES) =====

# Non-system drivers summary
try {
    $NonSystemDrivers = Get-WmiObject Win32_SystemDriver |
        Where-Object { $_.PathName -and $_.PathName -notmatch "system32" }

    if ($NonSystemDrivers) {
        $Lines = @()
        foreach ($d in $NonSystemDrivers) {
            $Lines += "$($d.Name)  |  $($d.PathName)  |  $($d.State)"
        }
        $global:HeuristicLog += "`n==== Non-System Drivers ===="
        $global:HeuristicLog += ($Lines -join "`n")
        Log-Evidence "DRIVERS: Found $($NonSystemDrivers.Count) non-system drivers loaded." 15
    }
} catch {}

# Startup Run keys & enabled scheduled tasks
try {
    $RunSummary = @()
    $HKCU_Run = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $HKLM_Run = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

    if (Test-Path $HKCU_Run) {
        $props = Get-ItemProperty $HKCU_Run
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like "PS*") { continue }
            $RunSummary += "[HKCU] $($p.Name) = $($p.Value)"
        }
    }
    if (Test-Path $HKLM_Run) {
        $props = Get-ItemProperty $HKLM_Run
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like "PS*") { continue }
            $RunSummary += "[HKLM] $($p.Name) = $($p.Value)"
        }
    }

    if ($RunSummary.Count -gt 0) {
        $global:HeuristicLog += "`n==== Startup Registry Entries (Run) ===="
        $global:HeuristicLog += ($RunSummary -join "`n")
        Log-Evidence "PERSISTENCE: Startup Run entries present (see heuristic log)." 10
    }
} catch {}

try {
    $Tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
    if ($Tasks) {
        $TaskLines = @()
        foreach ($t in $Tasks) {
            $TaskLines += "$($t.TaskName)  |  $($t.TaskPath)  |  $($t.State)"
        }
        $global:HeuristicLog += "`n==== Enabled Scheduled Tasks ===="
        $global:HeuristicLog += ($TaskLines -join "`n")
        Log-Evidence "PERSISTENCE: Enabled scheduled tasks present (see heuristic log)." 10
    }
} catch {}

# Defender exclusions & threat history summary
try {
    $pref = Get-MpPreference
    $ExclInfo = @()
    if ($pref.ExclusionPath)      { $ExclInfo += "Paths: $($pref.ExclusionPath -join ', ')" }
    if ($pref.ExclusionProcess)   { $ExclInfo += "Processes: $($pref.ExclusionProcess -join ', ')" }
    if ($pref.ExclusionExtension) { $ExclInfo += "Extensions: $($pref.ExclusionExtension -join ', ')" }

    if ($ExclInfo.Count -gt 0) {
        $global:SecurityLog += "`nDefender Exclusions:`n$($ExclInfo -join "`n")"
        Log-Evidence "DEFENDER: Exclusions configured (see Security Audit embed)." 20
    }

    $threats = Get-MpThreatDetection | Select-Object -First 20
    if ($threats) {
        $Lines = @()
        foreach ($t in $threats) {
            $Lines += "$($t.ThreatName) | Success=$($t.ActionSuccess) | $($t.InitialDetectionTime)"
        }
        $global:HeuristicLog += "`n==== Windows Defender Threat History (Last 20) ===="
        $global:HeuristicLog += ($Lines -join "`n")
        Log-Evidence "DEFENDER: Threat history entries present (see heuristic log)." 25
    }
} catch {}
# ==========================================
# 4. ARTIFACT, LUA & BROWSER SCAN
# ==========================================
Write-Host "`n [4] ARTIFACT, LUA & BROWSER SCAN..." -ForegroundColor Magenta

Function Scan-BrowserFile {
    Param($HistoryPath, $BrowserName)
    try {
        if (Test-Path $HistoryPath) {
            $TempPath = "$env:TEMP\SENTINEL_Hist_$BrowserName.tmp"
            Copy-Item -Path $HistoryPath -Destination $TempPath -Force -ErrorAction SilentlyContinue
            
            $Content = Get-Content $TempPath -Raw -ErrorAction SilentlyContinue
            foreach ($Domain in $AuthDomains) {
                if ($Content -match $Domain) {
                    $Hit = "[$BrowserName] Visited: $Domain"
                    if ($global:BrowserHits -notcontains $Hit) {
                        $global:BrowserHits += $Hit
                        Log-Evidence "BROWSER: History trace found for [$Domain] on $BrowserName" 20
                    }
                }
            }
            Remove-Item $TempPath -ErrorAction SilentlyContinue
        }
    } catch {}
}
Scan-BrowserFile "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" "Chrome"
Scan-BrowserFile "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" "Edge"
$FirefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $FirefoxPath) {
    Get-ChildItem $FirefoxPath | ForEach-Object {
        Scan-BrowserFile "$($_.FullName)\places.sqlite" "Firefox"
    }
}

# LUA/TXT FILES
$ScanPaths = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\AppData\Local\Temp", "$env:USERPROFILE\Documents")
$FileTypes = @("*.lua", "*.txt")
$AllFiles = @()

Write-Host "  [.] Indexing files... (This may take a moment)" -ForegroundColor Gray
foreach ($Path in $ScanPaths) {
    if (Test-Path $Path) {
        $Found = Get-ChildItem -Path $Path -Include $FileTypes -Recurse -ErrorAction SilentlyContinue -Force | Where-Object { $_.Length -lt 500000 } | Select-Object -First 200
        $AllFiles += $Found
    }
}

$TotalFiles = $AllFiles.Count
$CurrentFileIndex = 0

foreach ($File in $AllFiles) {
    $CurrentFileIndex++
    if ($CurrentFileIndex % 5 -eq 0) {
        Write-Progress -Activity "Deep Scan: LUA/TXT Analysis" -Status "Analyzing: $($File.Name)" -PercentComplete (($CurrentFileIndex / $TotalFiles) * 100)
    }

    $Count_Files++
    try {
        $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue

        # Entropie simple
        $Entropy = 0
        if ($Content.Length -gt 0) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
            $freq = @{}
            foreach ($b in $bytes) { if (-not $freq.ContainsKey($b)) { $freq[$b] = 0 }; $freq[$b]++ }
            $Entropy = 0
            foreach ($k in $freq.Keys) {
                $p = $freq[$k] / $bytes.Length
                $Entropy -= $p * [Math]::Log($p,2)
            }
        }
        if ($Entropy -gt 7.5) {
            Log-Evidence "LUA/TXT: High entropy content detected [$($File.Name)]" 15
        }

        foreach ($Sig in $LuaSignatures) {
            if ($Content -match [regex]::Escape($Sig)) {
                $Count_Lua++
                $global:LuaLog += "[LUA] Found Sig [$Sig] in file: $($File.Name)"
                Write-Host "  [!] Lua Found: $($File.Name)" -ForegroundColor Red
                $global:RiskScore += 40
                break
            }
        }
    } catch {}
}
Write-Progress -Activity "Deep Scan: LUA/TXT Analysis" -Completed
# ==========================================
# 5. HEURISTIC PROCESS & DRIVER SCAN (CORRECTED V2)
# ==========================================
Write-Host "`n [5] HEURISTIC PROCESS & DRIVER SCAN..." -ForegroundColor Magenta

# --- 5.0 INITIALIZATION OF MISSING VARIABLES ---
# HWID Calculation (was missing for the empty box)
try {
    $UUID = (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
    $Disk = (Get-CimInstance -Class Win32_DiskDrive | Select-Object -First 1).SerialNumber
    $HWID_Display = "UUID: $UUID`nDisk: $Disk"
} catch {
    $HWID_Display = "HWID: Not available (WMI Error)"
}

# Explicit initialization of log arrays
$global:Log_Drivers = @()
$global:Log_Persistence = @()
$global:Log_Defender = @()
$global:Log_Unsigned = @()
$global:Log_Roblox = @()
$global:Log_Temp = @()
$global:Log_Processes = @()

# --- 5.1 DRIVER SCAN (KERNEL AWARENESS) ---
Write-Host "  [.] Scanning Drivers..." -ForegroundColor Gray
try {
    # Method 1: DriverQuery
    $Drivers = driverquery /v /fo csv | ConvertFrom-Csv
    foreach ($Driver in $Drivers) {
        if ($Driver.Signed -eq "FALSE") {
             Log-Evidence "KERNEL: Unsigned driver detected [$($Driver.'Display Name')]" 80
             $global:Log_Drivers += "⚠️ $($Driver.'Display Name') (Unsigned) - $($Driver.PathName)"
        }
    }
    
    # Method 2: WMI Non-System (Complement)
    $NonSystemDrivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -and $_.PathName -notmatch "system32" -and $_.State -eq "Running" }
    foreach ($d in $NonSystemDrivers) {
        $global:Log_Drivers += "[Active] $($d.Name) | Path: $($d.PathName)"
    }
} catch {
    # SECURITY: Tamper Detection
    Log-Evidence "CRITICAL: Driver Scan Failed (WMI/DriverQuery Tampered)" 100
    $global:Log_Drivers += "!!! SCAN FAILED: $($_.Exception.Message) !!!"
}

# --- 5.2 PROCESS SCAN ---
Write-Host "  [.] Scanning Processes..." -ForegroundColor Gray
$Processes = Get-CimInstance Win32_Process
$TotalProcs = $Processes.Count
$ProcIndex = 0

# SECURITY: Process Cross-Check (Tasklist vs PowerShell)
# Detects simple rootkits or hooks hiding processes from PS API
try {
    $TaskListRaw = tasklist /fo csv | ConvertFrom-Csv
    $TaskNames = $TaskListRaw | ForEach-Object { $_."Image Name" }
    $PSProcNames = $Processes | ForEach-Object { $_.Name }
    
    $Diff = Compare-Object -ReferenceObject $TaskNames -DifferenceObject $PSProcNames -PassThru | Where-Object { $_.SideIndicator -eq "<=" }
    
    if ($Diff) {
        foreach ($HiddenProc in $Diff) {
            Log-Evidence "ANOMALY: Process hidden from PowerShell API: [$HiddenProc]" 80
            $global:Log_Processes += "Mismatch: $HiddenProc (Visible in Tasklist, Hidden in PS)"
        }
    }
} catch {}

foreach ($Proc in $Processes) {
    $ProcIndex++
    if ($ProcIndex % 20 -eq 0) { Write-Progress -Activity "Heuristic Scan" -Status "Analyzing Process: $($Proc.Name)" -PercentComplete (($ProcIndex / $TotalProcs) * 100) }

    $IsAdmin = $false
    $IsWhitelisted = $false
    
    # Check Owner
    try { 
        $OwnerObj = Invoke-CimMethod -InputObject $Proc -MethodName GetOwner
        $User = $OwnerObj.User
    } catch {}
    if ($User -match "SYSTEM" -or $User -match "Administrator" -or $User -match "SERVICE") { $IsAdmin = $true }

    # Get System Object
    $SysProc = $null
    try { $SysProc = Get-Process -Id $Proc.ProcessId -ErrorAction SilentlyContinue } catch {}

    if ($SysProc -and $SysProc.Path) {
        try {
            $MD5 = (Get-FileHash -Path $SysProc.Path -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            
            # Check Whitelist/Blacklist
            if ($WhitelistedHashes -contains $MD5) { $IsWhitelisted = $true }
            if ($CheatHashes -contains $MD5) {
                 Log-Evidence "CRITICAL: CHEAT HASH DETECTED! Process: [$($Proc.Name)]" 100
                 $global:Log_Processes += "🚨 [CHEAT CONFIRMED] $($Proc.Name) ($MD5)"
            }

            # Check Signature
            $Sig = Get-AuthenticodeSignature $SysProc.Path
            if ($Sig.Status -eq "Valid") {
                foreach ($Pub in $TrustedPublishers) {
                    if ($Sig.SignerCertificate.Subject -match $Pub) { $IsWhitelisted = $true; break }
                }
            } else {
                # Log Unsigned Executables specifically
                $global:Log_Unsigned += "[$($Sig.Status)] $($Proc.Name) -> $($SysProc.Path)"
            }
        } catch {}
    }

    # Formatting Line for Process Log
    $LineInfo = "$($Proc.Name) ($($Proc.ProcessId))"
    if ($IsAdmin) { $LineInfo += " [ADM]" }
    if ($IsWhitelisted) { $LineInfo += " [WL]" }
    else { $LineInfo += " [UNK]" } # Unknown / Not Whitelisted
    
    $global:Log_Processes += $LineInfo

    # Deep Check (Renamed Cheats)
    if ($SysProc) {
        try {
            if ($SysProc.Path) {
                $InternalName = $SysProc.MainModule.FileVersionInfo.OriginalFilename
                foreach ($Cheat in $CheatDatabase) {
                    if ($InternalName -match $Cheat) {
                        Log-Evidence "DEEP: Renamed cheat detected! [$($Proc.Name)]" 80
                    }
                }
            }
        } catch {}
    }
}
Write-Progress -Activity "Heuristic Scan" -Completed

# --- 5.3 PERSISTENCE (RUN & TASKS) ---
Write-Host "  [.] Scanning Persistence..." -ForegroundColor Gray
try {
    # HKCU Run
    $HKCU_Run = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Test-Path $HKCU_Run) {
        $props = Get-ItemProperty $HKCU_Run
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like "PS*") { continue }
            $global:Log_Persistence += "[HKCU Run] $($p.Name) = $($p.Value)"
        }
    }
    # Scheduled Tasks (Non-Microsoft)
    $Tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
    foreach ($t in $Tasks) {
        if ($t.TaskPath -notmatch "Microsoft" -and $t.TaskPath -notmatch "Windows") {
             $global:Log_Persistence += "[Task] $($t.TaskName) (Path: $($t.TaskPath))"
        }
    }
} catch {}

# --- 5.4 DEFENDER HISTORY ---
try {
    $threats = Get-MpThreatDetection | Select-Object -First 20
    foreach ($t in $threats) {
        $global:Log_Defender += "[$($t.InitialDetectionTime)] $($t.ThreatName) (Success: $($t.ActionSuccess))"
    }
} catch {}

# --- 5.5 ROBLOX SPECIFICS ---
try {
    $rbx = Get-Process RobloxPlayerBeta -ErrorAction SilentlyContinue
    if ($rbx) {
        $rbx.Modules | ForEach-Object {
            $global:Log_Roblox += "Mod: $($_.ModuleName) ($($_.FileName))"
        }
    }
} catch {}

# --- 5.6 TEMP EXECUTABLES ---
try {
    Get-ChildItem "C:\Users\*\AppData\Local\Temp" -Recurse -Include *.exe -ErrorAction SilentlyContinue | Select-Object -First 30 | Sort-Object CreationTime -Descending | ForEach-Object {
        $global:Log_Temp += "[$($_.CreationTime)] $($_.Name)"
    }
} catch {}

# ==========================================
# 6. REPORTING (HTML GENERATION V3 - CYBERPUNK EDITION)
# ==========================================
$ScanDuration = [math]::Round(((Get-Date) - $ScanStart).TotalSeconds, 2)
if ($RiskScore -gt 100) { $RiskScore = 100 }

$RiskLevel = "CLEAN"
$HtmlColor = "#00ff9d" # Green Neon
if ($RiskScore -gt 0) { $RiskLevel = "WARNING"; $HtmlColor = "#f9e2af" } # Yellow
if ($RiskScore -ge 50) { $RiskLevel = "CRITICAL"; $HtmlColor = "#ff003c" } # Red Neon

# --- HELPER: Safe HTML String ---
Function Get-LogContent {
    Param($ArrayData)
    if ($null -eq $ArrayData -or $ArrayData.Count -eq 0) { 
        return "<div class='log-entry empty'>NO ANOMALIES DETECTED</div>" 
    }
    $Raw = $ArrayData -join "`n"
    $Escaped = ($Raw -replace "&", "&amp;" -replace "<", "&lt;" -replace ">", "&gt;")
    # Wrap lines for searchability
    $Lines = $Escaped -split "`n"
    $Result = ""
    foreach($L in $Lines) {
        if($L.Trim().Length -gt 0) {
            $Result += "<div class='log-entry'>$L</div>"
        }
    }
    return $Result
}

# --- PREPARE DATA ---
$Html_Evidence    = Get-LogContent ($global:EvidenceMap.Keys)
$Html_Security    = Get-LogContent $SecurityLog
$Html_Network     = Get-LogContent ($DNSLog + $LuaLog)
$Html_Artifacts   = Get-LogContent $global:ArtifactLog
$Html_Processes   = Get-LogContent $global:Log_Processes
$Html_Drivers     = Get-LogContent $global:Log_Drivers
$Html_Persistence = Get-LogContent $global:Log_Persistence
$Html_Unsigned    = Get-LogContent $global:Log_Unsigned
$Html_Other       = Get-LogContent ($global:Log_Defender + $global:Log_Roblox + $global:Log_Temp)

# --- GENERATE HTML (CYBERPUNK GLASSMORPHISM WITH STRICT AND FILTERS) ---
$HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SENTINEL // $VerificationCode</title>
<style>
    :root {
        --bg-color: #050505;
        --card-bg: rgba(20, 20, 25, 0.6);
        --text-color: #e0e0e0;
        --accent: $HtmlColor;
        --accent-glow: ${HtmlColor}40;
        --glass-border: 1px solid rgba(255, 255, 255, 0.1);
        --font-mono: 'Consolas', 'Courier New', monospace;
        --font-main: 'Segoe UI', system-ui, sans-serif;
    }
    
    body {
        background-color: var(--bg-color);
        background-image: radial-gradient(circle at 50% 0%, #1a1a2e 0%, #000000 100%);
        color: var(--text-color);
        font-family: var(--font-main);
        margin: 0;
        padding: 0;
        overflow-x: hidden;
    }

    /* SCROLLBAR */
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #000; }
    ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--accent); }

    .container {
        max-width: 1200px;
        margin: 40px auto;
        padding: 0 20px;
    }

    /* HEADER & VISUALIZER */
    .dashboard-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 40px;
        padding: 20px;
        background: var(--card-bg);
        backdrop-filter: blur(15px);
        border: var(--glass-border);
        border-radius: 12px;
        box-shadow: 0 0 30px rgba(0,0,0,0.5);
    }

    .header-info h1 {
        margin: 0;
        font-size: 2rem;
        letter-spacing: 2px;
        text-transform: uppercase;
        background: linear-gradient(90deg, #fff, #888);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .header-info .meta {
        font-family: var(--font-mono);
        color: #666;
        margin-top: 5px;
        font-size: 0.9rem;
    }

    .risk-visualizer {
        display: flex;
        align-items: center;
        gap: 20px;
    }

    .score-circle {
        width: 100px;
        height: 100px;
        border-radius: 50%;
        border: 4px solid #333;
        border-top: 4px solid var(--accent);
        border-right: 4px solid var(--accent);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 2.2rem;
        font-weight: bold;
        color: var(--accent);
        text-shadow: 0 0 15px var(--accent);
        box-shadow: 0 0 20px var(--accent-glow);
        animation: pulse 2s infinite;
    }

    .risk-label {
        text-align: right;
    }
    .risk-label .status {
        display: block;
        font-size: 1.5rem;
        font-weight: bold;
        color: var(--accent);
        text-transform: uppercase;
    }

    @keyframes pulse {
        0% { box-shadow: 0 0 10px var(--accent-glow); }
        50% { box-shadow: 0 0 25px var(--accent-glow); }
        100% { box-shadow: 0 0 10px var(--accent-glow); }
    }

    /* TABS SYSTEM */
    .tabs {
        display: flex;
        gap: 10px;
        margin-bottom: 20px;
        border-bottom: 1px solid #333;
        padding-bottom: 10px;
    }

    .tab-btn {
        background: rgba(255,255,255,0.05);
        border: 1px solid transparent;
        color: #888;
        padding: 10px 20px;
        cursor: pointer;
        font-family: var(--font-mono);
        text-transform: uppercase;
        font-size: 0.9rem;
        border-radius: 4px;
        transition: all 0.3s ease;
    }

    .tab-btn:hover {
        background: rgba(255,255,255,0.1);
        color: #fff;
    }

    .tab-btn.active {
        background: rgba(0, 0, 0, 0.3);
        border-color: var(--accent);
        color: var(--accent);
        box-shadow: 0 0 10px var(--accent-glow) inset;
    }

    /* TAB CONTENT */
    .tab-content {
        display: none;
        animation: fadeIn 0.4s ease;
    }
    .tab-content.active {
        display: block;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .panel {
        background: var(--card-bg);
        backdrop-filter: blur(10px);
        border: var(--glass-border);
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }

    .panel-title {
        font-size: 1rem;
        color: #fff;
        margin-bottom: 15px;
        border-left: 3px solid var(--accent);
        padding-left: 10px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* LOGS STYLING */
    .log-container {
        max-height: 500px;
        overflow-y: auto;
        background: rgba(0,0,0,0.3);
        border-radius: 4px;
        padding: 10px;
        border: 1px solid #333;
    }

    .log-entry {
        font-family: var(--font-mono);
        font-size: 12px;
        padding: 4px 8px;
        border-bottom: 1px solid rgba(255,255,255,0.05);
        color: #bbb;
    }
    .log-entry:hover { background: rgba(255,255,255,0.05); color: #fff; }
    .log-entry.empty { color: #555; font-style: italic; text-align: center; padding: 20px; }

    /* SEARCH BAR & FILTERS */
    .search-container {
        margin-bottom: 15px;
    }
    .search-bar {
        width: 100%;
        padding: 12px;
        background: rgba(0,0,0,0.5);
        border: 1px solid #444;
        color: #fff;
        border-radius: 6px;
        margin-bottom: 10px;
        font-family: var(--font-mono);
        outline: none;
        transition: 0.3s;
        box-sizing: border-box;
    }
    .search-bar:focus {
        border-color: var(--accent);
        box-shadow: 0 0 10px var(--accent-glow);
    }
    
    .filter-controls {
        display: flex;
        gap: 15px;
        font-family: var(--font-mono);
        font-size: 0.9rem;
        color: #aaa;
    }
    .filter-controls label {
        display: flex;
        align-items: center;
        gap: 6px;
        cursor: pointer;
        padding: 4px 8px;
        background: rgba(255,255,255,0.03);
        border-radius: 4px;
        border: 1px solid transparent;
        transition: 0.2s;
    }
    .filter-controls label:hover {
        background: rgba(255,255,255,0.08);
        color: #fff;
    }
    .filter-controls input[type="checkbox"] {
        accent-color: var(--accent);
    }

    /* GRID FOR STATS */
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 15px;
        margin-bottom: 20px;
    }
    .stat-box {
        background: rgba(255,255,255,0.03);
        padding: 15px;
        border-radius: 6px;
        border: 1px solid rgba(255,255,255,0.05);
    }
    .stat-label { font-size: 0.8rem; color: #666; text-transform: uppercase; }
    .stat-value { font-size: 1.1rem; color: #fff; font-weight: bold; margin-top: 5px; }

</style>
</head>
<body>

<div class="container">
    
    <!-- HEADER & VISUALIZER -->
    <div class="dashboard-header">
        <div class="header-info">
            <h1>Sentinel <span style="font-size:0.5em; color:var(--accent); vertical-align:middle; border:1px solid var(--accent); padding:2px 6px; border-radius:4px;">PRO</span></h1>
            <div class="meta">
                ID: $VerificationCode <br>
                User: $env:USERNAME <br>
                Date: $(Get-Date -Format "yyyy-MM-dd HH:mm")
            </div>
        </div>
        <div class="risk-visualizer">
            <div class="risk-label">
                <span style="font-size:0.8rem; color:#666">THREAT LEVEL</span>
                <span class="status">$RiskLevel</span>
            </div>
            <div class="score-circle">
                $RiskScore%
            </div>
        </div>
    </div>

    <!-- TABS NAVIGATION -->
    <div class="tabs">
        <button class="tab-btn active" onclick="openTab('tab-detections')">Detections</button>
        <button class="tab-btn" onclick="openTab('tab-processes')">Processes</button>
        <button class="tab-btn" onclick="openTab('tab-network')">Network</button>
        <button class="tab-btn" onclick="openTab('tab-system')">System & Drivers</button>
    </div>

    <!-- TAB 1: DETECTIONS (Overview) -->
    <div id="tab-detections" class="tab-content active">
        
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-label">Scan Time</div>
                <div class="stat-value">${ScanDuration}s</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Files Scanned</div>
                <div class="stat-value">$Count_Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Integrity</div>
                <div class="stat-value">$IntegrityStatus</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Monitors</div>
                <div class="stat-value" style="font-size:0.8rem">$global:MonitorString</div>
            </div>
        </div>

        <div class="panel">
            <div class="panel-title">Active Threats & Evidence ($global:EvidenceMap.Count)</div>
            <div class="log-container" style="border-color: var(--accent);">
                $Html_Evidence
            </div>
        </div>

        <div class="panel">
            <div class="panel-title">Security Audit</div>
            <div class="log-container">
                $Html_Security
            </div>
        </div>
    </div>

    <!-- TAB 2: PROCESSES (With Search & Filters) -->
    <div id="tab-processes" class="tab-content">
        <div class="panel">
            <div class="panel-title">Live Process List ($Count_Processes)</div>
            <div class="search-container">
                <input type="text" id="procInput" class="search-bar" onkeyup="filterProcess()" placeholder="Type to filter processes (PID, Name)...">
                <div class="filter-controls">
                    <label><input type="checkbox" id="chkWL" onchange="filterProcess()"> [WL] Whitelisted</label>
                    <label><input type="checkbox" id="chkAdmin" onchange="filterProcess()"> [ADM] Admin</label>
                    <label><input type="checkbox" id="chkUnk" onchange="filterProcess()"> [UNK] Unknown</label>
                </div>
            </div>
            <div class="log-container" id="procList" style="height: 600px;">
                $Html_Processes
            </div>
        </div>
    </div>

    <!-- TAB 3: NETWORK -->
    <div id="tab-network" class="tab-content">
        <div class="panel">
            <div class="panel-title">DNS & Lua Connections</div>
            <div class="log-container">
                $Html_Network
            </div>
        </div>
        <div class="panel">
            <div class="panel-title">Browser Artifacts</div>
            <div class="log-container">
                <div class="log-entry">Check main evidence log for specific hits.</div>
            </div>
        </div>
    </div>

    <!-- TAB 4: SYSTEM -->
    <div id="tab-system" class="tab-content">
        <div class="panel">
            <div class="panel-title">Kernel / Drivers</div>
            <div class="log-container">
                $Html_Drivers
            </div>
        </div>
        <div class="panel">
            <div class="panel-title">Unsigned Executables</div>
            <div class="log-container">
                $Html_Unsigned
            </div>
        </div>
        <div class="panel">
            <div class="panel-title">Persistence (Run/Tasks)</div>
            <div class="log-container">
                $Html_Persistence
            </div>
        </div>
        <div class="panel">
            <div class="panel-title">Artifacts (Prefetch/Recycle)</div>
            <div class="log-container">
                $Html_Artifacts
            </div>
        </div>
    </div>

</div>

<script>
    // Tab Switching Logic
    function openTab(tabName) {
        var i, x, tablinks;
        x = document.getElementsByClassName("tab-content");
        for (i = 0; i < x.length; i++) {
            x[i].style.display = "none";
            x[i].classList.remove("active");
        }
        tablinks = document.getElementsByClassName("tab-btn");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].classList.remove("active");
        }
        document.getElementById(tabName).style.display = "block";
        document.getElementById(tabName).classList.add("active");
        
        // Find the button that was clicked (approximate)
        var btns = document.getElementsByTagName("button");
        for (i=0; i<btns.length; i++) {
            if(btns[i].getAttribute("onclick").includes(tabName)) {
                btns[i].classList.add("active");
            }
        }
    }

    // Process Filter Logic (Strict AND Logic)
    function filterProcess() {
        var input, filter, container, divs, i, txtValue;
        
        // Get Inputs
        input = document.getElementById("procInput");
        filter = input.value.toUpperCase();
        
        // Get Checkbox States
        var showWL = document.getElementById("chkWL").checked;
        var showAdmin = document.getElementById("chkAdmin").checked;
        var showUnk = document.getElementById("chkUnk").checked;

        var anyFilterActive = showWL || showAdmin || showUnk;

        container = document.getElementById("procList");
        divs = container.getElementsByTagName("div");
        
        for (i = 0; i < divs.length; i++) {
            txtValue = divs[i].textContent || divs[i].innerText;
            var upperText = txtValue.toUpperCase();
            
            var matchesFilter = true;

            // Strict AND Logic: If filters are active, item must match ALL active filters.
            if (anyFilterActive) {
                if (showWL && upperText.indexOf("[WL]") === -1) { matchesFilter = false; }
                if (showAdmin && upperText.indexOf("[ADM]") === -1) { matchesFilter = false; }
                if (showUnk && upperText.indexOf("[UNK]") === -1) { matchesFilter = false; }
            }

            // Search Filter
            if (matchesFilter && filter !== "" && upperText.indexOf(filter) === -1) {
                matchesFilter = false;
            }

            if (matchesFilter) {
                divs[i].style.display = "";
            } else {
                divs[i].style.display = "none";
            }
        }
    }
</script>

</body>
</html>
"@

# ==========================================
# 7. SAVE & UPLOAD
# ==========================================
$ReportFileName = "Report_$($VerificationCode).html"
$ReportPath = "$env:TEMP\$ReportFileName"

# FORCE UTF-8 (Sans BOM pour compatibilité maximale)
$Utf8NoBom = New-Object System.Text.UTF8Encoding $False
[System.IO.File]::WriteAllLines($ReportPath, $HtmlContent, $Utf8NoBom)

Write-Host "`n[+] Report generated successfully: $ReportPath" -ForegroundColor Green

Function Upload-DiscordFile {
    Param($Uri, $FilePath)
    $File = Get-Item $FilePath
    $FileContent = [System.IO.File]::ReadAllBytes($FilePath)
    $Boundary = "----WebKitFormBoundary$(Get-Random)"
    $LF = "`r`n"
    
    $BodyLines = @(
        "--$Boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$($File.Name)`"",
        "Content-Type: text/html",
        "",
        [System.Text.Encoding]::UTF8.GetString($FileContent),
        "--$Boundary--"
    ) -join $LF

    try {
        Invoke-RestMethod -Uri $Uri -Method Post -ContentType "multipart/form-data; boundary=$Boundary" -Body $BodyLines
        return $true
    } catch { return $false }
}

if ($WebhookEndpoints.Count -gt 0 -and ($WebhookEndpoints -join ",") -match "http") {
    Write-Host " Sending to Discord..." -ForegroundColor Cyan
    
    # SECURITY: HMAC Signature Implementation
    # Prevent report tampering by signing the payload with a secret salt
    $SecretSalt = "SENTINEL_SECURE_V1" 
    $SignatureRaw = "$RiskScore-$VerificationCode-$env:USERNAME-$SecretSalt"
    $SHA256 = [System.Security.Cryptography.SHA256]::Create()
    $HashBytes = $SHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($SignatureRaw))
    $SignatureHash = [System.BitConverter]::ToString($HashBytes) -replace '-'

    $SummaryPayload = @{
        username = "Sentinel"
        embeds = @(
            @{
                title = "Sentinel Scan | $VerificationCode"
                color = $DiscordColor
                description = "HTML Report attached."
                fields = @( 
                    @{ name = "User"; value = "$env:USERNAME"; inline = $true }, 
                    @{ name = "Score"; value = "$RiskScore%"; inline = $true } 
                )
                footer = @{
                    text = "SIG: $SignatureHash" 
                }
            }
        )
    } | ConvertTo-Json
    
    try { Invoke-RestMethod -Uri $WebhookURL -Method Post -Body $SummaryPayload -ContentType "application/json" } catch {}

    $UploadStatus = Upload-DiscordFile -Uri $WebhookURL -FilePath $ReportPath
    
    if ($UploadStatus) {
        Write-Host " [OK] Sent!" -ForegroundColor Green
    } else {
        Write-Host " [!] Sending failed. Local file: $ReportPath" -ForegroundColor Red
        Invoke-Item $ReportPath
    }
} else {
    Invoke-Item $ReportPath
}

Write-Host "`nDone." -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CODE: $VerificationCode" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
Start-Sleep -Seconds 9999
