<# 
.SYNOPSIS
  Workstation Health / Maintenance Report

.DESCRIPTION
  Generates a text report with (in this order):
   1) Machine identity, domain/workgroup
   2) OS Version information
   3) Hardware & system inventory
   4) Memory & pagefile usage
   5) Last restart (boot time)
   6) Last interactive logons (last 3)
   7) Volume used + size (flags > 90% used)
   8) User profile file counts (Documents/Downloads/Desktop/Pictures)
   9) BitLocker status (+ recovery key IDs; not full passwords)
  10) Disk health / SMART summary
  11) Last disk defrag (for non-SSD disks, if detectable)
  12) Restore points & shadow copies
  13) Local admins & password last changed
  14) Crash / BSOD diagnostics
  15) AV status & last Defender scans
  16) Windows Update status (last success, failed, pending)
  17) Installed software audit
  18) Windows Firewall State + WAN IP
  19) Security configuration checks (UAC, RDP, Defender)
  20) Summary counts of Warnings & Errors (last N days)
  21) Failed logon events (Security log)
  22) Detailed Error events (last N days, key logs)
  23) Screen lock / inactivity lock (current user)
  24) Additional housekeeping suggestions

.NOTES
  Run as Administrator for best results (Security log, BitLocker, AV, etc.)
#>

[CmdletBinding()]
param(
    [int]$DaysToCheck = 30,
    [string]$TimeZoneId = "SE Asia Standard Time",   # Thailand (UTC+7)
    [switch]$ShowScriptHash
)

$script:ScriptVersion = "1.4"


# -------------- Helpers --------------

function Get-FirstNonEmptyLine {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    foreach ($line in ($Text -split "`r?`n")) {
        $t = $line.Trim()
        if ($t) { return $t }
    }
    return $null
}

function Try-ParseVersion {
    param([string]$Text)

    $line = Get-FirstNonEmptyLine -Text $Text
    if (-not $line) { return $null }

    # Accept only digits and dots, must include at least one dot: 1.1, 1.11, 1.2, 10.0.1 etc.
    if ($line -notmatch '^\d+(\.\d+)+$') { return $null }

    try { return [version]$line } catch { return $null }
}

function Convert-RemoteVersionText {
    param([string]$Text)

    $line = Get-FirstNonEmptyLine -Text $Text
    if (-not $line) { return $null }

    $line = $line.Trim()

    if ($line -match '^\d+(\.\d+)+$') { return $line }
    return $null
}


function Invoke-VssAdmin {
    param(
        [Parameter(Mandatory)]
        [string]$Arguments
    )

    $result = [pscustomobject]@{
        Success    = $false
        Denied     = $false
        Lines      = @()
        ErrorText  = $null
    }

    try {
        $vss = Join-Path $env:WINDIR "System32\vssadmin.exe"

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $vss
        $psi.Arguments              = $Arguments
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()

        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()

        $p.WaitForExit()

        $raw = @()
        if ($stdout) { $raw += $stdout -split "`r?`n" }
        if ($stderr) { $raw += $stderr -split "`r?`n" }
        $raw = $raw | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -ne "" }

        $permDenied = $raw -match "correct permissions|elevated administrator"
        $noItems    = $raw -match "No items found"

        if ($permDenied) {
            $result.Denied    = $true
            $result.ErrorText = "Cannot query VSS (vssadmin denied - non-elevated execution context)."
            return $result
        }

        if ($noItems) {
            $result.Success = $true
            $result.Lines   = @("No items found.")
            return $result
        }

        if ($raw.Count -gt 0) {
            $result.Success = $true
            $result.Lines   = $raw
            return $result
        }

        $result.ErrorText = "VSSADMIN returned no output."
        return $result

    } catch {
        $result.ErrorText = $_.Exception.Message
        return $result
    }
}

function New-ReportObject {
    return New-Object System.Collections.Generic.List[string]
}

function Add-Line {
    param(
        [string]$Text = ''
    )
    $script:Report.Add($Text) | Out-Null
}

function Add-Section {
    param(
        [string]$Title
    )
    Add-Line ""
    Add-Line ("=" * 80)
    Add-Line ("= {0}" -f $Title)
    Add-Line ("=" * 80)
}

function Convert-ToReportTime {
    param(
        [Nullable[datetime]]$Date,
        [switch]$AssumeUtc
    )
    if (-not $Date) { return $null }

    $dt = [datetime]$Date

    # Some sources return Kind=Unspecified even when the value is actually UTC.
    if ($AssumeUtc -and $dt.Kind -eq [System.DateTimeKind]::Unspecified) {
        $dt = [System.DateTime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    }

    # If it's UTC, convert to your report TZ; if it's Local/Unspecified, convert safely
    try {
        if ($dt.Kind -eq [System.DateTimeKind]::Utc) {
            return [System.TimeZoneInfo]::ConvertTimeFromUtc($dt, $script:ReportTimeZone)
        } else {
            # Treat as local time; convert between zones (handles DST rules etc.)
            return [System.TimeZoneInfo]::ConvertTime($dt, $script:ReportTimeZone)
        }
    } catch {
        # If conversion fails for any reason, just return original
        return $dt
    }
}

function Get-ReportTimeZoneLabel {
    $offset = $script:ReportTimeZone.GetUtcOffset((Get-Date))
    $sign = if ($offset.TotalMinutes -ge 0) { "+" } else { "-" }
    $abs  = [TimeSpan]::FromMinutes([math]::Abs($offset.TotalMinutes))
    return ("UTC{0}{1:00}:{2:00} ({3})" -f $sign, $abs.Hours, $abs.Minutes, $script:ReportTimeZone.Id)
}

function Format-DateWithAge {
    param(
        [Nullable[datetime]]$Date,
        [switch]$AssumeUtc
    )
    if (-not $Date) { return "Unknown" }

    $local = Convert-ToReportTime -Date $Date -AssumeUtc:$AssumeUtc
    if (-not $local) { return "Unknown" }

    $nowLocal = [System.TimeZoneInfo]::ConvertTime((Get-Date), $script:ReportTimeZone)
    $days = [int]((New-TimeSpan -Start $local -End $nowLocal).TotalDays)

    return ("{0:yyyy-MM-dd HH:mm} ({1} days ago)" -f $local, $days)
}

function Convert-WmiDateTimeToDateTime {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    # Already a DateTime?
    if ($Value -is [datetime]) { return [datetime]$Value }

    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }

    try {
        # Handles values like: 20260106045420.931722-000
        return [System.Management.ManagementDateTimeConverter]::ToDateTime($s)
    } catch {
        return $null
    }
}

function Safe-GetRegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

# Helper for screen saver lock config (current user)
function Get-ScreenSaverLockConfig {
    $result = [pscustomobject]@{
        Source         = $null
        Active         = $false
        Secure         = $false
        TimeoutSeconds = $null
    }

    # Policy-based settings first (if present)
    $polPath = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
    $ssaPol  = Safe-GetRegistryValue -Path $polPath -Name 'ScreenSaveActive'
    $sstPol  = Safe-GetRegistryValue -Path $polPath -Name 'ScreenSaveTimeOut'
    $sssPol  = Safe-GetRegistryValue -Path $polPath -Name 'ScreenSaverIsSecure'

    if ($ssaPol -eq '1' -and $sssPol -eq '1' -and -not [string]::IsNullOrWhiteSpace($sstPol)) {
        $timeoutSec = 0
        [void][int]::TryParse($sstPol, [ref]$timeoutSec)
        if ($timeoutSec -gt 0) {
            $result.Source         = 'Policy (HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop)'
            $result.Active         = $true
            $result.Secure         = $true
            $result.TimeoutSeconds = $timeoutSec
            return $result
        }
    }

    # Fallback to user settings
    $userPath = 'HKCU:\Control Panel\Desktop'
    $ssaUser  = Safe-GetRegistryValue -Path $userPath -Name 'ScreenSaveActive'
    $sstUser  = Safe-GetRegistryValue -Path $userPath -Name 'ScreenSaveTimeOut'
    $sssUser  = Safe-GetRegistryValue -Path $userPath -Name 'ScreenSaverIsSecure'

    if ($ssaUser -eq '1' -and $sssUser -eq '1' -and -not [string]::IsNullOrWhiteSpace($sstUser)) {
        $timeoutSec = 0
        [void][int]::TryParse($sstUser, [ref]$timeoutSec)
        if ($timeoutSec -gt 0) {
            $result.Source         = 'User (HKCU\Control Panel\Desktop)'
            $result.Active         = $true
            $result.Secure         = $true
            $result.TimeoutSeconds = $timeoutSec
            return $result
        }
    }

    return $result
}

function Get-RecentInteractiveUsers {
    param(
        [datetime]$Since,
        [int]$MaxEvents = 800
    )
    # Returns: list of objects { Account, Domain, IsDomain, LastLogonTime }
    $seen = @{}

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = $Since
        } -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        return @()
    }

    foreach ($ev in $events) {
        try {
            $xml = [xml]$ev.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $data[$d.Name] = $d.'#text'
            }

            $logonType = $data['LogonType']
            if ($logonType -ne '2' -and $logonType -ne '10') { continue } # interactive / RDP

            $user = $data['TargetUserName']
            $dom  = $data['TargetDomainName']

            if ([string]::IsNullOrWhiteSpace($user)) { continue }
            if ($user.EndsWith('$')) { continue } # machine accounts

            $acct = if ($dom) { "$dom\$user" } else { $user }

            if (-not $seen.ContainsKey($acct)) {
                $seen[$acct] = [pscustomobject]@{
                    Account       = $acct
                    Domain        = $dom
                    IsDomain      = $false
                    LastLogonTime = $ev.TimeCreated
                }
            } else {
                # keep the latest
                if ($ev.TimeCreated -gt $seen[$acct].LastLogonTime) {
                    $seen[$acct].LastLogonTime = $ev.TimeCreated
                }
            }
        } catch {
            # ignore malformed event
        }
    }

    # Determine "domain-ish" (best effort)
    foreach ($k in @($seen.Keys)) {
        $obj = $seen[$k]
        # If Domain equals computername, it's local. If blank, local-ish.
        if ($obj.Domain -and ($obj.Domain -ne $env:COMPUTERNAME)) {
            $obj.IsDomain = $true
        }
    }

    return ($seen.Values | Sort-Object LastLogonTime -Descending)
}

function Try-GetADPasswordLastSet {
    param([string]$SamOrUPN)

    # Requires RSAT ActiveDirectory module + domain access
    try {
        if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) { return $null }
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null

        # Try as sAMAccountName first, then UPN
        $u = Get-ADUser -Identity $SamOrUPN -Properties PasswordLastSet -ErrorAction SilentlyContinue
        if ($u -and $u.PasswordLastSet) { return $u.PasswordLastSet }

    } catch { }

    return $null
}

# Text progress bar helpers
$script:TotalSteps   = 24
$script:CurrentStep  = 0
$script:BarLength    = 56  # number of dots

# ---------------- Urgent notice queue ----------------
if (-not $script:UrgentNotices) {
    $script:UrgentNotices = New-Object System.Collections.Generic.List[object]
}

function Add-UrgentNotice {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Red','Yellow')][string]$Color = 'Red'
    )
    # store objects like: { Message="...", Color="Red" }
    $script:UrgentNotices.Add([pscustomobject]@{
        Message = $Message
        Color   = $Color
    }) | Out-Null
}

function Show-UrgentNotices {
    if (-not $script:UrgentNotices -or $script:UrgentNotices.Count -eq 0) { return }

    Write-Host ""
    Write-Host ("=" * 80)
    Write-Host "URGENT / IMPORTANT NOTICES" -ForegroundColor Yellow
    Write-Host ("=" * 80)

    foreach ($n in $script:UrgentNotices) {
        $c = 'Red'
        if ($n.Color) { $c = $n.Color }
        Write-Host ("- {0}" -f $n.Message) -ForegroundColor $c
    }
    Write-Host ""
}

function Add-UrgentNoticesToReport {
    if (-not $script:UrgentNotices -or $script:UrgentNotices.Count -eq 0) { return }

    Add-Section "URGENT / IMPORTANT NOTICES"
    foreach ($n in $script:UrgentNotices) {
        Add-Line ("- {0}" -f $n.Message)
    }
}

function Initialize-ScriptHeaderText {
    Write-Host ("Machine Health Check Report Generator v{0} - Copyright Clarity IT Co., Ltd. 2026." -f $script:ScriptVersion)
    Write-Host "Do not share or modify this script. For Clarity IT internal use only."
    Write-Host ""
}

function Initialize-TextProgressBar {
    Write-Host "Generating machine health check report..."
    Write-Host ""
    Write-Host "0%        20%        40%        60%        80%       100%"
    Write-Host "|----------|----------|----------|----------|----------|"

    $script:CurrentStep = 0
    $line = (" " * $script:BarLength)
    Write-Host $line -NoNewline
}

function Update-TextProgressBar {
    param(
        [int]$StepNumber
    )
    $script:CurrentStep = [math]::Min($StepNumber, $script:TotalSteps)
    $ratio = $script:CurrentStep / [double]$script:TotalSteps
    $dots  = [math]::Floor($ratio * $script:BarLength)

    $line = ("." * $dots).PadRight($script:BarLength, " ")
    # Carriage return to start of the same line, overwrite, stay on same line
    Write-Host ("`r{0}" -f $line) -NoNewline
}

function Get-ThisScriptPath {
    # Most reliable when running a .ps1 file
    if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
        return $PSCommandPath
    }

    # Fallback (sometimes empty in RMM/ISE)
    $p = $MyInvocation.MyCommand.Path
    if ($p -and (Test-Path $p)) {
        return $p
    }

    # Another fallback (rare)
    try {
        $p2 = $MyInvocation.PSCommandPath
        if ($p2 -and (Test-Path $p2)) { return $p2 }
    } catch { }

    return $null
}

function Normalize-RemoteVersionFileText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $t = $Text.Trim()

    # If it looks like space-separated ASCII codes (entire file encoded)
    # Allow trailing whitespace/newlines safely
    if ($t -match '^\d+(?:\s+\d+)+\s*$') {
        try {
            $nums = $t -split '\s+' | Where-Object { $_ -ne "" } | ForEach-Object { [int]$_ }

            $sb = New-Object System.Text.StringBuilder
            foreach ($n in $nums) {
                if ($n -eq 10) { [void]$sb.Append("`n"); continue } # LF -> newline
                if ($n -eq 13) { continue }                         # ignore CR

                # printable ASCII
                if ($n -ge 32 -and $n -le 126) {
                    [void]$sb.Append([char]$n)
                }
            }

            $decoded = $sb.ToString().Trim()
            if ($decoded) { return $decoded }
        } catch { }
    }

    # Otherwise assume already normal text
    return $Text
}

function Get-ThisScriptSha256Hex {
    $path = Get-ThisScriptPath
    if (-not $path) { return $null }

    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $hashBytes = $sha.ComputeHash($fs)
            } finally {
                $fs.Close()
            }
        } finally {
            $sha.Dispose()
        }

        # bytes -> hex
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $hashBytes) { [void]$sb.AppendFormat("{0:x2}", $b) }
        return $sb.ToString().ToUpperInvariant()
    } catch {
        return $null
    }
}

function Parse-RemoteSha256Line {
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    $t = $Line.Trim()

    # Allow "SHA256=<64hex>" or just "<64hex>"
    if ($t -match '^(?i)\s*SHA256\s*=\s*([0-9A-F]{64})\s*$') {
        return $Matches[1].ToUpperInvariant()
    }
    if ($t -match '^\s*([0-9A-F]{64})\s*$') {
        return $Matches[1].ToUpperInvariant()
    }

    return $null
}


# -----------------------------------------------------------------------------
# End of Helpers section
# -----------------------------------------------------------------------------

if ($ShowScriptHash) {
    $h = Get-ThisScriptSha256Hex
    if ($h) {
        Write-Host ("SCRIPT SHA256: {0}" -f $h) -ForegroundColor Yellow
    } else {
        Write-Host "SCRIPT SHA256: Unable to compute (script path not available or unreadable)." -ForegroundColor Red
    }
    return
}

# -----------------------------------------------------------------------------
# Version check
# -----------------------------------------------------------------------------
$script:VersionCheckUrl    = "https://healthcheck.clarityit.com/script/_script_current_version"
$script:DownloadZipUrl     = "https://healthcheck.clarityit.com/script/healthcheck_script.zip"
$script:VersionCheckStatus = "Not checked"

function Invoke-VersionCheckOrWarn {

    param(
        [string]$CheckUrl,
        [string]$CurrentVersionString,
        [string]$ZipUrl
    )

    # Use ONE parser consistently
    $currentVer = Try-ParseVersion -Text $CurrentVersionString
    if (-not $currentVer) {
        $script:VersionCheckStatus = "Failed (invalid local version format)"
        Write-Host ("WARNING: Healthcheck version check failed (invalid local version '{0}'). Continuing..." -f $CurrentVersionString) -ForegroundColor Red
        return $true
    }

    try {
        # TLS: prefer TLS 1.2, but don't accidentally break by limiting too hard
        try {
            $sp = [Net.ServicePointManager]::SecurityProtocol
            # Add TLS12 if not present; keep existing flags
            [Net.ServicePointManager]::SecurityProtocol = $sp -bor [Net.SecurityProtocolType]::Tls12
        } catch { }

        $headers = @{
            "Cache-Control" = "no-cache"
            "User-Agent" = ("ClarityIT-Healthcheck/{0}" -f $script:ScriptVersion)
        }

        $resp = Invoke-WebRequest -Uri $CheckUrl -UseBasicParsing -TimeoutSec 8 -Headers $headers -ErrorAction Stop

        # Force string handling
        $raw = [string]$resp.Content
        $normalized = Normalize-RemoteVersionFileText -Text $raw
        if (-not $normalized) { $normalized = $raw }

        # --- Optional SHA256 integrity enforcement (line 2 of remote file) ---
        try {
            $lines = $normalized -split "`r?`n"
            $remoteHash = $null
            if ($lines.Count -ge 2) {
                $remoteHash = Parse-RemoteSha256Line -Line $lines[1]
            }

            if ($remoteHash) {
                $localHash = Get-ThisScriptSha256Hex
                if (-not $localHash) {
                    $script:VersionCheckStatus = "Failed (SHA256 check - cannot compute local hash)"
                    Write-Host "Script integrity check failed (cannot compute local SHA256). Exiting." -ForegroundColor Red
                    return $false
                }

                if ($localHash -ne $remoteHash) {
                    $script:VersionCheckStatus = ("Failed (SHA256 mismatch local={0} remote={1})" -f $localHash, $remoteHash)
                    Write-Host "Script integrity check failed. Exiting." -ForegroundColor Red
                    return $false
                }
            }
        } catch {
            # If remote hash exists but parsing/checking throws unexpectedly, fail closed
            $script:VersionCheckStatus = "Failed (SHA256 check error)"
            Write-Host "Script integrity check failed (SHA256 check error). Exiting." -ForegroundColor Red
            return $false
        }

        $remoteVersionString = Convert-RemoteVersionText -Text $normalized
        if (-not $remoteVersionString) {
            $firstLine = (($normalized -split "`r?`n") | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -First 1)
            if (-not $firstLine) { $firstLine = "<empty>" }

            $script:VersionCheckStatus = "Failed (remote content not a version)"
            Write-Host ("WARNING: Healthcheck version check failed (remote content not a version; first line='{0}'). Continuing..." -f $firstLine.Trim()) -ForegroundColor Red
            return $true
        }

        $remoteVer = Try-ParseVersion -Text $remoteVersionString
        if (-not $remoteVer) {
            $script:VersionCheckStatus = "Failed (remote version parse failed)"
            Write-Host ("WARNING: Healthcheck version check failed (invalid remote version '{0}'). Continuing..." -f $remoteVersionString) -ForegroundColor Red
            return $true
        }

        if ($remoteVer -gt $currentVer) {
            $script:VersionCheckStatus = ("Outdated (local={0}, latest={1})" -f $currentVer, $remoteVer)
            Write-Host ("OUTDATED SCRIPT: Current v{0} | Latest v{1}" -f $currentVer, $remoteVer) -ForegroundColor Red
            Write-Host "Please download the latest script package from:" -ForegroundColor Yellow
            Write-Host ("  {0}" -f $ZipUrl) -ForegroundColor Yellow
            Write-Host ""
            return $false
        }

        $script:VersionCheckStatus = ("OK")
        return $true

    } catch {
        $script:VersionCheckStatus = "Failed (unreachable / timeout / TLS / DNS / proxy)"

        # Show the real reason (single line)
        $reason = $_.Exception.Message
        if ($_.Exception.InnerException -and $_.Exception.InnerException.Message) {
            $reason = $reason + " | " + $_.Exception.InnerException.Message
        }

        Write-Host ("WARNING: Healthcheck version check failed. ({0})" -f $reason) -ForegroundColor Red
        Write-Host ("Continuing...") -ForegroundColor Red
        return $true
    }
}


# -------------- Init --------------

Initialize-ScriptHeaderText

# -----------------------------------------------------------------------------
# PowerShell minimum version check (requires 5.x)
# -----------------------------------------------------------------------------
try {
    $psMaj = $PSVersionTable.PSVersion.Major
    $psMin = $PSVersionTable.PSVersion.Minor
    $psVerText = "{0}.{1}" -f $psMaj, $psMin

    if ($psMaj -lt 5) {
        Write-Host ("PowerShell version {0} is not supported. Please upgrade to PowerShell 5 by:" -f $psVerText) -ForegroundColor Red
        Write-Host "1) Confirm you are on Windows 7 SP1, 8.1, Windows Server 2008 R2 SP1 (or newer)." -ForegroundColor Red
        Write-Host "2) Ensure .NET Framework 4.5.2 (or newer) is installed : https://www.microsoft.com/en-us/download/details.aspx?id=42642" -ForegroundColor Red
        Write-Host "3) Download and install WMF 5.1 : https://www.microsoft.com/en-us/download/details.aspx?id=54616" -ForegroundColor Red
        return
    }
} catch {
    # If we can't read PSVersionTable for any reason, fail safe (but this is very rare)
    Write-Host "PowerShell version could not be determined. Please use PowerShell 5 (prefer 5.1)." -ForegroundColor Red
    Write-Host "1) Confirm you are on Windows 7 SP1, 8.1, Windows Server 2008 R2 SP1 (or newer)." -ForegroundColor Red
    Write-Host "2) Ensure .NET Framework 4.5.2 (or newer) is installed : https://www.microsoft.com/en-us/download/details.aspx?id=42642" -ForegroundColor Red
    Write-Host "3) Download and install WMF 5.1 : https://www.microsoft.com/en-us/download/details.aspx?id=54616" -ForegroundColor Red
    return
}


$continue = Invoke-VersionCheckOrWarn -CheckUrl $script:VersionCheckUrl -CurrentVersionString $script:ScriptVersion -ZipUrl $script:DownloadZipUrl
if (-not $continue) { return }

$ErrorActionPreference = 'Stop'
$Report = New-ReportObject
$since = (Get-Date).AddDays(-$DaysToCheck)
$computerName = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Time zone handling
try {
    $script:ReportTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)
} catch {
    # Fallback to local system time zone if the ID is not valid
    $script:ReportTimeZone = [System.TimeZoneInfo]::Local
}

# Save to same folder as script
$scriptPath = $MyInvocation.MyCommand.Path
if ($scriptPath) {
    $OutputFolder = Split-Path -Parent $scriptPath
} else {
    # Fallback if running interactively
    $OutputFolder = (Get-Location).Path
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$outputPath = Join-Path $OutputFolder ("WorkstationReport_{0}_{1}.txt" -f $computerName, $timestamp)

Initialize-TextProgressBar

$genLocal   = Convert-ToReportTime -Date (Get-Date)
$sinceLocal = Convert-ToReportTime -Date $since

# Header (goes into report only)
Add-Line "Machine Health Check Report for $computerName"
Add-Line ("Generated: {0:yyyy-MM-dd HH:mm:ss}" -f $genLocal)
Add-Line ("Report time zone: {0}" -f (Get-ReportTimeZoneLabel))
Add-Line ("Time window for event checks: Last {0} days (since {1:yyyy-MM-dd HH:mm:ss})" -f $DaysToCheck, $sinceLocal)
Add-Line ("Script version: {0}" -f $script:ScriptVersion)
Add-Line ("Version check: {0}" -f $script:VersionCheckStatus)
Add-Line ""

# -----------------------------------------------------------------------------
#  1) Machine identity, domain/workgroup
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 1
Add-Section "1) Machine Identity, Domain/Workgroup"

try {
    $csIdentity = Get-CimInstance Win32_ComputerSystem

    $compName = $csIdentity.Name
    $isDomain = $csIdentity.PartOfDomain

    if ($isDomain) {
        $membershipType = "Domain"
        $joinedName     = $csIdentity.Domain
    } else {
        $membershipType = "Workgroup"
        $joinedName     = $csIdentity.Workgroup
    }

    Add-Line ("Computer name : {0}" -f $compName)
    Add-Line ("Membership    : {0}" -f $membershipType)
    Add-Line ("Joined to     : {0}" -f $joinedName)
} catch {
    Add-Line "Could not determine domain/workgroup membership: $_"
}

# -----------------------------------------------------------------------------
#  2) OS Version Information
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 2
Add-Section "2) OS Version Information"

try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    Add-Line ("Edition      : {0}" -f $osInfo.Caption)
    Add-Line ("Version      : {0} (Build {1})" -f $osInfo.Version, $osInfo.BuildNumber)
    Add-Line ("Architecture : {0}" -f $osInfo.OSArchitecture)
    Add-Line ("Install date : {0}" -f (Format-DateWithAge $osInfo.InstallDate))
} catch {
    Add-Line "Could not retrieve OS version information: $_"
}

# -----------------------------------------------------------------------------
#  3) Hardware & system inventory
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 3
Add-Section "3) Hardware & System Inventory"

try {
    # Manufacturer / model / serial / asset tag
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bio  = Get-CimInstance Win32_BIOS
    $prod = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue

    $manufacturer = $cs.Manufacturer
    $model        = $cs.Model
    $serial       = $bio.SerialNumber
    $assetTag     = $prod.IdentifyingNumber

    $oemVendors = @('HP', 'Hewlett-Packard', 'Dell', 'Lenovo', 'Acer', 'Microsoft')

    # match vendor by substring
    $isKnownOem = $false
    foreach ($v in $oemVendors) {
        if ($manufacturer -like "*$v*") { $isKnownOem = $true; break }
    }

    if ($isKnownOem) {
        Add-Line ("Manufacturer : {0}" -f $manufacturer)
        Add-Line ("Model        : {0}" -f $model)
        Add-Line ("Serial No.   : {0}" -f $serial)
        Add-Line ("Asset Tag    : {0}" -f $assetTag)
    } else {
        Add-Line ("Manufacturer : {0}" -f $manufacturer)
        Add-Line ("Model        : {0}" -f $model)
        Add-Line ("Serial No.   : {0}" -f $serial)
        Add-Line ("Asset Tag    : {0}" -f $assetTag)
        Add-Line "Note: Manufacturer not in OEM list (HP/Dell/Lenovo/Acer)."
    }

    Add-Line ""
    # CPU
    $cpus = Get-CimInstance Win32_Processor
    Add-Line "CPU(s):"
    foreach ($cpu in $cpus) {
        Add-Line ("  {0} | Cores={1}, Logical={2}, MaxClock={3} MHz" -f $cpu.Name, $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors, $cpu.MaxClockSpeed)
    }

    # RAM modules
    $dimms = Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue
    if ($dimms) {
        Add-Line ""
        Add-Line "Physical memory modules:"
        foreach ($d in $dimms) {
            $gb = [math]::Round($d.Capacity / 1GB, 2)
            Add-Line ("  Bank={0}, Size={1} GB, Speed={2} MHz, Manufacturer={3}, Part={4}" -f $d.BankLabel, $gb, $d.Speed, $d.Manufacturer, $d.PartNumber)
        }
    }

    # Disks
    # -------------------------------------------------------------------------
    # Physical disks (Make/Model/Capacity/Serial/Firmware) - best effort
    # -------------------------------------------------------------------------
    Add-Line ""
    Add-Line "Physical disks:"

    try {
        $storageDisks = @(Get-Disk -ErrorAction SilentlyContinue)
        $physicalDisks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)

        function Guess-ManufacturerFromModel {
            param([string]$Model)

            if ([string]::IsNullOrWhiteSpace($Model)) { return $null }

            # Common model-prefix/vendor heuristics (best-effort)
            if ($Model -match '^\s*ST\d+') { return "Seagate" }
            if ($Model -match '\bKIOXIA\b') { return "KIOXIA" }
            if ($Model -match '\bSAMSUNG\b') { return "Samsung" }
            if ($Model -match '\bWDC\b|\bWD\b') { return "Western Digital" }
            if ($Model -match '\bHGST\b') { return "HGST" }
            if ($Model -match '\bTOSHIBA\b') { return "Toshiba" }
            if ($Model -match '\bMICRON\b') { return "Micron" }
            if ($Model -match '\bKINGSTON\b') { return "Kingston" }

            return $null
        }

        if ($storageDisks -and $storageDisks.Count -gt 0) {

            foreach ($d in ($storageDisks | Sort-Object Number)) {

                $capGB = if ($d.Size) { [math]::Round($d.Size / 1GB, 2) } else { $null }
                $bus   = if ($d.BusType) { [string]$d.BusType } else { "Unknown" }

                # Try to enrich with Get-PhysicalDisk (serial match is most reliable)
                $manu = $null
                $model = $d.FriendlyName
                $serial = $null
                $fw = $null

                try { $serial = ($d.SerialNumber | ForEach-Object { "$_".Trim() }) } catch { }
                try { $fw     = ($d.FirmwareVersion | ForEach-Object { "$_".Trim() }) } catch { }

                $pd = $null
                if ($physicalDisks -and $serial) {
                    $pd = $physicalDisks | Where-Object {
                        $_.SerialNumber -and ("$($_.SerialNumber)".Trim() -eq $serial)
                    } | Select-Object -First 1
                }

                if ($pd) {
                    if ($pd.Manufacturer -and $pd.Manufacturer -ne "(Standard disk drives)") { $manu = $pd.Manufacturer }
                    if ($pd.Model) { $model = $pd.Model }
                    if (-not $fw -and $pd.FirmwareVersion) { $fw = $pd.FirmwareVersion }
                }

                if (-not $manu) {
                    $guess = Guess-ManufacturerFromModel -Model $model
                    if ($guess) { $manu = $guess } else { $manu = "(Unknown)" }
                }

                $modelOut  = $model
                if ([string]::IsNullOrWhiteSpace([string]$modelOut)) { $modelOut = "<unknown>" }

                $capOut = $capGB
                if ($null -eq $capOut -or $capOut -eq "") { $capOut = 0 }

                $serialOut = $serial
                if ([string]::IsNullOrWhiteSpace([string]$serialOut)) { $serialOut = "<unknown>" }

                $fwOut = $fw
                if ([string]::IsNullOrWhiteSpace([string]$fwOut)) { $fwOut = "<unknown>" }

                $capNum = 0
                try { $capNum = [double]$capOut } catch { $capNum = 0 }

                Add-Line ("  Make={0} | Model={1} | Capacity={2:N2} GB | Serial={3} | Firmware={4} | Bus={5} | Disk#{6}" -f `
                    $manu, $modelOut, $capNum, $serialOut, $fwOut, $bus, $d.Number
                )

            }

        } else {
            # Fallback: WMI only (less accurate for Make/Interface)
            $wmiDisks = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)
            foreach ($wd in $wmiDisks) {
                $capGB = if ($wd.Size) { [math]::Round($wd.Size/1GB,2) } else { 0 }
                $manu  = $wd.Manufacturer
                if (-not $manu -or $manu -eq "(Standard disk drives)") {
                    $guess = Guess-ManufacturerFromModel -Model $wd.Model
                    $manu = if ($guess) { $guess } else { "(Unknown)" }
                }

                $wdModel = $wd.Model
                if ([string]::IsNullOrWhiteSpace($wdModel)) { $wdModel = "<unknown>" }

                $wdSerial = $wd.SerialNumber
                if ([string]::IsNullOrWhiteSpace($wdSerial)) { $wdSerial = "<unknown>" }

                $wdFw = $wd.FirmwareRevision
                if ([string]::IsNullOrWhiteSpace($wdFw)) { $wdFw = "<unknown>" }

                $wdIf = $wd.InterfaceType
                if ([string]::IsNullOrWhiteSpace($wdIf)) { $wdIf = "Unknown" }

                $wdDev = $wd.DeviceID
                if ([string]::IsNullOrWhiteSpace($wdDev)) { $wdDev = "<unknown>" }

                Add-Line ("  Make={0} | Model={1} | Capacity={2} GB | Serial={3} | Firmware={4} | Interface={5} | Device={6}" -f `
                    $manu, $wdModel, $capGB, $wdSerial, $wdFw, $wdIf, $wdDev)

            }
            Add-Line "  Note: Win32_DiskDrive InterfaceType/Manufacturer may be inaccurate (often shows SCSI / Standard disk drives)."
        }

    } catch {
        Add-Line ("  Could not query physical disks: {0}" -f $_.Exception.Message)
    }


    # -------------------------------------------------------------------------
    # Logical disks (existing block can remain after this)
    # -------------------------------------------------------------------------
    Add-Line ""
    Add-Line "Logical disks:"
    $disks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
    foreach ($d in $disks) {
        Add-Line ("  {0} | Model={1}, Interface={2}, Size={3} GB" -f $d.DeviceID, $d.Model, $d.InterfaceType, [math]::Round($d.Size/1GB,2))
    }


    # -------------------------------------------------------------------------
    # Volume layout
    # -------------------------------------------------------------------------
    Add-Line ""
    Add-Line "Volumes (drive letters):"
    try {
        # Best effort enrichment: CIM drive types are very clear (CD-ROM, Network, Removable, etc.)
        $ldMap = @{}
        try {
            $lds = @(Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue)
            foreach ($ld in $lds) {
                if ($ld.DeviceID -and $ld.DeviceID -match '^[A-Z]:$') {
                    $ldMap[$ld.DeviceID.Substring(0,1)] = $ld
                }
            }
        } catch { }

        # Don't filter on FileSystemType (CD/DVD often has Unknown/blank)
        $vols = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter })
        if (-not $vols -or $vols.Count -eq 0) {
            Add-Line "  No drive-letter volumes found."
        } else {
            foreach ($v in ($vols | Sort-Object DriveLetter)) {

                $dl = [string]$v.DriveLetter
                $label = $v.FileSystemLabel
                if ([string]::IsNullOrWhiteSpace($label)) { $label = "" }

                $fs = $v.FileSystemType
                if ([string]::IsNullOrWhiteSpace([string]$fs)) { $fs = "Unknown" }

                $sizeGB = 0
                if ($v.Size -and $v.Size -gt 0) { $sizeGB = [math]::Round($v.Size / 1GB, 2) }

                # Determine clearer media/type
                $typeText = $null

                # Prefer CIM DriveType if present
                $ld = $null
                if ($ldMap.ContainsKey($dl)) { $ld = $ldMap[$dl] }

                if ($ld -and $ld.DriveType -ne $null) {
                    switch ([int]$ld.DriveType) {
                        2 { $typeText = "Removable" }
                        3 { $typeText = "Local Disk" }
                        4 { $typeText = "Network" }
                        5 { $typeText = "CD-ROM" }
                        6 { $typeText = "RAM Disk" }
                        default { $typeText = "Unknown" }
                    }
                }

                # If CIM not available, fall back to Get-Volume properties
                if (-not $typeText) {
                    $dt = $v.DriveType
                    if ($dt) { $typeText = [string]$dt } else { $typeText = "Unknown" }
                }

                # MediaType can also help (esp. for removable)
                $media = $v.MediaType
                $mediaText = $null
                if ($media) { $mediaText = [string]$media }

                $extra = @()
                $extra += ("Type={0}" -f $typeText)
                if ($mediaText) { $extra += ("Media={0}" -f $mediaText) }

                Add-Line ("  {0}: | {1} | Label={2} | FS={3} | Size={4} GB" -f `
                    $dl, ($extra -join " | "), $label, $fs, $sizeGB)
            }
        }

    } catch {
        Add-Line ("  Could not enumerate volumes: {0}" -f $_.Exception.Message)
    }


    # GPUs
    Add-Line ""
    Add-Line "Graphics adapters:"
    $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
    foreach ($g in $gpus) {
        $vramGB = if ($g.AdapterRAM) { [math]::Round($g.AdapterRAM/1GB,2) } else { 0 }
        Add-Line ("  {0} | VRAM ~{1} GB, Driver={2}" -f $g.Name, $vramGB, $g.DriverVersion)
    }

    # NICs
    Add-Line ""
    Add-Line "Network adapters (physical, up):"
    $nics = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
    foreach ($n in $nics) {
        Add-Line ("  {0} | MAC={1}, LinkSpeed={2}" -f $n.Name, $n.MacAddress, $n.LinkSpeed)
    }
} catch {
    Add-Line "Hardware inventory query failed or partially unavailable: $_"
}

# Printers (last item in hardware section)
Add-Line ""
Add-Line "Printers:"

# --- Helper: Registry WSD resolution (best-effort) ---
if (-not (Get-Command Resolve-WsdPortTarget -ErrorAction SilentlyContinue)) {
    function Resolve-WsdPortTarget {
        param([string]$PortName)

        $out = [pscustomobject]@{
            Host = $null
            Url  = $null
            Note = $null
        }

        try {
            $base = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
            $monitors = Get-ChildItem $base -ErrorAction SilentlyContinue

            foreach ($m in $monitors) {
                $candidate = Get-ChildItem -Path $m.PSPath -Recurse -ErrorAction SilentlyContinue |
                             Where-Object { $_.PSChildName -eq $PortName } |
                             Select-Object -First 1

                if ($candidate) {
                    $props = Get-ItemProperty -Path $candidate.PSPath -ErrorAction SilentlyContinue

                    foreach ($k in @('HostName','IPAddress','TargetHost','DeviceHost','PrinterHost','DeviceAddress')) {
                        if ($props.$k) { $out.Host = $props.$k; break }
                    }
                    foreach ($k in @('URL','DeviceURL','TargetURL','Endpoint','Uri','DeviceUri')) {
                        if ($props.$k) { $out.Url = $props.$k; break }
                    }

                    $out.Note = "From registry: $($candidate.PSPath)"
                    return $out
                }
            }

            $portsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Ports\$PortName"
            if (Test-Path $portsKey) {
                $props = Get-ItemProperty -Path $portsKey -ErrorAction SilentlyContinue
                foreach ($k in @('HostName','IPAddress')) {
                    if ($props.$k) { $out.Host = $props.$k; break }
                }
                foreach ($k in @('URL','Uri')) {
                    if ($props.$k) { $out.Url = $props.$k; break }
                }
                $out.Note = "From registry: $portsKey"
                return $out
            }
        } catch { }

        return $out
    }
}

try {
    # Default printer (best effort)
    $defaultPrinterName = $null
    try {
        $defaultPrinterName = (Get-CimInstance Win32_Printer -Filter "Default=$true" -ErrorAction SilentlyContinue |
                               Select-Object -First 1).Name
    } catch { }

    if ($defaultPrinterName) {
        Add-Line ("Default printer: {0}" -f $defaultPrinterName)
    } else {
        Add-Line "Default printer: Not detected or not set."
    }

    # Detect PrintManagement availability
    $usePrintCmdlets = $false
    if (Get-Command Get-Printer -ErrorAction SilentlyContinue) {
        $usePrintCmdlets = $true
    }

    $printers = @()
    $ports    = @{}

    if ($usePrintCmdlets) {
        try {
            $printers = @(Get-Printer -ErrorAction SilentlyContinue | Sort-Object Name)
        } catch {
            $usePrintCmdlets = $false
        }

        if ($usePrintCmdlets) {
            try {
                @(Get-PrinterPort -ErrorAction SilentlyContinue) | ForEach-Object {
                    if ($_.Name) { $ports[$_.Name] = $_ }
                }
            } catch { }
        }

        # Under-report check
        try {
            $cimCount = @(Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue).Count
            if ($cimCount -gt $printers.Count) {
                $usePrintCmdlets = $false
            }
        } catch { }
    }

    if (-not $usePrintCmdlets) {
        $printers = @(Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue | Sort-Object Name)
    }

    if (-not $printers -or $printers.Count -eq 0) {
        Add-Line "  No printers found."
        return
    }

    # TCP/IP port lookup
    $tcpPorts = @{}
    try {
        @(Get-CimInstance -ClassName Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue) | ForEach-Object {
            if ($_.Name) { $tcpPorts[$_.Name] = $_ }
        }
    } catch { }

    foreach ($p in $printers) {
        try {
            $name    = $p.Name
            $driver  = $p.DriverName
            $port    = $p.PortName
            $isDef   = $false
            $status  = "Online/Unknown"
            $share   = $null
            $loc     = $null
            $comment = $null

            if ($usePrintCmdlets) {
                $isDef   = ($name -eq $defaultPrinterName)
                $loc     = $p.Location
                $comment = $p.Comment

                if ($p.PrinterStatus -and $p.PrinterStatus -ne 3) {
                    $status = "Status=$($p.PrinterStatus)"
                }
            } else {
                $isDef   = $p.Default
                $status  = if ($p.WorkOffline) { "Offline" } else { "Online/Unknown" }
                if ($p.Shared -and $p.ShareName) { $share = $p.ShareName }
                $loc     = $p.Location
                $comment = $p.Comment
            }

            # Determine type
            $type = "Local"
            if ($name -match '^\\\\') { $type = "Network Share" }
            elseif ($port -match '^WSD-') { $type = "Network (WSD)" }
            elseif ($port -match '^IP_' -or $port -match '^TCPIP' -or $tcpPorts.ContainsKey($port)) { $type = "Network (TCP/IP)" }
            elseif ($port -match '^IPP' -or $port -match '^HTTP' -or $port -match 'https?') { $type = "Network (IPP/HTTP)" }

            # Resolve endpoint host/url (NOTE: do NOT use $host)
            $printerHost = $null
            $url         = $null

            if ($usePrintCmdlets -and $port -and $ports.ContainsKey($port)) {
                $po = $ports[$port]
                if ($po.PrinterHostAddress) { $printerHost = $po.PrinterHostAddress }
                elseif ($po.HostAddress)    { $printerHost = $po.HostAddress }
                elseif ($po.PrinterHostName){ $printerHost = $po.PrinterHostName }
                if ($po.Url) { $url = $po.Url }
            }

            if (-not $printerHost -and $port -and $tcpPorts.ContainsKey($port)) {
                $printerHost = $tcpPorts[$port].HostAddress
            } elseif (-not $printerHost -and $port -match '^IP_(\d{1,3}(\.\d{1,3}){3})$') {
                $printerHost = $Matches[1]
            }

            if (($port -match '^WSD-') -and (-not $printerHost -or -not $url)) {
                $wsd = Resolve-WsdPortTarget -PortName $port
                if (-not $printerHost -and $wsd.Host) { $printerHost = $wsd.Host }
                if (-not $url         -and $wsd.Url)  { $url         = $wsd.Url }
            }

            $extra = @()
            if ($printerHost) { $extra += "Host=$printerHost" }
            if ($url)         { $extra += "URL=$url" }
            if ($share)       { $extra += "Share=$share" }
            if ($loc)         { $extra += "Location=$loc" }
            if ($comment)     { $extra += "Comment=$comment" }

            $extraText = if ($extra.Count -gt 0) { " | " + ($extra -join " | ") } else { "" }

            Add-Line ("  {0} | {1} | Default={2} | {3} | Driver={4} | Port={5}{6}" -f `
                $name, $type, $isDef, $status, $driver, $port, $extraText)

        } catch {
            $pn = $null
            try { $pn = $p.Name } catch { }
            if ([string]::IsNullOrWhiteSpace($pn)) { $pn = "<unknown>" }

            Add-Line ("  {0} | ERROR reading printer object: {1}" -f $pn, $_.Exception.Message)
        }
    }

} catch {
    Add-Line ("  Printer query failed or partially unavailable: {0}" -f $_.Exception.Message)
}


# -----------------------------------------------------------------------------
#  4) Memory & pagefile usage
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 4
Add-Section "4) Memory & Pagefile Usage"

try {
    $os = Get-CimInstance Win32_OperatingSystem

    $totalRAMGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeRAMGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedRAMGB  = [math]::Round($totalRAMGB - $freeRAMGB, 2)
    $ramUsedPct = if ($totalRAMGB -gt 0) { [math]::Round(($usedRAMGB / $totalRAMGB) * 100, 1) } else { 0 }

    Add-Line ("Physical RAM: Total={0} GB, Used={1} GB, Free={2} GB ({3:N1}% used)" -f $totalRAMGB, $usedRAMGB, $freeRAMGB, $ramUsedPct)

    # NOTICE / URGENT about high RAM usage
    try {
        if ($ramUsedPct -ge 90) {
            Add-UrgentNotice -Color Red -Message ("URGENT: RAM usage is high ({0:N1}% used: {1:N2}/{2:N2} GB)." -f $ramUsedPct, $usedRAMGB, $totalRAMGB)
        } elseif ($ramUsedPct -ge 80) {
            Add-UrgentNotice -Color Yellow -Message ("NOTICE: RAM usage is elevated ({0:N1}% used: {1:N2}/{2:N2} GB)." -f $ramUsedPct, $usedRAMGB, $totalRAMGB)
        }
    } catch { }

    Add-Line ""
    $pagefiles = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)

    if ($pagefiles -and $pagefiles.Count -gt 0) {
        Add-Line "Pagefile(s):"

        $totalAllocGB = 0.0
        $totalUsedGB  = 0.0

        foreach ($pf in $pagefiles) {
            $allocGB = [math]::Round($pf.AllocatedBaseSize / 1024, 2)   # MB -> GB
            $usedGB  = [math]::Round($pf.CurrentUsage / 1024, 2)        # MB -> GB

            $totalAllocGB += $allocGB
            $totalUsedGB  += $usedGB

            $pfUsedPct = 0
            if ($allocGB -gt 0) { $pfUsedPct = [math]::Round(($usedGB / $allocGB) * 100, 1) }

            Add-Line ("  {0} - Allocated={1:N2} GB, InUse={2:N2} GB ({3:N1}% of allocated)" -f $pf.Name, $allocGB, $usedGB, $pfUsedPct)

            # Per-pagefile notices
            try {
                if ($allocGB -gt 0 -and $pfUsedPct -ge 90) {
                    Add-UrgentNotice -Color Red -Message ("URGENT: Pagefile usage is high on {0} ({1:N1}% of allocated: {2:N2}/{3:N2} GB)." -f $pf.Name, $pfUsedPct, $usedGB, $allocGB)
                } elseif ($allocGB -gt 0 -and $pfUsedPct -ge 70) {
                    Add-UrgentNotice -Color Yellow -Message ("NOTICE: Pagefile usage is elevated on {0} ({1:N1}% of allocated: {2:N2}/{3:N2} GB)." -f $pf.Name, $pfUsedPct, $usedGB, $allocGB)
                }
            } catch { }
        }

        # Totals summary + notices
        $totalPct = 0
        if ($totalAllocGB -gt 0) { $totalPct = [math]::Round(($totalUsedGB / $totalAllocGB) * 100, 1) }

        Add-Line ("Pagefile totals: Allocated={0:N2} GB, InUse={1:N2} GB ({2:N1}% of allocated)" -f $totalAllocGB, $totalUsedGB, $totalPct)

        try {
            if ($totalAllocGB -gt 0 -and $totalPct -ge 90) {
                Add-UrgentNotice -Color Red -Message ("URGENT: Total pagefile usage is high ({0:N1}% of allocated: {1:N2}/{2:N2} GB)." -f $totalPct, $totalUsedGB, $totalAllocGB)
            } elseif ($totalAllocGB -gt 0 -and $totalPct -ge 70) {
                Add-UrgentNotice -Color Yellow -Message ("NOTICE: Total pagefile usage is elevated ({0:N1}% of allocated: {1:N2}/{2:N2} GB)." -f $totalPct, $totalUsedGB, $totalAllocGB)
            }
        } catch { }

    } else {
        Add-Line "No pagefile information available (or none configured)."

        # Pagefile missing can be fine on some systems, but it's often useful to flag
        try {
            Add-UrgentNotice -Color Yellow -Message "NOTICE: No pagefile usage information returned (pagefile may be disabled or WMI unavailable)."
        } catch { }
    }

} catch {
    Add-Line ("Could not query memory/pagefile: {0}" -f $_.Exception.Message)
}


# -----------------------------------------------------------------------------
#  5) Last restart (boot time)
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 5
Add-Section "5) Last Restart (Boot Time)"

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $lastBoot = $os.LastBootUpTime
    Add-Line ("Last boot: {0}" -f (Format-DateWithAge $lastBoot))
} catch {
    Add-Line "Could not determine last boot time: $_"
}

# -----------------------------------------------------------------------------
#  6) Last interactive logons (last 4)
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 6
Add-Section "6) Last Interactive Logons (Last 4)"

try {
    # Event 4624 = successful logon
    # LogonType: 2 = interactive (console), 10 = remote interactive (RDP)
    $rawEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4624
    } -MaxEvents 200 -ErrorAction Stop

    $interactive = @()

    foreach ($ev in $rawEvents) {
        $xml = [xml]$ev.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }

        $logonType = $data['LogonType']
        if ($logonType -ne '2' -and $logonType -ne '10') { continue }

        $user  = $data['TargetUserName']
        $dom   = $data['TargetDomainName']
        $ip    = $data['IpAddress']
        $sid   = $data['TargetUserSid']

        # ignore machine accounts
        if ($user -and -not $user.EndsWith('$')) {
            $interactive += [pscustomobject]@{
                TimeCreated = $ev.TimeCreated
                UserName    = $user
                Domain      = $dom
                IPAddress   = $ip
                LogonType   = $logonType
                SID         = $sid
            }
        }
    }

    $top4 = $interactive | Sort-Object TimeCreated -Descending | Select-Object -First 4

    if (-not $top4 -or $top4.Count -eq 0) {
        Add-Line "No recent interactive logons (type 2 or 10) found in Security log."
    } else {
        Add-Line "Last 4 interactive / remote-interactive logons (4624, types 2 & 10):"
        foreach ($i in $top4) {
            $ltDesc = if ($i.LogonType -eq '2') { 'Interactive (Console)' } else { 'Remote Interactive (RDP)' }
            $ipDisplay = if ($i.IPAddress) { $i.IPAddress } else { '-' }
            $lt = Convert-ToReportTime -Date $i.TimeCreated
            Add-Line ("  {0:yyyy-MM-dd HH:mm:ss} | {1}\{2} | {3} | IP={4}" -f $lt, $i.Domain, $i.UserName, $ltDesc, $ipDisplay)
        }
    }
} catch {
    Add-Line "Could not query last interactive logons: $_"
}

# -----------------------------------------------------------------------------
#  7) Volume usage (fixed drives)
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 7
Add-Section "7) Volume Usage (Fixed Drives)"

try {
    $volumes = Get-Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystemType }

    $header = "{0,-10} {1,-15} {2,12} {3,12} {4,8} {5}" -f "Drive", "Label", "Size(GB)", "Used(GB)", "Used%", "Notes"
    Add-Line $header
    Add-Line ("-" * $header.Length)

    foreach ($v in $volumes) {
        if (-not $v.Size) { continue }
        if (-not $v.DriveLetter) { continue }  # no letter => skip (avoid odd mountpoints)

        $sizeGB = [math]::Round($v.Size / 1GB, 2)
        $freeGB = [math]::Round($v.SizeRemaining / 1GB, 2)
        $usedGB = [math]::Round($sizeGB - $freeGB, 2)

        $usedPct = if ($v.Size -gt 0) {
            [math]::Round((($v.Size - $v.SizeRemaining) / [double]$v.Size) * 100, 1)
        } else { 0 }

        $note = ""
        if ($usedPct -ge 90) {
            $note = "*** WARNING: > 90% used ***"

            # URGENT notice
            # Example: "URGENT: Drive C: is 92.3% used (461.5/500.0 GB)."
            try {
                Add-UrgentNotice -Color Red -Message ("URGENT: Drive {0}: is {1:N1}% used ({2:N2}/{3:N2} GB)." -f `
                    $v.DriveLetter, $usedPct, $usedGB, $sizeGB)
            } catch { }
        }

        # PS5-safe replacement for nullable label
        $label = if ($v.FileSystemLabel) { $v.FileSystemLabel } else { "" }

        Add-Line ("{0,-10} {1,-15} {2,12:N2} {3,12:N2} {4,8:N1} {5}" -f `
            ($v.DriveLetter + ":"), $label, $sizeGB, $usedGB, $usedPct, $note)
    }

} catch {
    Add-Line ("Could not retrieve volume information: {0}" -f $_.Exception.Message)
}


# -----------------------------------------------------------------------------
#  8) User profile file counts
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 8
Add-Section "8) User Profile File Counts (Documents/Downloads/Desktop/Pictures)"

# Threshold for prompting backup notice
$script:ProfileFileCountNoticeThreshold = 200

function Get-UserFolderStats {
    param(
        [string]$ProfilePath
    )

    $folders = @('Documents', 'Downloads', 'Desktop', 'Pictures')
    $stats = @()

    foreach ($folder in $folders) {
        $path = Join-Path $ProfilePath $folder
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
                $count = $files.Count
                $size  = ($files | Measure-Object Length -Sum).Sum
                $stats += [pscustomobject]@{
                    FolderName  = $folder
                    Path        = $path
                    FileCount   = $count
                    TotalSizeGB = if ($size) { [math]::Round($size/1GB, 2) } else { 0 }
                }
            } catch {
                $stats += [pscustomobject]@{
                    FolderName  = $folder
                    Path        = $path
                    FileCount   = "Error"
                    TotalSizeGB = "Error"
                }
            }
        }
    }

    return $stats
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$profilesToCheck = @()

if ($isAdmin) {
    Add-Line "Running as Administrator: checking all user profiles under C:\Users."
    $excludeNames = @('Public', 'Default', 'Default User', 'All Users', 'DefaultAppPool')
    $profilesToCheck = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $excludeNames -notcontains $_.Name }
} else {
    Add-Line "Not running as Administrator: checking only current user profile."
    $profilesToCheck = @((Get-Item $env:USERPROFILE))
}

foreach ($profile in $profilesToCheck) {
    Add-Line ""
    Add-Line ("Profile: {0}" -f $profile.FullName)

    $stats = Get-UserFolderStats -ProfilePath $profile.FullName

    if (-not $stats -or $stats.Count -eq 0) {
        Add-Line "  No standard folders (Documents/Downloads/Desktop/Pictures) found."
        continue
    }

    Add-Line ("  {0,-10} {1,10} {2,12}" -f "Folder", "Files", "TotalSizeGB")
    foreach ($s in $stats) {
        $alert = ""
        if ([int]$s.FileCount -ge 500) {
            $alert = "  *** High file count - ensure backups! ***"
        }
        Add-Line ("  {0,-10} {1,10} {2,12} {3}" -f $s.FolderName, $s.FileCount, $s.TotalSizeGB, $alert)
    }

    # --- NOTICE: high local file count suggests locally stored data; ensure backups ---
    try {
        $profileName = $profile.Name
        if ([string]::IsNullOrWhiteSpace($profileName)) {
            # Fallback: last path element
            $profileName = Split-Path -Leaf $profile.FullName
        }

        $over = @()
        foreach ($s in $stats) {

            # Skip non-numeric counts (e.g., "Error")
            $fc = 0
            if ($null -ne $s.FileCount -and [int]::TryParse([string]$s.FileCount, [ref]$fc)) {
                if ($fc -gt $script:ProfileFileCountNoticeThreshold) {
                    $over += ("{0}={1} files" -f $s.FolderName, $fc)
                }
            }
        }

        if ($over.Count -gt 0) {
            Add-UrgentNotice -Message (
                ("NOTICE: Profile '{0}' has high local file counts ({1}). Ensure locally stored user data is backed up." -f `
                    $profileName, ($over -join ", "))
            ) -Color Red
        }
    } catch { }

}

# -----------------------------------------------------------------------------
#  9) BitLocker status
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 9
Add-Section "9) BitLocker Status (Volumes & Recovery Key IDs)"

if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    try {
        $blv = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if (-not $blv) {
            Add-Line "No BitLocker volumes found or BitLocker not accessible on this system."
        } else {
            foreach ($v in $blv) {
                Add-Line ""
                Add-Line ("Volume: {0}" -f ($v.MountPoint -join ", "))
                Add-Line ("  VolumeType       : {0}" -f $v.VolumeType)
                Add-Line ("  ProtectionStatus : {0}" -f $v.ProtectionStatus)
                Add-Line ("  EncryptionMethod : {0}" -f $v.EncryptionMethod)
                Add-Line ("  Encryption%      : {0}" -f $v.EncryptionPercentage)

                $recoveryProtectors = $v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
                if ($recoveryProtectors) {
                    Add-Line "  Recovery Key Protector IDs:"
                    foreach ($rp in $recoveryProtectors) {
                        Add-Line ("    {0}" -f $rp.KeyProtectorId)
                    }
                    Add-Line "  (Use these IDs to match recovery keys in AD/Azure/Intune; full passwords not written to this report.)"
                } else {
                    Add-Line "  No RecoveryPassword key protectors listed."
                }
            }
        }
    } catch {
        Add-Line "Error querying BitLocker volumes: $_"
    }
} else {
    Add-Line "Get-BitLockerVolume command not available (no BitLocker module or unsupported OS)."
}

# -----------------------------------------------------------------------------
# 10) Disk health / SMART
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 10
Add-Section "10) Disk Health / SMART (Where Available)"

try {
    $pds = Get-PhysicalDisk -ErrorAction Stop
    foreach ($pd in $pds) {
        Add-Line ("Disk: {0}" -f $pd.FriendlyName)
        Add-Line ("  MediaType        : {0}" -f $pd.MediaType)
        Add-Line ("  Size (GB)        : {0}" -f [math]::Round($pd.Size/1GB,2))
        Add-Line ("  HealthStatus     : {0}" -f $pd.HealthStatus)
        Add-Line ("  OperationalStatus: {0}" -f ($pd.OperationalStatus -join ", "))
    }
} catch {
    Add-Line "Get-PhysicalDisk not available or failed (older OS / rights)."
}

# -----------------------------------------------------------------------------
# 11) Disk Defragmentation (Non-SSD)
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 11
Add-Section "11) Disk Defragmentation (Non-SSD)"

function Get-DefragLogStatus {
    param([string]$LogName)

    try {
        $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        return "OK"
    } catch {
        return $_.Exception.Message
    }
}

function Get-LastDefragEventSummary {
    param(
        [int[]]$DiskNumbersToCareAbout = @(),
        [datetime]$Since = (Get-Date).AddDays(-365)
    )

    # Returns a PSCustomObject: Found, Time, MessageFirstLine, Note
    $out = [pscustomobject]@{
        Found = $false
        Time  = $null
        Msg   = $null
        Note  = $null
    }

    $logName = "Microsoft-Windows-Defrag/Operational"

    try {
        # Pull a reasonable recent window; filter in-memory
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $logName
            StartTime = $Since
        } -ErrorAction Stop

        if (-not $events) {
            $out.Note = "No events returned from Defrag Operational log."
            return $out
        }

        # Look for “completed/success” style messages (language-dependent, but works well in English installs)
        $candidates = $events | Where-Object {
            $_.Message -and ($_.Message -match '(?i)\bcompleted\b|\bsuccess\b|\bsuccessfully\b|\boptimization\b|\bdefragment')
        } | Sort-Object TimeCreated -Descending

        foreach ($e in $candidates) {
            # If we can, try to match disk number mention
            if ($DiskNumbersToCareAbout -and $DiskNumbersToCareAbout.Count -gt 0) {
                $hit = $false
                foreach ($dn in $DiskNumbersToCareAbout) {
                    if ($e.Message -match ("(?i)\bdisk\s+" + [regex]::Escape([string]$dn) + "\b")) {
                        $hit = $true; break
                    }
                }
                if (-not $hit) { continue }
            }

            $out.Found = $true
            $out.Time  = $e.TimeCreated
            $out.Msg   = ($e.Message -split "`r?`n")[0].Trim()
            return $out
        }

        # If none matched disk numbers, still return most recent candidate
        if ($candidates -and $candidates.Count -gt 0) {
            $e = $candidates | Select-Object -First 1
            $out.Found = $true
            $out.Time  = $e.TimeCreated
            $out.Msg   = ($e.Message -split "`r?`n")[0].Trim()
            $out.Note  = "No disk-number match; showing most recent relevant event."
            return $out
        }

        $out.Note = "No defrag/optimize-like events found in the period checked."
        return $out

    } catch {
        $out.Note = $_.Exception.Message
        return $out
    }
}

try {
    # Identify non-SSD disks (best effort)
    $nonSsdModels = @()
    $nonSsdDiskNumbers = @()

    try {
        $pd = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
        $gd = @(Get-Disk -ErrorAction SilentlyContinue)

        if ($pd -and $gd) {
            # Heuristic join: use FriendlyName/Model-ish text to decide non-SSD and map to Get-Disk Number
            foreach ($d in ($gd | Sort-Object Number)) {
                $friendly = $d.FriendlyName
                $bus = [string]$d.BusType

                # If Get-PhysicalDisk is present, use its MediaType where possible
                $media = $null
                $match = $pd | Where-Object {
                    $_.FriendlyName -and $friendly -and ($_.FriendlyName -eq $friendly)
                } | Select-Object -First 1
                if ($match) { $media = [string]$match.MediaType }

                # Decide HDD vs SSD:
                $isSsd = $false
                if ($media -match '(?i)SSD') { $isSsd = $true }
                elseif ($bus -match '(?i)NVMe') { $isSsd = $true }

                if (-not $isSsd) {
                    $nonSsdDiskNumbers += $d.Number
                    if ($friendly) { $nonSsdModels += $friendly }
                }
            }
        }
    } catch { }

    # Fallback if Storage cmdlets aren’t giving us anything
    if (-not $nonSsdDiskNumbers -or $nonSsdDiskNumbers.Count -eq 0) {
        try {
            $wmiDisks = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)
            foreach ($wd in $wmiDisks) {
                # We can't reliably detect SSD here; keep behavior conservative:
                # only list disks that *look* like rotational by model not containing NVMe/SSD keywords
                if ($wd.Model -and ($wd.Model -notmatch '(?i)\bNVMe\b|\bSSD\b')) {
                    $nonSsdModels += $wd.Model
                }
            }
        } catch { }
    }

    if ($nonSsdModels -and $nonSsdModels.Count -gt 0) {
        Add-Line ("Non-SSD Disks detected: {0}" -f ($nonSsdModels -join ", "))
    } else {
        Add-Line "Non-SSD Disks detected: (Unable to determine; Storage cmdlets not available or no matches.)"
    }

    # 1) Try Defrag Operational log
    $logName = "Microsoft-Windows-Defrag/Operational"
    $logStatus = Get-DefragLogStatus -LogName $logName

    if ($logStatus -eq "OK") {
        $last = Get-LastDefragEventSummary -DiskNumbersToCareAbout $nonSsdDiskNumbers -Since (Get-Date).AddDays(-365)

        if ($last.Found -and $last.Time) {
            $rt = Convert-ToReportTime -Date $last.Time
            Add-Line ("Last defrag/optimize event (from Defrag Operational log): {0:yyyy-MM-dd HH:mm}" -f $rt)
            Add-Line ("  {0}" -f $last.Msg)
            if ($last.Note) { Add-Line ("  Note: {0}" -f $last.Note) }
        } else {
            Add-Line "Defrag Operational log is available, but no recent defrag/optimize completion event was found."
            if ($last.Note) { Add-Line ("  Note: {0}" -f $last.Note) }
        }

    } else {
        Add-Line "Defrag Operational log not available or could not be read."
        Add-Line ("  Reason: {0}" -f $logStatus)

        # 2) Fallback: Scheduled task
        try {
            $taskPath = "\Microsoft\Windows\Defrag\"
            $taskName = "ScheduledDefrag"
            $t = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
            $ti = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop

            Add-Line ""
            Add-Line "ScheduledDefrag task status (fallback):"
            Add-Line ("  LastRunTime   : {0}" -f (Format-DateWithAge $ti.LastRunTime))
            Add-Line ("  LastTaskResult: {0}" -f $ti.LastTaskResult)
            Add-Line ("  NextRunTime   : {0}" -f (Format-DateWithAge $ti.NextRunTime))
            Add-Line "  Note: This indicates when Windows last attempted scheduled optimize/defrag."

        } catch {
            Add-Line ""
            Add-Line ("Could not read ScheduledDefrag task info: {0}" -f $_.Exception.Message)
        }
    }

    # If non-SSD disks exist, and Defrag Operational log is disabled, note it + defer a YELLOW notice
    try {
        if ($nonSsdDisks -and $nonSsdDisks.Count -gt 0) {

            $defragChannel = "Microsoft-Windows-Defrag/Operational"
            $enabled = Test-EventLogChannelEnabled -ChannelName $defragChannel

            if ($enabled -eq $false) {
                Add-Line ""
                Add-Line "NOTE: Defrag Operational log is disabled."
                Add-Line "      This may prevent determining the last defrag/optimize time from event logs."
                Add-Line "      If organisational policy allows, enable it (requires admin) with:"
                Add-Line "      wevtutil sl Microsoft-Windows-Defrag/Operational /e:true"

                Add-UrgentNotice -Message (
                    "NOTICE: Defrag Operational log is DISABLED. This may prevent reporting last defrag/optimize for HDDs. " +
                    "If organisational policy allows, enable it (admin) using: wevtutil sl Microsoft-Windows-Defrag/Operational /e:true") -Color Yellow
            }
        }
    } catch { }


} catch {
    Add-Line ("Disk defrag history query failed: {0}" -f $_.Exception.Message)
}


# -----------------------------------------------------------------------------
# 12) Restore points & shadow copies
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 12
Add-Section "12) Restore Points & Shadow Copies"

# -----------------------
# Restore points + System Protection
# -----------------------
try {
    if (-not (Get-Command Get-ComputerRestorePoint -ErrorAction SilentlyContinue)) {
        Add-Line "Get-ComputerRestorePoint not available on this OS."
    } else {

        # System Protection status (best-effort indicator)
        Add-Line "System Protection (per volume):"
        try {
            # NOTE: This is best-effort; availability varies by OS/build.
            $sp = Get-CimInstance -Namespace root/default -ClassName SystemRestoreConfig -ErrorAction SilentlyContinue
            if ($sp) {
                foreach ($item in $sp) {
                    # Some builds expose limited fields. We just print what we can.
                    $drive = $item.Drive
                    if ([string]::IsNullOrWhiteSpace($drive)) { $drive = "<unknown>" }

                    $enabled = "Enabled/Configured"
                    Add-Line ("  {0} - {1}" -f $drive, $enabled)
                }
            } else {
                Add-Line "  Unable to determine System Protection settings."
            }
        } catch {
            Add-Line ("  Could not query System Protection status: {0}" -f $_.Exception.Message)
        }

        Add-Line ""

        $rps = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $rps) {
            Add-Line "System restore points: None found."
            Add-Line "  *** WARNING: No restore points = reduced recoverability. ***"
        } else {

            Add-Line ("System restore points found: {0}" -f $rps.Count)
            Add-Line "Restore points (newest -> oldest):"

            # Build normalized objects with real DateTime values
            $rpNorm = @()
            foreach ($rp in $rps) {
                $dt = Convert-WmiDateTimeToDateTime $rp.CreationTime
                $rpNorm += [pscustomobject]@{
                    SequenceNumber   = $rp.SequenceNumber
                    RestorePointType = $rp.RestorePointType
                    Description      = $rp.Description
                    CreationRaw      = $rp.CreationTime
                    CreationDT       = $dt
                }
            }

            # Sort with real DateTime when possible; fall back to raw string if unparseable
            $rpSorted = $rpNorm | Sort-Object `
                @{ Expression = { if ($_.CreationDT) { $_.CreationDT } else { [datetime]::MinValue } }; Descending = $true }, `
                @{ Expression = { $_.CreationRaw }; Descending = $true }

            foreach ($rp in $rpSorted) {
                if ($rp.CreationDT) {
                    $rt = Convert-ToReportTime -Date $rp.CreationDT
                    Add-Line ("  {0:yyyy-MM-dd HH:mm}  | Seq={1} | Type={2} | {3}" -f `
                        $rt, $rp.SequenceNumber, $rp.RestorePointType, $rp.Description)
                } else {
                    Add-Line ("  <unparseable time: {0}>  | Seq={1} | Type={2} | {3}" -f `
                        $rp.CreationRaw, $rp.SequenceNumber, $rp.RestorePointType, $rp.Description)
                }
            }

            # Oldest/Newest summary (only if we have parseable datetimes)
            $parseable = $rpNorm | Where-Object { $_.CreationDT }
            if ($parseable -and $parseable.Count -gt 0) {
                $newest = $parseable | Sort-Object CreationDT -Descending | Select-Object -First 1
                $oldest = $parseable | Sort-Object CreationDT | Select-Object -First 1

                Add-Line ""
                Add-Line ("Newest restore point: {0}" -f (Format-DateWithAge $newest.CreationDT))
                Add-Line ("Oldest restore point: {0}" -f (Format-DateWithAge $oldest.CreationDT))
            }
        }
    }
} catch {
    Add-Line ("Could not query restore points: {0}" -f $_.Exception.Message)
}

# -----------------------
# Shadow copies (VSSADMIN)
# -----------------------
try {
    Add-Line ""
    Add-Line "Shadow Copy / VSS status:"

    $isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                 ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    Add-Line ("Running elevated admin token: {0}" -f $isElevated)

    $shadows = Invoke-VssAdmin -Arguments "list shadows"

    if ($shadows.Denied) {
        Add-Line $shadows.ErrorText
    }
    elseif ($shadows.Success) {

        if ($shadows.Lines -contains "No items found.") {
            Add-Line "Shadow copies: None found."
        } else {
            $shadowCount = ($shadows.Lines | Select-String -Pattern "Shadow Copy ID" -ErrorAction SilentlyContinue).Count
            Add-Line ("Shadow copies detected: {0}" -f $shadowCount)

            Add-Line "Shadow copies (summary, first ~20 lines):"
            $shadows.Lines | Select-Object -First 20 | ForEach-Object { Add-Line ("  {0}" -f $_) }
            Add-Line "  (Output truncated for brevity.)"
        }

        Add-Line ""
        $storage = Invoke-VssAdmin -Arguments "list shadowstorage"
        if ($storage.Success) {
            if ($storage.Lines -contains "No items found.") {
                Add-Line "Shadow storage: No configuration reported."
            } else {
                Add-Line "Shadow storage configuration (summary, first ~25 lines):"
                $storage.Lines | Select-Object -First 25 | ForEach-Object { Add-Line ("  {0}" -f $_) }
                Add-Line "  (Output truncated for brevity.)"
            }
        } elseif ($storage.Denied) {
            Add-Line "Shadow storage: Cannot query (permission denied)."
        } else {
            Add-Line ("Shadow storage: Could not query ({0})" -f $storage.ErrorText)
        }

    }
    else {
        Add-Line ("Shadow copies: Could not query ({0})" -f $shadows.ErrorText)
    }

} catch {
    Add-Line ("Could not query shadow copies: {0}" -f $_.Exception.Message)
}


# -----------------------------------------------------------------------------
# 13) Local administrators, local users, last logon & password last changed
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 13
Add-Section "13) Local Administrators, Local Users, Last Logon & Password Last Changed"

try {
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    Add-Line ("Total members of local Administrators group: {0}" -f $admins.Count)

    # --- Existing detailed output (KEEP) ---
    foreach ($a in $admins) {
        $name = $a.Name
        Add-Line ""
        Add-Line ("Member: {0} (Class: {1}; Source: {2})" -f $name, $a.ObjectClass, $a.PrincipalSource)

        if ($a.ObjectClass -eq 'User' -and $a.PrincipalSource -eq 'Local') {
            $simpleName = $name
            if ($name -like "*\*") {
                $simpleName = $name.Split("\")[-1]
            }

            try {
                $localUser = Get-LocalUser -Name $simpleName -ErrorAction Stop
                Add-Line ("  Local user; Password last set: {0}" -f (Format-DateWithAge $localUser.PasswordLastSet))
                Add-Line ("  Enabled: {0}" -f $localUser.Enabled)
            } catch {
                Add-Line ("  Could not query local user details: {0}" -f $_.Exception.Message)
            }
        } else {
            Add-Line "  Likely domain or group account; password age not available from this workstation."
        }
    }

    # --- Local Admins summary table ---
    Add-Line ""
    Add-Line "Local Administrators (summary table):"

    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {

        # Build a lookup of local users for fast table enrichment
        $localUserLookup = @{}
        try {
            Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
                $localUserLookup[$_.Name.ToLower()] = $_
            }
        } catch { }

        Add-Line ("  {0,-35} {1,-10} {2,-10} {3,-8} {4,-22} {5,-22}" -f `
            "Member", "Class", "Source", "Enabled", "LastLogon", "PasswordLastSet")
        Add-Line ("  " + ("-" * 115))

        foreach ($a in $admins) {

            $memberName = $a.Name
            $class      = $a.ObjectClass
            $source     = $a.PrincipalSource

            $enabled    = "N/A"
            $lastLogon  = "N/A"
            $pwdLastSet = "N/A"

            # For local user accounts, enrich with Get-LocalUser
            if ($class -eq 'User' -and $source -eq 'Local') {

                $simpleName = $memberName
                if ($memberName -like "*\*") {
                    $simpleName = $memberName.Split("\")[-1]
                }

                $lu = $null
                if ($localUserLookup.ContainsKey($simpleName.ToLower())) {
                    $lu = $localUserLookup[$simpleName.ToLower()]
                } else {
                    try { $lu = Get-LocalUser -Name $simpleName -ErrorAction SilentlyContinue } catch { }
                }

                if ($lu) {
                    $enabled    = [string]$lu.Enabled
                    $lastLogon  = if ($lu.LastLogon) { Format-DateWithAge $lu.LastLogon } else { "Never/Unknown" }
                    $pwdLastSet = if ($lu.PasswordLastSet) { Format-DateWithAge $lu.PasswordLastSet } else { "Never/Unknown" }
                } else {
                    $enabled    = "Unknown"
                    $lastLogon  = "Unknown"
                    $pwdLastSet = "Unknown"
                }
            }

            Add-Line ("  {0,-35} {1,-10} {2,-10} {3,-8} {4,-22} {5,-22}" -f `
                $memberName, $class, $source, $enabled, $lastLogon, $pwdLastSet)
        }

    } else {
        Add-Line "  Get-LocalUser not available on this OS / PowerShell environment."
        Add-Line "  (Cannot populate Enabled/LastLogon/PasswordLastSet for local admin users.)"
    }

} catch {
    Add-Line ("Could not query local Administrators group: {0}" -f $_.Exception.Message)
}

# --- All local users table  ---
Add-Line ""
Add-Line "Local user accounts (all local users):"

if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    try {
        $localUsers = Get-LocalUser -ErrorAction Stop | Sort-Object Name
        Add-Line ("Total local users: {0}" -f $localUsers.Count)
        Add-Line ("  {0,-25} {1,-8} {2,-22} {3,-22}" -f "User", "Enabled", "LastLogon", "PasswordLastSet")
        Add-Line ("  " + ("-" * 78))

        foreach ($u in $localUsers) {
            $lastLogon = if ($u.LastLogon) { Format-DateWithAge $u.LastLogon } else { "Never/Unknown" }
            $pwdLast   = if ($u.PasswordLastSet) { Format-DateWithAge $u.PasswordLastSet } else { "Never/Unknown" }

            Add-Line ("  {0,-25} {1,-8} {2,-22} {3,-22}" -f $u.Name, $u.Enabled, $lastLogon, $pwdLast)
        }
    } catch {
        Add-Line ("  Could not enumerate local users: {0}" -f $_.Exception.Message)
    }
} else {
    Add-Line "  Get-LocalUser not available on this OS / PowerShell environment."
}

# --- Domain / recent interactive users (from Security log) ---
Add-Line ""
Add-Line ("Recent interactive users on this PC (Security log 4624, last {0} days):" -f $DaysToCheck)

try {
    $recentUsers = Get-RecentInteractiveUsers -Since $since -MaxEvents 1200

    if (-not $recentUsers -or $recentUsers.Count -eq 0) {
        Add-Line "  None found (or cannot read Security log)."
    } else {

        Add-Line ("  {0,-40} {1,-8} {2,-28} {3,-28}" -f "Account", "Domain", "LastLogon", "PasswordLastSet (Domain)")
        Add-Line ("  " + ("-" * 110))

        foreach ($ru in ($recentUsers | Select-Object -First 25)) {

            $acct = $ru.Account
            $dom  = if ($ru.Domain) { $ru.Domain } else { "" }
            $ll   = if ($ru.LastLogonTime) { Format-DateWithAge $ru.LastLogonTime } else { "Unknown" }

            # Only try AD password for domain accounts
            $pwd = "N/A"
            if ($ru.IsDomain) {
                # Extract username part after DOMAIN\
                $sam = $acct
                if ($acct -like "*\*") { $sam = $acct.Split("\")[-1] }

                $pls = Try-GetADPasswordLastSet -SamOrUPN $sam
                if ($pls) {
                    $pwd = Format-DateWithAge $pls
                } else {
                    $pwd = "Unavailable (no AD module/access)"
                }
            }

            Add-Line ("  {0,-40} {1,-8} {2,-28} {3,-28}" -f $acct, $dom, $ll, $pwd)
        }

        Add-Line "  (Showing top 25 most recent interactive/RDP logons.)"
    }

} catch {
    Add-Line ("  Could not enumerate recent interactive users: {0}" -f $_.Exception.Message)
}



# -----------------------------------------------------------------------------
# 14) Crash / BSOD diagnostics
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 14
Add-Section "14) Crash / BSOD Diagnostics (Last $DaysToCheck Days)"

try {
    $bugcheckEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 1001
        StartTime = $since
    } -ErrorAction SilentlyContinue

    $kernelPowerEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 41
        StartTime = $since
    } -ErrorAction SilentlyContinue

    Add-Line ("BugCheck events (ID 1001) in last {0} days: {1}" -f $DaysToCheck, ($bugcheckEvents.Count))
    foreach ($e in $bugcheckEvents) {
        $ct = Convert-ToReportTime -Date $e.TimeCreated
        Add-Line ("  {0:yyyy-MM-dd HH:mm:ss} - {1}" -f $ct, $e.Message.Split("`n")[0])
    }

    Add-Line ""
    Add-Line ("Kernel-Power (ID 41) in last {0} days: {1}" -f $DaysToCheck, ($kernelPowerEvents.Count))
    foreach ($e in $kernelPowerEvents) {
        $ct = Convert-ToReportTime -Date $e.TimeCreated
        Add-Line ("  {0:yyyy-MM-dd HH:mm:ss} - {1}" -f $ct, $e.Message.Split("`n")[0])
    }

    $minidumpPath = "C:\Windows\Minidump"
    if (Test-Path $minidumpPath) {
        $dumps = Get-ChildItem $minidumpPath -Filter "*.dmp" -ErrorAction SilentlyContinue
        Add-Line ""
        Add-Line ("Minidump files in {0}: {1}" -f $minidumpPath, $dumps.Count)
        foreach ($d in $dumps | Sort-Object LastWriteTime -Descending | Select-Object -First 10) {
            $dt = Convert-ToReportTime -Date $d.LastWriteTime
            Add-Line ("  {0:yyyy-MM-dd HH:mm:ss} - {1}" -f $dt, $d.Name)
        }
    } else {
        Add-Line ""
        Add-Line "No C:\Windows\Minidump folder detected."
    }
} catch {
    Add-Line "Could not query crash / BSOD information: $_"
}

# -----------------------------------------------------------------------------
# 15) Anti-Virus status / Defender scans
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 15
Add-Section "15) Anti-Virus Status / Last Full Scan"

try {
    # Use SilentlyContinue so "Access denied" doesn't spew to console
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    if ($avProducts) {
        Add-Line "Anti-virus products detected (from Security Center):"
        foreach ($av in $avProducts) {
            Add-Line ("  {0}" -f $av.displayName)
        }
    } else {
        Add-Line "Could not query SecurityCenter2 AntiVirusProduct (access denied or not available)."
    }
} catch {
    Add-Line "Could not query SecurityCenter2 AntiVirusProduct: $_"
}

if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    try {
        $mp = Get-MpComputerStatus
        $lastFullScan   = $mp.FullScanEndTime
        $lastQuickScan  = $mp.QuickScanEndTime

        Add-Line ""
        Add-Line "Windows Defender scan info:"
        Add-Line ("  Last full scan:  {0}" -f (Format-DateWithAge $lastFullScan))
        Add-Line ("  Last quick scan: {0}" -f (Format-DateWithAge $lastQuickScan))
    } catch {
        Add-Line "Get-MpComputerStatus failed: $_"
    }
} else {
    Add-Line ""
    Add-Line "Windows Defender module not available (third-party AV may be in use exclusively)."
    Add-Line "Last full scan date for third-party AV is not consistently exposed via PowerShell."
}

# -----------------------------------------------------------------------------
# 16) Windows Update status
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 16
Add-Section "16) Windows Update Status"

# --- Windows Update Configuration Summary ---
Add-Line ""
Add-Line "Windows Update configuration summary:"

# Service state
try {
    $wuSvc  = Get-Service -Name 'wuauserv' -ErrorAction Stop
    Add-Line ("  Service (wuauserv) : Status={0}, StartType={1}" -f $wuSvc.Status, $wuSvc.StartType)
} catch {
    Add-Line "  Service (wuauserv) : Could not query."
}

# Common policy locations
$wuPolRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$wuPolAU   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

# WSUS / WU server selection
try {
    $useWUServer = Safe-GetRegistryValue -Path $wuPolAU -Name 'UseWUServer'
    $wuServer    = Safe-GetRegistryValue -Path $wuPolRoot -Name 'WUServer'
    $wuStatusSrv = Safe-GetRegistryValue -Path $wuPolRoot -Name 'WUStatusServer'

    if ($null -ne $useWUServer) {
        $mode = if ($useWUServer -eq 1) { "WSUS (UseWUServer=1)" } else { "Microsoft Update (UseWUServer=0)" }
        Add-Line ("  Update source      : {0}" -f $mode)
        if ($useWUServer -eq 1) {
            if ($wuServer)    { Add-Line ("  WSUS server        : {0}" -f $wuServer) }
            if ($wuStatusSrv) { Add-Line ("  WSUS status server : {0}" -f $wuStatusSrv) }
        }
    } else {
        Add-Line "  Update source      : Not set via policy (default Windows behaviour)."
    }
} catch {
    Add-Line "  Update source      : Could not read WSUS policy values."
}

# Automatic Updates policy interpretation
try {
    $noAutoUpdate = Safe-GetRegistryValue -Path $wuPolAU -Name 'NoAutoUpdate'
    $auOptions    = Safe-GetRegistryValue -Path $wuPolAU -Name 'AUOptions'

    if ($null -ne $noAutoUpdate -and $noAutoUpdate -eq 1) {
        Add-Line "  Automatic updates  : DISABLED by policy (NoAutoUpdate=1)"
    } elseif ($null -ne $auOptions) {
        $auText = switch ([int]$auOptions) {
            2 { "Notify for download and auto install (AUOptions=2)" }
            3 { "Auto download and notify for install (AUOptions=3)" }
            4 { "Auto download and schedule the install (AUOptions=4)" }
            5 { "Allow local admin to choose settings (AUOptions=5)" }
            default { "Unknown/other (AUOptions=$auOptions)" }
        }
        Add-Line ("  Automatic updates  : {0}" -f $auText)
    } else {
        Add-Line "  Automatic updates  : Not set via policy (default Windows behaviour)."
    }
} catch {
    Add-Line "  Automatic updates  : Could not read AU policy values."
}

# Pause state (common in Win10/Win11 UX settings)
try {
    $ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    $pauseQ = Safe-GetRegistryValue -Path $ux -Name 'PauseQualityUpdatesStartTime'
    $pauseF = Safe-GetRegistryValue -Path $ux -Name 'PauseFeatureUpdatesStartTime'

    if ($pauseQ) { Add-Line ("  Pause Quality      : Start={0}" -f (Format-DateWithAge $pauseQ)) }
    else         { Add-Line "  Pause Quality      : Not detected." }

    if ($pauseF) { Add-Line ("  Pause Feature      : Start={0}" -f (Format-DateWithAge $pauseF)) }
    else         { Add-Line "  Pause Feature      : Not detected." }
} catch {
    Add-Line "  Pause state        : Could not query."
}

function Get-WindowsUpdateReport {
    $result = [ordered]@{
        LastSuccessfulUpdate = $null
        FailedUpdates        = @()
        PendingUpdates       = @()
        Error                = $null
    }

    try {
        $session  = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()

        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $history = $searcher.QueryHistory(0, $count)

            $lastOk = $history |
                Where-Object { $_.ResultCode -eq 2 -and $_.Date -ne $null } |
                Sort-Object Date -Descending |
                Select-Object -First 1

            if ($lastOk) {
                $result.LastSuccessfulUpdate = $lastOk
            }

            $failed = $history |
                Where-Object { $_.ResultCode -in 3, 4, 5 }
            $result.FailedUpdates = $failed
        }

        $pendingSearcher = $session.CreateUpdateSearcher()
        $pendingResult   = $pendingSearcher.Search("IsInstalled=0 and IsHidden=0")
        if ($pendingResult.Updates.Count -gt 0) {
            $pend = @()
            for ($i = 0; $i -lt $pendingResult.Updates.Count; $i++) {
                $pend += $pendingResult.Updates.Item($i)
            }
            $result.PendingUpdates = $pend
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

$wu = Get-WindowsUpdateReport

if ($wu.Error) {
    Add-Line "Could not query Windows Update via COM: $($wu.Error)"
} else {
    if ($wu.LastSuccessfulUpdate) {
        Add-Line ("Last successful update: {0}" -f (Format-DateWithAge $wu.LastSuccessfulUpdate.Date -AssumeUtc))
        Add-Line ("  Title: {0}" -f $wu.LastSuccessfulUpdate.Title)
    } else {
        Add-Line "No successful updates found in history."
    }

    # --- Console urgent warning if too many failed updates ---
    try {
        $failedCount = 0
        if ($wu -and $wu.FailedUpdates) { $failedCount = @($wu.FailedUpdates).Count }

        if ($failedCount -gt 3) {
            Add-UrgentNotice -Message ("URGENT: There are {0} failed / problematic updates in history" -f $wu.FailedUpdates.Count) -Color Red
        }

    } catch { }

    Add-Line ""
    Add-Line "Failed / problematic updates in history:"
    if ($wu.FailedUpdates.Count -eq 0) {
        Add-Line "  None."
    } else {
        foreach ($f in $wu.FailedUpdates | Sort-Object Date -Descending) {
            $fd = Convert-ToReportTime -Date $f.Date -AssumeUtc
            Add-Line ("  {0:yyyy-MM-dd HH:mm} ResultCode={1}  Title={2}" -f $fd, $f.ResultCode, $f.Title)
        }
    }

    Add-Line ""
    Add-Line "Pending (not yet installed) updates:"
    if ($wu.PendingUpdates.Count -eq 0) {
        Add-Line "  None."
    } else {
        foreach ($p in $wu.PendingUpdates) {
            Add-Line ("  Title: {0}" -f $p.Title)
        }
    }
}

# -----------------------------------------------------------------------------
# 17) Installed software audit
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 17
Add-Section "17) Installed Software Audit (from Uninstall registry keys)"

function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $list = @()
    foreach ($path in $paths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($i in $items) {
                if ([string]::IsNullOrWhiteSpace($i.DisplayName)) { continue }
                $list += [pscustomobject]@{
                    Name        = $i.DisplayName
                    Version     = $i.DisplayVersion
                    Publisher   = $i.Publisher
                    InstallDate = $i.InstallDate
                }
            }
        } catch {
            # ignore path errors
        }
    }

    $list | Sort-Object Name -Unique
}

try {
    $apps = Get-InstalledSoftware
    Add-Line ("Total installed entries found: {0}" -f $apps.Count)
    Add-Line "Name, Version, Publisher (top 50 alphabetically):"
    foreach ($a in $apps | Select-Object Name, Version, Publisher | Sort-Object Name | Select-Object -First 50) {
        Add-Line ("  {0} | {1} | {2}" -f $a.Name, $a.Version, $a.Publisher)
    }
    Add-Line "  (List truncated to 50 entries for readability.)"
} catch {
    Add-Line "Could not query installed software: $_"
}

# -----------------------------------------------------------------------------
# 18) Windows Firewall state + WAN IP
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 18
Add-Section "18) Windows Firewall State + WAN IP"

try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)

    $disabled = @()

    foreach ($p in $profiles) {
        Add-Line ("Profile: {0}" -f $p.Name)
        Add-Line ("  Enabled:                 {0}" -f $p.Enabled)
        Add-Line ("  DefaultInbound:          {0}" -f $p.DefaultInboundAction)
        Add-Line ("  DefaultOutbound:         {0}" -f $p.DefaultOutboundAction)
        Add-Line ("  AllowInboundRules:       {0}" -f $p.AllowInboundRules)
        Add-Line ("  AllowLocalFirewallRules: {0}" -f $p.AllowLocalFirewallRules)
        Add-Line ""

        # Track any disabled scopes for deferred urgent notice
        if ($p.Enabled -eq $false) {
            $disabled += $p.Name
        }
    }

    # Deferred notice (does NOT spoil progress bar)
    if ($disabled.Count -gt 0) {
        Add-UrgentNotice -Message (
            ("NOTICE: Windows Firewall is DISABLED for profile(s): {0}. Please enable Firewall for all scopes (Domain/Private/Public) unless organisational policy explicitly requires otherwise." -f `
             ($disabled -join ", "))
        ) -Color Red
    }

} catch {
    Add-Line "Could not query Windows Firewall profiles (requires newer OS / admin)."

    # Optional: also warn via deferred notice if you want visibility on screen
    try {
        Add-UrgentNotice -Message (
            "NOTICE: Could not query Windows Firewall profiles. Firewall status unknown (permissions/OS limitation)."
        ) -Color Yellow
    } catch { }
}

Add-Line ""
Add-Line "External WAN IP (best-effort via public service):"
try {
    $wc = New-Object Net.WebClient
    try {
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    } catch {
        # ignore proxy credential errors
    }

    $wanIp = $wc.DownloadString("https://api.ipify.org").Trim()
    if ($wanIp) {
        Add-Line ("  {0}" -f $wanIp)
    } else {
        Add-Line "  Could not determine (empty response from service)."
    }
} catch {
    Add-Line "  Could not determine (no internet / proxy / DNS / firewall blocking)."
}

# -----------------------------------------------------------------------------
# 19) Security configuration checks (UAC, RDP, Defender)
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 19
Add-Section "19) Security Configuration Checks (UAC, RDP, Defender)"

# UAC / EnableLUA
$enableLUA = Safe-GetRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
if ($null -ne $enableLUA) {
    Add-Line ("UAC (EnableLUA): {0} (1=enabled, 0=disabled)" -f $enableLUA)
    if ($enableLUA -eq 0) {
        Add-Line "  *** WARNING: UAC is disabled. ***"
    }
} else {
    Add-Line "UAC status not available from registry."
}

# RDP / fDenyTSConnections
$fDeny = Safe-GetRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
if ($null -ne $fDeny) {
    $rdpEnabled = if ($fDeny -eq 0) { "ENABLED" } else { "DISABLED" }
    Add-Line ("RDP status: {0} (fDenyTSConnections={1})" -f $rdpEnabled, $fDeny)
    if ($rdpEnabled -eq "ENABLED") {
        Add-Line "  Ensure RDP is restricted, firewalled, and secured if not strictly required."
    }
} else {
    Add-Line "RDP status not available from registry."
}

# Defender real-time protection
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    try {
        $pref = Get-MpPreference
        Add-Line ""
        Add-Line "Windows Defender preference summary:"
        Add-Line ("  DisableRealtimeMonitoring: {0}" -f $pref.DisableRealtimeMonitoring)
        Add-Line ("  DisableIOAVProtection    : {0}" -f $pref.DisableIOAVProtection)
        Add-Line ("  MAPSReporting            : {0}" -f $pref.MAPSReporting)
        Add-Line ("  SubmitSamplesConsent     : {0}" -f $pref.SubmitSamplesConsent)
        if ($pref.DisableRealtimeMonitoring) {
            Add-Line "  *** WARNING: Real-time protection is disabled. ***"
        }
    } catch {
        Add-Line "Could not query Defender preferences: $_"
    }
} else {
    Add-Line ""
    Add-Line "Get-MpPreference not available (possibly non-Defender AV only)."
}

# -----------------------------------------------------------------------------
# 20) Summary counts of Warnings & Errors
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 20
Add-Section "20) Summary Count of Warnings and Errors (Last $DaysToCheck Days)"

$eventLogsToDetail = @('Application', 'System', 'Security')

foreach ($log in $eventLogsToDetail) {
    try {
        $errorCount = (Get-WinEvent -FilterHashtable @{
                LogName   = $log
                Level     = 2
                StartTime = $since
            } -ErrorAction SilentlyContinue).Count

        $warningCount = (Get-WinEvent -FilterHashtable @{
                LogName   = $log
                Level     = 3
                StartTime = $since
            } -ErrorAction SilentlyContinue).Count

        Add-Line ("Log {0,-11}  Errors: {1,5}   Warnings: {2,5}" -f $log, $errorCount, $warningCount)
    } catch {
        Add-Line ("Log {0,-11}  Could not read: {1}" -f $log, $_.Exception.Message)
    }
}

# -----------------------------------------------------------------------------
# 21) Failed logon events
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 21
Add-Section "21) Failed Logon Events (Last $DaysToCheck Days)"

try {
    $failedLogons = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $since
    } -ErrorAction Stop

    $countFailed = $failedLogons.Count
    Add-Line ("Total failed logon events (ID 4625) in last {0} days: {1}" -f $DaysToCheck, $countFailed)
} catch {
    Add-Line "Could not read Security log or it is not available: $_"
}


# -----------------------------------------------------------------------------
# 22) Detailed Error events
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 22
Add-Section "22) Error Events (Last $DaysToCheck Days - Application/System/Security)"

# Track urgent signals across logs (console-only)
$script:BadBlockCount        = 0
$script:BadBlockExample      = $null

$script:DiskResetCount       = 0   # Event 129 storahci/storport reset
$script:NtfsCorruptionCount  = 0   # NTFS errors (55/57)
$script:DiskIoErrorCount     = 0   # Disk errors (7/51/153)
$script:KernelPower41Count   = 0   # Unexpected power loss / hard reset
$script:WheaCount            = 0   # Hardware error (WHEA-Logger)
$script:BugcheckCount        = 0   # System bugcheck (1001)

foreach ($log in $eventLogsToDetail) {
    Add-Line ""
    Add-Line ("--- Log: {0} ---" -f $log)

    try {
        $errors = Get-WinEvent -FilterHashtable @{
            LogName   = $log
            Level     = 2
            StartTime = $since
        } -ErrorAction Stop

        if (-not $errors -or $errors.Count -eq 0) {
            Add-Line "No Error events in last $DaysToCheck days."
            continue
        }

        # ---------- URGENT detection (console-only), mostly in System ----------
        if ($log -eq 'System') {
            try {
                # Bad block text (often Disk source, various IDs)
                $bb = @($errors | Where-Object { $_.Message -match 'has a bad block' })
                $script:BadBlockCount = $bb.Count
                if ($script:BadBlockCount -gt 0) {
                    $dev = $null
                    $m = $bb[0].Message
                    if ($m -match 'The device,\s*(\\\\Device\\\\Harddisk\d+\\\\DR\d+),\s*has a bad block') {
                        $dev = $Matches[1]
                    } else {
                        $dev = '\Device\Harddisk?\DR?'
                    }
                    $script:BadBlockExample = $dev

                    Add-UrgentNotice -Message ("URGENT: {0} has a bad block. Occurrences in last {1} days: {2}" -f $dev, $DaysToCheck, $script:BadBlockCount) -Color Red
                }

                # Storport/StorAHCI reset (very common early disk/controller trouble)
                $sr = @($errors | Where-Object { $_.Id -eq 129 -or $_.Message -match 'Reset to device' })
                $script:DiskResetCount = $sr.Count
                if ($script:DiskResetCount -gt 0) {
                    Add-UrgentNotice -Message ("URGENT: Storage device/controller resets detected (Event 129 / Reset to device). Occurrences in last {0} days: {1}" -f $DaysToCheck, $script:DiskResetCount) -Color Red

                }

                # Disk I/O errors commonly tied to failing disks/cables (IDs vary by driver)
                $dio = @($errors | Where-Object { $_.Id -in 7,51,153 })
                $script:DiskIoErrorCount = $dio.Count
                if ($script:DiskIoErrorCount -gt 0) {
                    Add-UrgentNotice -Message ("URGENT: Disk I/O errors detected (Event 7/51/153). Occurrences in last {0} days: {1}" -f $DaysToCheck, $script:DiskIoErrorCount) -Color Red
                }

                # NTFS corruption / disk structure issues
                $ntfs = @($errors | Where-Object { $_.Id -in 55,57 -or $_.ProviderName -match 'Ntfs' })
                $script:NtfsCorruptionCount = $ntfs.Count
                if ($script:NtfsCorruptionCount -gt 0) {
                    Add-UrgentNotice -Message ("URGENT: NTFS/file system errors detected (Event 55/57 or NTFS source). Occurrences in last {0} days: {1}" -f $DaysToCheck, $script:NtfsCorruptionCount) -Color Red

                }

                # Kernel-Power 41 is often Critical (Level 1), so it may not appear in $errors (Level 2).
                # We query it explicitly here (still bounded by StartTime).
                try {
                    $kp = Get-WinEvent -FilterHashtable @{
                        LogName   = 'System'
                        Id        = 41
                        StartTime = $since
                    } -ErrorAction SilentlyContinue
                    $script:KernelPower41Count = @($kp).Count
                    if ($script:KernelPower41Count -gt 0) {
                        Add-UrgentNotice -Message ("URGENT: Unexpected power loss / hard reset detected (Kernel-Power Event 41). Occurrences in last {0} days: {1}" -f $DaysToCheck, $script:KernelPower41Count) -Color Red
                    }
                } catch { }

                # WHEA hardware errors can be Error (Level 2) or Warning (Level 3); you may miss them at Level=2 only.
                # We do a targeted query for WHEA-Logger IDs commonly used for hardware errors.
                try {
                    $whea = Get-WinEvent -FilterHashtable @{
                        LogName   = 'System'
                        ProviderName = 'Microsoft-Windows-WHEA-Logger'
                        StartTime = $since
                    } -ErrorAction SilentlyContinue
                    $script:WheaCount = @($whea).Count
                    if ($script:WheaCount -gt 0) {
                        Add-UrgentNotice -Message ("URGENT: Hardware errors detected (WHEA-Logger). Occurrences in last {0} days: {1}" -f $DaysToCheck, $script:WheaCount) -Color Red
                    }
                } catch { }

                # Bugcheck (1001) is System log Error level sometimes; count it for urgency
                try {
                    $bc = Get-WinEvent -FilterHashtable @{
                        LogName   = 'System'
                        Id        = 1001
                        StartTime = $since
                    } -ErrorAction SilentlyContinue
                    $script:BugcheckCount = @($bc).Count
                    if ($script:BugcheckCount -gt 0) {
                        Add-UrgentNotice -Message ("URGENT: System crash/bugcheck events detected (Event 1001). Occurrences in last {0} days: {1}" -f $DaysToCheck, $script:BugcheckCount) -Color Red


                    }
                } catch { }

            } catch { }
        }

        # ---------- Standard report output ----------
        foreach ($e in $errors) {
            $msgFirstLine = $e.Message.Split("`n")[0]
            $et = Convert-ToReportTime -Date $e.TimeCreated
            Add-Line ("{0:yyyy-MM-dd HH:mm:ss}  ID {1}  Source: {2}" -f $et, $e.Id, $e.ProviderName)
            Add-Line ("  {0}" -f $msgFirstLine)
        }

    } catch {
        Add-Line ("Could not read log {0}: {1}" -f $log, $_.Exception.Message)
    }
}


# -----------------------------------------------------------------------------
# 23) Screen lock / inactivity lock (current user)
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 23
Add-Section "23) Screen Lock / Inactivity Lock (Current User)"

$maxLockSeconds = 30 * 60  # 30 minutes

# Machine inactivity timeout (locks session)
$inactSeconds = Safe-GetRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs'
if ($inactSeconds -and $inactSeconds -gt 0) {
    $inactMinutes = [math]::Round($inactSeconds / 60, 1)
    Add-Line ("Machine inactivity lock (InactivityTimeoutSecs): {0} seconds (~{1} minutes)" -f $inactSeconds, $inactMinutes)
} else {
    Add-Line "Machine inactivity lock (InactivityTimeoutSecs): Not configured or zero."
    $inactSeconds = $null
}

# Screen saver lock for current user
$ssConfig = Get-ScreenSaverLockConfig

if ($ssConfig.Active -and $ssConfig.Secure -and $ssConfig.TimeoutSeconds) {
    $ssMinutes = [math]::Round($ssConfig.TimeoutSeconds / 60, 1)
    Add-Line ""
    Add-Line "Screen saver lock configuration:"
    Add-Line ("  Source         : {0}" -f $ssConfig.Source)
    Add-Line ("  Active         : {0}" -f $ssConfig.Active)
    Add-Line ("  Secure (lock)  : {0}" -f $ssConfig.Secure)
    Add-Line ("  Timeout        : {0} seconds (~{1} minutes)" -f $ssConfig.TimeoutSeconds, $ssMinutes)
} else {
    Add-Line ""
    Add-Line "Screen saver lock configuration:"
    Add-Line "  No password-protected screen saver with timeout detected for the current HKCU."
}

# Determine effective earliest inactivity lock time
$effectiveLockSeconds = $null

if ($inactSeconds -and $inactSeconds -gt 0) {
    $effectiveLockSeconds = [int]$inactSeconds
}

if ($ssConfig.Active -and $ssConfig.Secure -and $ssConfig.TimeoutSeconds -gt 0) {
    if (-not $effectiveLockSeconds -or $ssConfig.TimeoutSeconds -lt $effectiveLockSeconds) {
        $effectiveLockSeconds = [int]$ssConfig.TimeoutSeconds
    }
}

Add-Line ""

if ($effectiveLockSeconds -and $effectiveLockSeconds -le $maxLockSeconds) {
    $effMinutes = [math]::Round($effectiveLockSeconds / 60, 1)
    Add-Line ("Effective inactivity lock: ~{0} minutes after idle. OK (<= 30 minutes)." -f $effMinutes)
} else {
    Add-Line "WARNING: No automatic lock within 30 minutes of inactivity detected for this user/machine."
    Add-Line "         Review Group Policy, InactivityTimeoutSecs, or screen saver settings to enforce auto-lock."
}

# -----------------------------------------------------------------------------
# 24) Additional housekeeping suggestions
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 24
Add-Section "24) Additional Maintenance / Housekeeping Suggestions"

Add-Line "- Verify regular system and user-data backups (esp. large local profile folders) and test restores periodically."
Add-Line "- Review startup programs/services; remove or disable unneeded entries to improve performance."
Add-Line "- Remove unused software, old VPN clients, and toolbars to reduce attack surface and clutter."
Add-Line "- Ensure OS and key apps (browser/Office/PDF readers/runtime) are up to date with security patches."
Add-Line "- Review local admin accounts regularly; remove accounts no longer needed."
Add-Line "- Confirm that RDP, SMB shares, and remote tools are locked down or disabled when not required."
Add-Line "- For laptops/mobile devices, ensure BitLocker is enabled and recovery keys are safely stored in AD/Azure/Intune."
Add-Line "- Consider periodic health checks: 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth' if corruption is suspected."

# -------------- Write report --------------

Add-UrgentNoticesToReport

try {
    $Report | Out-File -FilePath $outputPath -Encoding UTF8 -Force
} catch {
    # Finish progress line then show error
    Update-TextProgressBar -StepNumber $script:TotalSteps
    Write-Host ""
    Write-Host "Completed with error writing the report: $_"
    return
}

# Finish progress to 100%, move to next line, print completion message
Update-TextProgressBar -StepNumber $script:TotalSteps
Write-Host ""
Write-Host "Completed. Report written to: $outputPath"

# Show queued urgent notices AFTER progress bar is complete
Show-UrgentNotices


# -------------- Upload report -------------
try {
    $uploadUrl = "https://healthcheck.clarityit.com/upload_report.php"
    $uploadCode = "@HC2026@"

    # Read the saved report file as text (UTF-8). If this fails, do nothing.
    $reportText = Get-Content -Path $outputPath -Raw -Encoding UTF8 -ErrorAction Stop

    # Filename field should be the actual saved filename (not full path)
    $fileNameLeaf = [System.IO.Path]::GetFileName($outputPath)

    # Respect server limit (100 KB) quietly: skip upload if too large
    # (Server says MAX_REPORT_BYTES = 100 KB)
    $reportBytes = [System.Text.Encoding]::UTF8.GetByteCount($reportText)
    if ($reportBytes -le 102400) {

        # Ensure TLS 1.2 enabled (do not remove existing flags)
        try {
            $sp = [Net.ServicePointManager]::SecurityProtocol
            [Net.ServicePointManager]::SecurityProtocol = $sp -bor [Net.SecurityProtocolType]::Tls12
        } catch { }

        $headers = @{
            "Cache-Control" = "no-cache"
            "User-Agent" = ("ClarityIT-Healthcheck/{0}" -f $script:ScriptVersion)
        }

        # Build classic form POST fields (application/x-www-form-urlencoded)
        $body = @{
            code     = $uploadCode
            filename = $fileNameLeaf
            report   = $reportText
        }

        # POST silently; ignore output
        $null = Invoke-WebRequest -Uri $uploadUrl -Method Post -UseBasicParsing -TimeoutSec 8 -Headers $headers -Body $body -ErrorAction Stop
    }
} catch {
    # Ignore all upload errors
}
