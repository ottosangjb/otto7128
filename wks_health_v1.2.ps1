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
    [string]$TimeZoneId = "SE Asia Standard Time"   # Thailand (UTC+7)
)

$script:ScriptVersion = "1.2"


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

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $line = (($Text -split "`r?`n") | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -First 1)
    if (-not $line) { return $null }

    $line = $line.Trim()

    # Case 1: already looks like a version (e.g., "1.1")
    if ($line -match '^\d+(\.\d+)+$') {
        return $line
    }

    # Case 2: looks like space-separated ASCII codes (e.g., "49 46 49 10")
    # Convert first N codes into characters, ignore 10/13 (LF/CR)
    if ($line -match '^\d+(\s+\d+)+$') {
        try {
            $nums = $line -split '\s+' | Where-Object { $_ -ne "" } | ForEach-Object { [int]$_ }

            $chars = New-Object System.Collections.Generic.List[char]
            foreach ($n in $nums) {
                if ($n -eq 10 -or $n -eq 13) { continue }  # newline
                if ($n -lt 32 -or $n -gt 126) { continue } # non-printable ASCII
                $chars.Add([char]$n)
            }

            $candidate = (-join $chars).Trim()

            # Only accept dotted version
            if ($candidate -match '^\d+(\.\d+)+$') {
                return $candidate
            }
        } catch { }
    }

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

# Text progress bar helpers
$script:TotalSteps   = 24
$script:CurrentStep  = 0
$script:BarLength    = 56  # number of dots

function Initialize-ScriptHeaderText {
    Write-Host ("Machine Health Check Report Generator v{0} - Copyright Clarity IT Co., Ltd. 2025." -f $script:ScriptVersion)
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

# -----------------------------------------------------------------------------
# End of Helpers section
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Version check
# -----------------------------------------------------------------------------
$script:VersionCheckUrl    = "https://healthcheck.clarityit.com/_script_current_version"
$script:DownloadZipUrl     = "https://healthcheck.clarityit.com/healthcheck_script.zip"
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
            "User-Agent"    = "ClarityIT-Healthcheck/1.0"
        }

        $resp = Invoke-WebRequest -Uri $CheckUrl -UseBasicParsing -TimeoutSec 8 -Headers $headers -ErrorAction Stop

        # Force string handling
        $raw = [string]$resp.Content

        $remoteVersionString = Convert-RemoteVersionText -Text $raw
        if (-not $remoteVersionString) {
            $firstLine = (($raw -split "`r?`n") | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -First 1)
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

    $oemVendors = @('HP', 'Hewlett-Packard', 'Dell', 'Lenovo', 'Acer')
    if ($oemVendors -contains $manufacturer) {
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
    Add-Line ""
    Add-Line "Logical disks:"
    $disks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
    foreach ($d in $disks) {
        Add-Line ("  {0} | Model={1}, Interface={2}, Size={3} GB" -f $d.DeviceID, $d.Model, $d.InterfaceType, [math]::Round($d.Size/1GB,2))
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
Add-Line "Printers (one per row):"

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

    Add-Line ("Physical RAM: Total={0} GB, Used={1} GB, Free={2} GB ({3}% used)" -f $totalRAMGB, $usedRAMGB, $freeRAMGB, $ramUsedPct)

    $pagefiles = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
    if ($pagefiles) {
        Add-Line "Pagefile(s):"
        foreach ($pf in $pagefiles) {
            $allocGB = [math]::Round($pf.AllocatedBaseSize / 1024, 2)
            $usedGB  = [math]::Round($pf.CurrentUsage / 1024, 2)
            Add-Line ("  {0} - Allocated={1} GB, InUse={2} GB" -f $pf.Name, $allocGB, $usedGB)
        }
    } else {
        Add-Line "No pagefile information available (or none configured)."
    }
} catch {
    Add-Line "Could not query memory/pagefile: $_"
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
#  6) Last interactive logons (last 3)
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 6
Add-Section "6) Last Interactive Logons (Last 3)"

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

    $top3 = $interactive | Sort-Object TimeCreated -Descending | Select-Object -First 3

    if (-not $top3 -or $top3.Count -eq 0) {
        Add-Line "No recent interactive logons (type 2 or 10) found in Security log."
    } else {
        Add-Line "Last 3 interactive / remote-interactive logons (4624, types 2 & 10):"
        foreach ($i in $top3) {
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

        $sizeGB = [math]::Round($v.Size / 1GB, 2)
        $freeGB = [math]::Round($v.SizeRemaining / 1GB, 2)
        $usedGB = [math]::Round($sizeGB - $freeGB, 2)
        $usedPct = if ($v.Size -gt 0) {
            [math]::Round((($v.Size - $v.SizeRemaining) / $v.Size) * 100, 1)
        } else { 0 }

        $note = ""
        if ($usedPct -ge 90) { $note = "*** WARNING: > 90% used ***" }

        # PS5-safe replacement for nullable label
        $label = if ($v.FileSystemLabel) { $v.FileSystemLabel } else { "" }

        Add-Line ("{0,-10} {1,-15} {2,12:N2} {3,12:N2} {4,8:N1} {5}" -f `
            $v.DriveLetter, $label, $sizeGB, $usedGB, $usedPct, $note)
    }

} catch {
    Add-Line "Could not retrieve volume information: $_"
}

# -----------------------------------------------------------------------------
#  8) User profile file counts
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 8
Add-Section "8) User Profile File Counts (Documents/Downloads/Desktop/Pictures)"

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
        if ([int]$s.FileCount -ge 5000) {
            $alert = "  *** High file count - ensure backups! ***"
        }
        Add-Line ("  {0,-10} {1,10} {2,12} {3}" -f $s.FolderName, $s.FileCount, $s.TotalSizeGB, $alert)
    }
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
        Add-Line ""
    }
} catch {
    Add-Line "Get-PhysicalDisk not available or failed (older OS / rights)."
}

# -----------------------------------------------------------------------------
# 11) Disk Defragmentation (Non-SSD)
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 11
Add-Section "11) Disk Defragmentation (Non-SSD)"

$nonSsdDisks = @()
try {
    $nonSsdDisks = Get-PhysicalDisk -ErrorAction Stop | Where-Object {
        $_.MediaType -ne 'SSD'
    }
} catch {
    Add-Line "Could not query physical disks (Get-PhysicalDisk not available or insufficient rights)."
}

if ($nonSsdDisks.Count -eq 0) {
    Add-Line "No non-SSD physical disks detected (or unable to determine media type)."
} else {
    Add-Line ("Non-SSD Disks detected: {0}" -f ($nonSsdDisks.FriendlyName -join ", "))
    $defragLogName = 'Microsoft-Windows-Defrag/Operational'
    try {
        $logInfo = Get-WinEvent -ListLog $defragLogName -ErrorAction Stop
        $lastDefragEvent = Get-WinEvent -LogName $defragLogName -MaxEvents 200 |
            Where-Object { $_.Id -eq 258 } |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 1

        if ($lastDefragEvent) {
            $formatted = Format-DateWithAge $lastDefragEvent.TimeCreated
            Add-Line ("Last optimization/defrag event: {0}" -f $formatted)
            Add-Line ("Details: {0}" -f $lastDefragEvent.Message.Split("`n")[0])
        } else {
            Add-Line "No defrag/optimization events found in Defrag Operational log."
        }
    } catch {
        Add-Line "Defrag Operational log not available or could not be read."
    }
}

# -----------------------------------------------------------------------------
# 12) Restore points & shadow copies
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 12
Add-Section "12) Restore Points & Shadow Copies"

# Restore points
try {
    if (Get-Command Get-ComputerRestorePoint -ErrorAction SilentlyContinue) {
        $rps = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($rps) {
            Add-Line "System restore points:"
            foreach ($rp in $rps | Sort-Object SequenceNumber -Descending | Select-Object -First 10) {
                $rt = Convert-ToReportTime -Date $rp.CreationTime
                Add-Line ("  Seq={0}  Type={1}  Desc={2}  Created={3:yyyy-MM-dd HH:mm}" -f $rp.SequenceNumber, $rp.RestorePointType, $rp.Description, $rt)
            }
        } else {
            Add-Line "No restore points found."
        }
    } else {
        Add-Line "Get-ComputerRestorePoint not available on this OS."
    }
} catch {
    Add-Line "Could not query restore points: $_"
}

# Restore points
try {
    if (Get-Command Get-ComputerRestorePoint -ErrorAction SilentlyContinue) {

        # System Protection status (recoverability indicator)
        Add-Line "System Protection (per volume):"
        try {
            $sp = Get-CimInstance -Namespace root/default -ClassName SystemRestoreConfig -ErrorAction SilentlyContinue
            if ($sp) {
                foreach ($item in $sp) {
                    $enabled = if ($item.RPSessionInterval -ge 0) { "Enabled/Configured" } else { "Unknown" }
                    Add-Line ("  {0} - {1}" -f $item.Drive, $enabled)
                }
            } else {
                Add-Line "  Unable to determine System Protection settings."
            }
        } catch {
            Add-Line "  Could not query System Protection status."
        }

        Add-Line ""

        $rps = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($rps) {
            Add-Line ("System restore points found: {0}" -f $rps.Count)

            # List restore point dates (sorted)
            Add-Line "Restore point dates (newest -> oldest):"
            foreach ($rp in ($rps | Sort-Object CreationTime -Descending)) {
                $rt = Convert-ToReportTime -Date $rp.CreationTime
                Add-Line ("  {0:yyyy-MM-dd HH:mm}  | Seq={1} | Type={2} | {3}" -f $rt, $rp.SequenceNumber, $rp.RestorePointType, $rp.Description)
            }

            # Oldest/Newest summary
            $newest = $rps | Sort-Object CreationTime -Descending | Select-Object -First 1
            $oldest = $rps | Sort-Object CreationTime | Select-Object -First 1

            Add-Line ""
            Add-Line ("Newest restore point: {0}" -f (Format-DateWithAge $newest.CreationTime))
            Add-Line ("Oldest restore point: {0}" -f (Format-DateWithAge $oldest.CreationTime))
        } else {
            Add-Line "No restore points found."
            Add-Line "  *** WARNING: No restore points = reduced recoverability. ***"
        }
    } else {
        Add-Line "Get-ComputerRestorePoint not available on this OS."
    }
} catch {
    Add-Line "Could not query restore points: $_"
}


# Shadow copies
try {
    Add-Line ""
    Add-Line "Shadow Copy / VSS status:"

    $isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                 ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    Add-Line ("Running elevated admin token: {0}" -f $isElevated)

    # Try list shadows first
    $shadows = Invoke-VssAdmin -Arguments "list shadows"

    if ($shadows.Denied) {
        # Elegant: single line, do not attempt shadowstorage (will also fail)
        Add-Line $shadows.ErrorText
    }
    elseif ($shadows.Success) {

        if ($shadows.Lines -contains "No items found.") {
            Add-Line "Shadow copies: None found."
        } else {
            $shadowCount = ($shadows.Lines | Select-String -Pattern "Shadow Copy ID" -ErrorAction SilentlyContinue).Count
            Add-Line ("Shadow copies detected: {0}" -f $shadowCount)

            Add-Line "Shadow copies (summary, first ~20 lines):"
            $shadows.Lines | Select-Object -First 20 | ForEach-Object { Add-Line "  $_" }
            Add-Line "  (Output truncated for brevity.)"
        }

        # Only attempt shadowstorage if shadows query succeeded
        Add-Line ""
        $storage = Invoke-VssAdmin -Arguments "list shadowstorage"
        if ($storage.Success) {
            if ($storage.Lines -contains "No items found.") {
                Add-Line "Shadow storage: No configuration reported."
            } else {
                Add-Line "Shadow storage configuration (summary, first ~25 lines):"
                $storage.Lines | Select-Object -First 25 | ForEach-Object { Add-Line "  $_" }
                Add-Line "  (Output truncated for brevity.)"
            }
        } elseif ($storage.Denied) {
            # Rare case (usually won't happen if list shadows succeeded, but safe)
            Add-Line "Shadow storage: Cannot query (permission denied)."
        } else {
            Add-Line ("Shadow storage: Could not query ({0})" -f $storage.ErrorText)
        }

    }
    else {
        Add-Line ("Shadow copies: Could not query ({0})" -f $shadows.ErrorText)
    }

} catch {
    Add-Line ""
    Add-Line "Could not query shadow copies: $_"
}


# -----------------------------------------------------------------------------
# 13) Local administrators, local users, last logon & password last changed
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 13
Add-Section "13) Local Administrators & Password Last Changed"

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
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($p in $profiles) {
        Add-Line ("Profile: {0}" -f $p.Name)
        Add-Line ("  Enabled:           {0}" -f $p.Enabled)
        Add-Line ("  DefaultInbound:    {0}" -f $p.DefaultInboundAction)
        Add-Line ("  DefaultOutbound:   {0}" -f $p.DefaultOutboundAction)
        Add-Line ("  AllowInboundRules: {0}" -f $p.AllowInboundRules)
        Add-Line ("  AllowLocalFirewallRules: {0}" -f $p.AllowLocalFirewallRules)
        Add-Line ""
    }
} catch {
    Add-Line "Could not query Windows Firewall profiles (requires newer OS / admin)."
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

        foreach ($e in $errors) {
            $msgFirstLine = $e.Message.Split("`n")[0]
            $et = Convert-ToReportTime -Date $e.TimeCreated
            Add-Line ("{0:yyyy-MM-dd HH:mm:ss}  ID {1}  Source: {2}" -f $et, $e.Id, $e.ProviderName)
            Add-Line ("  {0}" -f $msgFirstLine)
        }
    } catch {
        Add-Line "Could not read log ${log}: $_"
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
            "User-Agent"    = "ClarityIT-Healthcheck/1.0"
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
