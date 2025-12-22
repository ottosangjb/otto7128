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
    [int]$DaysToCheck = 30
)

# -------------- Helpers --------------

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

function Format-DateWithAge {
    param(
        [Nullable[datetime]]$Date
    )
    if (-not $Date) { return "Unknown" }
    $days = [int]((New-TimeSpan -Start $Date -End (Get-Date)).TotalDays)
    return ("{0:yyyy-MM-dd HH:mm} ({1} days ago)" -f $Date, $days)
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

function Initialize-TextProgressBar {
    Write-Host "Machine Health Check Report Generator - Copyright Clarity IT Co., Ltd. 2025."
    Write-Host "Do not share or modify this script. For Clarity IT internal use only."
    Write-Host ""

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

# -------------- Init --------------

$ErrorActionPreference = 'Stop'
$Report = New-ReportObject
$since = (Get-Date).AddDays(-$DaysToCheck)
$computerName = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

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

# Header (goes into report only)
Add-Line "Workstation Health Report for $computerName"
Add-Line ("Generated: {0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date))
Add-Line ("Time window for event checks: Last {0} days (since {1})" -f $DaysToCheck, $since)
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
            Add-Line ("  {0:yyyy-MM-dd HH:mm:ss} | {1}\{2} | {3} | IP={4}" -f $i.TimeCreated, $i.Domain, $i.UserName, $ltDesc, $ipDisplay)
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
                Add-Line ("  Seq={0}  Type={1}  Desc={2}  Created={3:yyyy-MM-dd HH:mm}" -f $rp.SequenceNumber, $rp.RestorePointType, $rp.Description, $rp.CreationTime)
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

# Shadow copies
try {
    $vssOutput = (cmd /c "vssadmin list shadows") 2>$null
    if ($vssOutput -and $vssOutput -notmatch "No items found") {
        Add-Line ""
        Add-Line "Shadow copies reported by vssadmin (first ~20 lines):"
        $vssOutput | Select-Object -First 20 | ForEach-Object { Add-Line "  $_" }
        Add-Line "  (Output truncated for brevity.)"
    } else {
        Add-Line ""
        Add-Line "No shadow copies found (or vssadmin not available)."
    }
} catch {
    Add-Line ""
    Add-Line "Could not query shadow copies: $_"
}

# -----------------------------------------------------------------------------
# 13) Local administrators & password last changed
# -----------------------------------------------------------------------------
Update-TextProgressBar -StepNumber 13
Add-Section "13) Local Administrators & Password Last Changed"

try {
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    Add-Line ("Total members of local Administrators group: {0}" -f $admins.Count)

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
                Add-Line "  Could not query local user details: $_"
            }
        } else {
            Add-Line "  Likely domain or group account; password age not available from this workstation."
        }
    }
} catch {
    Add-Line "Could not query local Administrators group: $_"
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
        Add-Line ("  {0:yyyy-MM-dd HH:mm:ss} - {1}" -f $e.TimeCreated, $e.Message.Split("`n")[0])
    }

    Add-Line ""
    Add-Line ("Kernel-Power (ID 41) in last {0} days: {1}" -f $DaysToCheck, ($kernelPowerEvents.Count))
    foreach ($e in $kernelPowerEvents) {
        Add-Line ("  {0:yyyy-MM-dd HH:mm:ss} - {1}" -f $e.TimeCreated, $e.Message.Split("`n")[0])
    }

    $minidumpPath = "C:\Windows\Minidump"
    if (Test-Path $minidumpPath) {
        $dumps = Get-ChildItem $minidumpPath -Filter "*.dmp" -ErrorAction SilentlyContinue
        Add-Line ""
        Add-Line ("Minidump files in {0}: {1}" -f $minidumpPath, $dumps.Count)
        foreach ($d in $dumps | Sort-Object LastWriteTime -Descending | Select-Object -First 10) {
            Add-Line ("  {0:yyyy-MM-dd HH:mm:ss} - {1}" -f $d.LastWriteTime, $d.Name)
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
        Add-Line ("Last successful update: {0}" -f (Format-DateWithAge $wu.LastSuccessfulUpdate.Date))
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
            Add-Line ("  {0:yyyy-MM-dd HH:mm}  ResultCode={1}  Title={2}" -f $f.Date, $f.ResultCode, $f.Title)
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
            Add-Line ("{0:yyyy-MM-dd HH:mm:ss}  ID {1}  Source: {2}" -f $e.TimeCreated, $e.Id, $e.ProviderName)
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
