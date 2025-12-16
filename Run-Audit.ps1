<#
    Run-Audit.ps1
    System Audit Script with progress output, security baseline, and optional Nmap
    Markdown output formatted to be pandoc-friendly for DOCX conversion.
#>

$ErrorActionPreference = "Stop"

# ------------------------- #
# Paths (per computer)      #
# ------------------------- #
$ComputerName = $env:COMPUTERNAME
if (-not $ComputerName -or $ComputerName -eq "") {
    $ComputerName = "UnknownComputer"
}

$ReportPath     = "C:\Temp\${ComputerName}-Audit.md"
$HtmlReportPath = "C:\Temp\${ComputerName}-Audit.html"
$LogPath        = "C:\Windows\Temp\AuditLog.txt"
$NmapXmlPath    = "C:\Temp\${ComputerName}-Nmap.xml"

# Ensure directories exist
New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null

# ------------------------- #
# Logging Helper            #
# ------------------------- #
function Log {
    param([string]$Message)
    Add-Content -Path $LogPath -Value "$(Get-Date -Format u) - $Message"
}

# ------------------------- #
# Safe Invocation Wrapper   #
# ------------------------- #
function Safe-Invoke {
    param(
        [scriptblock]$Code,
        [string]$Name
    )
    try {
        return & $Code
    }
    catch {
        Log "$Name failed: $_"
        return "Error"
    }
}

# ------------------------- #
# Elevation Detection       #
# ------------------------- #
function Test-IsElevated {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# ------------------------- #
# Self Elevation            #
# ------------------------- #
function Start-SelfElevate {
    Write-Host "Requesting elevation..." -ForegroundColor Yellow
    Log "Attempting elevation"

    $psi = New-Object System.Diagnostics.ProcessStartInfo

    if ($PSCommandPath) {
        # Running as a .ps1 script – relaunch via powershell.exe
        $psi.FileName  = "powershell.exe"
        $psi.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    }
    else {
        # Likely running as a PS2EXE-compiled executable
        $exePath = Convert-Path -LiteralPath ([Environment]::GetCommandLineArgs()[0])
        $psi.FileName  = $exePath
        $psi.Arguments = ""
    }

    $psi.Verb = "runas"

    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        # Exit the non-elevated instance
        exit
    }
    catch {
        Write-Host "Elevation denied. Continuing in limited mode." -ForegroundColor DarkYellow
        Log "Elevation denied by user"
    }
}

# ---------------------------------- #
# Windows Update Dependency Check    #
# ---------------------------------- #
function Ensure-PSWindowsUpdate {
    Write-Host "Ensuring PSWindowsUpdate + dependencies..." -ForegroundColor Yellow

    # Make sure TLS 1.2 is enabled (common cause of PSGallery weirdness on older builds)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    # Trust PSGallery (avoids prompts)
    try {
        $psg = Get-PSRepository -Name PSGallery -ErrorAction Stop
        if ($psg.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        }
    } catch {
        # If PowerShellGet is *really* old, this might fail; continue and rely on -Confirm:$false
    }

    # Ensure NuGet provider exists
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Write-Host "Installing NuGet provider..." -ForegroundColor Yellow
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -Confirm:$false | Out-Null
        Import-PackageProvider -Name NuGet -Force | Out-Null
    }

    # Ensure PSWindowsUpdate module is installed
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "Installing PSWindowsUpdate from PSGallery..." -ForegroundColor Yellow
        Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser -Confirm:$false -SkipPublisherCheck | Out-Null
    }

    Import-Module PSWindowsUpdate -Force -ErrorAction Stop
    Write-Host "PSWindowsUpdate ready." -ForegroundColor DarkGreen
}

Write-Host "=== Starting System Audit for $ComputerName ===" -ForegroundColor Cyan


$IsElevated = Test-IsElevated
if (-not $IsElevated) {
    Start-SelfElevate
    $IsElevated = Test-IsElevated
}

if ($IsElevated) {
    # Process-scope execution policy bypass so modules like PSWindowsUpdate can run
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
        Write-Host "[0] Process execution policy set to Bypass for this session." -ForegroundColor Green
        Log "Process execution policy set to Bypass"
    }
    catch {
        Write-Host "[0] Failed to set process execution policy. Continuing anyway." -ForegroundColor DarkYellow
        Log "Failed to set process execution policy: $_"
    }

    Write-Host "[0] Running as Administrator." -ForegroundColor Green
    Log "Running elevated"
}
else {
    Write-Host "[0] Running as standard user. Some checks will be skipped." -ForegroundColor DarkYellow
    Log "Running non-elevated"
}

# ------------------------- #
# Ask about Nmap            #
# ------------------------- #
$RunNmap = $false
if ($IsElevated) {
    $response = Read-Host "Do you want to run an Nmap scan? (Y/N)"
    if ($response.Trim().ToUpper() -eq "Y") {
        $RunNmap = $true
        Write-Host "[0] Nmap scanning enabled." -ForegroundColor Cyan
        Log "Nmap enabled"
    }
    else {
        Write-Host "[0] Nmap scan disabled by user." -ForegroundColor DarkYellow
        Log "Nmap disabled by user"
    }
}
else {
    Write-Host "[0] Nmap scan disabled (session not elevated)." -ForegroundColor DarkYellow
    Log "Nmap disabled due to non-elevated session"
}

# ------------------------- #
# Begin Markdown Report     #
# ------------------------- #
$Report = @()

$Report += "# System Audit Report"
$Report += ""
$Report += "- Computer: $ComputerName"
$Report += "- Generated: $(Get-Date)"
$Report += ""
$Report += "---"
$Report += ""

# ============================================================
# [1] SYSTEM INFORMATION
# ============================================================
Write-Host "[1/10] Collecting system information..." -ForegroundColor Yellow
$Report += "## System Information"
Write-Host "#System Information#" -ForegroundColor Magenta
Write-Host ""
$Report += ""

# Computer Name
$compName = Safe-Invoke { $env:COMPUTERNAME } "Computer Name"
$Report += "- Computer Name: $compName"
Write-Host "Computer Name: $compName" -ForegroundColor DarkGreen

# OS Info
$os = Safe-Invoke { Get-CimInstance Win32_OperatingSystem } "Operating System"
if ($os -ne "Error") {
    $Report += "- Operating System:"
    Write-Host "<Operating System>" -ForegroundColor DarkMagenta
    Write-Host ""

    # Name
    $Report += "  - Name: $($os.Caption)"
    Write-Host "Name: $($os.Caption)" -ForegroundColor DarkGreen

    # Version
    $Report += "  - Version: $($os.Version)"
    Write-Host "Version: $($os.Version)" -ForegroundColor DarkGreen

    # Build Number
    $Report += "  - Build Number: $($os.BuildNumber)"
    Write-Host "Build Number: $($os.BuildNumber)" -ForegroundColor DarkGreen

    # Architecture
    $Report += "  - Architecture: $($os.OSArchitecture)"
    Write-Host "Architecture: $($os.OSArchitecture)" -ForegroundColor DarkGreen
}

# Feature Version
$winVer = Safe-Invoke {
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" |
        Select-Object -Property ReleaseId, DisplayVersion
} "Feature Version"
if ($winVer -ne "Error") {
    $ver = if ($winVer.DisplayVersion) { $winVer.DisplayVersion } else { $winVer.ReleaseId }
    $Report += "- Windows Feature Version: $ver"
}

# CPU Info
$cpu = Safe-Invoke {
    Get-CimInstance Win32_Processor |
        Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors
} "CPU Info"
if ($cpu -ne "Error") {
    $Report += "- Processor:"
    $Report += "  - Name: $($cpu.Name)"
    $Report += "  - Cores: $($cpu.NumberOfCores)"
    $Report += "  - Logical Processors: $($cpu.NumberOfLogicalProcessors)"
}

# RAM
$mem = Safe-Invoke {
    Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory
} "Memory Info"
if ($mem -ne "Error") {
    $ramGB = [math]::Round($mem.TotalPhysicalMemory / 1GB, 2)
    $Report += "- Memory:"
    $Report += "  - Installed RAM: $ramGB GB"
}

# Physical Disks
$disks = Safe-Invoke {
    Get-CimInstance Win32_DiskDrive | Select-Object Model, Size
} "Disk Info"
if ($disks -ne "Error") {
    $Report += "- Physical Disks:"
    foreach ($d in $disks) {
        $sizeGB = [math]::Round($d.Size / 1GB, 2)
        $Report += "  - Model: $($d.Model)"
        $Report += "    - Size: $sizeGB GB"
    }
}

# Uptime
$boot = Safe-Invoke {
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
} "Uptime"
if ($boot -ne "Error") {
    $uptime = New-TimeSpan -Start $boot
    $Report += "- Uptime:"
    $Report += "  - $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
}

$Report += ""

# ============================================================
# [2] INSTALLED SOFTWARE
# ============================================================
Write-Host "[2/10] Collecting installed software..." -ForegroundColor Yellow
$Report += "## Installed Software"
$Report += ""

function Get-InstalledSoftwareInventory {
    param([switch]$IncludeAllUsers)

    $results = New-Object System.Collections.Generic.List[object]

    function Add-UninstallEntriesFromRoot {
        param(
            [Parameter(Mandatory)] [string]$Root,
            [Parameter(Mandatory)] [string]$Scope
        )

        foreach ($p in @(
            "$Root\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "$Root\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )) {
            try {
                Get-ItemProperty -Path $p -ErrorAction Stop |
                    Where-Object { $_.DisplayName } |
                    ForEach-Object {
                        $results.Add([pscustomobject]@{
                            DisplayName     = $_.DisplayName
                            DisplayVersion  = $_.DisplayVersion
                            Publisher       = $_.Publisher
                            InstallLocation = $_.InstallLocation
                            Scope           = $Scope
                        }) | Out-Null
                    }
            }
            catch {
                # Intentionally silent: missing keys are common.
            }
        }
    }

    # Machine-wide
    Add-UninstallEntriesFromRoot -Root "HKLM:" -Scope "Machine"

    # Current user
    Add-UninstallEntriesFromRoot -Root "HKCU:" -Scope "CurrentUser"

    if ($IncludeAllUsers) {
        # 1) Already-loaded user hives
        $userSids = @()
        try {
            $userSids = Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction Stop |
                Where-Object {
                    $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' -and
                    $_.PSChildName -notlike '*_Classes'
                } |
                Select-Object -ExpandProperty PSChildName
        }
        catch { }

        foreach ($sid in $userSids) {
            Add-UninstallEntriesFromRoot -Root ("Registry::HKEY_USERS\{0}" -f $sid) -Scope ("UserHive:{0}" -f $sid)
        }

        # 2) Offline hives from profile list (requires elevation)
        $profileList = @()
        try {
            $profileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction Stop |
                Select-Object PSChildName, ProfileImagePath
        }
        catch { }

        foreach ($p in $profileList) {
            $sid = $p.PSChildName
            if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }

            $profilePath = $p.ProfileImagePath
            if (-not $profilePath) { continue }

            $ntUser = Join-Path $profilePath 'NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $ntUser)) { continue }

            # Use a short safe hive name (avoid SID in hive name)
            $tempHiveName = "AUDIT_{0}" -f ([Math]::Abs($sid.GetHashCode()))
            $tempHiveRoot = "Registry::HKEY_USERS\$tempHiveName"

            if (Test-Path -Path $tempHiveRoot) { continue }

            $loaded = $false
            try {
                $null = & reg.exe load ("HKU\{0}" -f $tempHiveName) "$ntUser" 2>$null
                if ($LASTEXITCODE -eq 0) { $loaded = $true }
            }
            catch { $loaded = $false }

            if ($loaded) {
                try {
                    Add-UninstallEntriesFromRoot -Root $tempHiveRoot -Scope ("OfflineUser:{0}" -f $sid)
                }
                finally {
                    try { $null = & reg.exe unload ("HKU\{0}" -f $tempHiveName) 2>$null } catch { }
                }
            }
        }
    }

    $results |
        Where-Object { $_.DisplayName } |
        Sort-Object DisplayName, DisplayVersion, Scope -Unique
}

$apps = Safe-Invoke {
    Get-InstalledSoftwareInventory -IncludeAllUsers:($IsElevated)
} "Installed Software"

if ($apps -ne "Error" -and $apps) {

    # Ensure array semantics
    $appsList = @($apps)
    $appCount = $appsList.Count

    # Minimal console feedback
    Write-Host ("Applications found: {0}" -f $appCount) -ForegroundColor DarkGreen

    # Report summary
    $Report += "- Applications Found: $appCount"
    $Report += ""

    # Helper: sanitize markdown table cells
    function _Cell([string]$s) {
        if ([string]::IsNullOrWhiteSpace($s)) { return "N/A" }
        $s = $s -replace "`r|`n", " "
        $s = $s -replace "\|", "/"
        return ($s -replace "\s{2,}", " ").Trim()
    }

    # Pandoc-friendly table
    $Report += "| Name | Version | Publisher | Scope |"
    $Report += "|---|---|---|---|"

    foreach ($app in $appsList | Sort-Object DisplayName, DisplayVersion, Scope) {
        $name  = _Cell $app.DisplayName
        $ver   = _Cell $app.DisplayVersion
        $pub   = _Cell $app.Publisher
        $scope = _Cell $app.Scope

        $Report += "| $name | $ver | $pub | $scope |"
    }

}
else {
    $Report += "- Applications Found: 0"
    $Report += ""
    $Report += "_Could not retrieve installed software list._"
    Write-Host "Could not retrieve installed software list." -ForegroundColor DarkGray
}


$Report += ""

# ============================================================
# [3] WINDOWS PATCHES / HOTFIXES
# ============================================================
Write-Host "[3/10] Collecting installed Windows patches..." -ForegroundColor Yellow
$Report += "## Windows Patches / Hotfixes"
$Report += ""

if ($IsElevated) {
    $patches = Safe-Invoke {
        Get-HotFix | Sort-Object InstalledOn -Descending
    } "Windows Patches"

    if ($patches -ne "Error" -and $patches) {

        $patchList  = @($patches)
        $patchCount = $patchList.Count

        # Minimal console feedback
        Write-Host ("Patches found: {0}" -f $patchCount) -ForegroundColor DarkGreen

        # Report summary
        $Report += "- Patches Found: $patchCount"
        $Report += ""

        function _Cell([string]$s) {
            if ([string]::IsNullOrWhiteSpace($s)) { return "N/A" }
            $s = $s -replace "`r|`n", " "
            $s = $s -replace "\|", "/"
            return ($s -replace "\s{2,}", " ").Trim()
        }

        # Pandoc-friendly table
        $Report += "| KB | Installed On | Description |"
        $Report += "|---|---|---|"

        foreach ($p in ($patchList | Sort-Object InstalledOn -Descending)) {
            $kb   = _Cell $p.HotFixID
            $date = if ($p.InstalledOn) { _Cell ($p.InstalledOn.ToShortDateString()) } else { "Unknown" }
            $desc = _Cell $p.Description

            $Report += "| $kb | $date | $desc |"
        }

    }
    elseif ($patches -eq "Error") {
        $Report += "- Could not retrieve installed patches / hotfixes."
        Write-Host "Could not retrieve installed patches / hotfixes." -ForegroundColor DarkGray
    }
    else {
        $Report += "- Patches Found: 0"
        $Report += ""
        $Report += "_No installed patches / hotfixes found._"
    }
}

$Report += ""

# ============================================================
# [4] PENDING WINDOWS UPDATES
# ============================================================
Write-Host "[4/10] Checking for pending Windows updates..." -ForegroundColor Yellow

Ensure-PSWindowsUpdate

$Report += "## Pending Windows Updates"
$Report += ""

if ($IsElevated) {

    # Ensure PSWindowsUpdate module is installed, non-interactively, with feedback
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "PSWindowsUpdate module not found. Installing from PSGallery..." -ForegroundColor Yellow
        Log "PSWindowsUpdate module not found. Attempting install from PSGallery."

        $installResult = Safe-Invoke {
            $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
            if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            }
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -Confirm:$false
        } "Install PSWindowsUpdate"

        if ($installResult -eq "Error") {
            Write-Host "PSWindowsUpdate module installation failed. Pending updates check may not be available." -ForegroundColor Red
            Log "PSWindowsUpdate installation failed."
        }
        else {
            Write-Host "PSWindowsUpdate module installed successfully." -ForegroundColor Green
            Log "PSWindowsUpdate module installed successfully."
        }
    }
    else {
        Write-Host "PSWindowsUpdate module already installed." -ForegroundColor DarkGray
        Log "PSWindowsUpdate module already installed."
    }

    $pendingUpdates = Safe-Invoke {
        Import-Module PSWindowsUpdate -Force
        Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot |
            Select-Object KBArticleIDs, Title
    } "Pending Windows Updates"

    if ($pendingUpdates -ne "Error" -and $pendingUpdates) {
        $puList = @($pendingUpdates)
        $kbAll = @()
        foreach ($u in $puList) {
            if ($u.KBArticleIDs) { $kbAll += $u.KBArticleIDs }
        }
        $kbAll = $kbAll | Where-Object { $_ } | Sort-Object -Unique
        $kbPreview = ($kbAll | Select-Object -First 30) -join ", "
        Write-Host ("Pending updates: {0}" -f $puList.Count) -ForegroundColor DarkGreen
        if ($kbPreview) { Write-Host ("Pending KBs: {0}" -f $kbPreview) -ForegroundColor DarkGray }

        foreach ($upd in $puList) {
            $kb = if ($upd.KBArticleIDs) { ($upd.KBArticleIDs -join ", ") } else { "N/A" }
            $Report += "- Update:"
            $Report += "  - Title: $($upd.Title)"
            $Report += "  - KB: $kb"
        }
    }
    elseif ($pendingUpdates -eq "Error") {
        $Report += "- Could not retrieve pending updates."
    }
    else {
        Write-Host "Pending updates: 0" -ForegroundColor DarkGreen
        $Report += "- No pending updates found."
    }
}
else {
    $Report += "- Skipped (requires elevation)."
    Log "Skipped Get-WindowsUpdate (not elevated)"
    Write-Host "Skipped (requires elevation)." -ForegroundColor DarkGray
}

$Report += ""

# ============================================================
# [5] NETWORK ADAPTERS
# ============================================================
Write-Host "[5/10] Gathering network adapters..." -ForegroundColor Yellow
$Report += "## Network Adapters"
$Report += ""

# Report still includes all adapters (as before)
$nets = Safe-Invoke {
    Get-NetAdapter | Select-Object Name, Status, MacAddress
} "Network Adapters"

if ($nets -ne "Error") {
    foreach ($n in $nets) {
        $Report += "- Adapter: $($n.Name)"
        $Report += "  - Status: $($n.Status)"
        $Report += "  - MAC Address: $($n.MacAddress)"
    }
}
else {
    $Report += "- Could not retrieve network adapter information."
    Write-Host "Could not retrieve network adapter information." -ForegroundColor DarkGray
}

# Console: primary adapter(s) only
$primaryCfg = Safe-Invoke {
    Get-NetIPConfiguration | Where-Object {
        $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway -and $_.IPv4Address
    } | Select-Object -First 3
} "Primary Network Config"

if ($primaryCfg -ne "Error" -and $primaryCfg) {
    foreach ($cfg in @($primaryCfg)) {
        $name = $cfg.InterfaceAlias
        $ip4  = if ($cfg.IPv4Address) { ($cfg.IPv4Address.IPAddress | Select-Object -First 1) } else { "N/A" }
        $gw4  = if ($cfg.IPv4DefaultGateway) { $cfg.IPv4DefaultGateway.NextHop } else { "N/A" }
        $dns  = if ($cfg.DnsServer.ServerAddresses) { ($cfg.DnsServer.ServerAddresses -join ", ") } else { "N/A" }
        Write-Host ("Primary: {0}  IP {1}  GW {2}" -f $name, $ip4, $gw4) -ForegroundColor DarkGreen
        Write-Host ("DNS: {0}" -f $dns) -ForegroundColor DarkGray
    }
}

$Report += ""

# ============================================================
# [6] SMB SHARES
# ============================================================
Write-Host "[6/10] Gathering SMB shares..." -ForegroundColor Yellow
$Report += "## SMB Shares"
$Report += ""

$shares = Safe-Invoke {
    Get-SmbShare | Select-Object Name, Path
} "SMB Shares"

if ($shares -ne "Error") {
    $shareList = @($shares)
    # Console: show shares found (keep short; hide default admin shares in console)
    $nonAdmin = $shareList | Where-Object { $_.Name -notmatch '^\w\$$' -and $_.Name -notin @('ADMIN$', 'C$', 'IPC$') }
    if ($nonAdmin -and $nonAdmin.Count -gt 0) {
        Write-Host ("SMB shares found: {0} (excluding default admin shares)" -f $nonAdmin.Count) -ForegroundColor DarkGreen
        foreach ($s in ($nonAdmin | Select-Object -First 15)) {
            Write-Host ("- {0} -> {1}" -f $s.Name, $s.Path) -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "SMB shares found: 0 (excluding default admin shares)" -ForegroundColor DarkGreen
    }

    foreach ($s in $shareList) {
        $Report += "- Share: $($s.Name)"
        $Report += "  - Path: $($s.Path)"
    }
}
else {
    $Report += "- Could not retrieve SMB share information."
}

$Report += ""

# ============================================================
# [7] PRINTERS
# ============================================================
Write-Host "[7/10] Gathering printers..." -ForegroundColor Yellow
$Report += "## Printers"
$Report += ""

$printers = Safe-Invoke { Get-Printer } "Printers"

function _Cell([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return "N/A" }
    $s = $s -replace "`r|`n", " "
    $s = $s -replace "\|", "/"
    return ($s -replace "\s{2,}", " ").Trim()
}

if ($printers -ne "Error" -and $printers) {

    $printerList  = @($printers)
    $printerCount = $printerList.Count

    # Minimal console feedback
    Write-Host ("Printers found: {0}" -f $printerCount) -ForegroundColor DarkGreen

    # Report summary
    $Report += "- Printers Found: $printerCount"
    $Report += ""

    # Pandoc-friendly table
    $Report += "| Name | Driver | Port | Shared | Default |"
    $Report += "|---|---|---|---|---|"

    foreach ($p in ($printerList | Sort-Object Name)) {
        $name    = _Cell $p.Name
        $driver  = _Cell $p.DriverName
        $port    = _Cell $p.PortName
        $shared  = if ($null -ne $p.Shared)  { $p.Shared }  else { "N/A" }
        $default = if ($null -ne $p.Default) { $p.Default } else { "N/A" }

        $Report += "| $name | $driver | $port | $shared | $default |"
    }

}
elseif ($printers -eq "Error") {
    $Report += "- Could not retrieve printers."
    Write-Host "Could not retrieve printers." -ForegroundColor DarkGray
}
else {
    $Report += "- Printers Found: 0"
    $Report += ""
    $Report += "_No printers found._"
    Write-Host "Printers found: 0" -ForegroundColor DarkYellow
}

$Report += ""

# ============================================================
# [8] SECURITY BASELINE CHECKS
# ============================================================
Write-Host "[8/10] Performing security baseline checks..." -ForegroundColor Yellow
if ($IsElevated) {
    $Report += "## Security Baseline Checks"
    $Report += ""

    # --- BitLocker Status ---
    $Report += "### BitLocker"
    $Report += ""

    $bitlocker = Safe-Invoke { Get-BitLockerVolume } "BitLocker Status"

    if ($bitlocker -ne "Error") {
        foreach ($vol in $bitlocker) {
            $Report += "- Volume: $($vol.VolumeLetter)"
            $Report += "  - Protection Status: $($vol.ProtectionStatus)"
            $Report += "  - Lock Status: $($vol.LockStatus)"
            $Report += "  - Encryption Method: $($vol.EncryptionMethod)"
            $Report += ""

            # Console warnings only
            if ($vol.ProtectionStatus -ne 'On' -and $vol.ProtectionStatus -ne 1) {
                Write-Host ("WARNING: BitLocker protection is not ON for volume {0}" -f $vol.VolumeLetter) -ForegroundColor DarkYellow
            }
        }
    }
    else {
        $Report += "- Could not retrieve BitLocker information."
        Write-Host "WARNING: Could not retrieve BitLocker information." -ForegroundColor DarkYellow
        $Report += ""
    }

    # --- TPM ---
    $Report += "### TPM"
    $Report += ""

    $tpm = Safe-Invoke { Get-Tpm } "TPM Status"

    if ($tpm -ne "Error") {
        $Report += "- TPM Present: $($tpm.TpmPresent)"
        $Report += "- Manufacturer: $($tpm.ManufacturerIdTxt)"
        $Report += "- Version: $($tpm.ManufacturerVersion)"
        $Report += "- Ready: $($tpm.TpmReady)"
        $Report += "- Activated: $($tpm.TpmActivated)"

        if (-not $tpm.TpmPresent) { Write-Host "WARNING: TPM not present" -ForegroundColor DarkYellow }
        elseif (-not $tpm.TpmReady) { Write-Host "WARNING: TPM present but not ready" -ForegroundColor DarkYellow }
    }
    else {
        $Report += "- Could not retrieve TPM status."
        Write-Host "WARNING: Could not retrieve TPM status." -ForegroundColor DarkYellow
    }

    $Report += ""

    # --- Secure Boot ---
    $Report += "### Secure Boot"
    $Report += ""

    $secureBoot = Safe-Invoke { Confirm-SecureBootUEFI } "Secure Boot Check"

    if ($secureBoot -eq $true) {
        $Report += "- Secure Boot: Enabled"
    }
    elseif ($secureBoot -eq $false) {
        $Report += "- Secure Boot: Disabled"
        Write-Host "WARNING: Secure Boot is disabled" -ForegroundColor DarkYellow
    }
    else {
        $Report += "- Secure Boot: Not Supported or Unknown"
        # Unknown isn't necessarily a warning; keep console quiet.
    }

    $Report += ""

    # --- Windows Firewall ---
    $Report += "### Windows Firewall"
    $Report += ""

    $fw = Safe-Invoke { Get-NetFirewallProfile } "Firewall Status"

    if ($fw -ne "Error") {
        foreach ($p in $fw) {
            $Report += "- Profile: $($p.Name)"
            $Report += "  - Enabled: $($p.Enabled)"
            $Report += "  - Default Inbound Action: $($p.DefaultInboundAction)"
            $Report += "  - Default Outbound Action: $($p.DefaultOutboundAction)"
            $Report += ""

            if (-not $p.Enabled) {
                Write-Host ("WARNING: Firewall profile disabled: {0}" -f $p.Name) -ForegroundColor DarkYellow
            }
        }
    }
    else {
        $Report += "- Could not retrieve firewall settings."
        Write-Host "WARNING: Could not retrieve firewall settings." -ForegroundColor DarkYellow
        $Report += ""
    }

    # --- Defender Status ---
    $Report += "### Windows Defender"
    $Report += ""

    $def = Safe-Invoke { Get-MpComputerStatus } "Defender Status"

    if ($def -ne "Error") {
        $Report += "- Real-Time Protection: $($def.RealTimeProtectionEnabled)"
        $Report += "- Antivirus Signature Version: $($def.AntivirusSignatureVersion)"
        $Report += "- Last Quick Scan: $($def.LastQuickScanEndTime)"
        $Report += "- Last Full Scan: $($def.LastFullScanEndTime)"

        if (-not $def.RealTimeProtectionEnabled) {
            Write-Host "WARNING: Defender real-time protection is disabled" -ForegroundColor DarkYellow
        }
    }
    else {
        $Report += "- Could not retrieve Defender status."
        Write-Host "WARNING: Could not retrieve Defender status." -ForegroundColor DarkYellow
    }

    $Report += ""

    # --- Local Administrators ---
    $Report += "### Local Administrators"
    $Report += ""

    $admins = Safe-Invoke { Get-LocalGroupMember -Group 'Administrators' } "Local Admin Group"

    if ($admins -ne "Error") {
        foreach ($adm in $admins) {
            $Report += "- $($adm.Name)"
            $Report += "  - Type: $($adm.ObjectClass)"
        }

        # Console warning if non-built-in local admin accounts exist
        $adminList = @($admins) | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
        $nonBuiltin = $adminList | Where-Object { $_ -and $_ -notmatch '\\Administrator$' -and $_ -notmatch '^BUILTIN\\' }
        if ($nonBuiltin -and $nonBuiltin.Count -gt 0) {
            Write-Host ("WARNING: Additional local admins found: {0}" -f (($nonBuiltin | Select-Object -First 10) -join ", ")) -ForegroundColor DarkYellow
        }
    }
    else {
        $Report += "- Could not retrieve local administrator list."
        Write-Host "WARNING: Could not retrieve local administrator list." -ForegroundColor DarkYellow
    }
}
else {
    $Report += "- Skipped (requires elevation)."
    Log "Skipped Security Baseline (not elevated)"
    Write-Host "Skipped (requires elevation)." -ForegroundColor DarkGray
}
$Report += ""

# ============================================================
# [9] AZURE AD JOIN STATUS
# ============================================================
Write-Host "[9/10] Checking Azure AD join status..." -ForegroundColor Yellow
$Report += "## Azure AD Join Status"
$Report += ""

$aadInfo = Safe-Invoke {
    $ds     = dsregcmd.exe /status
    $output = $ds | Out-String
    $joined = ($output -match "AzureAdJoined\s*:\s*YES")
    $tenantId = if ($output -match "TenantId\s*:\s*(\S+)") { $matches[1] } else { "N/A" }
    $tenantName = if ($output -match "TenantName\s*:\s*(.+)") { $matches[1].Trim() } else { "N/A" }
    [PSCustomObject]@{
        Joined     = $joined
        TenantId   = $tenantId
        TenantName = $tenantName
    }
} "Azure AD Join Status"

if ($aadInfo -ne "Error") {
    $Report += "- Azure AD Joined: $($aadInfo.Joined)"
    $Report += "- Tenant ID: $($aadInfo.TenantId)"
    $Report += "- Tenant Name: $($aadInfo.TenantName)"

    $joinText = if ($aadInfo.Joined) { "YES" } else { "NO" }
    Write-Host ("Azure AD Joined: {0}  Tenant: {1}" -f $joinText, $aadInfo.TenantName) -ForegroundColor DarkGreen
}
else {
    $Report += "- Azure AD Join Status: Not Available / Error"
    Write-Host "Azure AD Join Status: Not Available / Error." -ForegroundColor DarkGray
}

$Report += ""

# ============================================================
# [10] OPTIONAL NMAP SCAN (XML ONLY)
# ============================================================
Write-Host "[10/10] Nmap scan stage..." -ForegroundColor Yellow

# NOTE:
# - No console output from Nmap execution
# - No Markdown/HTML report content for Nmap
# - Nmap still produces its own XML report at $NmapXmlPath when enabled
if ($RunNmap -and $IsElevated) {

    $nmapExe = "C:\Program Files (x86)\Nmap\nmap.exe"

    if (-not (Test-Path $nmapExe)) {
        Log "Nmap not found. Installing via winget."
        $install = Safe-Invoke {
            winget install --id Insecure.Nmap --source winget --accept-package-agreements --accept-source-agreements --silent
        } "Nmap Installation"
        if ($install -eq "Error") {
            Log "Nmap installation failed. Scan skipped."
        }
    }

    if (Test-Path $nmapExe) {
        $ip = Safe-Invoke {
            Get-NetIPAddress |
                Where-Object { $_.AddressFamily -eq "IPv4" -and $_.PrefixOrigin -ne "WellKnown" } |
                Select-Object -First 1
        } "Detect IPv4 network"

        if ($ip -ne "Error" -and $ip) {
            $cidr = "$($ip.IPAddress)/$($ip.PrefixLength)"
            Log "Running Nmap scan on $cidr (XML: $NmapXmlPath)"

            $scanResult = Safe-Invoke {
                & $nmapExe -sS -O -sV -T4 -oX $NmapXmlPath $cidr | Out-Null
            } "Nmap Scan"

            if ($scanResult -eq "Error") {
                Log "Nmap scan failed."
            }
        }
        else {
            Log "No suitable IPv4 adapter found for Nmap."
        }
    }
    else {
        Log "Nmap not found after attempted install."
    }
}
elseif ($RunNmap -and -not $IsElevated) {
    Log "Nmap requested but skipped (not elevated)."
}
else {
    Log "Nmap not requested."
}

# ============================================================
# Save Markdown Report
# ============================================================
Write-Host "[Final] Saving Markdown report: $ReportPath" -ForegroundColor Cyan
try {
    $Report -join "`r`n" | Out-File -FilePath $ReportPath -Force -Encoding UTF8
    Write-Host "Markdown report saved to $ReportPath" -ForegroundColor Green
    Log "Markdown report written to $ReportPath"
}
catch {
    Write-Host "Failed to write Markdown report: $_" -ForegroundColor Red
    Log "Failed to write Markdown report: $_"
}

# ============================================================
# Save HTML Report
# ============================================================
Write-Host "[Final] Saving HTML report: $HtmlReportPath" -ForegroundColor Cyan
try {
$htmlContent = @"
<html>
<head>
<title>System Audit Report - $ComputerName</title>
<style>
body { font-family: Consolas, monospace; background-color:#f4f4f4; padding:20px; }
h1, h2, h3 { color: #2E5C6E; }
pre { background-color:#fff; padding:10px; border:1px solid #ccc; overflow-x:auto; }
hr { border:0; border-top:1px solid #ccc; margin:10px 0; }
</style>
</head>
<body>
<h1>System Audit Report - $ComputerName</h1>
<p>Generated: $(Get-Date)</p>
<hr>
<pre>
$($Report -join "`r`n")
</pre>
</body>
</html>
"@
    $htmlContent | Out-File -FilePath $HtmlReportPath -Force -Encoding UTF8
    Write-Host "HTML report saved to $HtmlReportPath" -ForegroundColor Green
    Log "HTML report written to $HtmlReportPath"
}
catch {
    Write-Host "Failed to write HTML report: $_" -ForegroundColor Red
    Log "Failed to write HTML report: $_"
}

Write-Host "=== Audit Completed for $ComputerName ===" -ForegroundColor Green
Log "Audit completed for $ComputerName"

Write-Host ""
Write-Host "Audit complete. Press ENTER to exit..." -ForegroundColor Cyan
[void][System.Console]::ReadLine()
