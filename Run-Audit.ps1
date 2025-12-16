<#
    Run-Audit.ps1
    System Audit Script with progress output, security baseline, and optional Nmap
    Markdown output formatted to be pandoc-friendly for DOCX conversion.

    NOTE (2025-12): Markdown tables are generated without any literal pipe characters
    in the script source for table strings. Table rows are built using [char]124.
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
    try {
        Add-Content -Path $LogPath -Value "$(Get-Date -Format u) - $Message"
    } catch {
        # Never let logging break the audit
    }
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
        exit
    }
    catch {
        Write-Host "Elevation denied. Continuing in limited mode." -ForegroundColor DarkYellow
        Log "Elevation denied by user"
    }
}

# ------------------------- #
# Markdown Helpers          #
# ------------------------- #
$mdPipe = [char]124

function Md-Cell {
    param([object]$Value)

    $s = if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { "N/A" } else { [string]$Value }

    $s = $s -replace "`r", " "
    $s = $s -replace "`n", " "
    $s = $s.Replace([string]$mdPipe, "/")
    $s = ($s -replace '\s{2,}', ' ').Trim()

    return $s
}

function Md-Row {
    param([string[]]$Cells)
    $sep = " " + [string]$mdPipe + " "
    return ([string]$mdPipe + " " + (($Cells | ForEach-Object { $_ }) -join $sep) + " " + [string]$mdPipe)
}

function Md-HeaderSep {
    param([int]$Count)
    $parts = @()
    for ($i=0; $i -lt $Count; $i++) { $parts += "---" }
    return ([string]$mdPipe + ($parts -join [string]$mdPipe) + [string]$mdPipe)
}

# ------------------------- #
# Windows Updates (WUA API) #
# ------------------------- #
function Get-PendingWindowsUpdatesWUA {
    <#
      Returns pending updates using the Windows Update Agent (WUA) API.
      Includes a META record with ResultCode/Criteria/Count for diagnostics.
    #>

    try {
        $svc = Get-Service -Name wuauserv -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue | Out-Null
        }
    } catch { }

    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()

    $criteria = "IsInstalled=0 and IsHidden=0"
    $result   = $searcher.Search($criteria)

    $updates = @()

    for ($i = 0; $i -lt $result.Updates.Count; $i++) {
        $u = $result.Updates.Item($i)

        $kb = "N/A"
        try {
            if ($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0) {
                $kb = ($u.KBArticleIDs -join ", ")
            }
        } catch {}

        $cats = "N/A"
        try {
            if ($u.Categories -and $u.Categories.Count -gt 0) {
                $cats = (@($u.Categories) | ForEach-Object { $_.Name } | Sort-Object -Unique) -join ", "
            }
        } catch {}

        $updates += [pscustomobject]@{
            Title          = $u.Title
            KB             = $kb
            Categories     = $cats
            Downloaded     = $u.IsDownloaded
            Mandatory      = $u.IsMandatory
            RebootRequired = $u.RebootRequired
            EulaAccepted   = $u.EulaAccepted
        }
    }

    $meta = [pscustomobject]@{
        Title          = "<META>"
        KB             = "N/A"
        Categories     = ("ResultCode={0}; Criteria={1}; Count={2}" -f $result.ResultCode, $criteria, $result.Updates.Count)
        Downloaded     = $false
        Mandatory      = $false
        RebootRequired = $false
        EulaAccepted   = $true
    }

    return @($meta) + $updates
}

Write-Host "=== Starting System Audit for $ComputerName ===" -ForegroundColor Cyan
Log "Audit started for $ComputerName"

$IsElevated = Test-IsElevated
if (-not $IsElevated) {
    Start-SelfElevate
    $IsElevated = Test-IsElevated
}

if ($IsElevated) {
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
$Report += ""

$compName = Safe-Invoke { $env:COMPUTERNAME } "Computer Name"
$Report += ("- Computer Name: {0}" -f (Md-Cell $compName))
Write-Host ("Computer Name: {0}" -f $compName) -ForegroundColor DarkGreen

$os = Safe-Invoke { Get-CimInstance Win32_OperatingSystem } "Operating System"
if ($os -ne "Error") {
    $Report += "- Operating System:"
    $Report += ("  - Name: {0}" -f (Md-Cell $os.Caption))
    $Report += ("  - Version: {0}" -f (Md-Cell $os.Version))
    $Report += ("  - Build Number: {0}" -f (Md-Cell $os.BuildNumber))
    $Report += ("  - Architecture: {0}" -f (Md-Cell $os.OSArchitecture))

    Write-Host "<Operating System>" -ForegroundColor DarkMagenta
    Write-Host ("Name: {0}" -f $os.Caption) -ForegroundColor DarkGreen
    Write-Host ("Version: {0}" -f $os.Version) -ForegroundColor DarkGreen
    Write-Host ("Build Number: {0}" -f $os.BuildNumber) -ForegroundColor DarkGreen
    Write-Host ("Architecture: {0}" -f $os.OSArchitecture) -ForegroundColor DarkGreen
}

$winVer = Safe-Invoke {
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" |
        Select-Object -Property ReleaseId, DisplayVersion
} "Feature Version"
if ($winVer -ne "Error") {
    $ver = if ($winVer.DisplayVersion) { $winVer.DisplayVersion } else { $winVer.ReleaseId }
    $Report += ("- Windows Feature Version: {0}" -f (Md-Cell $ver))
}

$cpu = Safe-Invoke {
    Get-CimInstance Win32_Processor |
        Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors
} "CPU Info"
if ($cpu -ne "Error") {
    $Report += "- Processor:"
    $Report += ("  - Name: {0}" -f (Md-Cell $cpu.Name))
    $Report += ("  - Cores: {0}" -f (Md-Cell $cpu.NumberOfCores))
    $Report += ("  - Logical Processors: {0}" -f (Md-Cell $cpu.NumberOfLogicalProcessors))
}

$mem = Safe-Invoke { Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory } "Memory Info"
if ($mem -ne "Error") {
    $ramGB = [math]::Round($mem.TotalPhysicalMemory / 1GB, 2)
    $Report += "- Memory:"
    $Report += ("  - Installed RAM: {0} GB" -f (Md-Cell $ramGB))
}

$disks = Safe-Invoke { Get-CimInstance Win32_DiskDrive | Select-Object Model, Size } "Disk Info"
if ($disks -ne "Error" -and $disks) {
    $Report += "- Physical Disks:"
    foreach ($d in @($disks)) {
        $sizeGB = [math]::Round($d.Size / 1GB, 2)
        $Report += ("  - Model: {0}" -f (Md-Cell $d.Model))
        $Report += ("    - Size: {0} GB" -f (Md-Cell $sizeGB))
    }
}

$boot = Safe-Invoke { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } "Uptime"
if ($boot -ne "Error") {
    $uptime = New-TimeSpan -Start $boot
    $Report += "- Uptime:"
    $Report += ("  - {0} days, {1} hours, {2} minutes" -f (Md-Cell $uptime.Days), (Md-Cell $uptime.Hours), (Md-Cell $uptime.Minutes))
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
            catch { }
        }
    }

    Add-UninstallEntriesFromRoot -Root "HKLM:" -Scope "Machine"
    Add-UninstallEntriesFromRoot -Root "HKCU:" -Scope "CurrentUser"

    if ($IncludeAllUsers) {
        $userSids = @()
        try {
            $userSids = Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction Stop |
                Where-Object {
                    $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' -and
                    $_.PSChildName -notlike '*_Classes'
                } |
                Select-Object -ExpandProperty PSChildName
        } catch { }

        foreach ($sid in $userSids) {
            Add-UninstallEntriesFromRoot -Root ("Registry::HKEY_USERS\{0}" -f $sid) -Scope ("UserHive:{0}" -f $sid)
        }

        $profileList = @()
        try {
            $profileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction Stop |
                Select-Object PSChildName, ProfileImagePath
        } catch { }

        foreach ($p in $profileList) {
            $sid = $p.PSChildName
            if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }

            $profilePath = $p.ProfileImagePath
            if (-not $profilePath) { continue }

            $ntUser = Join-Path $profilePath 'NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $ntUser)) { continue }

            $tempHiveName = "AUDIT_{0}" -f ([Math]::Abs($sid.GetHashCode()))
            $tempHiveRoot = "Registry::HKEY_USERS\$tempHiveName"
            if (Test-Path -Path $tempHiveRoot) { continue }

            $loaded = $false
            try {
                $null = & reg.exe load ("HKU\{0}" -f $tempHiveName) "$ntUser" 2>$null
                if ($LASTEXITCODE -eq 0) { $loaded = $true }
            } catch { $loaded = $false }

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

$apps = Safe-Invoke { Get-InstalledSoftwareInventory -IncludeAllUsers:($IsElevated) } "Installed Software"

if ($apps -ne "Error" -and $apps) {
    $appsList = @($apps)
    $appCount = $appsList.Count

    Write-Host ("Applications found: {0}" -f $appCount) -ForegroundColor DarkGreen

    $Report += ("- Applications Found: {0}" -f $appCount)
    $Report += ""

    $Report += (Md-Row @("Name", "Version", "Publisher", "Scope"))
    $Report += (Md-HeaderSep 4)

    foreach ($app in ($appsList | Sort-Object DisplayName, DisplayVersion, Scope)) {
        $Report += (Md-Row @(
            (Md-Cell $app.DisplayName),
            (Md-Cell $app.DisplayVersion),
            (Md-Cell $app.Publisher),
            (Md-Cell $app.Scope)
        ))
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
    $patches = Safe-Invoke { Get-HotFix | Sort-Object InstalledOn -Descending } "Windows Patches"

    if ($patches -ne "Error" -and $patches) {
        $patchList  = @($patches)
        $patchCount = $patchList.Count

        Write-Host ("Patches found: {0}" -f $patchCount) -ForegroundColor DarkGreen

        $Report += ("- Patches Found: {0}" -f $patchCount)
        $Report += ""

        $Report += (Md-Row @("KB", "Installed On", "Description"))
        $Report += (Md-HeaderSep 3)

        foreach ($p in ($patchList | Sort-Object InstalledOn -Descending)) {
            $kb   = Md-Cell $p.HotFixID
            $date = if ($p.InstalledOn) { Md-Cell ($p.InstalledOn.ToShortDateString()) } else { "Unknown" }
            $desc = Md-Cell $p.Description

            $Report += (Md-Row @($kb, $date, $desc))
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
else {
    $Report += "- Skipped (requires elevation)."
}

$Report += ""

# ============================================================
# [4] PENDING WINDOWS UPDATES (WUA API)
# ============================================================
Write-Host "[4/10] Checking pending Windows Updates..." -ForegroundColor Yellow
$Report += "## Pending Windows Updates"
$Report += ""

$pendingUpdates = Safe-Invoke { Get-PendingWindowsUpdatesWUA } "Pending Windows Updates (WUA API)"

if ($pendingUpdates -eq "Error") {
    Write-Host "Pending updates check failed (WUA API)." -ForegroundColor Red
    $Report += "- Could not query pending updates (WUA API)."
}
else {
    $list = @($pendingUpdates)
    $meta = $list | Where-Object { $_.Title -eq "<META>" } | Select-Object -First 1
    $real = $list | Where-Object { $_.Title -ne "<META>" }

    if ($meta) {
        $Report += ("- WUA Search: {0}" -f (Md-Cell $meta.Categories))
        $Report += ""
    }

    if (-not $real -or @($real).Count -eq 0) {
        Write-Host "No pending updates found." -ForegroundColor DarkGreen
        $Report += "- No pending updates found."
    }
    else {
        $count = @($real).Count
        Write-Host ("Pending updates: {0}" -f $count) -ForegroundColor Yellow
        $Report += ("- Pending updates: **{0}**" -f (Md-Cell $count))
        $Report += ""

        $Report += (Md-Row @("KB", "Title", "Categories", "Downloaded", "Mandatory", "Reboot"))
        $Report += (Md-HeaderSep 6)

        foreach ($u in @($real)) {
            $Report += (Md-Row @(
                (Md-Cell $u.KB),
                (Md-Cell $u.Title),
                (Md-Cell $u.Categories),
                (Md-Cell $u.Downloaded),
                (Md-Cell $u.Mandatory),
                (Md-Cell $u.RebootRequired)
            ))
        }
    }
}

$Report += ""

# ============================================================
# [5] NETWORK ADAPTERS
# ============================================================
Write-Host "[5/10] Gathering network adapters..." -ForegroundColor Yellow
$Report += "## Network Adapters"
$Report += ""

$nets = Safe-Invoke { Get-NetAdapter | Select-Object Name, Status, MacAddress } "Network Adapters"

if ($nets -ne "Error" -and $nets) {
    foreach ($n in @($nets)) {
        $Report += ("- Adapter: {0}" -f (Md-Cell $n.Name))
        $Report += ("  - Status: {0}" -f (Md-Cell $n.Status))
        $Report += ("  - MAC Address: {0}" -f (Md-Cell $n.MacAddress))
    }
}
else {
    $Report += "- Could not retrieve network adapter information."
    Write-Host "Could not retrieve network adapter information." -ForegroundColor DarkGray
}

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

$shares = Safe-Invoke { Get-SmbShare | Select-Object Name, Path } "SMB Shares"

if ($shares -ne "Error" -and $shares) {
    $shareList = @($shares)
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
        $Report += ("- Share: {0}" -f (Md-Cell $s.Name))
        $Report += ("  - Path: {0}" -f (Md-Cell $s.Path))
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

if ($printers -ne "Error" -and $printers) {
    $printerList  = @($printers)
    $printerCount = $printerList.Count

    Write-Host ("Printers found: {0}" -f $printerCount) -ForegroundColor DarkGreen

    $Report += ("- Printers Found: {0}" -f (Md-Cell $printerCount))
    $Report += ""

    $Report += (Md-Row @("Name", "Driver", "Port", "Shared", "Default"))
    $Report += (Md-HeaderSep 5)

    foreach ($p in ($printerList | Sort-Object Name)) {
        $Report += (Md-Row @(
            (Md-Cell $p.Name),
            (Md-Cell $p.DriverName),
            (Md-Cell $p.PortName),
            (Md-Cell $p.Shared),
            (Md-Cell $p.Default)
        ))
    }
}
elseif ($printers -eq "Error") {
    $Report += "- Could not retrieve printers."
}
else {
    $Report += "- Printers Found: 0"
    $Report += ""
    $Report += "_No printers found._"
}

$Report += ""

# ============================================================
# [8] SECURITY BASELINE CHECKS
# ============================================================
Write-Host "[8/10] Performing security baseline checks..." -ForegroundColor Yellow
if ($IsElevated) {
    $Report += "## Security Baseline Checks"
    $Report += ""

    $Report += "### BitLocker"
    $Report += ""

    $bitlocker = Safe-Invoke { Get-BitLockerVolume } "BitLocker Status"
    if ($bitlocker -ne "Error" -and $bitlocker) {
        foreach ($vol in @($bitlocker)) {
            $Report += ("- Volume: {0}" -f (Md-Cell $vol.VolumeLetter))
            $Report += ("  - Protection Status: {0}" -f (Md-Cell $vol.ProtectionStatus))
            $Report += ("  - Lock Status: {0}" -f (Md-Cell $vol.LockStatus))
            $Report += ("  - Encryption Method: {0}" -f (Md-Cell $vol.EncryptionMethod))
            $Report += ""

            if ($vol.ProtectionStatus -ne 'On' -and $vol.ProtectionStatus -ne 1) {
                Write-Host ("WARNING: BitLocker protection is not ON for volume {0}" -f $vol.VolumeLetter) -ForegroundColor DarkYellow
            }
        }
    }
    else {
        $Report += "- Could not retrieve BitLocker information."
        $Report += ""
    }

    $Report += "### TPM"
    $Report += ""

    $tpm = Safe-Invoke { Get-Tpm } "TPM Status"
    if ($tpm -ne "Error" -and $tpm) {
        $Report += ("- TPM Present: {0}" -f (Md-Cell $tpm.TpmPresent))
        $Report += ("- Manufacturer: {0}" -f (Md-Cell $tpm.ManufacturerIdTxt))
        $Report += ("- Version: {0}" -f (Md-Cell $tpm.ManufacturerVersion))
        $Report += ("- Ready: {0}" -f (Md-Cell $tpm.TpmReady))
        $Report += ("- Activated: {0}" -f (Md-Cell $tpm.TpmActivated))
    }
    else {
        $Report += "- Could not retrieve TPM status."
    }

    $Report += ""
    $Report += "### Secure Boot"
    $Report += ""

    $secureBoot = Safe-Invoke { Confirm-SecureBootUEFI } "Secure Boot Check"
    if ($secureBoot -eq $true) { $Report += "- Secure Boot: Enabled" }
    elseif ($secureBoot -eq $false) { $Report += "- Secure Boot: Disabled" }
    else { $Report += "- Secure Boot: Not Supported or Unknown" }

    $Report += ""
    $Report += "### Windows Firewall"
    $Report += ""

    $fw = Safe-Invoke { Get-NetFirewallProfile } "Firewall Status"
    if ($fw -ne "Error" -and $fw) {
        foreach ($p in @($fw)) {
            $Report += ("- Profile: {0}" -f (Md-Cell $p.Name))
            $Report += ("  - Enabled: {0}" -f (Md-Cell $p.Enabled))
            $Report += ("  - Default Inbound Action: {0}" -f (Md-Cell $p.DefaultInboundAction))
            $Report += ("  - Default Outbound Action: {0}" -f (Md-Cell $p.DefaultOutboundAction))
            $Report += ""
        }
    }
    else {
        $Report += "- Could not retrieve firewall settings."
        $Report += ""
    }

    $Report += "### Windows Defender"
    $Report += ""

    $def = Safe-Invoke { Get-MpComputerStatus } "Defender Status"
    if ($def -ne "Error" -and $def) {
        $Report += ("- Real-Time Protection: {0}" -f (Md-Cell $def.RealTimeProtectionEnabled))
        $Report += ("- Antivirus Signature Version: {0}" -f (Md-Cell $def.AntivirusSignatureVersion))
        $Report += ("- Last Quick Scan: {0}" -f (Md-Cell $def.LastQuickScanEndTime))
        $Report += ("- Last Full Scan: {0}" -f (Md-Cell $def.LastFullScanEndTime))
    }
    else {
        $Report += "- Could not retrieve Defender status."
    }

    $Report += ""
    $Report += "### Local Administrators"
    $Report += ""

    $admins = Safe-Invoke { Get-LocalGroupMember -Group 'Administrators' } "Local Admin Group"
    if ($admins -ne "Error" -and $admins) {
        foreach ($adm in @($admins)) {
            $Report += ("- {0}" -f (Md-Cell $adm.Name))
            $Report += ("  - Type: {0}" -f (Md-Cell $adm.ObjectClass))
        }
    }
    else {
        $Report += "- Could not retrieve local administrator list."
    }
}
else {
    $Report += "- Skipped (requires elevation)."
    Log "Skipped Security Baseline (not elevated)"
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

if ($aadInfo -ne "Error" -and $aadInfo) {
    $Report += ("- Azure AD Joined: {0}" -f (Md-Cell $aadInfo.Joined))
    $Report += ("- Tenant ID: {0}" -f (Md-Cell $aadInfo.TenantId))
    $Report += ("- Tenant Name: {0}" -f (Md-Cell $aadInfo.TenantName))
}

$Report += ""

# ============================================================
# [10] OPTIONAL NMAP SCAN (XML ONLY)
# ============================================================
Write-Host "[10/10] Nmap scan stage..." -ForegroundColor Yellow

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
    $Report -join "`r`n" | Out-File -FilePath $ReportPath -Force -Encoding utf8
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
    $htmlContent | Out-File -FilePath $HtmlReportPath -Force -Encoding utf8
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
