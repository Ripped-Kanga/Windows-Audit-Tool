<#
    Run-Audit.ps1
    System Audit Script with progress output, security baseline, and optional Nmap.

    Output:
      - HTML report written to C:\Temp\<COMPUTER>-Audit.html
      - Nmap (optional) writes XML to C:\Temp\<COMPUTER>-Nmap.xml
      - Operational log written to C:\Windows\Temp\AuditLog.txt
#>

$ErrorActionPreference = "Stop"

# ------------------------- #
# Paths (per computer)      #
# ------------------------- #
$ComputerName = $env:COMPUTERNAME
if (-not $ComputerName -or $ComputerName -eq "") {
    $ComputerName = "UnknownComputer"
}

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

# ------------------------- #
# Installed software        #
# ------------------------- #
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

# ------------------------- #
# HTML helpers              #
# ------------------------- #
$Html = New-Object System.Text.StringBuilder

function Html-Enc {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return "N/A" }
    $s = [string]$Value
    $s = $s -replace "`r", " "
    $s = $s -replace "`n", " "
    $s = ($s -replace '\s{2,}', ' ').Trim()
    return [System.Net.WebUtility]::HtmlEncode($s)
}

function Html-Add {
    param([string]$Line)
    [void]$Html.AppendLine($Line)
}

function Html-StartSection {
    param([string]$Title)
    Html-Add "<div class='section'>"
    Html-Add ("<h2>{0}</h2>" -f (Html-Enc $Title))
}

function Html-EndSection {
    Html-Add "</div>"
}

function Html-AddNote {
    param(
        [string]$Text,
        [ValidateSet('info','good','warn','bad')][string]$Kind = 'info'
    )
    $klass = switch ($Kind) {
        'good' { 'badge good' }
        'warn' { 'badge warn' }
        'bad'  { 'badge bad' }
        default { 'badge' }
    }
    Html-Add ("<p><span class='{0}'>{1}</span></p>" -f $klass, (Html-Enc $Text))
}

function Html-AddKV {
    param([hashtable]$Pairs)
    if (-not $Pairs -or $Pairs.Count -eq 0) { return }
    Html-Add "<div class='kv'>"
    foreach ($k in $Pairs.Keys) {
        Html-Add ("<div class='key'>{0}</div><div>{1}</div>" -f (Html-Enc $k), (Html-Enc $Pairs[$k]))
    }
    Html-Add "</div>"
}

function Html-StartDetails {
    param([string]$Summary, [switch]$Open)
    $openAttr = if ($Open) { " open" } else { "" }
    Html-Add ("<details{0}><summary>{1}</summary>" -f $openAttr, (Html-Enc $Summary))
}

function Html-EndDetails {
    Html-Add "</details>"
}

function Html-AddTable {
    param(
        [Parameter(Mandatory=$true)][object[]]$Items,
        [Parameter(Mandatory=$true)][array]$Columns
    )

    if (-not $Items -or $Items.Count -eq 0) {
        Html-Add "<p class='small'>No data.</p>"
        return
    }

    Html-Add "<table><thead><tr>"
    foreach ($c in $Columns) {
        Html-Add ("<th>{0}</th>" -f (Html-Enc $c.Header))
    }
    Html-Add "</tr></thead><tbody>"

    foreach ($row in $Items) {
        Html-Add "<tr>"
        foreach ($c in $Columns) {
            $raw = $false
            if ($c.ContainsKey('Raw')) { $raw = [bool]$c.Raw }

            $value = $null
            if ($c.ContainsKey('Value')) {
                $value = & $c.Value $row
            } elseif ($c.ContainsKey('Property')) {
                $value = $row.($c.Property)
            }

            if ($raw) {
                $cell = if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { "N/A" } else { [string]$value }
                Html-Add ("<td>{0}</td>" -f $cell)
            } else {
                Html-Add ("<td>{0}</td>" -f (Html-Enc $value))
            }
        }
        Html-Add "</tr>"
    }

    Html-Add "</tbody></table>"
}

# ------------------------- #
# Start                    #
# ------------------------- #
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

# ============================================================
# [1] SYSTEM INFORMATION
# ============================================================
Write-Host "[1/10] Collecting system information..." -ForegroundColor Yellow
Html-StartSection "System Information"

$kv = [ordered]@{}

$compName = Safe-Invoke { $env:COMPUTERNAME } "Computer Name"
$kv["Computer Name"] = $compName
Write-Host ("Computer Name: {0}" -f $compName) -ForegroundColor DarkGreen

$os = Safe-Invoke { Get-CimInstance Win32_OperatingSystem } "Operating System"
if ($os -ne "Error") {
    $kv["Operating System"] = $os.Caption
    $kv["OS Version"] = $os.Version
    $kv["Build Number"] = $os.BuildNumber
    $kv["Architecture"] = $os.OSArchitecture

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
    $kv["Windows Feature Version"] = $ver
}

$cpu = Safe-Invoke {
    Get-CimInstance Win32_Processor |
        Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors
} "CPU Info"
if ($cpu -ne "Error") {
    $kv["Processor"] = $cpu.Name
    $kv["Cores"] = $cpu.NumberOfCores
    $kv["Logical Processors"] = $cpu.NumberOfLogicalProcessors
}

$mem = Safe-Invoke { Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory } "Memory Info"
if ($mem -ne "Error") {
    $ramGB = [math]::Round($mem.TotalPhysicalMemory / 1GB, 2)
    $kv["Installed RAM (GB)"] = $ramGB
}

$boot = Safe-Invoke { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } "Uptime"
if ($boot -ne "Error") {
    $uptime = New-TimeSpan -Start $boot
    $kv["Uptime"] = ("{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)
}

Html-AddKV -Pairs $kv

$disks = Safe-Invoke { Get-CimInstance Win32_DiskDrive | Select-Object Model, Size } "Disk Info"
if ($disks -ne "Error" -and $disks) {
    $diskList = @($disks) | ForEach-Object {
        [pscustomobject]@{
            Model = $_.Model
            SizeGB = [math]::Round($_.Size / 1GB, 2)
        }
    }
    Html-StartDetails -Summary ("Physical Disks ({0})" -f $diskList.Count)
    Html-AddTable -Items $diskList -Columns @(
        @{ Header="Model"; Property="Model" },
        @{ Header="Size (GB)"; Property="SizeGB" }
    )
    Html-EndDetails
}

Html-EndSection

# ============================================================
# [2] INSTALLED SOFTWARE
# ============================================================
Write-Host "[2/10] Collecting installed software..." -ForegroundColor Yellow
Html-StartSection "Installed Software"

$apps = Safe-Invoke { Get-InstalledSoftwareInventory -IncludeAllUsers:($IsElevated) } "Installed Software"

if ($apps -ne "Error" -and $apps) {
    $appsList = @($apps) | Sort-Object DisplayName, DisplayVersion, Scope
    $appCount = $appsList.Count

    Write-Host ("Applications found: {0}" -f $appCount) -ForegroundColor DarkGreen
    Html-AddNote -Text ("Applications found: {0}" -f $appCount) -Kind info

    $open = $false
    if ($appCount -le 200) { $open = $true }

    Html-StartDetails -Summary ("Applications ({0})" -f $appCount) -Open:($open)
    Html-AddTable -Items $appsList -Columns @(
        @{ Header="Name"; Property="DisplayName" },
        @{ Header="Version"; Property="DisplayVersion" },
        @{ Header="Publisher"; Property="Publisher" },
        @{ Header="Scope"; Property="Scope" }
    )
    Html-EndDetails
}
else {
    Html-AddNote -Text "Could not retrieve installed software list." -Kind warn
    Write-Host "Could not retrieve installed software list." -ForegroundColor DarkGray
}

Html-EndSection

# ============================================================
# [3] WINDOWS PATCHES / HOTFIXES
# ============================================================
Write-Host "[3/10] Collecting installed Windows patches..." -ForegroundColor Yellow
Html-StartSection "Windows Patches / Hotfixes"

if ($IsElevated) {
    $patches = Safe-Invoke { Get-HotFix | Sort-Object InstalledOn -Descending } "Windows Patches"

    if ($patches -ne "Error" -and $patches) {
        $patchList  = @($patches) | Sort-Object InstalledOn -Descending
        $patchCount = $patchList.Count

        Write-Host ("Patches found: {0}" -f $patchCount) -ForegroundColor DarkGreen
        Html-AddNote -Text ("Patches found: {0}" -f $patchCount) -Kind info

        $open = $false
        if ($patchCount -le 200) { $open = $true }

        Html-StartDetails -Summary ("Hotfixes ({0})" -f $patchCount) -Open:($open)

        $patchRows = $patchList | ForEach-Object {
            [pscustomobject]@{
                KB = $_.HotFixID
                InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToShortDateString() } else { "Unknown" }
                Description = $_.Description
            }
        }

        Html-AddTable -Items $patchRows -Columns @(
            @{ Header="KB"; Property="KB" },
            @{ Header="Installed On"; Property="InstalledOn" },
            @{ Header="Description"; Property="Description" }
        )
        Html-EndDetails
    }
    elseif ($patches -eq "Error") {
        Html-AddNote -Text "Could not retrieve installed patches / hotfixes." -Kind warn
        Write-Host "Could not retrieve installed patches / hotfixes." -ForegroundColor DarkGray
    }
    else {
        Html-AddNote -Text "No installed patches / hotfixes found." -Kind info
    }
}
else {
    Html-AddNote -Text "Skipped (requires elevation)." -Kind warn
}

Html-EndSection

# ============================================================
# [4] PENDING WINDOWS UPDATES (WUA API)
# ============================================================
Write-Host "[4/10] Checking pending Windows Updates..." -ForegroundColor Yellow
Html-StartSection "Pending Windows Updates"

$pendingUpdates = Safe-Invoke { Get-PendingWindowsUpdatesWUA } "Pending Windows Updates (WUA API)"

if ($pendingUpdates -eq "Error") {
    Write-Host "Pending updates check failed (WUA API)." -ForegroundColor Red
    Html-AddNote -Text "Could not query pending updates (WUA API)." -Kind bad
}
else {
    $list = @($pendingUpdates)
    $meta = $list | Where-Object { $_.Title -eq "<META>" } | Select-Object -First 1
    $real = $list | Where-Object { $_.Title -ne "<META>" }

    if ($meta) {
        Html-Add ("<p class='small'><span class='code'>WUA Search:</span> {0}</p>" -f (Html-Enc $meta.Categories))
    }

    if (-not $real -or @($real).Count -eq 0) {
        Write-Host "No pending updates found." -ForegroundColor DarkGreen
        Html-AddNote -Text "No pending updates found." -Kind good
    }
    else {
        $count = @($real).Count
        Write-Host ("Pending updates: {0}" -f $count) -ForegroundColor Yellow
        Html-AddNote -Text ("Pending updates: {0}" -f $count) -Kind warn

        $updateRows = @($real) | ForEach-Object {
            [pscustomobject]@{
                KB = $_.KB
                Title = $_.Title
                Categories = $_.Categories
                Downloaded = $_.Downloaded
                Mandatory = $_.Mandatory
                RebootRequired = $_.RebootRequired
            }
        }

        Html-StartDetails -Summary ("Updates ({0})" -f $count) -Open
        Html-AddTable -Items $updateRows -Columns @(
            @{ Header="KB"; Property="KB" },
            @{ Header="Title"; Property="Title" },
            @{ Header="Categories"; Property="Categories" },
            @{ Header="Downloaded"; Property="Downloaded" },
            @{ Header="Mandatory"; Property="Mandatory" },
            @{ Header="Reboot"; Property="RebootRequired" }
        )
        Html-EndDetails
    }
}

Html-EndSection

# ============================================================
# [5] NETWORK ADAPTERS
# ============================================================
Write-Host "[5/10] Gathering network adapters..." -ForegroundColor Yellow
Html-StartSection "Network"

$nets = Safe-Invoke { Get-NetAdapter | Select-Object Name, Status, MacAddress } "Network Adapters"

if ($nets -ne "Error" -and $nets) {
    $netList = @($nets) | Sort-Object Name
    Html-StartDetails -Summary ("Network Adapters ({0})" -f $netList.Count) -Open
    Html-AddTable -Items $netList -Columns @(
        @{ Header="Name"; Property="Name" },
        @{ Header="Status"; Property="Status" },
        @{ Header="MAC Address"; Property="MacAddress" }
    )
    Html-EndDetails
}
else {
    Html-AddNote -Text "Could not retrieve network adapter information." -Kind warn
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

        Html-Add ("<h3>{0}</h3>" -f (Html-Enc ("Primary Configuration: " + $name)))
        Html-AddKV -Pairs ([ordered]@{
            "IPv4" = $ip4
            "Gateway" = $gw4
            "DNS" = $dns
        })
    }
}

Html-EndSection

# ============================================================
# [6] SMB SHARES
# ============================================================
Write-Host "[6/10] Gathering SMB shares..." -ForegroundColor Yellow
Html-StartSection "SMB Shares"

$shares = Safe-Invoke { Get-SmbShare | Select-Object Name, Path } "SMB Shares"

if ($shares -ne "Error" -and $shares) {
    $shareList = @($shares) | Sort-Object Name
    $nonAdmin = $shareList | Where-Object { $_.Name -notmatch '^\w\$$' -and $_.Name -notin @('ADMIN$', 'C$', 'IPC$') }

    if ($nonAdmin -and $nonAdmin.Count -gt 0) {
        Write-Host ("SMB shares found: {0} (excluding default admin shares)" -f $nonAdmin.Count) -ForegroundColor DarkGreen
        Html-AddNote -Text ("Non-admin SMB shares found: {0}" -f $nonAdmin.Count) -Kind warn
    }
    else {
        Write-Host "SMB shares found: 0 (excluding default admin shares)" -ForegroundColor DarkGreen
        Html-AddNote -Text "No non-admin SMB shares found." -Kind good
    }

    Html-StartDetails -Summary ("All Shares ({0})" -f $shareList.Count)
    Html-AddTable -Items $shareList -Columns @(
        @{ Header="Share"; Property="Name" },
        @{ Header="Path"; Property="Path" }
    )
    Html-EndDetails
}
else {
    Html-AddNote -Text "Could not retrieve SMB share information." -Kind warn
}

Html-EndSection

# ============================================================
# [7] PRINTERS
# ============================================================
Write-Host "[7/10] Gathering printers..." -ForegroundColor Yellow
Html-StartSection "Printers"

$printers = Safe-Invoke { Get-Printer } "Printers"

if ($printers -ne "Error" -and $printers) {
    $printerList  = @($printers) | Sort-Object Name
    $printerCount = $printerList.Count

    Write-Host ("Printers found: {0}" -f $printerCount) -ForegroundColor DarkGreen
    Html-AddNote -Text ("Printers found: {0}" -f $printerCount) -Kind info

    Html-StartDetails -Summary ("Printers ({0})" -f $printerCount) -Open
    Html-AddTable -Items $printerList -Columns @(
        @{ Header="Name"; Property="Name" },
        @{ Header="Driver"; Property="DriverName" },
        @{ Header="Port"; Property="PortName" },
        @{ Header="Shared"; Property="Shared" },
        @{ Header="Default"; Property="Default" }
    )
    Html-EndDetails
}
elseif ($printers -eq "Error") {
    Html-AddNote -Text "Could not retrieve printers." -Kind warn
}
else {
    Html-AddNote -Text "No printers found." -Kind info
}

Html-EndSection

# ============================================================
# [8] SECURITY BASELINE CHECKS
# ============================================================
Write-Host "[8/10] Performing security baseline checks..." -ForegroundColor Yellow
Html-StartSection "Security Baseline Checks"

if ($IsElevated) {

    # --- BitLocker ---
    Html-Add "<h3>BitLocker</h3>"
    $bitlocker = Safe-Invoke { Get-BitLockerVolume } "BitLocker Status"
    if ($bitlocker -ne "Error" -and $bitlocker) {
        $blRows = @($bitlocker) | ForEach-Object {
            $protOn = ($_.ProtectionStatus -eq 'On' -or $_.ProtectionStatus -eq 1)
            [pscustomobject]@{
                Volume = $_.VolumeLetter
                Protection = if ($protOn) { "<span class='badge good'>On</span>" } else { "<span class='badge warn'>Off</span>" }
                LockStatus = $_.LockStatus
                EncryptionMethod = $_.EncryptionMethod
            }
        }

        Html-AddTable -Items $blRows -Columns @(
            @{ Header="Volume"; Property="Volume" },
            @{ Header="Protection"; Property="Protection"; Raw=$true },
            @{ Header="Lock Status"; Property="LockStatus" },
            @{ Header="Encryption Method"; Property="EncryptionMethod" }
        )

        foreach ($vol in @($bitlocker)) {
            if ($vol.ProtectionStatus -ne 'On' -and $vol.ProtectionStatus -ne 1) {
                Write-Host ("WARNING: BitLocker protection is not ON for volume {0}" -f $vol.VolumeLetter) -ForegroundColor DarkYellow
            }
        }
    }
    else {
        Html-AddNote -Text "Could not retrieve BitLocker information." -Kind warn
    }

    # --- TPM ---
    Html-Add "<h3>TPM</h3>"
    $tpm = Safe-Invoke { Get-Tpm } "TPM Status"
    if ($tpm -ne "Error" -and $tpm) {
        Html-AddKV -Pairs ([ordered]@{
            "TPM Present"   = $tpm.TpmPresent
            "Manufacturer"  = $tpm.ManufacturerIdTxt
            "Version"       = $tpm.ManufacturerVersion
            "Ready"         = $tpm.TpmReady
            "Activated"     = $tpm.TpmActivated
        })
    }
    else {
        Html-AddNote -Text "Could not retrieve TPM status." -Kind warn
    }

    # --- Secure Boot ---
    Html-Add "<h3>Secure Boot</h3>"
    $secureBoot = Safe-Invoke { Confirm-SecureBootUEFI } "Secure Boot Check"
    if ($secureBoot -eq $true) {
        Html-AddNote -Text "Secure Boot: Enabled" -Kind good
    }
    elseif ($secureBoot -eq $false) {
        Html-AddNote -Text "Secure Boot: Disabled" -Kind warn
    }
    else {
        Html-AddNote -Text "Secure Boot: Not supported or unknown" -Kind info
    }

    # --- Firewall ---
    Html-Add "<h3>Windows Firewall</h3>"
    $fw = Safe-Invoke { Get-NetFirewallProfile } "Firewall Status"
    if ($fw -ne "Error" -and $fw) {
        $fwRows = @($fw) | ForEach-Object {
            $enabled = $_.Enabled -eq $true
            [pscustomobject]@{
                Profile = $_.Name
                Enabled = if ($enabled) { "<span class='badge good'>Enabled</span>" } else { "<span class='badge warn'>Disabled</span>" }
                Inbound = $_.DefaultInboundAction
                Outbound = $_.DefaultOutboundAction
            }
        }
        Html-AddTable -Items $fwRows -Columns @(
            @{ Header="Profile"; Property="Profile" },
            @{ Header="Enabled"; Property="Enabled"; Raw=$true },
            @{ Header="Default Inbound Action"; Property="Inbound" },
            @{ Header="Default Outbound Action"; Property="Outbound" }
        )
    }
    else {
        Html-AddNote -Text "Could not retrieve firewall settings." -Kind warn
    }

    # --- Defender ---
    Html-Add "<h3>Windows Defender</h3>"
    $def = Safe-Invoke { Get-MpComputerStatus } "Defender Status"
    if ($def -ne "Error" -and $def) {
        Html-AddKV -Pairs ([ordered]@{
            "Real-time protection"         = $def.RealTimeProtectionEnabled
            "Antivirus signature version"  = $def.AntivirusSignatureVersion
            "Last quick scan"              = $def.LastQuickScanEndTime
            "Last full scan"               = $def.LastFullScanEndTime
        })
    }
    else {
        Html-AddNote -Text "Could not retrieve Defender status." -Kind warn
    }

    # --- Local Administrators ---
    Html-Add "<h3>Local Administrators</h3>"
    $admins = Safe-Invoke { Get-LocalGroupMember -Group 'Administrators' } "Local Admin Group"
    if ($admins -ne "Error" -and $admins) {
        $admRows = @($admins) | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name
                Type = $_.ObjectClass
            }
        }
        Html-AddTable -Items $admRows -Columns @(
            @{ Header="Name"; Property="Name" },
            @{ Header="Type"; Property="Type" }
        )
    }
    else {
        Html-AddNote -Text "Could not retrieve local administrator list." -Kind warn
    }
}
else {
    Html-AddNote -Text "Skipped (requires elevation)." -Kind warn
    Log "Skipped Security Baseline (not elevated)"
}

Html-EndSection

# ============================================================
# [9] AZURE AD JOIN STATUS
# ============================================================
Write-Host "[9/10] Checking Azure AD join status..." -ForegroundColor Yellow
Html-StartSection "Azure AD Join Status"

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
    Html-AddKV -Pairs ([ordered]@{
        "Azure AD Joined" = $aadInfo.Joined
        "Tenant ID" = $aadInfo.TenantId
        "Tenant Name" = $aadInfo.TenantName
    })
}
else {
    Html-AddNote -Text "Could not retrieve Azure AD join status." -Kind warn
}

Html-EndSection

# ============================================================
# [10] OPTIONAL NMAP SCAN (XML ONLY)
# ============================================================
Write-Host "[10/10] Nmap scan stage..." -ForegroundColor Yellow

# --- helpers (scoped to this section) ---
function Log-Tail {
    param(
        [string]$Path,
        [int]$Last = 120,
        [string]$Prefix = "winget"
    )
    try {
        if (Test-Path $Path) {
            Get-Content -Path $Path -Tail $Last -ErrorAction Stop |
                ForEach-Object { Log ("${Prefix}: " + $_) }
        } else {
            Log ("${Prefix}: (log file not found: $Path)")
        }
    } catch {
        Log ("${Prefix}: Failed to read log tail: " + $_.Exception.Message)
    }
}

function Test-VC2013Runtime {
    # MSVCR120.dll is Visual C++ 2013 runtime (VC120)
    return (Test-Path "$env:WINDIR\System32\msvcr120.dll") -or (Test-Path "$env:WINDIR\SysWOW64\msvcr120.dll")
}

function Invoke-WingetInstallAsUser {
    param(
        [Parameter(Mandatory=$true)][string]$WingetId,
        [string]$WingetLogPath = "C:\Temp\winget-install.log"
    )

    try {
        if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }

        $interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
        if (-not $interactiveUser) {
            Log "No interactive user session detected. Can't run winget in user context."
            return $false
        }

        $dir = Split-Path -Parent $WingetLogPath
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

        Log "Starting winget install as interactive user: $interactiveUser"
        Log "Package: $WingetId"
        Log "winget output: $WingetLogPath"
        Log "Note: UAC prompt may appear once the installer launches."

        $taskName = "Audit-WinGet-" + ([guid]::NewGuid().ToString("N"))
        $tempPs1  = "C:\Temp\$taskName.ps1"

        # Write a tiny PS script to avoid schtasks /TR quoting issues
        $script = @"
`$ErrorActionPreference = 'Continue'
try {
  `$args = @(
    'install','-e','--id','$WingetId',
    '--source','winget',
    '--accept-package-agreements','--accept-source-agreements',
    '--silent','--disable-interactivity'
  )
  & winget @args 2>&1 | Out-File -FilePath '$WingetLogPath' -Encoding utf8
  exit `$LASTEXITCODE
} catch {
  (`$_.Exception.Message) | Out-File -FilePath '$WingetLogPath' -Append -Encoding utf8
  exit 1
}
"@
        Set-Content -Path $tempPs1 -Value $script -Encoding UTF8

        # Avoid /SD (locale issues). schtasks wants an /ST even though we'll /Run immediately.
        $startTime = (Get-Date).AddMinutes(1).ToString("HH:mm")
        $tr = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$tempPs1`""

        $createOut = & schtasks.exe /Create `
            /TN $taskName /TR $tr `
            /SC ONCE /ST $startTime `
            /RU $interactiveUser /RL LIMITED /F 2>&1
        Log ("schtasks-create: " + ($createOut -join " "))

        $runOut = & schtasks.exe /Run /TN $taskName 2>&1
        Log ("schtasks-run: " + ($runOut -join " "))

        # Clean up task definition + temp script shortly after start (running instance continues)
        Start-Sleep -Seconds 2
        $delOut = & schtasks.exe /Delete /TN $taskName /F 2>&1
        Log ("schtasks-delete: " + ($delOut -join " "))

        Remove-Item -Path $tempPs1 -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        Log ("Invoke-WingetInstallAsUser failed: " + $_.Exception.Message)
        return $false
    }
}

function Wait-ForCondition {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$Condition,
        [int]$TimeoutSeconds = 900,
        [int]$PollSeconds = 3
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if (& $Condition) { $sw.Stop(); return $true }
        Start-Sleep -Seconds $PollSeconds
    }
    $sw.Stop()
    return $false
}

# --- main ---
if ($RunNmap -and $IsElevated) {

    if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }

    # Nmap install paths (either can happen)
    $nmapExeX86 = "C:\Program Files (x86)\Nmap\nmap.exe"
    $nmapExeX64 = "C:\Program Files\Nmap\nmap.exe"

    # Helpful diagnostics
    Safe-Invoke {
        & winget --info 2>&1 | ForEach-Object { Log ("winget-info: " + $_) }
    } "winget --info"

    # ---- VC++ 2013 Runtime (MSVCR120.dll) ----
    if (-not (Test-VC2013Runtime)) {
        Log "VC++ 2013 runtime (MSVCR120.dll) not detected. Installing prerequisites via winget..."

        $vcX86Log = "C:\Temp\winget-vcredist2013-x86.log"
        $vcX64Log = "C:\Temp\winget-vcredist2013-x64.log"

        # Install x86 then x64 (many apps still need x86 on x64 Windows)
        $vc1 = Safe-Invoke {
            if (-not (Invoke-WingetInstallAsUser -WingetId "Microsoft.VCRedist.2013.x86" -WingetLogPath $vcX86Log)) {
                throw "Failed to launch VC++ 2013 x86 install."
            }
            "OK"
        } "VC++ 2013 x86 install"

        $vc2 = Safe-Invoke {
            if (-not (Invoke-WingetInstallAsUser -WingetId "Microsoft.VCRedist.2013.x64" -WingetLogPath $vcX64Log)) {
                throw "Failed to launch VC++ 2013 x64 install."
            }
            "OK"
        } "VC++ 2013 x64 install"

        # Wait until the runtime appears
        $vcOk = Wait-ForCondition -TimeoutSeconds 900 -PollSeconds 3 -Condition { Test-VC2013Runtime }
        if (-not $vcOk) {
            Log "Timed out waiting for VC++ 2013 runtime to appear."
            Log "Last VC++ x86 winget output:"
            Log-Tail -Path $vcX86Log -Last 160 -Prefix "winget-vc2013-x86"
            Log "Last VC++ x64 winget output:"
            Log-Tail -Path $vcX64Log -Last 160 -Prefix "winget-vc2013-x64"
            Log "Prereq install timed out. Nmap scan skipped."
        } else {
            Log "VC++ 2013 runtime detected."
        }
    } else {
        Log "VC++ 2013 runtime detected."
    }

    # ---- Nmap install ----
    if (-not (Test-Path $nmapExeX86) -and -not (Test-Path $nmapExeX64)) {
        Log "Nmap not found. Installing via winget (user context; UAC may appear)."

        $nmapLog = "C:\Temp\winget-nmap-install.log"

        $install = Safe-Invoke {
            if (-not (Invoke-WingetInstallAsUser -WingetId "Insecure.Nmap" -WingetLogPath $nmapLog)) {
                throw "Could not start winget in user context."
            }

            $ok = Wait-ForCondition -TimeoutSeconds 1200 -PollSeconds 3 -Condition {
                (Test-Path $nmapExeX86) -or (Test-Path $nmapExeX64)
            }

            if (-not $ok) {
                Log "Timed out waiting for Nmap to appear."
                Log "Last Nmap winget output:"
                Log-Tail -Path $nmapLog -Last 200 -Prefix "winget-nmap"
                throw "Nmap did not install within timeout."
            }

            "OK"
        } "Nmap Installation"

        if ($install -eq "Error") {
            Log "Nmap installation failed. Scan skipped."
        }
    }

    # Resolve final nmap path
    $nmapExe = if (Test-Path $nmapExeX64) { $nmapExeX64 } elseif (Test-Path $nmapExeX86) { $nmapExeX86 } else { $null }

    if ($nmapExe) {

        # If runtime still missing, don't even try to run nmap (prevents the MSVCR120 popup)
        if (-not (Test-VC2013Runtime)) {
            Log "VC++ 2013 runtime still not detected; skipping Nmap execution to avoid MSVCR120.dll error."
        }
        else {
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

# Add Nmap summary section to report (XML only)
Html-StartSection "Nmap Scan"
if ($RunNmap -and $IsElevated) {
    if (Test-Path $NmapXmlPath) {
        Html-AddNote -Text ("Nmap scan completed. XML saved to: {0}" -f $NmapXmlPath) -Kind good
    } else {
        Html-AddNote -Text ("Nmap was requested, but no XML output was found at: {0} (check {1})" -f $NmapXmlPath, $LogPath) -Kind warn
    }
}
elseif ($RunNmap -and -not $IsElevated) {
    Html-AddNote -Text "Nmap requested but skipped (not elevated)." -Kind warn
}
else {
    Html-AddNote -Text "Nmap not requested." -Kind info
}
Html-EndSection

# ============================================================
# Save HTML Report
# ============================================================
Write-Host "[Final] Saving HTML report: $HtmlReportPath" -ForegroundColor Cyan
try {
$generated = Get-Date
$elevText = if ($IsElevated) { "Yes" } else { "No" }
$nmapText = if ($RunNmap) { "Enabled" } else { "Disabled" }

$htmlContent = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System Audit Report - $ComputerName</title>
<style>
:root{
  --bg:#f6f8fb; --card:#ffffff; --text:#1f2937; --muted:#6b7280;
  --accent:#2E5C6E; --border:#d1d5db;
}
*{ box-sizing:border-box; }
body{ font-family: Segoe UI, Arial, sans-serif; background:var(--bg); color:var(--text); margin:0; padding:24px; }
.container{ max-width: 1100px; margin:0 auto; }
.header{
  background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:18px 20px; box-shadow:0 1px 2px rgba(0,0,0,.04);
}
h1{ margin:0 0 6px; color:var(--accent); font-size: 28px; }
.meta{ color:var(--muted); font-size: 13px; line-height:1.4; }
.section{
  margin-top:16px; background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:16px 18px; box-shadow:0 1px 2px rgba(0,0,0,.04);
}
.section h2{ margin:0 0 10px; color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:8px; font-size: 20px; }
.section h3{ margin:16px 0 8px; color:#334155; font-size: 16px; }
.kv{ display:grid; grid-template-columns: 240px 1fr; gap:6px 12px; font-size: 14px; }
.kv div.key{ color:var(--muted); }
.small{ font-size:12px; color:var(--muted); }
.code{ font-family: Consolas, 'Courier New', monospace; }
details{ margin-top:10px; }
summary{ cursor:pointer; user-select:none; font-weight:600; color:#334155; padding:6px 0; }
table{ width:100%; border-collapse: collapse; margin-top:10px; font-size: 13px; }
th,td{ border:1px solid var(--border); padding:8px 10px; vertical-align: top; }
th{ background:#eef3f7; text-align:left; position:sticky; top:0; z-index:1; }
tr:nth-child(even) td{ background:#fafbfd; }
.badge{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; border:1px solid var(--border); background:#f9fafb; }
.badge.good{ background:#ecfdf5; border-color:#a7f3d0; }
.badge.warn{ background:#fffbeb; border-color:#fde68a; }
.badge.bad{ background:#fef2f2; border-color:#fecaca; }
.footer{ margin-top:16px; color:var(--muted); font-size:12px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>System Audit Report - $ComputerName</h1>
    <div class="meta">Generated: $generated • Elevated: $elevText • Nmap: $nmapText</div>
    <div class="meta">Report: <span class="code">$HtmlReportPath</span> • Log: <span class="code">$LogPath</span></div>
  </div>

$($Html.ToString())

  <div class="footer">
    <div>Note: Large tables may take a moment to render in the browser.</div>
  </div>
</div>
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
