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
    Write-host ""
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

$apps = Safe-Invoke {
    Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
        HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, DisplayVersion |
        Where-Object { $_.DisplayName } |
        Sort-Object DisplayName
} "Installed Software"

if ($apps -ne "Error") {
    foreach ($app in $apps) {
        $name = $app.DisplayName
        $ver  = if ($app.DisplayVersion) { $app.DisplayVersion } else { "N/A" }
        $Report += "- $name"
        $Report += "  - Version: $ver"
    }
}
else {
    $Report += "- Could not retrieve installed software list."
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

    if ($patches -ne "Error") {
        foreach ($p in $patches) {
            $installedDate = if ($p.InstalledOn) { $p.InstalledOn.ToShortDateString() } else { "Unknown" }
            $Report += "- Hotfix: $($p.HotFixID)"
            $Report += "  - Installed On: $installedDate"
            $Report += "  - Description: $($p.Description)"
        }
    }
    else {
        $Report += "- Could not retrieve installed patches / hotfixes."
    }
}
else {
    $Report += "- Skipped (requires elevation)."
    Log "Skipped Get-HotFix (not elevated)"
    Write-Host "Skipped (requires elevation)." -ForegroundColor DarkGray
}

$Report += ""

# ============================================================
# [4] PENDING WINDOWS UPDATES
# ============================================================
Write-Host "[4/10] Checking for pending Windows updates..." -ForegroundColor Yellow
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
        foreach ($upd in $pendingUpdates) {
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
    foreach ($s in $shares) {
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

$printers = Safe-Invoke {
    Get-Printer
} "Printers"

if ($printers -ne "Error") {
    foreach ($p in $printers) {
        $Report += "- Printer: $($p.Name)"
        $Report += "  - Driver: $($p.DriverName)"
    }
}
else {
    $Report += "- Could not retrieve printers."
    Write-Host "Could not retrieve printers." -ForegroundColor DarkGray
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
        }
    }
    else {
        $Report += "- Could not retrieve BitLocker information."
        Write-Host "Could not retrieve BitLocker information." -ForegroundColor DarkGray
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
    }
    else {
        $Report += "- Could not retrieve TPM status."
        Write-Host "Could not retrieve TPM status." -ForegroundColor DarkGray
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
    }
    else {
        $Report += "- Secure Boot: Not Supported or Unknown"
        Write-Host "Secure Boot: Not supported or unknown." -ForegroundColor DarkGray
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
        }
    }
    else {
        $Report += "- Could not retrieve firewall settings."
        Write-Host "Could not retrieve firewall settings." -ForegroundColor DarkGray
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
    }
    else {
        $Report += "- Could not retrieve Defender status."
        Write-Host "Could not retrieve Defender status." -ForegroundColor DarkGray
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
    }
    else {
        $Report += "- Could not retrieve local administrator list."
        Write-Host "Could not retrieve local administrator list." -ForegroundColor DarkGray
    }
}
else {
    $Report += "- Skipped (requires elevation)."
    Log "Skipped Get-WindowsUpdate (not elevated)"
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
$Report += "## Nmap Scan"
$Report += ""

if ($RunNmap -and $IsElevated) {

    $nmapExe = "C:\Program Files (x86)\Nmap\nmap.exe"

    if (-not (Test-Path $nmapExe)) {
        Write-Host "Nmap not found. Installing via winget..." -ForegroundColor Yellow
        Log "Nmap not found. Installing via winget."
        $install = Safe-Invoke {
            winget install --id Insecure.Nmap --source winget --accept-package-agreements --accept-source-agreements --silent
        } "Nmap Installation"

        if ($install -eq "Error") {
            $Report += "- Nmap installation failed. Scan skipped."
            Log "Nmap install failed."
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
            Write-Host "Running Nmap port and OS detection on $cidr ..." -ForegroundColor Yellow
            Log "Running Nmap scan on $cidr"

            $Report += "- Nmap scan started."
            $Report += "  - Target network: $cidr"
            $Report += "  - XML output: $NmapXmlPath"

            # Nmap XML output only (no text into main report)
            $scanResult = Safe-Invoke {
                & $nmapExe -sS -O -sV -T4 -oX $NmapXmlPath $cidr
            } "Nmap Scan"

            if ($scanResult -eq "Error") {
                $Report += "- Nmap scan failed. See logs for details."
            }
        }
        else {
            $Report += "- Could not determine local IPv4 network. Nmap scan skipped."
            Log "No suitable IPv4 adapter found for Nmap."
        }
    }
    else {
        $Report += "- Nmap not available after install attempt. Scan skipped."
        Log "Nmap not found after attempted install."
    }
}
elseif ($RunNmap -and -not $IsElevated) {
    $Report += "- Nmap was requested but skipped because elevation is required."
}
else {
    $Report += "- Nmap scan not requested."
}

$Report += ""

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
