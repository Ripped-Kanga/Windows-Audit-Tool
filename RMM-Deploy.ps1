<#
    RMM-Deploy.ps1
    Generic deploy wrapper for RMM/MDM platforms.

    PURPOSE
      Upload this script to your RMM platform (Atera, NinjaRMM, Datto, etc.).
      It manages a locally-cached copy of Run-Audit.ps1 on the endpoint, keeps it
      current from GitHub Releases, then invokes it. Only Run-Audit.ps1 is versioned
      and updated -- this wrapper is stable.

      Designed to run as a daily RMM scheduled automation. A monthly guard check prevents
      the audit from running more than once per calendar month. The check scans the audit
      log for an "Audit completed for" entry timestamped in the current calendar month.
      Exits with code 3 and reports the skip reason. Use -ForceRun to override.

    SUPPORTED PLATFORMS
      -RmmPlatform Atera      (default) Atera RMM -- stdout flows to job log
      Additional platforms can be added by extending the platform configuration
      section below. Each platform defines its own log path, output format, and
      any custom field reporting.

    PARAMETERS
      -RmmPlatform            RMM platform name (default: Atera). Controls logging
                              format and platform-specific output.
      -ForceRun               Skip the monthly guard check and run the audit regardless.
      -CustomerName           Customer/business name to include in report.
      -HuduReport             Enable Hudu integration.
      -HuduAPIKey             Hudu API key.
      -HuduBaseURL            Hudu instance base URL.
      -HuduCompanySlug        Hudu company slug (hex string from URL).
      -HuduAssetLayoutName    Hudu asset layout name.
      -HuduEntryName          Override the Hudu asset name. Accepts tokens:
                                $ComputerName, $Date, $CustomerName
      -HtmlAttachmentName         Override the Hudu HTML attachment filename. Accepts
                              the same tokens. Default: "$Date - $ComputerName".

    EXIT CODES
      0  Audit completed (pass-through from Run-Audit.ps1)
      1  GitHub unreachable AND no cached Run-Audit.ps1 found
      2  Download failed AND no cached Run-Audit.ps1 found
      3  Audit already completed this month (use -ForceRun to override)
      Non-zero values from Run-Audit.ps1 are passed through as-is.
#>

#Requires -Version 5.1

param(
    [ValidateSet('Atera', 'NinjaRMM', 'Datto', 'Generic')]
    [string]$RmmPlatform = 'Atera',

    [string]$CustomerName,
    [switch]$HuduReport,
    [string]$HuduAPIKey,
    [string]$HuduBaseURL,
    [string]$HuduCompanySlug,
    [string]$HuduAssetLayoutName,
    [string]$HuduEntryName,
    [string]$HtmlAttachmentName,
    [switch]$ForceRun
)

# ============================================================
# Platform Configuration
#   Each platform defines logging behaviour and output format.
#   To add a new RMM: add a block below and the name to ValidateSet above.
# ============================================================
$DeployScriptVersion = "1.0.0"

$PlatformConfig = switch ($RmmPlatform) {
    'Atera' {
        @{
            Name         = 'Atera'
            DeployLog    = 'C:\Windows\Temp\AuditDeploy.txt'
            CachedDir    = 'C:\Program Files\Windows Audit Tool\Scripts'
            AuditLogPath = 'C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt'
            UserAgent    = 'RMM-Atera-Deploy'
            # Atera captures stdout from the script into its job log.
            # Write-Host output is the primary feedback channel.
        }
    }
    'NinjaRMM' {
        @{
            Name         = 'NinjaRMM'
            DeployLog    = 'C:\Windows\Temp\AuditDeploy.txt'
            CachedDir    = 'C:\Program Files\Windows Audit Tool\Scripts'
            AuditLogPath = 'C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt'
            UserAgent    = 'RMM-NinjaRMM-Deploy'
        }
    }
    'Datto' {
        @{
            Name         = 'Datto'
            DeployLog    = 'C:\Windows\Temp\AuditDeploy.txt'
            CachedDir    = 'C:\Program Files\Windows Audit Tool\Scripts'
            AuditLogPath = 'C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt'
            UserAgent    = 'RMM-Datto-Deploy'
        }
    }
    default {
        @{
            Name         = 'Generic'
            DeployLog    = 'C:\Windows\Temp\AuditDeploy.txt'
            CachedDir    = 'C:\Program Files\Windows Audit Tool\Scripts'
            AuditLogPath = 'C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt'
            UserAgent    = 'RMM-Generic-Deploy'
        }
    }
}

# ============================================================
# Resolve paths from platform config
# ============================================================
$LogPath      = $PlatformConfig.DeployLog
$CachedDir    = $PlatformConfig.CachedDir
$CachedPath   = Join-Path $CachedDir "Run-Audit.ps1"
$AuditLogPath = $PlatformConfig.AuditLogPath
$ApiUrl       = "https://api.github.com/repos/Ripped-Kanga/Windows-Audit-Tool/releases/latest"

# Ensure the Scripts directory exists
if (-not (Test-Path -LiteralPath $CachedDir -ErrorAction SilentlyContinue)) {
    New-Item -ItemType Directory -Path $CachedDir -Force -ErrorAction SilentlyContinue | Out-Null
}

# TLS 1.2 required by GitHub API (PS 5.1 may default to TLS 1.0)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================
# Logging — platform-aware
# ============================================================
function Write-DeployLog {
    param([string]$Message, [string]$Level = 'INFO')
    try {
        $timestamp = Get-Date -Format 'u'
        $line = "[$timestamp] [$($PlatformConfig.Name)] $Message"
        Add-Content -Path $LogPath -Value $line
    } catch {}
}

function Write-DeployOutput {
    <# Platform-aware console output. All platforms use Write-Host for now,
       but this function is the extension point for platform-specific output
       (e.g. NinjaRMM custom fields, Datto stderr channels). #>
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host ("[Deploy:{0}] {1}" -f $PlatformConfig.Name, $Message) -ForegroundColor $Color
}

Write-DeployLog ("Deploy script v{0} started | Platform: {1} | PS {2} | User: {3}" -f $DeployScriptVersion, $RmmPlatform, $PSVersionTable.PSVersion, $env:USERNAME)
Write-DeployLog ("Cache path: {0}" -f $CachedPath)

# ============================================================
# Monthly guard check
# ============================================================
if (-not $ForceRun) {
    $thisYearMon = (Get-Date).ToString("yyyy-MM")
    $priorRun    = $null

    if (Test-Path -LiteralPath $AuditLogPath -ErrorAction SilentlyContinue) {
        $priorRun = Get-Content -LiteralPath $AuditLogPath -ErrorAction SilentlyContinue |
            Where-Object { $_ -match ('^' + $thisYearMon) -and $_ -match 'Audit completed for ' } |
            Select-Object -Last 1
    }

    if ($priorRun) {
        Write-DeployLog ("Monthly guard: audit already completed this month -- {0}" -f $priorRun)
        Write-DeployOutput "Audit already completed this month." -Color Green
        Write-DeployOutput ("Log entry: {0}" -f $priorRun.TrimStart('[')) -Color Gray
        Write-DeployOutput "Use -ForceRun to override the monthly guard and run again." -Color Gray
        exit 3
    }

    Write-DeployLog ("Monthly guard: no completed audit found for {0} -- proceeding" -f $thisYearMon)
} else {
    Write-DeployLog "Monthly guard: -ForceRun specified -- skipping guard check"
    Write-DeployOutput "-ForceRun specified -- skipping monthly guard check." -Color Cyan
}

# ============================================================
# GitHub API — latest version
# ============================================================
$ApiVersion   = $null
$DownloadUrl  = $null
$ApiReachable = $false

try {
    $response = Invoke-RestMethod `
        -Uri        $ApiUrl `
        -Method     Get `
        -TimeoutSec 10 `
        -ErrorAction Stop `
        -Headers    @{ 'User-Agent' = $PlatformConfig.UserAgent; Accept = 'application/vnd.github.v3+json' }

    $rawTag     = [string]$response.tag_name
    $ApiVersion = $rawTag.TrimStart('v')
    $ApiReachable = $true

    foreach ($asset in @($response.assets)) {
        if ([string]$asset.name -like '*.ps1') {
            $DownloadUrl = [string]$asset.browser_download_url
            break
        }
    }

    Write-DeployLog ("GitHub API: latest release is {0}" -f $rawTag)
    if (-not $DownloadUrl) {
        Write-DeployLog "GitHub API: no .ps1 asset found in release -- will use cache if available"
    }
} catch {
    Write-DeployLog ("GitHub API unreachable: {0}" -f $_.Exception.Message)
    Write-DeployOutput ("WARNING: Could not reach GitHub API -- {0}" -f $_.Exception.Message) -Color Yellow
}

# ============================================================
# Read cached version
# ============================================================
$CachedVersion = $null
if (Test-Path -LiteralPath $CachedPath) {
    try {
        $head = Get-Content -LiteralPath $CachedPath -TotalCount 60 -ErrorAction Stop
        $match = ($head -join "`n") | Select-String -Pattern '\$ScriptVersion\s*=\s*["'']([ 0-9]+(?:\.[0-9]+)+)["'']'
        if ($match) {
            $CachedVersion = $match.Matches[0].Groups[1].Value
            Write-DeployLog ("Cached script version: {0}" -f $CachedVersion)
        } else {
            Write-DeployLog "Cached script found but version could not be extracted -- treating as corrupt"
        }
    } catch {
        Write-DeployLog ("Could not read cached script: {0}" -f $_.Exception.Message)
    }
} else {
    Write-DeployLog "No cached script found"
}

# ============================================================
# Version comparison
# ============================================================
$NeedDownload = $false
if (-not (Test-Path -LiteralPath $CachedPath)) {
    $NeedDownload = $true
    Write-DeployLog "Download required: no cached script"
} elseif (-not $CachedVersion) {
    $NeedDownload = $true
    Write-DeployLog "Download required: cached version unreadable"
} elseif ($ApiReachable -and $ApiVersion -and $DownloadUrl) {
    try {
        $NeedDownload = ([System.Version]$ApiVersion -gt [System.Version]$CachedVersion)
        if ($NeedDownload) {
            Write-DeployLog ("Download required: cached {0} < latest {1}" -f $CachedVersion, $ApiVersion)
        } else {
            Write-DeployLog ("Cache is current: v{0}" -f $CachedVersion)
        }
    } catch {
        $NeedDownload = $true
        Write-DeployLog ("Version comparison failed ({0}) -- forcing download" -f $_.Exception.Message)
    }
}

# ============================================================
# Download if needed
# ============================================================
if ($NeedDownload) {
    if (-not $DownloadUrl) {
        if (-not (Test-Path -LiteralPath $CachedPath)) {
            Write-DeployLog "FATAL: No download URL available and no cached script -- cannot proceed"
            Write-DeployOutput "ERROR: No cached script and GitHub asset URL unavailable." -Color Red
            exit 1
        }
        Write-DeployLog "No download URL available -- continuing with existing cache"
        Write-DeployOutput "WARNING: Could not obtain download URL -- using cached version." -Color Yellow
        $NeedDownload = $false
    } else {
        try {
            Write-DeployLog ("Downloading from: {0}" -f $DownloadUrl)
            Write-DeployOutput ("Downloading Run-Audit.ps1 v{0}..." -f $ApiVersion) -Color Cyan
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $CachedPath -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop

            if (-not (Test-Path -LiteralPath $CachedPath) -or (Get-Item -LiteralPath $CachedPath).Length -eq 0) {
                throw "Downloaded file is missing or empty"
            }

            $head = Get-Content -LiteralPath $CachedPath -TotalCount 60 -ErrorAction SilentlyContinue
            $match = ($head -join "`n") | Select-String -Pattern '\$ScriptVersion\s*=\s*["'']([ 0-9]+(?:\.[0-9]+)+)["'']'
            if ($match) { $CachedVersion = $match.Matches[0].Groups[1].Value }

            Write-DeployLog ("Download complete: Run-Audit.ps1 v{0}" -f $CachedVersion)
            Write-DeployOutput ("Download complete: Run-Audit.ps1 v{0}" -f $CachedVersion) -Color Green
        } catch {
            Write-DeployLog ("Download failed: {0}" -f $_.Exception.Message)
            Write-DeployOutput ("WARNING: Download failed -- {0}" -f $_.Exception.Message) -Color Yellow
            if (-not (Test-Path -LiteralPath $CachedPath)) {
                Write-DeployLog "FATAL: Download failed and no cached script -- cannot proceed"
                Write-DeployOutput "ERROR: No cached script available. Cannot run audit." -Color Red
                exit 2
            }
            Write-DeployOutput "Falling back to existing cached version." -Color Yellow
        }
    }
}

# ============================================================
# HuduEntryName / HtmlAttachmentName token expansion
# ============================================================
$tokenDate         = Get-Date -Format 'yyyy-MM-dd'
$tokenCustomerName = if ($CustomerName) { $CustomerName } else { '' }

$ResolvedHuduEntryName  = $null
if ($HuduEntryName) {
    $ResolvedHuduEntryName = $HuduEntryName `
        -replace '\$ComputerName', $env:COMPUTERNAME `
        -replace '\$Date',         $tokenDate `
        -replace '\$CustomerName', $tokenCustomerName
    Write-DeployLog ("HuduEntryName resolved: '{0}' -> '{1}'" -f $HuduEntryName, $ResolvedHuduEntryName)
}

$ResolvedHtmlAttachmentName = $null
if ($HtmlAttachmentName) {
    $ResolvedHtmlAttachmentName = $HtmlAttachmentName `
        -replace '\$ComputerName', $env:COMPUTERNAME `
        -replace '\$Date',         $tokenDate `
        -replace '\$CustomerName', $tokenCustomerName
    Write-DeployLog ("HtmlAttachmentName resolved: '{0}' -> '{1}'" -f $HtmlAttachmentName, $ResolvedHtmlAttachmentName)
}

# ============================================================
# Build argument list
# ============================================================
$argList = @('-ExecutionPolicy', 'Bypass', '-File', $CachedPath, '-Silent')
if ($PSBoundParameters.ContainsKey('CustomerName'))        { $argList += @('-CustomerName', $CustomerName) }
if ($PSBoundParameters.ContainsKey('HuduReport') -and $HuduReport) { $argList += '-HuduReport' }
if ($PSBoundParameters.ContainsKey('HuduAPIKey'))          { $argList += @('-HuduAPIKey', $HuduAPIKey) }
if ($PSBoundParameters.ContainsKey('HuduBaseURL'))         { $argList += @('-HuduBaseURL', $HuduBaseURL) }
if ($PSBoundParameters.ContainsKey('HuduCompanySlug'))     { $argList += @('-HuduCompanySlug', $HuduCompanySlug) }
if ($PSBoundParameters.ContainsKey('HuduAssetLayoutName')) { $argList += @('-HuduAssetLayoutName', $HuduAssetLayoutName) }
if ($ResolvedHuduEntryName)                                { $argList += @('-HuduEntryName', $ResolvedHuduEntryName) }
if ($ResolvedHtmlAttachmentName)                               { $argList += @('-HtmlAttachmentName', $ResolvedHtmlAttachmentName) }

# Log argument list with API key masked
$logArgs = $argList | ForEach-Object {
    if ($_ -eq $HuduAPIKey -and $HuduAPIKey) { '***' } else { $_ }
}
Write-DeployLog ("Invoking: powershell.exe {0}" -f ($logArgs -join ' '))

# ============================================================
# Execute
# ============================================================
Write-DeployOutput ("Run-Audit.ps1 v{0} ready. Starting audit..." -f $CachedVersion) -Color Cyan

try {
    & powershell.exe @argList
    $childExit = $LASTEXITCODE
} catch {
    Write-DeployLog ("Failed to launch Run-Audit.ps1: {0}" -f $_.Exception.Message)
    Write-DeployOutput ("ERROR: Could not launch Run-Audit.ps1 -- {0}" -f $_.Exception.Message) -Color Red
    exit 1
}

Write-DeployLog ("Run-Audit.ps1 completed with exit code {0}" -f $childExit)
Write-DeployOutput ("Audit completed with exit code {0}" -f $childExit) -Color $(if ($childExit -eq 0) { 'Green' } else { 'Yellow' })

# ============================================================
# Platform-specific post-run actions
#   Extend here for custom field updates, ticket creation, etc.
# ============================================================
switch ($RmmPlatform) {
    'Atera' {
        # Atera captures all stdout automatically -- no additional action needed.
    }
    'NinjaRMM' {
        # Future: Use Ninja-Property-Set to write custom fields
        # Example: Ninja-Property-Set auditHealthScore $score
    }
    'Datto' {
        # Future: Write to Datto stdout/stderr channels or UDFs
    }
}

exit $childExit
