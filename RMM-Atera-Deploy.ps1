<#
    RMM-Atera-Deploy.ps1
    Static deploy wrapper for Atera automation.

    PURPOSE
      Upload this script once to Atera (Devices > Scripts). It manages a locally-cached
      copy of Run-Audit.ps1 on the endpoint, keeps it current from GitHub Releases, then
      invokes it. You never need to update this script in Atera -- only Run-Audit.ps1 is
      versioned and updated.

      Designed to run as a daily Atera scheduled automation. A monthly guard check prevents
      the audit from running more than once per calendar month. The check scans the audit
      log for an "Audit completed for" entry timestamped in the current calendar month --
      this works regardless of whether Hudu integration is used (Hudu deployments delete
      the local HTML report on completion, but the log entry is always written).
      Exits with code 3 and reports the skip reason. Use -ForceRun to override.

    ATERA SETUP NOTES
      - Set execution policy to Bypass in the Atera script configuration
      - Recommended script timeout: 600 seconds (10 minutes) -- covers GitHub fetch + full audit
      - Recommended run schedule: daily (the monthly guard prevents redundant runs)
      - Runs as SYSTEM
        Cached script:  C:\Program Files\Windows Audit Tool\Scripts\Run-Audit.ps1
        Deploy log:     C:\Windows\Temp\AuditDeploy.txt
        Audit log:      C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt
        Audit report:   C:\Program Files\Windows Audit Tool\Results\<ComputerName>-Audit.html

    PARAMETERS
      Pass only what you need. -Silent is always injected automatically.
      -ForceRun              Skip the monthly guard check and run the audit regardless.
      -HuduEntryName         Override the Hudu asset name. Accepts plain text or tokens:
                               $ComputerName  - endpoint hostname (e.g. DESKTOP-ABC123)
                               $Date          - run date in yyyy-MM-dd format
                               $CustomerName  - value of -CustomerName if provided
                             Examples:
                               -HuduEntryName "$ComputerName"
                               -HuduEntryName "$Date - $ComputerName - Audit"
                             In Atera's parameter field enter the value literally (no quotes
                             needed) -- tokens are expanded on the endpoint at runtime.
                             If omitted, Run-Audit.ps1 uses its default: "HOSTNAME - dd/MM/yyyy".
      Example (Hudu deployment):
        -HuduReport -HuduAPIKey "key" -HuduBaseURL "https://..." -HuduCompanySlug "abc123" -HuduAssetLayoutName "Audit Reports" -HuduEntryName "$ComputerName"

    EXIT CODES
      0  Audit completed (pass-through from Run-Audit.ps1)
      1  GitHub unreachable AND no cached Run-Audit.ps1 found -- cannot proceed
      2  Download failed AND no cached Run-Audit.ps1 found -- cannot proceed
      3  Audit already completed this month -- no action taken (use -ForceRun to override)
      Non-zero values from Run-Audit.ps1 are passed through as-is.

    LIMITATION
      No file locking -- running two Atera jobs simultaneously against the same endpoint
      is unsupported and may cause a corrupted cache file.
#>

#Requires -Version 5.1

param(
    [string]$CustomerName,
    [switch]$HuduReport,
    [string]$HuduAPIKey,
    [string]$HuduBaseURL,
    [string]$HuduCompanySlug,
    [string]$HuduAssetLayoutName,
    [string]$HuduEntryName,
    [switch]$ForceRun
)

# ------------------------- #
# Constants                 #
# ------------------------- #
$DeployScriptVersion = "1.2.0"
$LogPath      = "C:\Windows\Temp\AuditDeploy.txt"
$CachedDir    = "C:\Program Files\Windows Audit Tool\Scripts"
$CachedPath   = Join-Path $CachedDir "Run-Audit.ps1"
$AuditLogPath = "C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt"
$ApiUrl       = "https://api.github.com/repos/Ripped-Kanga/Windows-Audit-Tool/releases/latest"

# Ensure the Scripts directory exists before any read/write against $CachedPath
if (-not (Test-Path -LiteralPath $CachedDir -ErrorAction SilentlyContinue)) {
    New-Item -ItemType Directory -Path $CachedDir -Force -ErrorAction SilentlyContinue | Out-Null
}

# TLS 1.2 required by GitHub API (PS 5.1 may default to TLS 1.0)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------- #
# Logging                   #
# ------------------------- #
$Log = {
    param($Msg)
    try {
        Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'u')] $Msg"
    } catch {}
}

& $Log ("Deploy script v{0} started | PS {1} | User: {2}" -f $DeployScriptVersion, $PSVersionTable.PSVersion, $env:USERNAME)
& $Log ("Cache path: {0}" -f $CachedPath)

# ------------------------- #
# Monthly guard check       #
# ------------------------- #
if (-not $ForceRun) {
    $thisYearMon = (Get-Date).ToString("yyyy-MM")
    $priorRun    = $null

    if (Test-Path -LiteralPath $AuditLogPath -ErrorAction SilentlyContinue) {
        # Match log lines like: [2026-03-15 09:12:34Z] Audit completed for HOSTNAME
        $priorRun = Get-Content -LiteralPath $AuditLogPath -ErrorAction SilentlyContinue |
            Where-Object { $_ -match ('^\[' + $thisYearMon) -and $_ -match 'Audit completed for ' } |
            Select-Object -Last 1
    }

    if ($priorRun) {
        & $Log ("Monthly guard: audit already completed this month -- {0}" -f $priorRun)
        Write-Host "[Deploy] Audit already completed this month." -ForegroundColor Green
        Write-Host ("[Deploy] Log entry: {0}" -f $priorRun.TrimStart('[')) -ForegroundColor Gray
        Write-Host "[Deploy] Use -ForceRun to override the monthly guard and run again." -ForegroundColor Gray
        exit 3
    }

    & $Log ("Monthly guard: no completed audit found for {0} -- proceeding" -f $thisYearMon)
} else {
    & $Log "Monthly guard: -ForceRun specified -- skipping guard check"
    Write-Host "[Deploy] -ForceRun specified -- skipping monthly guard check." -ForegroundColor Cyan
}

# ------------------------- #
# GitHub API -- latest ver  #
# ------------------------- #
$ApiVersion   = $null
$DownloadUrl  = $null
$ApiReachable = $false

try {
    $response = Invoke-RestMethod `
        -Uri        $ApiUrl `
        -Method     Get `
        -TimeoutSec 10 `
        -ErrorAction Stop `
        -Headers    @{ 'User-Agent' = 'RMM-Atera-Deploy'; Accept = 'application/vnd.github.v3+json' }

    $rawTag     = [string]$response.tag_name
    $ApiVersion = $rawTag.TrimStart('v')
    $ApiReachable = $true

    # Find the .ps1 asset download URL
    foreach ($asset in @($response.assets)) {
        if ([string]$asset.name -like '*.ps1') {
            $DownloadUrl = [string]$asset.browser_download_url
            break
        }
    }

    & $Log ("GitHub API: latest release is {0}" -f $rawTag)
    if (-not $DownloadUrl) {
        & $Log "GitHub API: no .ps1 asset found in release — will use cache if available"
    }
} catch {
    & $Log ("GitHub API unreachable: {0}" -f $_.Exception.Message)
    Write-Host "[Deploy] WARNING: Could not reach GitHub API — $($_.Exception.Message)" -ForegroundColor Yellow
}

# ------------------------- #
# Read cached version       #
# ------------------------- #
$CachedVersion = $null
if (Test-Path -LiteralPath $CachedPath) {
    try {
        $head = Get-Content -LiteralPath $CachedPath -TotalCount 60 -ErrorAction Stop
        $match = ($head -join "`n") | Select-String -Pattern '\$ScriptVersion\s*=\s*["'']([0-9]+(?:\.[0-9]+)+)["'']'
        if ($match) {
            $CachedVersion = $match.Matches[0].Groups[1].Value
            & $Log ("Cached script version: {0}" -f $CachedVersion)
        } else {
            & $Log "Cached script found but version could not be extracted — treating as corrupt"
        }
    } catch {
        & $Log ("Could not read cached script: {0}" -f $_.Exception.Message)
    }
} else {
    & $Log "No cached script found"
}

# ------------------------- #
# Version comparison        #
# ------------------------- #
$NeedDownload = $false
if (-not (Test-Path -LiteralPath $CachedPath)) {
    $NeedDownload = $true
    & $Log "Download required: no cached script"
} elseif (-not $CachedVersion) {
    $NeedDownload = $true
    & $Log "Download required: cached version unreadable"
} elseif ($ApiReachable -and $ApiVersion -and $DownloadUrl) {
    try {
        $NeedDownload = ([System.Version]$ApiVersion -gt [System.Version]$CachedVersion)
        if ($NeedDownload) {
            & $Log ("Download required: cached {0} < latest {1}" -f $CachedVersion, $ApiVersion)
        } else {
            & $Log ("Cache is current: v{0}" -f $CachedVersion)
        }
    } catch {
        # Version string not parseable (e.g. pre-release tag) — force download to be safe
        $NeedDownload = $true
        & $Log ("Version comparison failed ({0}) — forcing download" -f $_.Exception.Message)
    }
}

# ------------------------- #
# Download if needed        #
# ------------------------- #
if ($NeedDownload) {
    if (-not $DownloadUrl) {
        # API was reachable but no asset URL — or API was unreachable and no cache
        if (-not (Test-Path -LiteralPath $CachedPath)) {
            & $Log "FATAL: No download URL available and no cached script — cannot proceed"
            Write-Host "[Deploy] ERROR: No cached script and GitHub asset URL unavailable." -ForegroundColor Red
            exit 1
        }
        & $Log "No download URL available — continuing with existing cache"
        Write-Host "[Deploy] WARNING: Could not obtain download URL — using cached version." -ForegroundColor Yellow
        $NeedDownload = $false
    } else {
        try {
            & $Log ("Downloading from: {0}" -f $DownloadUrl)
            Write-Host ("[Deploy] Downloading Run-Audit.ps1 v{0}..." -f $ApiVersion) -ForegroundColor Cyan
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $CachedPath -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop

            # Verify download
            if (-not (Test-Path -LiteralPath $CachedPath) -or (Get-Item -LiteralPath $CachedPath).Length -eq 0) {
                throw "Downloaded file is missing or empty"
            }

            # Re-read version from freshly downloaded file
            $head = Get-Content -LiteralPath $CachedPath -TotalCount 60 -ErrorAction SilentlyContinue
            $match = ($head -join "`n") | Select-String -Pattern '\$ScriptVersion\s*=\s*["'']([0-9]+(?:\.[0-9]+)+)["'']'
            if ($match) { $CachedVersion = $match.Matches[0].Groups[1].Value }

            & $Log ("Download complete: Run-Audit.ps1 v{0}" -f $CachedVersion)
            Write-Host ("[Deploy] Download complete: Run-Audit.ps1 v{0}" -f $CachedVersion) -ForegroundColor Green
        } catch {
            & $Log ("Download failed: {0}" -f $_.Exception.Message)
            Write-Host ("[Deploy] WARNING: Download failed — {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            if (-not (Test-Path -LiteralPath $CachedPath)) {
                & $Log "FATAL: Download failed and no cached script — cannot proceed"
                Write-Host "[Deploy] ERROR: No cached script available. Cannot run audit." -ForegroundColor Red
                exit 2
            }
            Write-Host "[Deploy] Falling back to existing cached version." -ForegroundColor Yellow
        }
    }
}

# ------------------------- #
# HuduEntryName expansion   #
# ------------------------- #
$ResolvedHuduEntryName = $null
if ($HuduEntryName) {
    $tokenDate             = Get-Date -Format 'yyyy-MM-dd'
    $tokenCustomerName     = if ($CustomerName) { $CustomerName } else { '' }
    $ResolvedHuduEntryName = $HuduEntryName `
        -replace '\$ComputerName', $env:COMPUTERNAME `
        -replace '\$Date',         $tokenDate `
        -replace '\$CustomerName', $tokenCustomerName
    & $Log ("HuduEntryName resolved: '{0}' -> '{1}'" -f $HuduEntryName, $ResolvedHuduEntryName)
}

# ------------------------- #
# Build argument list       #
# ------------------------- #
$argList = @('-ExecutionPolicy', 'Bypass', '-File', $CachedPath, '-Silent')
if ($PSBoundParameters.ContainsKey('CustomerName'))        { $argList += @('-CustomerName', $CustomerName) }
if ($PSBoundParameters.ContainsKey('HuduReport') -and $HuduReport) { $argList += '-HuduReport' }
if ($PSBoundParameters.ContainsKey('HuduAPIKey'))          { $argList += @('-HuduAPIKey', $HuduAPIKey) }
if ($PSBoundParameters.ContainsKey('HuduBaseURL'))         { $argList += @('-HuduBaseURL', $HuduBaseURL) }
if ($PSBoundParameters.ContainsKey('HuduCompanySlug'))     { $argList += @('-HuduCompanySlug', $HuduCompanySlug) }
if ($PSBoundParameters.ContainsKey('HuduAssetLayoutName')) { $argList += @('-HuduAssetLayoutName', $HuduAssetLayoutName) }
if ($ResolvedHuduEntryName)                                { $argList += @('-HuduEntryName', $ResolvedHuduEntryName) }

# Log argument list with API key masked
$logArgs = $argList | ForEach-Object {
    if ($_ -eq $HuduAPIKey -and $HuduAPIKey) { '***' } else { $_ }
}
& $Log ("Invoking: powershell.exe {0}" -f ($logArgs -join ' '))

# ------------------------- #
# Execute                   #
# ------------------------- #
# Use & (call operator) against powershell.exe so stdout/stderr are inherited —
# all Run-Audit.ps1 Write-Host output flows directly to Atera's job log.
# $LASTEXITCODE captures the child process exit code after an external executable call.
Write-Host ("[Deploy] Run-Audit.ps1 v{0} ready. Starting audit..." -f $CachedVersion) -ForegroundColor Cyan

try {
    & powershell.exe @argList
    $childExit = $LASTEXITCODE
} catch {
    & $Log ("Failed to launch Run-Audit.ps1: {0}" -f $_.Exception.Message)
    Write-Host ("[Deploy] ERROR: Could not launch Run-Audit.ps1 — {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}

& $Log ("Run-Audit.ps1 completed with exit code {0}" -f $childExit)
Write-Host ("[Deploy] Audit completed with exit code {0}" -f $childExit) -ForegroundColor $(if ($childExit -eq 0) { 'Green' } else { 'Yellow' })

exit $childExit
