<#
    Run-Audit.ps1
    System Audit Script with progress output + security baseline.

    Output:
      RMM / Silent mode (or running from C:\Program Files\...):
        HTML report  ->  C:\Program Files\Windows Audit Tool\Results\<COMPUTER>-Audit.html
        Audit log    ->  C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt
      Interactive mode (run from any other location):
        HTML report  ->  <script-dir>\Windows Audit Tool\<COMPUTER>-Audit.html
        Audit log    ->  <script-dir>\Windows Audit Tool\AuditLog.txt

      Bootstrap log (first few lines, before paths are resolved):
        C:\Windows\Temp\AuditLog.txt
#>

param(
    # Suppress UAC elevation prompt and final interactive pause.
    # Intended for unattended deployment via RMM/MDM tools (Atera, Intune, etc.)
    # where the script is always launched in an already-elevated context.
    [switch]$Silent,

    # Update switches - download newer release assets from GitHub then run the audit.
    [Alias('update-all')]    [switch]$UpdateAll,
    [Alias('update-script')] [switch]$UpdateScript,
    [Alias('update-exe')]    [switch]$UpdateExe,

    # Customer / business name to include in the report title and filename.
    # Required when using -Silent; prompted interactively otherwise.
    [Alias('customer-name')]
    [string]$CustomerName,

    # Hudu API integration - upload the audit report directly to a Hudu asset.
    # All Hudu parameters require -HuduReport to be set.
    [Alias('hudu-report')]
    [switch]$HuduReport,

    [Alias('hudu-api-key')]
    [string]$HuduAPIKey,

    [Alias('hudu-base-url')]
    [string]$HuduBaseURL,

    [Alias('hudu-company-slug')]
    [string]$HuduCompanySlug,

    [Alias('hudu-asset-layout-name')]
    [string]$HuduAssetLayoutName
)

$ErrorActionPreference = "Stop"

# ------------------------- #
# Version                   #
# ------------------------- #
$ScriptVersion = "1.3.2.9"

# ------------------------- #
# Paths (per computer)      #
# ------------------------- #
$ComputerName = $env:COMPUTERNAME
if (-not $ComputerName -or $ComputerName -eq "") {
    $ComputerName = "UnknownComputer"
}

$LogPath = "C:\Windows\Temp\AuditLog.txt"
# Bootstrap log path — used only until $ScriptDir and $IsRmmMode are resolved inside the main try block.
# $HtmlReportPath, $HuduHtmlReportPath, $ReportDir, and final $LogPath are all set there.

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
# Enhanced Error Logging    #
# ------------------------- #
function Log-ExceptionDetail {
    param(
        [Parameter(Mandatory=$true)][string]$Context,
        [Parameter(Mandatory=$true)]$ErrorRecord
    )
    try {
        $ex = $ErrorRecord.Exception
        Log ("{0} failed: {1}" -f $Context, ($ErrorRecord.ToString()))
        if ($ex) {
            Log ("{0} exception type: {1}" -f $Context, ($ex.GetType().FullName))
            if ($ex.Message) { Log ("{0} exception message: {1}" -f $Context, $ex.Message) }
        }
        if ($ErrorRecord.InvocationInfo) {
            $inv = $ErrorRecord.InvocationInfo
            if ($inv.PositionMessage) { Log ("{0} position: {1}" -f $Context, ($inv.PositionMessage -replace '\r?\n',' ')) }
            if ($inv.ScriptName) { Log ("{0} script: {1}" -f $Context, $inv.ScriptName) }
            if ($inv.Line) { Log ("{0} line: {1}" -f $Context, ($inv.Line.Trim())) }
        }
        if ($ErrorRecord.ScriptStackTrace) {
            Log ("{0} stack: {1}" -f $Context, ($ErrorRecord.ScriptStackTrace -replace '\r?\n',' | '))
        }
    } catch {
        # swallow
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
        Log-ExceptionDetail -Context $Name -ErrorRecord $_
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

    $extraArgs = ""
    if ($Silent) { $extraArgs += " -Silent" }
    if ($CustomerName) { $extraArgs += " -CustomerName `"$CustomerName`"" }

    if ($PSCommandPath) {
        # Running as a .ps1 script - relaunch via powershell.exe
        $psi.FileName  = "powershell.exe"
        $psi.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`"$extraArgs"
    }
    else {
        # Likely running as a PS2EXE-compiled executable
        $exePath = Convert-Path -LiteralPath ([Environment]::GetCommandLineArgs()[0])
        $psi.FileName  = $exePath
        $psi.Arguments = $extraArgs.TrimStart()
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
# Console Output Helpers    #
# ------------------------- #
function Write-Step {
    param(
        [Parameter(Mandatory=$true)][int]$Index,
        [Parameter(Mandatory=$true)][int]$Total,
        [Parameter(Mandatory=$true)][string]$Title
    )
    Write-Host ("[{0}/{1}] {2}" -f $Index, $Total, $Title) -ForegroundColor Yellow
    Log ("STEP {0}/{1}: {2}" -f $Index, $Total, $Title)
}

function Write-Mode {
    param([bool]$IsElevated)
    $modeText = if ($IsElevated) { "Yes" } else { "No" }
    $color    = if ($IsElevated) { "Green" } else { "DarkYellow" }
    Write-Host ("[0] Elevated: {0}" -f $modeText) -ForegroundColor $color
    Log ("Elevated: {0}" -f $modeText)
}

function Write-Action {
    param(
        [Parameter(Mandatory=$true)][string]$What,
        [ValidateSet('run','skip','ok','warn','bad','info')][string]$Kind = 'info'
    )
    $color = switch ($Kind) {
        'run'  { 'Cyan' }
        'skip' { 'DarkYellow' }
        'ok'   { 'Green' }
        'warn' { 'Yellow' }
        'bad'  { 'Red' }
        default { 'Gray' }
    }
    Write-Host ("    - {0}" -f $What) -ForegroundColor $color
    Log ("ACTION: {0}" -f $What)
}

function Write-PrivilegedGate {
    param(
        [Parameter(Mandatory=$true)][bool]$IsElevated,
        [Parameter(Mandatory=$true)][string]$What
    )
    if ($IsElevated) {
        Write-Action -What ("Running: {0}" -f $What) -Kind run
        return $true
    } else {
        Write-Action -What ("Skipped (not elevated): {0}" -f $What) -Kind skip
        Log ("Skipped (not elevated): {0}" -f $What)
        return $false
    }
}

# ------------------------- #
# Windows Updates (WUA API) #
# ------------------------- #
function Get-PendingWindowsUpdatesWUA {
    <#
      Returns pending, hidden, and recently-failed updates using the Windows Update Agent (WUA) API.
      Returns a PSCustomObject with Pending, Hidden, and Failed lists plus MetaInfo diagnostics.
    #>

    try {
        $svc = Get-Service -Name wuauserv -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue | Out-Null
        }
    } catch { }

    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()

    function Get-WuaUpdateList {
        param([string]$Criteria)
        $res  = $searcher.Search($Criteria)
        $list = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $res.Updates.Count; $i++) {
            $u  = $res.Updates.Item($i)
            $kb = "N/A"
            try { if ($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0) { $kb = ($u.KBArticleIDs -join ", ") } } catch {}
            $cats = "N/A"
            try { if ($u.Categories -and $u.Categories.Count -gt 0) { $cats = (@($u.Categories) | ForEach-Object { $_.Name } | Sort-Object -Unique) -join ", " } } catch {}
            $list.Add([pscustomobject]@{
                Title          = $u.Title
                KB             = $kb
                Categories     = $cats
                Downloaded     = $u.IsDownloaded
                Mandatory      = $u.IsMandatory
                RebootRequired = $u.RebootRequired
                EulaAccepted   = $u.EulaAccepted
            })
        }
        return [pscustomobject]@{ ResultCode = $res.ResultCode; Count = $res.Updates.Count; Items = @($list) }
    }

    $pendingResult = Get-WuaUpdateList "IsInstalled=0 and IsHidden=0"
    $hiddenResult  = Get-WuaUpdateList "IsInstalled=0 and IsHidden=1"

    # Failed update history (last 30 days; ResultCode 4 = failed)
    $failedHistory = [System.Collections.Generic.List[object]]::new()
    try {
        $totalHistory = $searcher.GetTotalHistoryCount()
        if ($totalHistory -gt 0) {
            $history = $searcher.QueryHistory(0, [Math]::Min($totalHistory, 200))
            $cutoff  = (Get-Date).AddDays(-30)
            for ($i = 0; $i -lt $history.Count; $i++) {
                $h = $history.Item($i)
                if ($h.ResultCode -eq 4 -and $h.Date -ge $cutoff) {
                    $kb = "N/A"
                    try { if ($h.Title -match 'KB(\d+)') { $kb = "KB$($Matches[1])" } } catch {}
                    $failedHistory.Add([pscustomobject]@{
                        Title      = $h.Title
                        KB         = $kb
                        Date       = $h.Date.ToString('yyyy-MM-dd HH:mm')
                        HResult    = ("0x{0:X8}" -f [uint32]$h.HResult)
                    })
                }
            }
        }
    } catch {}

    return [pscustomobject]@{
        MetaInfo = [pscustomobject]@{
            PendingResultCode = $pendingResult.ResultCode
            PendingCount      = $pendingResult.Count
            HiddenCount       = $hiddenResult.Count
        }
        Pending = $pendingResult.Items
        Hidden  = $hiddenResult.Items
        Failed  = @($failedHistory)
    }
}

# ------------------------- #
# Installed software        #
# ------------------------- #
function Get-InstalledSoftwareInventory {
    <#
      Installed software inventory (robust + trimmed) merging:
        - Uninstall registry keys (HKLM 64/32 + HKCU)
        - Loaded user hives (HKU) + offline NTUSER.DAT (when elevated)
        - Microsoft Store / AppX packages (current user; all users when elevated)
        - Winget list (best-effort, if present)

      Enhancements:
        - Normalizes all fields to strings to avoid type-mismatch crashes
        - Filters noisy "junk" entries (framework/system AppX, winget usage output, component explosions)
        - Enhanced logging on failure (includes sample object/property types)
    #>

    [CmdletBinding()]
    param([switch]$IncludeAllUsers)

    $results = New-Object System.Collections.Generic.List[object]

    function Normalize-Text {
        param([object]$Value)
        try {
            if ($null -eq $Value) { return "" }
            $s = [string]$Value
            $s = ($s -replace '\s+', ' ').Trim()

            # Reverse common UTF-8-bytes-decoded-as-CP437 artifacts.
            # These appear when winget or registry values contain Unicode punctuation
            # that was stored/transmitted as UTF-8 but decoded using CP437.
            # Each entry: (CP437-misread sequence) -> correct Unicode replacement.
            # Pattern: UTF-8 byte E2 always decodes to Gamma (U+0393) in CP437,
            #          byte 80 to C-cedilla (U+00C7), followed by a third varying byte.
            $s = $s.Replace([char]0x0393 + [char]0x00C7 + [char]0x00AA, '...')  # U+2026 ellipsis        (E2 80 A6)
            $s = $s.Replace([char]0x0393 + [char]0x00C7 + [char]0x00F6, ' - ')  # U+2014 em dash         (E2 80 94)
            $s = $s.Replace([char]0x0393 + [char]0x00C7 + [char]0x00F4, ' - ')  # U+2013 en dash         (E2 80 93)
            $s = $s.Replace([char]0x0393 + [char]0x00C7 + [char]0x00D6, "'")    # U+2019 right single q  (E2 80 99)
            $s = $s.Replace([char]0x0393 + [char]0x00C7 + [char]0x00FF, "'")    # U+2018 left single q   (E2 80 98)
            $s = $s.Replace([char]0x0393 + [char]0x00C7 + [char]0x009C, '"')    # U+201C left double q   (E2 80 9C)
            $s = $s.Replace([char]0x0393 + [char]0x00C7 + [char]0x009D, '"')    # U+201D right double q  (E2 80 9D)

            return $s
        } catch {
            return ""
        }
    }

    function Test-IsGuidLikeName {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        return ($Name -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(_|$)')
    }

    function Test-IsNoisyAppx {
        param([string]$Name, [string]$Publisher)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
        if (Test-IsGuidLikeName $Name) { return $true }

        $noisyPatterns = @(
            '^Microsoft\.VCLibs(\.|$)',
            '^Microsoft\.UI\.Xaml(\.|$)',
            '^Microsoft\.NET\.Native\.(Framework|Runtime)(\.|$)',
            '^Microsoft\.WindowsAppRuntime(\.|$)',
            '^Microsoft\.WinAppRuntime(\.|$)',
            '^MicrosoftCorporationII\.WinAppRuntime(\.|$)',

            '^Microsoft\.Windows\.Apprep\.',
            '^Microsoft\.Windows\.OOBE',
            '^Microsoft\.Windows\.AssignedAccess',
            '^Microsoft\.Windows\.CapturePicker',
            '^Microsoft\.Windows\.CloudExperienceHost',
            '^Microsoft\.Windows\.ContentDeliveryManager',
            '^Microsoft\.Windows\.PeopleExperienceHost',
            '^Microsoft\.Windows\.ShellExperienceHost',
            '^Microsoft\.Windows\.StartMenuExperienceHost',
            '^Microsoft\.Win32WebViewHost',

            '^Microsoft\.AAD\.BrokerPlugin',
            '^Microsoft\.AccountsControl',
            '^Microsoft\.CredDialogHost',
            '^Microsoft\.AsyncTextService',
            '^Microsoft\.Services\.Store\.',
            '^Microsoft\.ECApp',

            '^MicrosoftWindows\.Client\.',
            '^MicrosoftWindows\.LKG\.',
            '^WindowsWorkload\.',

            '^windows\.immersivecontrolpanel$',
            '^Windows\.PrintDialog$',
            '^Windows\.CBSPreview$'
        )

        foreach ($p in $noisyPatterns) {
            if ($Name -match $p) { return $true }
        }

        if ($Publisher -match '^CN=Microsoft Windows' -and $Name -match '_(cw5n1h2txyewy|8wekyb3d8bbwe)$') {
            return $true
        }

        return $false
    }

    function Test-IsWingetGarbageLine {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
        return ($Name -match '^(usage:|More help can be found|The following |Argument name was not recognized)')
    }

    function Test-IsComponentExplosion {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

        # Reduce noise, but keep major "real" apps
        if ($Name -match '^Microsoft Visual C\+\+ (20\d{2}|v14)' -and $Name -match '(Minimum|Additional)') { return $true }
        if ($Name -match '^Microsoft \.NET (Runtime|Host|Host FX Resolver)' -and $Name -match '\(x64\)') { return $true }
        if ($Name -match '^Python 3\.\d+\.\d+' -and $Name -match '(Core Interpreter|Documentation|Development Libraries|Standard Library|Test Suite|Tcl/Tk Support|pip Bootstrap|Executables|Add to Path)') { return $true }

        return $false
    }

    function Add-Result {
        param(
            [object]$Name,
            [object]$Version,
            [object]$Publisher,
            [object]$InstallLocation,
            [string]$Scope,
            [string]$Source
        )
        try {
            $n = Normalize-Text $Name
            if ([string]::IsNullOrWhiteSpace($n)) { return }

            $v = Normalize-Text $Version
            $p = Normalize-Text $Publisher
            $il = Normalize-Text $InstallLocation

            # Trim junk
            if ($Source -match '^AppX' -and (Test-IsNoisyAppx -Name $n -Publisher $p)) { return }
            if ($Source -eq 'Winget' -and (Test-IsWingetGarbageLine -Name $n)) { return }
            if (Test-IsComponentExplosion -Name $n) { return }

            $results.Add([pscustomobject]@{
                DisplayName     = $n
                DisplayVersion  = $v
                Publisher       = $p
                InstallLocation = $il
                Scope           = $Scope
                Source          = $Source
            }) | Out-Null
        } catch {
            Log-ExceptionDetail -Context "Installed Software Add-Result" -ErrorRecord $_
        }
    }

    function Add-UninstallEntriesFromRoot {
        param(
            [Parameter(Mandatory)] [string]$Root,
            [Parameter(Mandatory)] [string]$Scope,
            [Parameter(Mandatory)] [string]$Source
        )

        foreach ($p in @(
            "$Root\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "$Root\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )) {
            try {
                Get-ItemProperty -Path $p -ErrorAction Stop |
                    Where-Object { $_.DisplayName -and ([string]$_.DisplayName).Trim() -ne "" } |
                    ForEach-Object {
                        Add-Result -Name $_.DisplayName -Version $_.DisplayVersion -Publisher $_.Publisher -InstallLocation $_.InstallLocation -Scope $Scope -Source $Source
                    }
            } catch {
                Log-ExceptionDetail -Context ("Installed Software registry read: {0}" -f $p) -ErrorRecord $_
            }
        }
    }

    # --- Registry (classic installs) ---
    Add-UninstallEntriesFromRoot -Root "HKLM:" -Scope "Machine"     -Source "UninstallHKLM"
    Add-UninstallEntriesFromRoot -Root "HKCU:" -Scope "CurrentUser" -Source "UninstallHKCU"

    # --- Loaded user hives (HKU) + offline hives (NTUSER.DAT) when elevated ---
    if ($IncludeAllUsers) {
        # Loaded HKU hives
        try {
            $userSids = Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction Stop |
                Where-Object {
                    $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' -and
                    $_.PSChildName -notlike '*_Classes'
                } |
                Select-Object -ExpandProperty PSChildName

            foreach ($sid in @($userSids)) {
                Add-UninstallEntriesFromRoot -Root ("Registry::HKEY_USERS\{0}" -f $sid) -Scope ("UserHive:{0}" -f $sid) -Source "UninstallHKU"
            }
        } catch {
            Log-ExceptionDetail -Context "Installed Software HKU enumerate" -ErrorRecord $_
        }

        # Offline user profiles (load NTUSER.DAT)
        try {
            $profileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction Stop |
                Select-Object PSChildName, ProfileImagePath

            foreach ($p in @($profileList)) {
                $sid = [string]$p.PSChildName
                if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }

                $profilePath = [string]$p.ProfileImagePath
                if ([string]::IsNullOrWhiteSpace($profilePath)) { continue }

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
                        Add-UninstallEntriesFromRoot -Root $tempHiveRoot -Scope ("OfflineUser:{0}" -f $sid) -Source "UninstallHKU-Offline"
                    }
                    finally {
                        try { $null = & reg.exe unload ("HKU\{0}" -f $tempHiveName) 2>$null } catch { }
                    }
                }
            }
        } catch {
            Log-ExceptionDetail -Context "Installed Software offline hives" -ErrorRecord $_
        }
    }

    # --- Microsoft Store / AppX packages ---
    try {
        Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object {
            $name = if ($_.PackageFamilyName) { $_.PackageFamilyName } else { $_.Name }
            Add-Result -Name $name -Version ($_.Version.ToString()) -Publisher $_.Publisher -InstallLocation $_.InstallLocation -Scope "CurrentUser" -Source "AppX"
        }
    } catch {
        Log-ExceptionDetail -Context "Installed Software AppX current user" -ErrorRecord $_
    }

    if ($IncludeAllUsers) {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
                $name = if ($_.PackageFamilyName) { $_.PackageFamilyName } else { $_.Name }
                Add-Result -Name $name -Version ($_.Version.ToString()) -Publisher $_.Publisher -InstallLocation $_.InstallLocation -Scope "AllUsers" -Source "AppX-AllUsers"
            }
        } catch {
            Log-ExceptionDetail -Context "Installed Software AppX all users" -ErrorRecord $_
        }
    }

    # --- Winget (best-effort; version-safe) ---
    try {
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($winget) {
            # Winget outputs UTF-8. Force OutputEncoding to UTF-8 before capturing so
            # Unicode characters (e.g. ellipsis in truncated names) are not decoded as CP437.
            $prevOutputEncoding = [Console]::OutputEncoding
            try {
                [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                # Don't pass flags that older winget builds reject
                $raw = & $winget.Source "list" "--disable-interactivity" "--accept-source-agreements" 2>&1
            } finally {
                [Console]::OutputEncoding = $prevOutputEncoding
            }
            $lines = @($raw) | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_.Trim() -ne "" }

            # If this looks like help/usage output, skip entirely
            if ($lines -match '^usage:\s+winget\s+list') {
                Log "Winget list returned usage/help output; skipping winget inventory."
            } else {
                # Attempt to parse the aligned table if present; otherwise treat as name-only lines.
                $sepHit = ($lines | Select-String -Pattern '^-{3,}\s+-{3,}' -SimpleMatch:$false | Select-Object -First 1)
                $dataLines = @()
                if ($sepHit -and $sepHit.LineNumber -and $sepHit.LineNumber -lt $lines.Count) {
                    $dataLines = $lines[($sepHit.LineNumber)..($lines.Count-1)]
                } elseif ($lines.Count -gt 2) {
                    $dataLines = $lines[2..($lines.Count-1)]
                }

                foreach ($l in @($dataLines)) {
                    try {
                        $t = $l.TrimEnd()
                        if (-not $t -or $t -match '^-{3,}$') { continue }
                        if (Test-IsWingetGarbageLine -Name $t) { continue }

                        $parts = $t -split '\s{2,}'
                        if ($parts.Count -ge 1) {
                            $name = $parts[0]
                            $ver  = if ($parts.Count -ge 3) { $parts[2] } else { "" }
                            Add-Result -Name $name -Version $ver -Publisher "" -InstallLocation "" -Scope "Machine/User" -Source "Winget"
                        }
                    } catch {
                        Log-ExceptionDetail -Context "Winget parse line" -ErrorRecord $_
                    }
                }
            }
        }
    } catch {
        Log-ExceptionDetail -Context "Installed Software Winget" -ErrorRecord $_
    }

    # --- De-dupe & aggregate sources (string-key grouping to avoid type mismatches) ---
    try {
        $norm = @($results) | ForEach-Object {
            # Ensure all fields are strings
            $_.DisplayName    = Normalize-Text $_.DisplayName
            $_.DisplayVersion = Normalize-Text $_.DisplayVersion
            $_.Publisher      = Normalize-Text $_.Publisher
            $_.InstallLocation= Normalize-Text $_.InstallLocation
            $_.Scope          = Normalize-Text $_.Scope
            $_.Source         = Normalize-Text $_.Source
            $_
        } | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" }

        $groups = $norm | Group-Object -Property @{ Expression = {
            "{0}`0{1}`0{2}`0{3}" -f ($_.DisplayName.ToLowerInvariant()),
                                ($_.DisplayVersion.ToLowerInvariant()),
                                ($_.Publisher.ToLowerInvariant()),
                                ($_.Scope.ToLowerInvariant())
        }}

        $out = foreach ($g in $groups) {
            $first = $g.Group | Select-Object -First 1
            $sources = ($g.Group | ForEach-Object { $_.Source } | Where-Object { $_ } | Sort-Object -Unique) -join ";"
            $first | Add-Member -NotePropertyName Sources -NotePropertyValue $sources -Force
            $first
        }

        return ($out | Sort-Object DisplayName, DisplayVersion, Scope)
    } catch {
        Log-ExceptionDetail -Context "Installed Software grouping/trim" -ErrorRecord $_
        try {
            $sample = @($results | Select-Object -First 20)
            Log ("Installed Software sample (first 20): {0}" -f (($sample | ForEach-Object { $_.DisplayName }) -join " | "))

            foreach ($s in $sample) {
                try {
                    $props = $s.PSObject.Properties | ForEach-Object { "{0}={1}" -f $_.Name, (if ($_.Value) { $_.Value.GetType().Name } else { "null" }) }
                    Log ("Installed Software row types: {0}" -f ($props -join ", "))
                } catch { }
            }
        } catch { }

        return ($results | Sort-Object DisplayName, DisplayVersion, Scope -Unique)
    }
}

# ------------------------- #
# Software de-duplication   #
# ------------------------- #
function Remove-SoftwareDuplicates {
    <#
      Cleans software inventory duplicates with two rules:

      1) Prefer a REAL version over "N/A"/blank for the same DisplayName.
         - If a name has at least one real version entry, drop the rows for that name where version is N/A/blank/unknown.

      2) De-duplicate on DisplayName + DisplayVersion.
         - If two entries have the same name and same version, keep only one.
         - If the versions differ, keep them both (distinct installs).

      When duplicates are collapsed, this function merges:
        - Scope   (unique values joined with ';')
        - Sources (unique values joined with ';')
      And prefers the row with richer Publisher/InstallLocation fields.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$Items
    )

    if (-not $Items -or $Items.Count -eq 0) { return @() }

    function Norm([object]$v) {
        try {
            if ($null -eq $v) { return "" }
            $s = [string]$v
            $s = ($s -replace '\s+', ' ').Trim()
            return $s
        } catch { return "" }
    }

    function NormName([object]$n) {
        (Norm $n).ToLowerInvariant()
    }

    function NormVersion([object]$v) {
        $vv = Norm $v
        if ([string]::IsNullOrWhiteSpace($vv)) { return "N/A" }
        if ($vv -match '^(N/A|NA|UNKNOWN|NOT AVAILABLE)$') { return "N/A" }
        return $vv
    }

    function Join-Unique([string[]]$vals) {
        (($vals | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Sort-Object -Unique) -join ';')
    }

    # ---------------------------
    # Pass 1: Drop N/A versions when a real version exists for that name
    # ---------------------------
    $filtered = foreach ($g in ($Items | Group-Object -Property @{ Expression = { NormName $_.DisplayName } })) {
        $rows = @($g.Group)
        $hasReal = $false
        foreach ($r in $rows) {
            if ((NormVersion $r.DisplayVersion) -ne "N/A") { $hasReal = $true; break }
        }

        if ($hasReal) {
            $rows | Where-Object { (NormVersion $_.DisplayVersion) -ne "N/A" }
        } else {
            $rows
        }
    }

    # ---------------------------
    # Pass 2: De-dupe on Name + Version (keep distinct versions), merge Scope/Sources
    # ---------------------------
    $groups = $filtered | Group-Object -Property @{ Expression = {
        $n = (NormName $_.DisplayName)
        $v = (NormVersion $_.DisplayVersion).ToLowerInvariant()
        "$n`0$v"
    }}

    $out = foreach ($g in $groups) {
        $rows = @($g.Group)
        if ($rows.Count -eq 1) {
            # Normalize version display if it is blank-ish
            $rows[0].DisplayName    = Norm $rows[0].DisplayName
            $rows[0].DisplayVersion = NormVersion $rows[0].DisplayVersion
            if (-not ($rows[0].PSObject.Properties.Name -contains 'Sources') -and ($rows[0].PSObject.Properties.Name -contains 'Source')) {
                $rows[0] | Add-Member -NotePropertyName Sources -NotePropertyValue (Norm $rows[0].Source) -Force
            }
            $rows[0]
            continue
        }

        # Prefer a row with more useful metadata.
        $best = $rows | Sort-Object -Descending -Property @{ Expression = {
            $score = 0
            if (-not [string]::IsNullOrWhiteSpace((Norm $_.Publisher))) { $score += 2 }
            if (-not [string]::IsNullOrWhiteSpace((Norm $_.InstallLocation))) { $score += 1 }
            if ($_.PSObject.Properties.Name -contains 'Sources') { $score += (Norm $_.Sources).Length } elseif ($_.PSObject.Properties.Name -contains 'Source') { $score += (Norm $_.Source).Length }
            $score
        }} | Select-Object -First 1

        # Merge scopes/sources across duplicates
        $scopes = $rows | ForEach-Object { Norm $_.Scope } | Where-Object { $_ } | Sort-Object -Unique

        $sources = $rows | ForEach-Object {
            if ($_.PSObject.Properties.Name -contains 'Sources') { Norm $_.Sources }
            elseif ($_.PSObject.Properties.Name -contains 'Source') { Norm $_.Source }
            else { "" }
        } | Where-Object { $_ } | ForEach-Object { $_ -split ';' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique

        if ($scopes.Count -gt 0) {
            $best.Scope = Join-Unique $scopes
        }

        if (-not ($best.PSObject.Properties.Name -contains 'Sources')) {
            $best | Add-Member -NotePropertyName Sources -NotePropertyValue "" -Force
        }
        if ($sources.Count -gt 0) {
            $best.Sources = Join-Unique $sources
        }

        $best.DisplayName    = Norm $best.DisplayName
        $best.DisplayVersion = NormVersion $best.DisplayVersion

        $best
    }

    return @($out)
}


# ------------------------- #
# HTML helpers              #
# ------------------------- #
$Html     = New-Object System.Text.StringBuilder
$HuduHtml = New-Object System.Text.StringBuilder
$Toc = New-Object System.Collections.Generic.List[object]
$SectionIdCounts = @{}
$SectionHealth       = @{}
$GlobalFindings      = [System.Collections.Generic.List[object]]::new()
$CurrentSectionId    = $null
$CurrentSectionTitle = $null

function Set-SectionHealth {
    param([ValidateSet('good','warn','bad')][string]$Status)
    if ($script:CurrentSectionId) {
        $rank = @{ 'good' = 0; 'warn' = 1; 'bad' = 2 }
        $current = $SectionHealth[$script:CurrentSectionId]
        if (-not $current -or $rank[$Status] -gt $rank[$current]) {
            $SectionHealth[$script:CurrentSectionId] = $Status
        }
    }
}

function New-SectionId {
    param([string]$Title)
    $base = ($Title.ToLowerInvariant() -replace '[^a-z0-9]+','-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($base)) { $base = 'section' }

    if (-not $SectionIdCounts.ContainsKey($base)) {
        $SectionIdCounts[$base] = 1
        return $base
    }

    $SectionIdCounts[$base] = [int]$SectionIdCounts[$base] + 1
    return ("{0}-{1}" -f $base, $SectionIdCounts[$base])
}

function Html-Enc {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return "N/A" }
    $s = [string]$Value
    $s = $s -replace "`r", " "
    $s = $s -replace "`n", " "
    $s = ($s -replace '\s{2,}', ' ').Trim()
    return [System.Net.WebUtility]::HtmlEncode($s)
}

function Convert-ToHuduInline {
    param([string]$L)
    # Transforms class-based HTML into inline-styled HTML for Hudu compatibility.
    # Hudu (Rails/ActionText) strips <style> blocks but preserves inline style= attributes.
    # Uses theme-neutral colors (inherit, rgba) for light/dark Hudu theme compatibility.
    #
    # CRITICAL: Hudu's sanitizer restructures nested <div> containers around block elements
    # (h2/h3/table get pulled out of parent divs, splitting the container). To survive this:
    #   - Section container divs are flattened to <hr> separators (no wrapping)
    #   - KV grids are converted from nested divs to <table> (tables survive intact)
    # Order matters: structural transforms and specific patterns before generic ones.

    # Section container - flatten to HR separator (Hudu breaks divs wrapping block elements)
    $L = $L -replace "<div class='section'>", "<hr style='border:none; border-top:2px solid rgba(128,128,128,0.15); margin:28px 0 0;'>"
    # Section end marker - keep </details>, remove the div close (HR is void, no close needed)
    $L = $L -replace "</details></div><!-- /section -->", "</details>"
    $L = $L -replace "</div><!-- /section -->", ""

    # Section-level details/summary (must come before generic details/summary rules)
    $L = $L -replace "<details class='section-details'>", "<details style='margin-top:0;'>"
    $L = $L -replace "<summary class='section-summary' id='([^']*)'>", "<summary id='`$1' style='cursor:pointer; font-weight:700; padding:12px 0; font-size:18px; border-bottom:2px solid rgba(128,128,128,0.2); margin-bottom:14px; list-style:none; scroll-margin-top:80px;'>"

    # Section number badge - dark blue bg with white text works in both themes
    $L = $L -replace "<span class='sec-num'>", "<span style='display:inline-flex; align-items:center; justify-content:center; min-width:28px; height:28px; border-radius:8px; background:#1e3a5f; color:#fff; font-size:13px; font-weight:700; margin-right:8px;'>"

    # Callouts - semi-transparent tinted backgrounds, inherit text color (single-line divs, no nesting issue)
    $L = $L -replace "<div class='callout callout-good'>", "<div style='padding:10px 14px; border-radius:8px; font-size:13px; margin:10px 0; border-left:4px solid #059669; background:rgba(5,150,105,0.1);'>"
    $L = $L -replace "<div class='callout callout-warn'>", "<div style='padding:10px 14px; border-radius:8px; font-size:13px; margin:10px 0; border-left:4px solid #d97706; background:rgba(217,119,6,0.1);'>"
    $L = $L -replace "<div class='callout callout-bad'>",  "<div style='padding:10px 14px; border-radius:8px; font-size:13px; margin:10px 0; border-left:4px solid #dc2626; background:rgba(220,38,38,0.1);'>"
    $L = $L -replace "<div class='callout callout-info'>", "<div style='padding:10px 14px; border-radius:8px; font-size:13px; margin:10px 0; border-left:4px solid #2E5C6E; background:rgba(46,92,110,0.1);'>"

    # KV grid - convert from nested divs to table (tables survive Hudu's sanitizer intact)
    $L = $L -replace "<div class='kv'>", "<table style='width:100%; border-collapse:collapse; margin-top:6px; font-size:14px;'>"
    $L = $L -replace "</div><!-- /kv -->", "</table>"
    # KV rows - convert div key/value pairs to table rows (values are Html-Enc'd, no nested tags)
    $L = $L -replace "<div class='key'>([^<]*)</div><div>([^<]*)</div>", "<tr><td style='width:240px; padding:4px 8px; opacity:0.7; font-weight:500; vertical-align:top;'>`$1</td><td style='padding:4px 8px; vertical-align:top;'>`$2</td></tr>"

    # Badges - keep strong semantic colors, semi-transparent backgrounds
    $L = $L -replace "<span class='badge good'>", "<span style='display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; background:rgba(5,150,105,0.15); border:1px solid rgba(5,150,105,0.3); color:#059669;'>"
    $L = $L -replace "<span class='badge warn'>", "<span style='display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; background:rgba(217,119,6,0.15); border:1px solid rgba(217,119,6,0.3); color:#d97706;'>"
    $L = $L -replace "<span class='badge bad'>",  "<span style='display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; background:rgba(220,38,38,0.15); border:1px solid rgba(220,38,38,0.3); color:#dc2626;'>"

    # Code span
    $L = $L -replace "<span class='code'>", "<span style='font-family:Consolas,monospace; font-size:12px;'>"

    # Severity rows - semi-transparent tinted backgrounds
    $L = $L -replace "<tr class='sev-good'>", "<tr style='background:rgba(5,150,105,0.1);'>"
    $L = $L -replace "<tr class='sev-warn'>", "<tr style='background:rgba(217,119,6,0.1);'>"
    $L = $L -replace "<tr class='sev-bad'>",  "<tr style='background:rgba(220,38,38,0.1);'>"

    # Tables (kv-table first, then generic)
    $L = $L -replace "<table class='kv-table'>", "<table style='width:100%; border-collapse:collapse; margin-top:6px; font-size:13px;'>"
    $L = $L -replace "<table>", "<table style='width:100%; border-collapse:collapse; margin-top:10px; font-size:13px;'>"

    # Table headers and cells - neutral borders, transparent header bg
    $L = $L -replace "<th>", "<th style='padding:8px 10px; border:1px solid rgba(128,128,128,0.2); background:rgba(128,128,128,0.08); text-align:left; font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:0.3px; vertical-align:top;'>"
    $L = $L -replace "<td>", "<td style='padding:8px 10px; border:1px solid rgba(128,128,128,0.2); vertical-align:top; overflow-wrap:break-word; word-break:break-word;'>"

    # H3 subheaders - inherit text color
    $L = $L -replace "<h3>", "<h3 style='margin:20px 0 10px; font-size:15px; font-weight:600;'>"

    # Details/summary (open variant first)
    $L = $L -replace "<details open>", "<details open style='margin-top:12px;'>"
    $L = $L -replace "<details>", "<details style='margin-top:12px;'>"
    $L = $L -replace "<summary>", "<summary style='cursor:pointer; font-weight:600; padding:8px 0; font-size:14px;'>"

    # Small text - use opacity instead of hardcoded color
    $L = $L -replace "<p class='small'>", "<p style='font-size:12px; opacity:0.6;'>"

    # Filter box (strip JS handler - won't work in Hudu)
    $L = $L -replace " class='filter-box'", " style='width:100%; padding:10px 14px; margin:10px 0 6px; border:1px solid rgba(128,128,128,0.2); border-radius:8px; font-size:14px;'"
    $L = $L -replace " onkeyup='filterSoftwareTable\(\)'", ""

    # Small div with id
    $L = $L -replace "<div id='sw-filter-count' class='small'>", "<div id='sw-filter-count' style='font-size:12px; opacity:0.6;'>"

    return $L
}

function Html-Add {
    param([string]$Line)
    [void]$Html.AppendLine($Line)
    [void]$HuduHtml.AppendLine((Convert-ToHuduInline $Line))
}

$SectionNumber = 0

function Html-StartSection {
    param([string]$Title)
    $script:SectionNumber++
    $id = New-SectionId -Title $Title
    $script:CurrentSectionId    = $id
    $script:CurrentSectionTitle = $Title
    $SectionHealth[$id] = 'good'
    $Toc.Add([pscustomobject]@{ Title = $Title; Id = $id; Number = $script:SectionNumber }) | Out-Null
    Html-Add "<div class='section'>"
    Html-Add ("<details class='section-details'><summary class='section-summary' id='{0}'><span class='sec-num'>{1}</span>{2}</summary>" -f (Html-Enc $id), $script:SectionNumber, (Html-Enc $Title))
}

function Html-EndSection { Html-Add "</details></div><!-- /section -->" }

function Html-AddNote {
    param(
        [string]$Text,
        [ValidateSet('info','good','warn','bad')][string]$Kind = 'info',
        [string]$KbUrl,
        [string]$KbTitle
    )
    if ($Kind -in @('good','warn','bad')) { Set-SectionHealth -Status $Kind }
    # Add all warn/bad findings to the global accumulator; KB link is optional and rendered where present.
    if ($Kind -in @('warn','bad') -and $script:CurrentSectionId) {
        $script:GlobalFindings.Add([pscustomobject]@{
            Section   = $script:CurrentSectionTitle
            SectionId = $script:CurrentSectionId
            Message   = $Text
            Kind      = $Kind
            KbUrl     = $KbUrl
            KbTitle   = if ($KbTitle) { $KbTitle } else { $KbUrl }
        })
    }
    $klass = switch ($Kind) {
        'good' { 'callout callout-good' }
        'warn' { 'callout callout-warn' }
        'bad'  { 'callout callout-bad' }
        default { 'callout callout-info' }
    }
    Html-Add ("<div class='{0}'>{1}</div>" -f $klass, (Html-Enc $Text))
}

function Html-AddKV {
    param([hashtable]$Pairs)
    if (-not $Pairs -or $Pairs.Count -eq 0) { return }
    Html-Add "<div class='kv'>"
    foreach ($k in $Pairs.Keys) {
        Html-Add ("<div class='key'>{0}</div><div>{1}</div>" -f (Html-Enc $k), (Html-Enc $Pairs[$k]))
    }
    Html-Add "</div><!-- /kv -->"
}

function Html-StartDetails {
    param([string]$Summary, [switch]$Open)
    $openAttr = if ($Open) { " open" } else { "" }
    Html-Add ("<details{0}><summary>{1}</summary>" -f $openAttr, (Html-Enc $Summary))
}

function Html-EndDetails { Html-Add "</details>" }

function Html-AddTable {
    param(
        [Parameter(Mandatory=$true)][object[]]$Items,
        [Parameter(Mandatory=$true)][array]$Columns,
        [scriptblock]$RowClass
    )

    if (-not $Items -or $Items.Count -eq 0) {
        Html-Add "<p class='small'>No data.</p>"
        return
    }

    Html-Add "<table><thead><tr>"
    foreach ($c in $Columns) { Html-Add ("<th>{0}</th>" -f (Html-Enc $c.Header)) }
    Html-Add "</tr></thead><tbody>"

    foreach ($row in $Items) {
        $klass = ""
        if ($RowClass) {
            try {
                $k = & $RowClass $row
                if ($k) { $klass = " class='" + (Html-Enc $k) + "'" }
            } catch { }
        }

        Html-Add ("<tr{0}>" -f $klass)

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
# Self-Update Check         #
# ------------------------- #
function Test-ForUpdate {
    <#
      Checks the GitHub Releases API for a newer version.
      Returns a PSCustomObject with update status and asset URLs, or $null on failure.
      Never throws - all errors are logged and swallowed.
    #>
    $repoOwner = "Ripped-Kanga"
    $repoName  = "Windows-Audit-Tool"
    $apiUrl    = "https://api.github.com/repos/$repoOwner/$repoName/releases/latest"

    try {
        # TLS 1.2 required by GitHub API
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -TimeoutSec 10 -ErrorAction Stop -Headers @{ Accept = "application/vnd.github.v3+json" }

        $latestTag = [string]$response.tag_name
        # Strip leading 'v' for comparison (e.g. "v1.0.0" -> "1.0.0")
        $latestClean  = $latestTag -replace '^v', ''
        $currentClean = $ScriptVersion -replace '^v', ''

        try {
            $latestVer  = [version]$latestClean
            $currentVer = [version]$currentClean
            $isNewer    = $latestVer -gt $currentVer
        } catch {
            # Version string not parseable - fall back to string comparison
            $isNewer = ($latestClean -ne $currentClean)
        }

        # Find download URLs for .ps1 and .exe release assets
        $ps1Asset = $null
        $exeAsset = $null
        if ($response.assets) {
            foreach ($asset in $response.assets) {
                $name = [string]$asset.name
                if ($name -like '*.ps1') { $ps1Asset = [string]$asset.browser_download_url }
                if ($name -like '*.exe') { $exeAsset = [string]$asset.browser_download_url }
            }
        }

        return [pscustomobject]@{
            UpdateAvailable = $isNewer
            LatestVersion   = $latestTag
            CurrentVersion  = $ScriptVersion
            ReleaseUrl      = [string]$response.html_url
            ReleaseNotes    = [string]$response.body
            Ps1DownloadUrl  = $ps1Asset
            ExeDownloadUrl  = $exeAsset
        }
    } catch {
        Log "Update check failed: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-SelfUpdate {
    <#
      Downloads updated release assets and replaces the local files.
      For .ps1: overwrites the running script and re-launches it.
      For .exe: downloads alongside. If the .exe is the running process,
      it cannot be overwritten while locked - write to a .new file and
      rename on next launch.
    #>
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$UpdateInfo,
        [switch]$IncludeScript,
        [switch]$IncludeExe
    )

    # Use the script-level $ScriptDir resolved at startup
    $localScriptDir = $ScriptDir
    $runningAsExe   = -not [bool]$PSCommandPath

    if (-not $localScriptDir) {
        Log "Self-update: could not determine script directory"
        Write-Action -What "Update failed: could not determine script directory" -Kind warn
        return $false
    }

    $updated = $false

    # Download .ps1
    if ($IncludeScript -and $UpdateInfo.Ps1DownloadUrl) {
        $ps1Target = Join-Path $localScriptDir "Run-Audit.ps1"
        try {
            Write-Action -What "Downloading Run-Audit.ps1..." -Kind run
            Invoke-WebRequest -Uri $UpdateInfo.Ps1DownloadUrl -OutFile $ps1Target -TimeoutSec 30 -ErrorAction Stop
            Write-Action -What "Updated Run-Audit.ps1" -Kind ok
            Log ("Self-update: downloaded Run-Audit.ps1 from {0}" -f $UpdateInfo.Ps1DownloadUrl)
            $updated = $true
        } catch {
            Write-Action -What ("Failed to download Run-Audit.ps1: {0}" -f $_.Exception.Message) -Kind warn
            Log ("Self-update: failed to download .ps1 - {0}" -f $_.Exception.Message)
        }
    }

    # Download .exe
    if ($IncludeExe -and $UpdateInfo.ExeDownloadUrl) {
        $exeTarget = Join-Path $localScriptDir "Run-Audit.exe"
        $exeTemp   = Join-Path $localScriptDir "Run-Audit.exe.update"

        if ($runningAsExe) {
            # Running exe is locked - download to temp file for manual swap
            try {
                Write-Action -What "Downloading Run-Audit.exe (staged for next launch)..." -Kind run
                Invoke-WebRequest -Uri $UpdateInfo.ExeDownloadUrl -OutFile $exeTemp -TimeoutSec 60 -ErrorAction Stop
                Write-Action -What "Downloaded Run-Audit.exe.update (rename to Run-Audit.exe after this run)" -Kind warn
                Log ("Self-update: downloaded .exe to {0} (running exe is locked)" -f $exeTemp)
                $updated = $true
            } catch {
                Write-Action -What ("Failed to download Run-Audit.exe: {0}" -f $_.Exception.Message) -Kind warn
                Log ("Self-update: failed to download .exe - {0}" -f $_.Exception.Message)
            }
        } else {
            # Running as .ps1 - exe is not locked, overwrite directly
            try {
                Write-Action -What "Downloading Run-Audit.exe..." -Kind run
                Invoke-WebRequest -Uri $UpdateInfo.ExeDownloadUrl -OutFile $exeTarget -TimeoutSec 60 -ErrorAction Stop
                Write-Action -What "Updated Run-Audit.exe" -Kind ok
                Log ("Self-update: downloaded Run-Audit.exe from {0}" -f $UpdateInfo.ExeDownloadUrl)
                $updated = $true
            } catch {
                Write-Action -What ("Failed to download Run-Audit.exe: {0}" -f $_.Exception.Message) -Kind warn
                Log ("Self-update: failed to download .exe - {0}" -f $_.Exception.Message)
            }
        }
    }

    return $updated
}

function Invoke-PendingExeSwap {
    <#
      If a previous update left a Run-Audit.exe.update file (because the exe
      was locked), swap it into place now before the audit starts.
    #>
    $localScriptDir = $ScriptDir
    if (-not $localScriptDir) { return }

    $pending = Join-Path $localScriptDir "Run-Audit.exe.update"
    $target  = Join-Path $localScriptDir "Run-Audit.exe"

    if (Test-Path -LiteralPath $pending) {
        try {
            Move-Item -LiteralPath $pending -Destination $target -Force -ErrorAction Stop
            Write-Action -What "Applied pending Run-Audit.exe update" -Kind ok
            Log "Self-update: swapped Run-Audit.exe.update into Run-Audit.exe"
        } catch {
            Write-Action -What ("Could not apply pending .exe update: {0}" -f $_.Exception.Message) -Kind warn
            Log ("Self-update: failed to swap .exe - {0}" -f $_.Exception.Message)
        }
    }
}

# ------------------------- #
# Hudu API Functions         #
# ------------------------- #
function Invoke-HuduRequest {
    <#
      Lightweight wrapper around Invoke-RestMethod for the Hudu REST API.
      Adds the x-api-key header automatically. Returns the parsed response.
      Throws on HTTP errors so callers can catch and report.
      Credentials are stored in script-scope variables set during validation.
    #>
    param(
        [string]$Method   = "GET",
        [string]$Endpoint,
        [hashtable]$Body
    )
    $baseUrl = $script:_HuduBaseURL.TrimEnd('/')
    $uri     = "$baseUrl/api/v1/$($Endpoint.TrimStart('/'))"
    $headers = @{ "x-api-key" = $script:_HuduAPIKey }
    $splat   = @{
        Uri         = $uri
        Method      = $Method
        Headers     = $headers
        ContentType = "application/json"
    }
    if ($Body) {
        $splat.Body = ($Body | ConvertTo-Json -Depth 10)
    }
    Invoke-RestMethod @splat
}

function Get-HuduAssetLayoutByName {
    <#
      Paginates through all asset layouts and returns the first one whose name
      matches exactly. Returns $null if not found.
    #>
    param([string]$Name)
    $page = 1
    do {
        $resp    = Invoke-HuduRequest -Endpoint "asset_layouts?page=$page"
        $layouts = @($resp.asset_layouts)
        if (-not $layouts -or $layouts.Count -eq 0) {
            # Some Hudu versions return a bare array
            $layouts = @($resp)
        }
        foreach ($layout in $layouts) {
            if ($layout.name -eq $Name) { return $layout }
        }
        $page++
        # Hudu returns 25 per page; stop when a page is short
    } while ($layouts.Count -ge 25)
    return $null
}

function Get-HuduCompanyBySlug {
    <#
      Paginates through all companies and returns the first one whose slug
      matches. The slug is the hex string from the Hudu URL path (e.g.
      https://instance.huducloud.com/c/0297b67dbba7 -> "0297b67dbba7").
      Returns $null if not found.
    #>
    param([string]$Slug)
    $page = 1
    do {
        $resp      = Invoke-HuduRequest -Endpoint "companies?page=$page"
        $companies = @($resp.companies)
        if (-not $companies -or $companies.Count -eq 0) {
            $companies = @($resp)
        }
        foreach ($c in $companies) {
            if ($c.slug -eq $Slug) { return $c }
        }
        $page++
    } while ($companies.Count -ge 25)
    return $null
}

function Add-HuduUpload {
    <#
      Uploads a file to Hudu and attaches it to the specified record.
      Uses System.Net.Http for PS 5.1 compatible multipart form upload.
      POST /api/v1/uploads with multipart/form-data.
      Returns $true on success, $false on failure (never throws).
    #>
    param(
        [string]$FilePath,
        [int]$RecordId,
        [string]$RecordType = "Asset"
    )
    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
        $file    = Get-Item -LiteralPath $FilePath -ErrorAction Stop
        $baseUrl = $script:_HuduBaseURL.TrimEnd('/')
        $uri     = "$baseUrl/api/v1/uploads"

        $httpClient = New-Object System.Net.Http.HttpClient
        $httpClient.DefaultRequestHeaders.Add("x-api-key", $script:_HuduAPIKey)

        $multipart  = New-Object System.Net.Http.MultipartFormDataContent
        $fileStream = [System.IO.File]::OpenRead($file.FullName)
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("text/html")
        $multipart.Add($fileContent, "file", $file.Name)
        $multipart.Add((New-Object System.Net.Http.StringContent($RecordId.ToString())), "upload[uploadable_id]")
        $multipart.Add((New-Object System.Net.Http.StringContent($RecordType)), "upload[uploadable_type]")

        $response = $httpClient.PostAsync($uri, $multipart).Result
        $fileStream.Dispose()
        $multipart.Dispose()
        $httpClient.Dispose()

        if ($response.IsSuccessStatusCode) {
            return $true
        }
        $respBody = $response.Content.ReadAsStringAsync().Result
        Write-Action -What ("Upload failed: {0} - {1}" -f $response.StatusCode, $respBody) -Kind bad
        Log ("Hudu: upload failed - {0} {1}" -f $response.StatusCode, $respBody)
        return $false
    }
    catch {
        Write-Action -What ("Upload error: {0}" -f $_.Exception.Message) -Kind bad
        Log ("Hudu: upload error - {0}" -f $_.Exception.Message)
        return $false
    }
}

function Publish-HuduAsset {
    <#
      Creates a new asset in Hudu under the specified company and asset layout.
      Uses the pre-resolved numeric company ID from $_HuduCompanyId, finds the
      layout by name, auto-detects the first RichText field, and populates it
      with the supplied HTML content. Optionally attaches a file to the asset.
      Returns $true on success, $false on failure (never throws).
    #>
    param(
        [string]$LayoutName,
        [string]$AssetName,
        [string]$HtmlContent,
        [string]$AttachmentPath
    )
    try {
        $companyId = $script:_HuduCompanyId

        # 1. Find the asset layout
        Write-Action -What "Looking up asset layout: $LayoutName" -Kind run
        $layout = Get-HuduAssetLayoutByName -Name $LayoutName
        if (-not $layout) {
            Write-Action -What "Asset layout '$LayoutName' not found in Hudu." -Kind bad
            Log "Hudu: asset layout '$LayoutName' not found"
            return [pscustomobject]@{ AssetCreated = $false; FileAttached = $false }
        }
        $layoutId = $layout.id
        Write-Action -What ("Found layout: {0} (ID {1})" -f $layout.name, $layoutId) -Kind ok
        Log ("Hudu: found asset layout '{0}' (ID {1})" -f $layout.name, $layoutId)

        # 2. Find the first RichText field in the layout
        $richField = $null
        foreach ($f in @($layout.fields)) {
            if ($f.field_type -eq "RichText") {
                $richField = $f
                break
            }
        }
        if (-not $richField) {
            Write-Action -What "No RichText field found in layout '$LayoutName'." -Kind bad
            Log "Hudu: no RichText field in layout '$LayoutName'"
            return [pscustomobject]@{ AssetCreated = $false; FileAttached = $false }
        }
        # Hudu field keys: label lowercased, spaces to underscores
        $fieldKey = ($richField.label -replace '[^a-zA-Z0-9\s]', '' -replace '\s+', '_').ToLower()
        Write-Action -What ("Target field: {0} -> {1}" -f $richField.label, $fieldKey) -Kind info
        Log ("Hudu: using field '{0}' (key '{1}')" -f $richField.label, $fieldKey)

        # 3. Create the asset
        Write-Action -What "Creating asset: $AssetName" -Kind run
        $body = @{
            asset = @{
                name            = $AssetName
                asset_layout_id = $layoutId
                company_id      = $companyId
                custom_fields   = @(
                    @{ $fieldKey = $HtmlContent }
                )
            }
        }
        $result = Invoke-HuduRequest -Method POST -Endpoint "companies/$companyId/assets" -Body $body
        if ($result -and $result.asset) {
            $assetId = $result.asset.id
            Write-Action -What ("Asset created successfully (ID: {0})" -f $assetId) -Kind ok
            Log ("Hudu: asset '{0}' created (ID {1})" -f $AssetName, $assetId)

            # Attach file if path provided
            $fileAttached = $false
            if ($AttachmentPath -and (Test-Path -LiteralPath $AttachmentPath)) {
                $fileName = Split-Path -Leaf $AttachmentPath
                Write-Action -What "Attaching report: $fileName" -Kind run
                $uploaded = Add-HuduUpload -FilePath $AttachmentPath -RecordId $assetId -RecordType "Asset"
                if ($uploaded) {
                    Write-Action -What "Attachment uploaded successfully" -Kind ok
                    Log ("Hudu: attached '{0}' to asset {1}" -f $fileName, $assetId)
                    $fileAttached = $true
                } else {
                    Write-Action -What "Attachment upload failed (asset was still created)." -Kind warn
                }
            }
            return [pscustomobject]@{ AssetCreated = $true; FileAttached = $fileAttached }
        }
        # Unexpected response shape
        Write-Action -What "Asset may have been created but response was unexpected." -Kind warn
        Log ("Hudu: unexpected response from asset create: {0}" -f ($result | ConvertTo-Json -Depth 3 -Compress))
        return [pscustomobject]@{ AssetCreated = $true; FileAttached = $false }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                $reader.Close()
                $errMsg = "{0} - {1}" -f $errMsg, $responseBody
            } catch { }
        }
        Write-Action -What ("Hudu API error: {0}" -f $errMsg) -Kind bad
        Log ("Hudu: API error - {0}" -f $errMsg)
        Log-ExceptionDetail -Context "Publish-HuduAsset" -ErrorRecord $_
        return [pscustomobject]@{ AssetCreated = $false; FileAttached = $false }
    }
}

# ------------------------- #
# Start                     #
# ------------------------- #
Add-Content -Path $LogPath -Value "$(Get-Date -Format u) - INIT: script loaded, arguments received" -ErrorAction SilentlyContinue

try {

Log "INIT: entered main try block"

# Resolve the directory containing the running script or .exe.
# $PSCommandPath is populated for .ps1; for a PS2EXE .exe it is $null.
$ScriptDir = $null
if ($PSCommandPath) {
    $ScriptDir = Split-Path -Parent $PSCommandPath
} else {
    try {
        $ScriptDir = Split-Path -Parent (Convert-Path -LiteralPath ([Environment]::GetCommandLineArgs()[0]))
    } catch {
        $ScriptDir = $null
    }
}
Log ("ScriptDir resolved: {0}" -f $(if ($ScriptDir) { $ScriptDir } else { '(null)' }))

# RMM mode: -Silent was passed, OR the script is running from a Program Files path.
$IsRmmMode = $Silent -or ($ScriptDir -and $ScriptDir -like 'C:\Program Files*')
Log ("Deployment mode: {0}" -f $(if ($IsRmmMode) { 'RMM/Silent' } else { 'Interactive' }))

if (-not $Silent) {
# Banner - Base64 encoded to keep .ps1 pure ASCII (PS 5.1 compat)
$BannerWindowsB64 = "4paI4paI4pWXICAgIOKWiOKWiOKVl+KWiOKWiOKVl+KWiOKWiOKWiOKVlyAgIOKWiOKWiOKVl+KWiOKWiOKWiOKWiOKWiOKWiOKVlyAg4paI4paI4paI4paI4paI4paI4pWXIOKWiOKWiOKVlyAgICDilojilojilZfilojilojilojilojilojilojilojilZcK4paI4paI4pWRICAgIOKWiOKWiOKVkeKWiOKWiOKVkeKWiOKWiOKWiOKWiOKVlyAg4paI4paI4pWR4paI4paI4pWU4pWQ4pWQ4paI4paI4pWX4paI4paI4pWU4pWQ4pWQ4pWQ4paI4paI4pWX4paI4paI4pWRICAgIOKWiOKWiOKVkeKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVnQrilojilojilZEg4paI4pWXIOKWiOKWiOKVkeKWiOKWiOKVkeKWiOKWiOKVlOKWiOKWiOKVlyDilojilojilZHilojilojilZEgIOKWiOKWiOKVkeKWiOKWiOKVkSAgIOKWiOKWiOKVkeKWiOKWiOKVkSDilojilZcg4paI4paI4pWR4paI4paI4paI4paI4paI4paI4paI4pWXCuKWiOKWiOKVkeKWiOKWiOKWiOKVl+KWiOKWiOKVkeKWiOKWiOKVkeKWiOKWiOKVkeKVmuKWiOKWiOKVl+KWiOKWiOKVkeKWiOKWiOKVkSAg4paI4paI4pWR4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWR4paI4paI4paI4pWX4paI4paI4pWR4pWa4pWQ4pWQ4pWQ4pWQ4paI4paI4pWRCuKVmuKWiOKWiOKWiOKVlOKWiOKWiOKWiOKVlOKVneKWiOKWiOKVkeKWiOKWiOKVkSDilZrilojilojilojilojilZHilojilojilojilojilojilojilZTilZ3ilZrilojilojilojilojilojilojilZTilZ3ilZrilojilojilojilZTilojilojilojilZTilZ3ilojilojilojilojilojilojilojilZEKIOKVmuKVkOKVkOKVneKVmuKVkOKVkOKVnSDilZrilZDilZ3ilZrilZDilZ0gIOKVmuKVkOKVkOKVkOKVneKVmuKVkOKVkOKVkOKVkOKVkOKVnSAg4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWdICDilZrilZDilZDilZ3ilZrilZDilZDilZ0g4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWd"
$BannerToolB64 = "IOKWiOKWiOKWiOKWiOKWiOKVlyDilojilojilZcgICDilojilojilZfilojilojilojilojilojilojilZcg4paI4paI4pWX4paI4paI4paI4paI4paI4paI4paI4paI4pWXICAgIOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKVlyDilojilojilojilojilojilojilZcgIOKWiOKWiOKWiOKWiOKWiOKWiOKVlyDilojilojilZcgICAgIArilojilojilZTilZDilZDilojilojilZfilojilojilZEgICDilojilojilZHilojilojilZTilZDilZDilojilojilZfilojilojilZHilZrilZDilZDilojilojilZTilZDilZDilZ0gICAg4pWa4pWQ4pWQ4paI4paI4pWU4pWQ4pWQ4pWd4paI4paI4pWU4pWQ4pWQ4pWQ4paI4paI4pWX4paI4paI4pWU4pWQ4pWQ4pWQ4paI4paI4pWX4paI4paI4pWRICAgICAK4paI4paI4paI4paI4paI4paI4paI4pWR4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWRICDilojilojilZHilojilojilZEgICDilojilojilZEgICAgICAgICAg4paI4paI4pWRICAg4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWRICAgICAK4paI4paI4pWU4pWQ4pWQ4paI4paI4pWR4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWRICDilojilojilZHilojilojilZEgICDilojilojilZEgICAgICAgICAg4paI4paI4pWRICAg4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWRICAg4paI4paI4pWR4paI4paI4pWRICAgICAK4paI4paI4pWRICDilojilojilZHilZrilojilojilojilojilojilojilZTilZ3ilojilojilojilojilojilojilZTilZ3ilojilojilZEgICDilojilojilZEgICAgICAgICAg4paI4paI4pWRICAg4pWa4paI4paI4paI4paI4paI4paI4pWU4pWd4pWa4paI4paI4paI4paI4paI4paI4pWU4pWd4paI4paI4paI4paI4paI4paI4paI4pWXCuKVmuKVkOKVnSAg4pWa4pWQ4pWdIOKVmuKVkOKVkOKVkOKVkOKVkOKVnSDilZrilZDilZDilZDilZDilZDilZ0g4pWa4pWQ4pWdICAg4pWa4pWQ4pWdICAgICAgICAgIOKVmuKVkOKVnSAgICDilZrilZDilZDilZDilZDilZDilZ0gIOKVmuKVkOKVkOKVkOKVkOKVkOKVnSDilZrilZDilZDilZDilZDilZDilZDilZ0="
# Version art character map - Base64 JSON mapping chars to 6-line art arrays
$VerCharMapB64 = "eyJ2IjogWyLilojilojilZcgICDilojilojilZciLCAi4paI4paI4pWRICAg4paI4paI4pWRIiwgIuKVmuKWiOKWiOKVlyDilojilojilZTilZ0iLCAiIOKVmuKWiOKWiOKWiOKWiOKVlOKVnSAiLCAiICDilZrilojilojilZTilZ0gICIsICIgICDilZrilZDilZ0gICAiXSwgIi4iOiBbIiAgICIsICIgICAiLCAiICAgIiwgIiAgICIsICLilojilojilZciLCAi4pWa4pWQ4pWdIl0sICIwIjogWyIg4paI4paI4paI4paI4paI4paI4pWXICIsICLilojilojilZTilZDilZDilZDilojilojilZciLCAi4paI4paI4pWRICAg4paI4paI4pWRIiwgIuKWiOKWiOKVkSAgIOKWiOKWiOKVkSIsICLilZrilojilojilojilojilojilojilZTilZ0iLCAiIOKVmuKVkOKVkOKVkOKVkOKVkOKVnSAiXSwgIjEiOiBbIiDilojilojilZciLCAi4paI4paI4paI4pWRIiwgIuKVmuKWiOKWiOKVkSIsICIg4paI4paI4pWRIiwgIiDilojilojilZEiLCAiIOKVmuKVkOKVnSJdLCAiMiI6IFsi4paI4paI4paI4paI4paI4paI4pWXICIsICLilZrilZDilZDilZDilZDilojilojilZciLCAiIOKWiOKWiOKWiOKWiOKWiOKVlOKVnSIsICLilojilojilZTilZDilZDilZDilZ0gIiwgIuKWiOKWiOKWiOKWiOKWiOKWiOKWiOKVlyIsICLilZrilZDilZDilZDilZDilZDilZDilZ0iXSwgIjMiOiBbIuKWiOKWiOKWiOKWiOKWiOKWiOKVlyAiLCAi4pWa4pWQ4pWQ4pWQ4pWQ4paI4paI4pWXIiwgIiDilojilojilojilojilojilZTilZ0iLCAiIOKVmuKVkOKVkOKVkOKWiOKWiOKVlyIsICLilojilojilojilojilojilojilZTilZ0iLCAi4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWdICJdLCAiNCI6IFsi4paI4paI4pWXICDilojilojilZciLCAi4paI4paI4pWRICDilojilojilZEiLCAi4paI4paI4paI4paI4paI4paI4paI4pWRIiwgIuKVmuKVkOKVkOKVkOKVkOKWiOKWiOKVkSIsICIgICAgIOKWiOKWiOKVkSIsICIgICAgIOKVmuKVkOKVnSJdLCAiNSI6IFsi4paI4paI4paI4paI4paI4paI4paI4pWXIiwgIuKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVnSIsICLilojilojilojilojilojilojilojilZciLCAi4pWa4pWQ4pWQ4pWQ4pWQ4paI4paI4pWRIiwgIuKWiOKWiOKWiOKWiOKWiOKWiOKWiOKVkSIsICLilZrilZDilZDilZDilZDilZDilZDilZ0iXSwgIjYiOiBbIiDilojilojilojilojilojilojilZcgIiwgIuKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVnSAiLCAi4paI4paI4paI4paI4paI4paI4paI4pWXICIsICLilojilojilZTilZDilZDilZDilojilojilZciLCAi4pWa4paI4paI4paI4paI4paI4paI4pWU4pWdIiwgIiDilZrilZDilZDilZDilZDilZDilZ0gIl0sICI3IjogWyLilojilojilojilojilojilojilojilZciLCAi4pWa4pWQ4pWQ4pWQ4pWQ4paI4paI4pWRIiwgIiAgICDilojilojilZTilZ0iLCAiICAg4paI4paI4pWU4pWdICIsICIgIOKWiOKWiOKVlOKVnSAgIiwgIiAg4pWa4pWQ4pWdICAgIl0sICI4IjogWyIg4paI4paI4paI4paI4paI4pWXICIsICLilojilojilZTilZDilZDilojilojilZciLCAi4pWa4paI4paI4paI4paI4paI4pWU4pWdIiwgIuKWiOKWiOKVlOKVkOKVkOKWiOKWiOKVlyIsICLilZrilojilojilojilojilojilZTilZ0iLCAiIOKVmuKVkOKVkOKVkOKVkOKVnSAiXSwgIjkiOiBbIiDilojilojilojilojilojilZcgIiwgIuKWiOKWiOKVlOKVkOKVkOKWiOKWiOKVlyIsICLilZrilojilojilojilojilojilZTilZ0iLCAiIOKVmuKVkOKVkOKVkOKWiOKWiOKVkSIsICIg4paI4paI4paI4paI4paI4pWU4pWdIiwgIiDilZrilZDilZDilZDilZDilZ0gIl19"
try {
    $WinText  = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($BannerWindowsB64))
    $ToolText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($BannerToolB64))
    $toolWidth = ($ToolText -split "`n" | Select-Object -First 1).Length
    $winWidth  = ($WinText -split "`n" | Select-Object -First 1).Length
    # WINDOWS block art - centered relative to AUDIT TOOL width
    foreach ($wLine in ($WinText -split "`n")) {
        $pad = [math]::Max(0, [math]::Floor(($toolWidth - $winWidth) / 2))
        Write-Host ((" " * $pad) + $wLine) -ForegroundColor White
    }
    # AUDIT TOOL block art
    Write-Host $ToolText -ForegroundColor Cyan
    # Separator line
    Write-Host ((" " * [math]::Max(0, [math]::Floor(($toolWidth - 40) / 2))) + ("-" * 40)) -ForegroundColor DarkGray
    # Render version in block art
    $charMap = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($VerCharMapB64)) | ConvertFrom-Json
    $verStr = "v" + ($ScriptVersion -replace '^v', '')
    $lines = @("","","","","","")
    foreach ($ch in $verStr.ToCharArray()) {
        $key = [string]$ch
        if ($charMap.PSObject.Properties[$key]) {
            $art = @($charMap.$key)
            for ($i = 0; $i -lt 6; $i++) { $lines[$i] += $art[$i] + " " }
        }
    }
    foreach ($line in $lines) {
        $pad = [math]::Max(0, [math]::Floor(($toolWidth - $line.Length) / 2))
        Write-Host ((" " * $pad) + $line) -ForegroundColor DarkCyan
    }
    Write-Host ""
} catch { }
Write-Host "  Starting System Audit for $ComputerName" -ForegroundColor Cyan
Write-Host ""
} # end if (-not $Silent) banner block
Log "INIT: banner complete"
Log "Audit started for $ComputerName (v$ScriptVersion)"

# Apply any pending .exe update from a prior run
Invoke-PendingExeSwap

# Determine if the user requested an update
$WantUpdate       = $UpdateAll -or $UpdateScript -or $UpdateExe
$WantUpdateScript = $UpdateAll -or $UpdateScript
$WantUpdateExe    = $UpdateAll -or $UpdateExe

# Check for updates - skipped in Silent mode unless an update flag was explicitly passed
$UpdateInfo = if ($WantUpdate -or -not $Silent) { Test-ForUpdate } else { $null }
if ($UpdateInfo -and $UpdateInfo.UpdateAvailable) {
    if ($WantUpdate) {
        # Explicit update request
        $doScript = $WantUpdateScript
        $doExe    = $WantUpdateExe

        Write-Host ("    Updating: {0} -> {1}" -f $UpdateInfo.CurrentVersion, $UpdateInfo.LatestVersion) -ForegroundColor Cyan
        Log ("Performing update: {0} -> {1}" -f $UpdateInfo.CurrentVersion, $UpdateInfo.LatestVersion)

        $didUpdate = Invoke-SelfUpdate -UpdateInfo $UpdateInfo -IncludeScript:$doScript -IncludeExe:$doExe
        if ($didUpdate -and $doScript -and $PSCommandPath -and $UpdateInfo.Ps1DownloadUrl) {
            # .ps1 was replaced - re-launch the updated script (without update flags) and exit
            Write-Host "    Restarting with updated script..." -ForegroundColor Cyan
            Log "Self-update: re-launching updated .ps1"
            $relaunchExtra = ""
            if ($Silent) { $relaunchExtra += " -Silent" }
            if ($CustomerName) { $relaunchExtra += " -CustomerName `"$CustomerName`"" }
            $relaunchArgs = "-ExecutionPolicy Bypass -File `"$PSCommandPath`"$relaunchExtra"
            Start-Process powershell.exe -ArgumentList $relaunchArgs -NoNewWindow -Wait
            exit $LASTEXITCODE
        }
    } else {
        # Interactive default: notify and pause
        Write-Host ""
        Write-Host ("    Update available: {0} -> {1}" -f $UpdateInfo.CurrentVersion, $UpdateInfo.LatestVersion) -ForegroundColor Yellow
        Write-Host "    It is recommended you update before continuing." -ForegroundColor Yellow
        Write-Host "    Restart the script with one of the following switches:" -ForegroundColor Yellow
        Write-Host "      .\Run-Audit.ps1 -UpdateAll       # update script + binary" -ForegroundColor Yellow
        Write-Host "      .\Run-Audit.ps1 -UpdateScript    # update script only" -ForegroundColor Yellow
        Write-Host "      .\Run-Audit.ps1 -UpdateExe       # update binary only" -ForegroundColor Yellow
        Write-Host ""
        Log ("Update available: {0} -> {1} ({2})" -f $UpdateInfo.CurrentVersion, $UpdateInfo.LatestVersion, $UpdateInfo.ReleaseUrl)
        Write-Host "    Press ENTER to continue with the current version..." -ForegroundColor DarkYellow
        [void][System.Console]::ReadLine()
    }
} elseif ($UpdateInfo) {
    if ($WantUpdate) {
        Write-Host "    Already up to date (v$ScriptVersion)" -ForegroundColor Green
    } else {
        Write-Host "    Version: up to date" -ForegroundColor Green
    }
} elseif ($WantUpdate) {
    Write-Host "    Update check failed (no internet or GitHub unreachable). Continuing..." -ForegroundColor Yellow
}

$IsElevated = Test-IsElevated
if (-not $IsElevated -and -not $Silent) {
    Start-SelfElevate
    $IsElevated = Test-IsElevated
}

if ($IsElevated) {
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
        Write-Action -What "Process execution policy set to Bypass for this session." -Kind ok
        Log "Process execution policy set to Bypass"
    }
    catch {
        Write-Action -What "Failed to set process execution policy. Continuing anyway." -Kind warn
        Log "Failed to set process execution policy: $_"
    }
}

Write-Mode -IsElevated:$IsElevated

# ------------------------------------ #
# Output Directory Routing             #
# ------------------------------------ #
# RMM/Silent (or running from C:\Program Files\...):
#   Reports -> C:\Program Files\Windows Audit Tool\Results\
#   Logs    -> C:\Program Files\Windows Audit Tool\Logs\
# Interactive (any other location):
#   Reports -> <script-dir>\Windows Audit Tool\
#   Logs    -> <script-dir>\Windows Audit Tool\
if ($IsRmmMode) {
    $ProgramFilesBase = "C:\Program Files\Windows Audit Tool"
    $ReportDir        = Join-Path $ProgramFilesBase "Results"
    $LogDir           = Join-Path $ProgramFilesBase "Logs"
} else {
    $OutputBase = Join-Path (if ($ScriptDir) { $ScriptDir } else { $env:USERPROFILE }) "Windows Audit Tool"
    $ReportDir  = $OutputBase
    $LogDir     = $OutputBase
}

foreach ($dir in @($ReportDir, $LogDir)) {
    if ($dir -and -not (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue)) {
        New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

# Update $LogPath to its final destination now that the output directory is resolved.
# The first few startup log entries already landed in the bootstrap path (C:\Windows\Temp\AuditLog.txt).
$LogPath = Join-Path $LogDir "AuditLog.txt"
Log ("Log continued at final path: {0}" -f $LogPath)

$HtmlReportPath     = Join-Path $ReportDir "${ComputerName}-Audit.html"
$HuduHtmlReportPath = Join-Path $ReportDir "${ComputerName}-Audit-Hudu.html"
Log ("Report output directory: {0}" -f $ReportDir)

# ------------------------- #
# Hudu Parameter Validation  #
# ------------------------- #
$HuduValid = $false
if ($HuduReport) {
    # Enforce TLS 1.2 for PS 5.1 (older defaults may reject Hudu's HTTPS cert)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $missingParams = @()
    if (-not $HuduAPIKey)           { $missingParams += "-HuduAPIKey" }
    if (-not $HuduBaseURL)          { $missingParams += "-HuduBaseURL" }
    if (-not $HuduCompanySlug)       { $missingParams += "-HuduCompanySlug" }
    if (-not $HuduAssetLayoutName)  { $missingParams += "-HuduAssetLayoutName" }

    if ($missingParams.Count -gt 0) {
        Write-Host ""
        Write-Host "  Hudu integration enabled but missing required parameters:" -ForegroundColor Red
        foreach ($p in $missingParams) {
            Write-Host "    - $p" -ForegroundColor Red
        }
        Write-Host "  Hudu upload will be skipped. The audit will continue normally." -ForegroundColor Yellow
        Write-Host ""
        Log ("Hudu: skipped - missing parameters: {0}" -f ($missingParams -join ", "))
    } else {
        $HuduValid = $true
        # Store in script-scope so Invoke-HuduRequest can access from nested functions
        $script:_HuduAPIKey  = $HuduAPIKey
        $script:_HuduBaseURL = $HuduBaseURL
        Write-Action -What "Hudu integration enabled" -Kind ok
        Write-Action -What ("  Base URL: {0}" -f $HuduBaseURL) -Kind info
        Write-Action -What ("  Company slug: {0}" -f $HuduCompanySlug) -Kind info
        Write-Action -What ("  Layout: {0}" -f $HuduAssetLayoutName) -Kind info
        Log ("Hudu: enabled - URL={0}, Slug={1}, Layout={2}" -f $HuduBaseURL, $HuduCompanySlug, $HuduAssetLayoutName)

        # Resolve company name and numeric ID from slug
        Write-Action -What "Resolving company name from Hudu..." -Kind run
        try {
            $huduCompany = Get-HuduCompanyBySlug -Slug $HuduCompanySlug
            if ($huduCompany -and $huduCompany.name) {
                $script:_HuduCompanyId = $huduCompany.id
                $CustomerName = $huduCompany.name
                Write-Action -What ("Company: {0} (ID {1})" -f $CustomerName, $huduCompany.id) -Kind ok
                Log ("Hudu: resolved company '{0}' (ID {1}) from slug '{2}'" -f $CustomerName, $huduCompany.id, $HuduCompanySlug)
            } else {
                Write-Action -What "Could not resolve company from slug '$HuduCompanySlug'." -Kind bad
                Log ("Hudu: slug '{0}' not found" -f $HuduCompanySlug)
                $HuduValid = $false
            }
        } catch {
            Write-Action -What ("Company lookup failed: {0}" -f $_.Exception.Message) -Kind bad
            Log ("Hudu: company lookup failed - {0}" -f $_.Exception.Message)
            $HuduValid = $false
        }
    }
}

# ------------------------- #
# Customer Name             #
# ------------------------- #
if (-not $CustomerName -and -not $Silent) {
    Write-Host ""
    Write-Host "Enter customer / business name (or press ENTER to skip):" -ForegroundColor Cyan
    $inputName = [System.Console]::ReadLine()
    if ($inputName -and $inputName.Trim() -ne "") {
        $CustomerName = $inputName.Trim()
    }
}
if ($CustomerName) {
    Write-Action -What ("Customer: {0}" -f $CustomerName) -Kind ok
    Log ("Customer name: {0}" -f $CustomerName)
    $HtmlReportPath     = Join-Path $ReportDir "${CustomerName} - ${ComputerName}-Audit.html"
    $HuduHtmlReportPath = Join-Path $ReportDir "${CustomerName} - ${ComputerName}-Audit-Hudu.html"
}

# ============================================================
# [1] SYSTEM INFORMATION
# ============================================================
Write-Step -Index 1 -Total 13 -Title "Collecting system information..."
Write-Action -What "Running: System Information (CIM/Registry)" -Kind run
Html-StartSection "System Information"

$kv = [ordered]@{}

$compName = Safe-Invoke { $env:COMPUTERNAME } "Computer Name"
$kv["Computer Name"] = $compName
Write-Action -What ("Computer Name: {0}" -f $compName) -Kind ok

$os = Safe-Invoke { Get-CimInstance Win32_OperatingSystem } "Operating System"
if ($os -ne "Error") {
    $kv["Operating System"] = $os.Caption
    $kv["OS Version"]       = $os.Version
    $kv["Build Number"]     = $os.BuildNumber
    $kv["Architecture"]     = $os.OSArchitecture

    Write-Action -What ("OS: {0} (v{1}, build {2}, {3})" -f $os.Caption, $os.Version, $os.BuildNumber, $os.OSArchitecture) -Kind ok
} else {
    Write-Action -What "Operating System: Error" -Kind warn
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
    $kv["Processor"]          = $cpu.Name
    $kv["Cores"]              = $cpu.NumberOfCores
    $kv["Logical Processors"] = $cpu.NumberOfLogicalProcessors
}

$mem = Safe-Invoke { Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory } "Memory Info"
if ($mem -ne "Error") {
    $ramGB = [math]::Round($mem.TotalPhysicalMemory / 1GB, 2)
    $kv["Installed RAM (GB)"] = $ramGB
}

$boot = if ($os -ne "Error" -and $os) { $os.LastBootUpTime } else { Safe-Invoke { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } "Uptime" }
if ($boot -ne "Error" -and $boot) {
    $uptime = New-TimeSpan -Start $boot
    $kv["Uptime"] = ("{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)
}

Html-AddKV -Pairs $kv

# Uptime health check - machines that haven't rebooted miss kernel-level patches
if ($boot -ne "Error" -and $boot) {
    if ($uptime.TotalDays -gt 30) {
        Write-Action -What ("Uptime: {0} days (exceeds 30-day threshold)" -f $uptime.Days) -Kind warn
        Html-AddNote -Text ("System has not rebooted in {0} days. Machines that go without rebooting for extended periods may be missing kernel-level patches." -f $uptime.Days) -Kind warn `
            -KbUrl "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview" -KbTitle "Windows Update overview"
    } else {
        Html-AddNote -Text ("Last reboot: {0} days ago" -f $uptime.Days) -Kind good
    }
}

$disks = Safe-Invoke { Get-CimInstance Win32_DiskDrive | Select-Object Model, Size } "Disk Info"
if ($disks -ne "Error" -and $disks) {
    $diskList = @($disks) | ForEach-Object {
        [pscustomobject]@{
            Model  = $_.Model
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
Write-Step -Index 2 -Total 13 -Title "Collecting installed software..."
Write-Action -What ("Running: Installed Software (Scope: {0})" -f ($(if($IsElevated){"HKLM/HKCU + HKU/offline + AppX(all users) + Winget(best-effort)"} else {"HKLM/HKCU + AppX(current user) + Winget(best-effort)"}))) -Kind run
Html-StartSection "Installed Software"

$apps = Safe-Invoke { Get-InstalledSoftwareInventory -IncludeAllUsers:($IsElevated) } "Installed Software"

if ($apps -ne "Error" -and $apps) {
    $appsListRaw = @($apps)
    $rawCount = $appsListRaw.Count

    # Remove duplicates (same Name + same Version) while keeping distinct versions.
    $appsList = Remove-SoftwareDuplicates -Items $appsListRaw
    $dedupCount = @($appsList).Count

    if ($dedupCount -ne $rawCount) {
        Write-Action -What ("Applications de-duplicated: {0} -> {1}" -f $rawCount, $dedupCount) -Kind info
    } else {
        Write-Action -What ("Applications de-duplicated: no duplicates found ({0})" -f $dedupCount) -Kind info
    }

    $appsList = @($appsList) | Sort-Object DisplayName, DisplayVersion, Scope
    $appCount = @($appsList).Count

    Write-Action -What ("Applications found: {0}" -f $appCount) -Kind ok
    Html-AddNote -Text ("Applications found: {0}" -f $appCount) -Kind info

    Html-StartDetails -Summary ("Applications ({0})" -f $appCount)
    Html-Add "<input type='text' id='sw-filter' placeholder='Filter software...' class='filter-box' onkeyup='filterSoftwareTable()'>"
    Html-Add "<div id='sw-filter-count' class='small'></div>"
    Html-AddTable -Items $appsList -Columns @(
        @{ Header="Name";      Property="DisplayName" },
        @{ Header="Version";   Property="DisplayVersion" },
        @{ Header="Publisher"; Property="Publisher" },
        @{ Header="Scope";     Property="Scope" },
        @{ Header="Sources";   Property="Sources" }
    )
    Html-Add @"
<script>
function filterSoftwareTable(){
  var f=document.getElementById('sw-filter').value.toLowerCase();
  var tbl=document.getElementById('sw-filter').closest('details').querySelector('table');
  if(!tbl)return;
  var rows=tbl.querySelectorAll('tbody tr');
  var shown=0;
  for(var i=0;i<rows.length;i++){
    var txt=rows[i].textContent.toLowerCase();
    var match=!f||txt.indexOf(f)!==-1;
    rows[i].style.display=match?'':'none';
    if(match)shown++;
  }
  var c=document.getElementById('sw-filter-count');
  c.textContent=f?'Showing '+shown+' of '+rows.length+' applications':'';
}
</script>
"@
    Html-EndDetails
}
else {
    Write-Action -What "Installed software inventory failed." -Kind warn
    Html-AddNote -Text "Could not retrieve installed software list." -Kind warn
}

Html-EndSection

# ============================================================
# [3] WINDOWS PATCHES / HOTFIXES
#   Recommendation applied:
#   - Try Get-HotFix in BOTH elevated and non-elevated sessions.
#   - Only suggest elevation if it fails while non-elevated.
# ============================================================
Write-Step -Index 3 -Total 13 -Title "Collecting installed Windows patches..."
Write-Action -What "Running: Installed patches/hotfixes (Get-HotFix)" -Kind run
Html-StartSection "Windows Patches / Hotfixes"

$patches = Safe-Invoke { Get-HotFix | Sort-Object InstalledOn -Descending } "Windows Patches"

if ($patches -ne "Error" -and $patches) {
    $patchList  = @($patches) | Sort-Object InstalledOn -Descending
    $patchCount = $patchList.Count

    # Patch currency check - how recently was the last patch applied?
    $latestPatch = $patchList | Where-Object { $_.InstalledOn } | Select-Object -First 1
    if ($latestPatch -and $latestPatch.InstalledOn) {
        $daysSincePatch = [math]::Floor((New-TimeSpan -Start $latestPatch.InstalledOn).TotalDays)
        if ($daysSincePatch -gt 90) {
            Write-Action -What ("Last patch: {0} days ago (exceeds 90-day threshold)" -f $daysSincePatch) -Kind bad
            Html-AddNote -Text ("Last patch was installed {0} days ago (KB: {1}). Systems should be patched at least every 90 days." -f $daysSincePatch, $latestPatch.HotFixID) -Kind bad `
                -KbUrl "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview" -KbTitle "Windows Update overview"
        } elseif ($daysSincePatch -gt 30) {
            Write-Action -What ("Last patch: {0} days ago (exceeds 30-day threshold)" -f $daysSincePatch) -Kind warn
            Html-AddNote -Text ("Last patch was installed {0} days ago (KB: {1}). Consider applying recent updates." -f $daysSincePatch, $latestPatch.HotFixID) -Kind warn `
                -KbUrl "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview" -KbTitle "Windows Update overview"
        } else {
            Html-AddNote -Text ("Last patch installed {0} days ago (KB: {1}). Patch currency is healthy." -f $daysSincePatch, $latestPatch.HotFixID) -Kind good
        }
    }

    Write-Action -What ("Patches found: {0}" -f $patchCount) -Kind ok

    $open = $false
    if ($patchCount -le 200) { $open = $true }

    Html-StartDetails -Summary ("Hotfixes ({0})" -f $patchCount) -Open:($open)

    $patchRows = $patchList | ForEach-Object {
        [pscustomobject]@{
            KB          = $_.HotFixID
            InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToShortDateString() } else { "Unknown" }
            Description = $_.Description
        }
    }

    Html-AddTable -Items $patchRows -Columns @(
        @{ Header="KB";           Property="KB" },
        @{ Header="Installed On"; Property="InstalledOn" },
        @{ Header="Description";  Property="Description" }
    )
    Html-EndDetails
}
elseif ($patches -eq "Error") {
    if (-not $IsElevated) {
        Write-Action -What "Hotfix inventory failed (non-elevated). Try running as Administrator." -Kind warn
        Html-AddNote -Text "Could not retrieve hotfixes in a non-elevated session. Try running as Administrator." -Kind warn
    } else {
        Write-Action -What "Hotfix inventory failed (even when elevated). Likely WMI/permissions issue." -Kind warn
        Html-AddNote -Text "Could not retrieve hotfixes (even when elevated). This may indicate WMI health/permissions issues." -Kind warn
    }
}
else {
    Write-Action -What "No installed hotfixes returned." -Kind info
    Html-AddNote -Text "No installed patches / hotfixes found." -Kind info
}

Html-EndSection

# ============================================================
# [4] PENDING WINDOWS UPDATES (WUA API)
# ============================================================
Write-Step -Index 4 -Total 13 -Title "Checking pending Windows Updates..."
Html-StartSection "Pending Windows Updates"

# ---- Last successful scan time ----
$wuLastScan = Safe-Invoke {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'
    $val = Get-ItemProperty -Path $regPath -Name LastSuccessTime -ErrorAction SilentlyContinue
    if ($val -and $val.LastSuccessTime) {
        $dt   = [datetime]::Parse($val.LastSuccessTime)
        $days = ([datetime]::Now - $dt).Days
        [pscustomobject]@{ DateTime = $dt.ToString('yyyy-MM-dd HH:mm'); DaysAgo = $days }
    } else { $null }
} "WU Last Scan Time"

# ---- Update source: WSUS / WUfB policy ----
$wuPolicy = Safe-Invoke {
    $p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    [pscustomobject]@{
        WUServer                        = if ($p) { [string]$p.WUServer } else { $null }
        UseWUServer                     = if ($p) { $p.UseWUServer } else { $null }
        DisableWindowsUpdateAccess      = if ($p) { $p.DisableWindowsUpdateAccess } else { $null }
        TargetGroup                     = if ($p) { [string]$p.TargetGroup } else { $null }
        DeferQualityUpdates             = if ($p) { $p.DeferQualityUpdates } else { $null }
        DeferQualityUpdatesPeriodInDays = if ($p) { $p.DeferQualityUpdatesPeriodInDays } else { $null }
        DeferFeatureUpdates             = if ($p) { $p.DeferFeatureUpdates } else { $null }
        DeferFeatureUpdatesPeriodInDays = if ($p) { $p.DeferFeatureUpdatesPeriodInDays } else { $null }
    }
} "WU/WUfB Policy"

# ---- Pending reboot signals ----
$rebootPending = Safe-Invoke {
    $signals = [System.Collections.Generic.List[string]]::new()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $signals.Add('Windows Update')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $signals.Add('Component Servicing')
    }
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $signals.Add('File Rename Operations') }
    [pscustomobject]@{ Pending = ($signals.Count -gt 0); Signals = ($signals -join ', ') }
} "Pending Reboot Check"

# ---- Microsoft Update service registration ----
$muEnabled = Safe-Invoke {
    $muGuid = '{7971f918-a847-4430-9279-4a52d1efe18d}'
    $svcMgr = New-Object -ComObject Microsoft.Update.ServiceManager
    $mu     = @($svcMgr.Services) | Where-Object { $_.ServiceID -eq $muGuid } | Select-Object -First 1
    [bool]($mu -and $mu.IsRegisteredWithAU)
} "Microsoft Update Service"

Write-Action -What "Running: Pending updates (WUA API)" -Kind run
$pendingUpdates = Safe-Invoke { Get-PendingWindowsUpdatesWUA } "Pending Windows Updates (WUA API)"

# ---- Summary header table ----
Html-Add "<table class='kv-table'><tbody>"

if ($wuLastScan -ne "Error" -and $wuLastScan) {
    $scanClass = if ($wuLastScan.DaysAgo -le 7) { '' } elseif ($wuLastScan.DaysAgo -le 30) { 'sev-warn' } else { 'sev-bad' }
    Html-Add ("<tr class='{0}'><th>Last Scan</th><td>{1} ({2} days ago)</td></tr>" -f $scanClass, (Html-Enc $wuLastScan.DateTime), (Html-Enc $wuLastScan.DaysAgo))
    Write-Action -What ("Last WU scan: {0} ({1} days ago)" -f $wuLastScan.DateTime, $wuLastScan.DaysAgo) -Kind $(if ($wuLastScan.DaysAgo -le 7) { "ok" } elseif ($wuLastScan.DaysAgo -le 30) { "warn" } else { "bad" })
} else {
    Html-Add "<tr class='sev-warn'><th>Last Scan</th><td>Could not determine</td></tr>"
}

if ($wuPolicy -ne "Error" -and $wuPolicy) {
    if ($wuPolicy.UseWUServer -eq 1 -and $wuPolicy.WUServer) {
        $srcText = "WSUS: $($wuPolicy.WUServer)"
        if ($wuPolicy.TargetGroup) { $srcText += " (Target group: $($wuPolicy.TargetGroup))" }
        Html-Add ("<tr><th>Update Source</th><td>{0}</td></tr>" -f (Html-Enc $srcText))
    } else {
        Html-Add "<tr><th>Update Source</th><td>Windows Update (direct / Microsoft)</td></tr>"
    }
    if ($wuPolicy.DisableWindowsUpdateAccess -eq 1) {
        Html-AddNote -Text "Windows Update access is disabled by policy - users cannot manually check for updates." -Kind warn `
            -KbUrl "https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings" -KbTitle "Windows Update policy settings"
    }
}

if ($muEnabled -ne "Error") {
    $muClass = if ($muEnabled) { 'sev-good' } else { 'sev-warn' }
    $muText  = if ($muEnabled) { 'Enabled (Office and other Microsoft products included)' } else { 'Disabled (Windows only; Office and other products excluded)' }
    Html-Add ("<tr class='{0}'><th>Microsoft Update</th><td>{1}</td></tr>" -f $muClass, (Html-Enc $muText))
    Write-Action -What ("Microsoft Update: {0}" -f $(if ($muEnabled) { "Enabled" } else { "Disabled" })) -Kind $(if ($muEnabled) { "ok" } else { "warn" })
}

if ($rebootPending -ne "Error" -and $rebootPending) {
    $rbClass = if ($rebootPending.Pending) { 'sev-warn' } else { '' }
    $rbText  = if ($rebootPending.Pending) { "Yes ($($rebootPending.Signals))" } else { 'No' }
    Html-Add ("<tr class='{0}'><th>Reboot Pending</th><td>{1}</td></tr>" -f $rbClass, (Html-Enc $rbText))
    if ($rebootPending.Pending) {
        Write-Action -What ("Reboot pending: {0}" -f $rebootPending.Signals) -Kind warn
    }
}

Html-Add "</tbody></table>"

# ---- Pending updates ----
if ($pendingUpdates -eq "Error") {
    Write-Action -What "Pending updates query failed." -Kind bad
    Html-AddNote -Text "Could not query pending updates (WUA API)." -Kind bad
}
else {
    $real = $pendingUpdates.Pending
    $meta = $pendingUpdates.MetaInfo

    if ($meta) {
        Html-Add ("<p class='small'><span class='code'>WUA:</span> ResultCode={0}; Count={1}</p>" -f (Html-Enc $meta.PendingResultCode), (Html-Enc $meta.PendingCount))
    }

    if (-not $real -or @($real).Count -eq 0) {
        Write-Action -What "No pending updates found." -Kind ok
        Html-AddNote -Text "No pending updates found." -Kind good
    }
    else {
        $count   = @($real).Count
        $cCrit   = @($real | Where-Object { $_.Categories -match 'Critical Updates' }).Count
        $cSec    = @($real | Where-Object { $_.Categories -match 'Security Updates' -and $_.Categories -notmatch 'Critical Updates' }).Count
        $cDriver = @($real | Where-Object { $_.Categories -match 'Drivers' }).Count
        $cEula   = @($real | Where-Object { $_.EulaAccepted -eq $false }).Count
        $cOther  = $count - $cCrit - $cSec - $cDriver

        $summaryParts = [System.Collections.Generic.List[string]]::new()
        if ($cCrit   -gt 0) { $summaryParts.Add("Critical: $cCrit") }
        if ($cSec    -gt 0) { $summaryParts.Add("Security: $cSec") }
        if ($cDriver -gt 0) { $summaryParts.Add("Drivers: $cDriver") }
        if ($cOther  -gt 0) { $summaryParts.Add("Other: $cOther") }
        $summaryStr = if ($summaryParts.Count -gt 0) { $summaryParts -join ' | ' } else { "Total: $count" }

        $overallKind = if ($cCrit -gt 0 -or $cSec -gt 0) { "bad" } else { "warn" }
        Write-Action -What ("Pending updates: {0} - {1}" -f $count, $summaryStr) -Kind $overallKind
        Html-AddNote -Text ("Pending updates: {0} - {1}" -f $count, $summaryStr) -Kind $(if ($cCrit -gt 0 -or $cSec -gt 0) { "bad" } else { "warn" })

        if ($cEula -gt 0) {
            Html-AddNote -Text ("$cEula update(s) have not had their EULA accepted and will not install automatically.") -Kind warn
        }

        $updateRows = @($real) | ForEach-Object {
            [pscustomobject]@{
                KB             = $_.KB
                Title          = $_.Title
                Categories     = $_.Categories
                Downloaded     = $_.Downloaded
                Mandatory      = $_.Mandatory
                RebootRequired = $_.RebootRequired
                EulaAccepted   = $_.EulaAccepted
            }
        }

        Html-StartDetails -Summary ("Pending Updates ({0})" -f $count) -Open
        Html-AddTable -Items $updateRows -Columns @(
            @{ Header="KB";            Property="KB" },
            @{ Header="Title";         Property="Title" },
            @{ Header="Categories";    Property="Categories" },
            @{ Header="Downloaded";    Property="Downloaded" },
            @{ Header="Mandatory";     Property="Mandatory" },
            @{ Header="Reboot";        Property="RebootRequired" },
            @{ Header="EULA Accepted"; Property="EulaAccepted" }
        ) -RowClass {
            param($r)
            if ($r.Categories -match 'Critical Updates|Security Updates') { return 'sev-bad' }
            if ($r.RebootRequired -eq $true -or $r.Mandatory -eq $true)   { return 'sev-bad' }
            return 'sev-warn'
        }
        Html-EndDetails
    }

    # ---- Hidden updates ----
    $hiddenList = $pendingUpdates.Hidden
    if ($hiddenList -and @($hiddenList).Count -gt 0) {
        $hCount = @($hiddenList).Count
        Write-Action -What ("Hidden updates: {0} (excluded from auto-install)" -f $hCount) -Kind warn
        Html-AddNote -Text ("$hCount update(s) are hidden and will not install automatically. Review whether any are security-relevant.") -Kind warn
        Html-StartDetails -Summary ("Hidden Updates ({0})" -f $hCount)
        Html-AddTable -Items $hiddenList -Columns @(
            @{ Header="KB";         Property="KB" },
            @{ Header="Title";      Property="Title" },
            @{ Header="Categories"; Property="Categories" }
        ) -RowClass { param($r) 'sev-warn' }
        Html-EndDetails
    }

    # ---- Failed update history (last 30 days) ----
    $failedList = $pendingUpdates.Failed
    if ($failedList -and @($failedList).Count -gt 0) {
        $fCount = @($failedList).Count
        Write-Action -What ("Failed updates (last 30 days): {0}" -f $fCount) -Kind bad
        Html-AddNote -Text ("$fCount update installation(s) failed in the last 30 days.") -Kind bad `
            -KbUrl "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-troubleshooting" -KbTitle "Windows Update troubleshooting"
        Html-StartDetails -Summary ("Failed Updates - Last 30 Days ({0})" -f $fCount)
        Html-AddTable -Items $failedList -Columns @(
            @{ Header="KB";      Property="KB" },
            @{ Header="Title";   Property="Title" },
            @{ Header="Date";    Property="Date" },
            @{ Header="HResult"; Property="HResult" }
        ) -RowClass { param($r) 'sev-bad' }
        Html-EndDetails
    }
}

Html-EndSection

# ============================================================
# [5] NETWORK ADAPTERS
# ============================================================
Write-Step -Index 5 -Total 13 -Title "Gathering network information..."
Html-StartSection "Network"

# ---- Adapter inventory ----
Write-Action -What "Running: Get-NetAdapter (full detail)" -Kind run
$adapters = Safe-Invoke {
    Get-NetAdapter | Sort-Object { if ($_.Status -eq 'Up') { 0 } else { 1 } }, Name |
    Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, MediaType,
        DriverVersion,
        @{ N='DriverDate'; E={ if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' } } },
        DriverProvider
} "Network Adapters"

if ($adapters -ne "Error" -and $adapters) {
    $adapterList = @($adapters)
    Write-Action -What ("Adapters found: {0}" -f $adapterList.Count) -Kind ok

    Html-StartDetails -Summary ("Network Adapters ({0})" -f $adapterList.Count) -Open
    Html-AddTable -Items $adapterList -Columns @(
        @{ Header="Name";         Property="Name" },
        @{ Header="Description";  Property="InterfaceDescription" },
        @{ Header="Status";       Property="Status" },
        @{ Header="MAC Address";  Property="MacAddress" },
        @{ Header="Speed";        Property="LinkSpeed" },
        @{ Header="Media Type";   Property="MediaType" },
        @{ Header="Driver";       Property="DriverVersion" },
        @{ Header="Driver Date";  Property="DriverDate" },
        @{ Header="Manufacturer"; Property="DriverProvider" }
    ) -RowClass {
        param($row)
        if     ($row.Status -eq 'Up')           { 'sev-good' }
        elseif ($row.Status -eq 'Disconnected') { '' }
        else                                    { 'sev-warn' }
    }
    Html-EndDetails
} else {
    Write-Action -What "Network adapter query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve network adapter information." -Kind warn
}

# ---- DHCP details from WMI (keyed by adapter description for correlation) ----
$dhcpMap = Safe-Invoke {
    $map = @{}
    @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True") | ForEach-Object {
        $map[$_.Description] = $_
    }
    $map
} "DHCP Configuration"

# ---- Per-adapter IP detail (connected adapters only) ----
Write-Action -What "Running: Get-NetIPConfiguration -Detailed" -Kind run
$ipConfigs = Safe-Invoke {
    @(Get-NetIPConfiguration -Detailed | Where-Object { $_.NetAdapter.Status -eq 'Up' })
} "Network IP Configuration"

if ($ipConfigs -ne "Error" -and $ipConfigs) {
    foreach ($cfg in $ipConfigs) {
        $adName = $cfg.InterfaceAlias
        $adDesc = if ($cfg.NetAdapter) { [string]$cfg.NetAdapter.InterfaceDescription } else { '' }

        # IPv4 with prefix length
        $ip4List = @($cfg.IPv4Address)
        $ip4 = if ($ip4List.Count -gt 0) {
            ($ip4List | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ' | '
        } else { 'N/A' }

        # IPv6 - globals first, then link-local
        $ip6List = @($cfg.IPv6Address | Where-Object { $_ })
        $ip6Parts = @()
        foreach ($a in ($ip6List | Where-Object { $_.IPAddress -notmatch '^fe80' })) {
            $ip6Parts += "$($a.IPAddress)/$($a.PrefixLength)"
        }
        foreach ($a in ($ip6List | Where-Object { $_.IPAddress -match '^fe80' })) {
            $ip6Parts += "$($a.IPAddress) (link-local)"
        }
        $ip6 = if ($ip6Parts) { $ip6Parts -join ' | ' } else { 'N/A' }

        # Gateways
        $gw4 = if ($cfg.IPv4DefaultGateway) {
            (@($cfg.IPv4DefaultGateway) | ForEach-Object { $_.NextHop }) -join ', '
        } else { 'N/A' }
        $gw6 = if ($cfg.IPv6DefaultGateway) {
            (@($cfg.IPv6DefaultGateway) | ForEach-Object { $_.NextHop }) -join ', '
        } else { 'N/A' }

        # DNS
        $dns = if ($cfg.DnsServer.ServerAddresses) { $cfg.DnsServer.ServerAddresses -join ', ' } else { 'N/A' }

        # DHCP status from NetIPv4Interface
        $dhcp4 = 'N/A'
        if ($cfg.NetIPv4Interface) {
            $dhcp4 = if ([string]$cfg.NetIPv4Interface.Dhcp -eq 'Enabled') { 'Enabled' } else { 'Disabled' }
        }

        # DHCP server + lease dates from WMI
        $dhcpServer = ''; $leaseObtained = ''; $leaseExpires = ''
        if ($dhcpMap -ne "Error" -and $dhcpMap -and $adDesc -and $dhcpMap.ContainsKey($adDesc)) {
            $wmi = $dhcpMap[$adDesc]
            if ($wmi.DHCPEnabled) {
                if ($wmi.DHCPServer)        { $dhcpServer    = [string]$wmi.DHCPServer }
                if ($wmi.DHCPLeaseObtained) { $leaseObtained = $wmi.DHCPLeaseObtained.ToString('yyyy-MM-dd HH:mm') }
                if ($wmi.DHCPLeaseExpires)  { $leaseExpires  = $wmi.DHCPLeaseExpires.ToString('yyyy-MM-dd HH:mm') }
            }
        }

        # Network profile (Public / Private / DomainAuthenticated)
        $netProfile = 'N/A'
        $profResult = Safe-Invoke {
            Get-NetConnectionProfile -InterfaceAlias $adName -ErrorAction SilentlyContinue
        } ("Net Profile: $adName")
        if ($profResult -ne "Error" -and $profResult) {
            $netProfile = [string]$profResult.NetworkCategory
        }

        # Link speed
        $speed = if ($cfg.NetAdapter -and $cfg.NetAdapter.LinkSpeed) { $cfg.NetAdapter.LinkSpeed } else { 'N/A' }

        Write-Action -What ("  $adName | $ip4 | GW $gw4") -Kind info

        $heading = if ($adDesc -and $adDesc -ne $adName) { "$adName - $adDesc" } else { $adName }
        Html-Add ("<h3>{0}</h3>" -f (Html-Enc $heading))

        $kv = [ordered]@{
            "IPv4 Address"    = $ip4
            "Default Gateway" = $gw4
            "DNS Servers"     = $dns
            "DHCP"            = $dhcp4
        }
        if ($dhcp4 -eq 'Enabled' -and $dhcpServer)  { $kv["DHCP Server"] = $dhcpServer }
        if ($leaseObtained -or $leaseExpires) {
            $leaseParts = @()
            if ($leaseObtained) { $leaseParts += "Obtained $leaseObtained" }
            if ($leaseExpires)  { $leaseParts += "Expires $leaseExpires" }
            $kv["Lease"] = $leaseParts -join '  ->  '
        }
        $kv["IPv6 Address"]    = $ip6
        if ($gw6 -ne 'N/A')    { $kv["IPv6 Gateway"]   = $gw6 }
        $kv["Network Profile"] = $netProfile
        $kv["Link Speed"]      = $speed

        Html-AddKV -Pairs $kv
    }
} elseif ($ipConfigs -eq "Error") {
    Write-Action -What "IP configuration query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve IP configuration details." -Kind warn
}

Html-EndSection

# ============================================================
# [6] SMB SHARES
# ============================================================
Write-Step -Index 6 -Total 13 -Title "Gathering SMB shares..."
Write-Action -What "Running: SMB shares (Get-SmbShare)" -Kind run
Html-StartSection "SMB Shares"

$shares = Safe-Invoke { Get-SmbShare | Select-Object Name, Path } "SMB Shares"

if ($shares -ne "Error" -and $shares) {
    $shareList = @($shares) | Sort-Object Name
    $nonAdmin = $shareList | Where-Object { $_.Name -notmatch '^\w\$$' -and $_.Name -notin @('ADMIN$', 'C$', 'IPC$') }

    if ($nonAdmin -and $nonAdmin.Count -gt 0) {
        Write-Action -What ("Non-admin SMB shares found: {0}" -f $nonAdmin.Count) -Kind warn
        Html-AddNote -Text ("Non-admin SMB shares found: {0}" -f $nonAdmin.Count) -Kind warn `
            -KbUrl "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3" -KbTitle "SMB security guidance"
    }
    else {
        Write-Action -What "No non-admin SMB shares found." -Kind ok
        Html-AddNote -Text "No non-admin SMB shares found." -Kind good
    }

    Html-StartDetails -Summary ("All Shares ({0})" -f $shareList.Count)
    Html-AddTable -Items $shareList -Columns @(
        @{ Header="Share"; Property="Name" },
        @{ Header="Path";  Property="Path" }
    ) -RowClass {
        param($r)
        $name = [string]$r.Name
        if ($name -match '^\w\$$' -or $name -in @('ADMIN$','C$','IPC$')) { return '' }
        return 'sev-warn'
    }
    Html-EndDetails
}
else {
    Write-Action -What "SMB share query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve SMB share information." -Kind warn
}

Html-EndSection

# ============================================================
# [7] PRINTERS
# ============================================================
Write-Step -Index 7 -Total 13 -Title "Gathering printers..."
Write-Action -What "Running: Printers (Get-Printer)" -Kind run
Html-StartSection "Printers"

$printers = Safe-Invoke { Get-Printer } "Printers"

if ($printers -ne "Error" -and $printers) {
    $printerList  = @($printers) | Sort-Object Name
    $printerCount = $printerList.Count

    Write-Action -What ("Printers found: {0}" -f $printerCount) -Kind ok
    Html-AddNote -Text ("Printers found: {0}" -f $printerCount) -Kind info

    Html-StartDetails -Summary ("Printers ({0})" -f $printerCount) -Open
    Html-AddTable -Items $printerList -Columns @(
        @{ Header="Name";    Property="Name" },
        @{ Header="Driver";  Property="DriverName" },
        @{ Header="Port";    Property="PortName" },
        @{ Header="Shared";  Property="Shared" },
        @{ Header="Default"; Property="Default" }
    )
    Html-EndDetails
}
elseif ($printers -eq "Error") {
    Write-Action -What "Printer query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve printers." -Kind warn
}
else {
    Write-Action -What "No printers found." -Kind info
    Html-AddNote -Text "No printers found." -Kind info
}

Html-EndSection

# ============================================================
# [8] SECURITY BASELINE CHECKS
# ============================================================
Write-Step -Index 8 -Total 13 -Title "Performing security baseline checks..."
Html-StartSection "Security Baseline Checks"

if (Write-PrivilegedGate -IsElevated:$IsElevated -What "Security baseline (BitLocker/TPM/SecureBoot/Firewall/Defender/Admins)") {

    # --- BitLocker ---
    Html-Add "<h3>BitLocker</h3>"
    $bitlocker = Safe-Invoke { Get-BitLockerVolume } "BitLocker Status"
    if ($bitlocker -ne "Error" -and $bitlocker) {
        $blRows = @($bitlocker) | ForEach-Object {
            $protOn = ($_.ProtectionStatus -eq 'On' -or $_.ProtectionStatus -eq 1)
            [pscustomobject]@{
                Volume           = $_.MountPoint
                Protection       = if ($protOn) { "<span class='badge good'>On</span>" } else { "<span class='badge warn'>Off</span>" }
                LockStatus       = $_.LockStatus
                EncryptionMethod = $_.EncryptionMethod
                _RowClass        = if ($protOn) { 'sev-good' } else { 'sev-warn' }
            }
        }

        Html-AddTable -Items $blRows -Columns @(
            @{ Header="Volume";            Property="Volume" },
            @{ Header="Protection";        Property="Protection"; Raw=$true },
            @{ Header="Lock Status";       Property="LockStatus" },
            @{ Header="Encryption Method"; Property="EncryptionMethod" }
        ) -RowClass { param($r) $r._RowClass }

        $off = @($bitlocker) | Where-Object { $_.ProtectionStatus -ne 'On' -and $_.ProtectionStatus -ne 1 }
        if ($off.Count -gt 0) {
            $offVols = ($off | ForEach-Object { $_.MountPoint }) -join ', '
            Write-Action -What ("BitLocker: {0} volume(s) not protected" -f $off.Count) -Kind warn
            Html-AddNote -Text ("BitLocker protection is off on volume(s): {0}" -f $offVols) -Kind warn `
                -KbUrl "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/" `
                -KbTitle "BitLocker overview"
        } else {
            Write-Action -What "BitLocker: Protection ON for all detected volumes" -Kind ok
        }
    }
    else {
        Write-Action -What "BitLocker query failed." -Kind warn
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
        Write-Action -What "TPM query failed." -Kind warn
        Html-AddNote -Text "Could not retrieve TPM status." -Kind warn
    }

    # --- Secure Boot ---
    Html-Add "<h3>Secure Boot</h3>"
    $secureBoot = Safe-Invoke { Confirm-SecureBootUEFI } "Secure Boot Check"
    if ($secureBoot -eq $true) {
        Html-AddNote -Text "Secure Boot: Enabled" -Kind good
    }
    elseif ($secureBoot -eq $false) {
        Html-AddNote -Text "Secure Boot: Disabled" -Kind warn `
            -KbUrl "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot" -KbTitle "Secure Boot overview"
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
            @{ Header="Profile";                 Property="Profile" },
            @{ Header="Enabled";                 Property="Enabled"; Raw=$true },
            @{ Header="Default Inbound Action";  Property="Inbound" },
            @{ Header="Default Outbound Action"; Property="Outbound" }
        )
        $fwOff = @($fw) | Where-Object { $_.Enabled -ne $true }
        if ($fwOff.Count -gt 0) {
            $fwOffNames = ($fwOff | ForEach-Object { $_.Name }) -join ', '
            Html-AddNote -Text ("Windows Firewall disabled on profile(s): {0}" -f $fwOffNames) -Kind warn `
                -KbUrl "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/" `
                -KbTitle "Windows Firewall overview"
        }
    }
    else {
        Write-Action -What "Firewall profile query failed." -Kind warn
        Html-AddNote -Text "Could not retrieve firewall settings." -Kind warn
    }

    # --- Anti-Virus Products ---
    Html-Add "<h3>Anti-Virus Products</h3>"
    $av = Safe-Invoke {
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
            Select-Object displayName, productState
    } "AntiVirus Products"

    $avList = @()
    if ($av -ne "Error" -and $av) {
        # Deduplicate by displayName - enterprise suites (e.g. Sophos Intercept X) register
        # multiple sub-components under the same product name in SecurityCenter2.
        # Keep the entry that reports "On" status; fall back to first occurrence.
        $avSeen    = @{}
        $avDeduped = [System.Collections.Generic.List[object]]::new()
        foreach ($avEntry in @($av)) {
            $avName = $avEntry.displayName
            if (-not $avSeen.ContainsKey($avName)) {
                $avSeen[$avName] = $avEntry
                $avDeduped.Add($avEntry)
            } else {
                # Prefer the "On" state (0x1000) over any other entry for the same name
                $isOn = ([UInt32]$avEntry.productState -band 0xF000) -eq 0x1000
                if ($isOn) {
                    $avSeen[$avName] = $avEntry
                    $idx = $avDeduped.FindIndex([Predicate[object]]{ param($r) $r.displayName -eq $avName })
                    if ($idx -ge 0) { $avDeduped[$idx] = $avEntry }
                }
            }
        }
        $avList = @($avDeduped)
        Write-Action -What ("Anti-Virus products detected: {0} (after deduplication)" -f $avList.Count) -Kind info

        $avRows = $avList | ForEach-Object {
            [UInt32]$state = $_.productState

            # Decode productState groups (reverse-engineered but widely used):
            # - ProductState   : 0xF000 (On=0x1000, Snoozed=0x2000, Expired=0x3000, Off=0x0000)
            # - SignatureStatus: 0x00F0 (UpToDate=0x00, OutOfDate=0x10)
            $psBits  = $state -band 0xF000
            $sigBits = $state -band 0x00F0

            $engine = switch ($psBits) {
                0x1000 { "On" }
                0x2000 { "Snoozed" }
                0x3000 { "Expired" }
                default { "Off" }
            }

            $sig = switch ($sigBits) {
                0x0000 { "UpToDate" }
                0x0010 { "OutOfDate" }
                default { "Unknown" }
            }

            $statusBadge = switch ($engine) {
                "On"      { "<span class='badge good'>Enabled</span>" }
                "Snoozed" { "<span class='badge warn'>Snoozed</span>" }
                "Expired" { "<span class='badge bad'>Expired</span>" }
                default   { "<span class='badge bad'>Off</span>" }
            }

            [pscustomobject]@{
                Product             = $_.displayName
                RealtimeProtection  = $statusBadge
                Signatures          = if ($sig -eq "UpToDate") { "<span class='badge good'>Up-to-date</span>" }
                                      elseif ($sig -eq "OutOfDate") { "<span class='badge bad'>Out-of-date</span>" }
                                      else { "<span class='badge warn'>Unknown</span>" }
            }
        }

        Html-AddTable -Items $avRows -Columns @(
            @{ Header="Product";                Property="Product" },
            @{ Header="Real-time Protection";   Property="RealtimeProtection"; Raw=$true },
            @{ Header="Signatures";             Property="Signatures"; Raw=$true }
        )
        $avOffItems = @($avList) | Where-Object { ([UInt32]$_.productState -band 0xF000) -ne 0x1000 }
        if ($avOffItems.Count -gt 0) {
            $avOffNames = ($avOffItems | ForEach-Object { $_.displayName }) -join ', '
            Html-AddNote -Text ("Anti-Virus product(s) not active: {0}" -f $avOffNames) -Kind bad `
                -KbUrl "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows" `
                -KbTitle "Microsoft Defender Antivirus"
        }
    }
    else {
        Write-Action -What "Anti-Virus product query failed." -Kind warn
        Html-AddNote -Text "Could not retrieve Anti-Virus products (Security Center)." -Kind warn
    }

    # --- Defender ---
    # Third-party AV active = any non-Defender product with real-time protection on (0x1000).
    # When that is the case and Defender's own real-time protection is off (passive mode),
    # the Defender detail table is irrelevant — show a brief passive-mode note instead.
    $thirdPartyAvActive = @($avList | Where-Object {
        $_.displayName -notmatch 'Windows Defender|Microsoft Defender' -and
        ([UInt32]$_.productState -band 0xF000) -eq 0x1000
    }).Count -gt 0

    Html-Add "<h3>Windows Defender</h3>"
    $def = Safe-Invoke { Get-MpComputerStatus } "Defender Status"
    if ($def -ne "Error" -and $def) {
        if ($thirdPartyAvActive -and -not $def.RealTimeProtectionEnabled) {
            $activeAvNames = ($avList | Where-Object {
                $_.displayName -notmatch 'Windows Defender|Microsoft Defender' -and
                ([UInt32]$_.productState -band 0xF000) -eq 0x1000
            } | ForEach-Object { $_.displayName }) -join ', '
            Write-Action -What "Defender passive — third-party AV active: $activeAvNames" -Kind info
            Html-AddNote -Text "Windows Defender is in passive mode. $activeAvNames is the active antivirus — Defender details are not applicable." -Kind info
        } else {
            Html-AddKV -Pairs ([ordered]@{
                "Real-time protection"         = $def.RealTimeProtectionEnabled
                "Antivirus signature version"  = $def.AntivirusSignatureVersion
                "Last quick scan"              = $def.LastQuickScanEndTime
                "Last full scan"               = $def.LastFullScanEndTime
            })
        }
    }
    else {
        Write-Action -What "Defender status query failed." -Kind warn
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
        Write-Action -What "Local Administrators query failed." -Kind warn
        Html-AddNote -Text "Could not retrieve local administrator list." -Kind warn
    }
}
else {
    Html-AddNote -Text "Skipped (requires elevation)." -Kind warn
}

Html-EndSection

# ============================================================
# [9] LOCAL USER ACCOUNTS
# ============================================================
Write-Step -Index 9 -Total 13 -Title "Enumerating local user accounts..."
Write-Action -What "Running: Local user accounts (Get-LocalUser)" -Kind run
Html-StartSection "Local User Accounts"

$localUsers = Safe-Invoke { Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, AccountExpires, Description } "Local User Accounts"

if ($localUsers -ne "Error" -and $localUsers) {
    $userList = @($localUsers) | Sort-Object Name
    $userCount = $userList.Count
    $enabledCount = @($userList | Where-Object { $_.Enabled -eq $true }).Count
    $noPasswordReq = @($userList | Where-Object { $_.Enabled -eq $true -and $_.PasswordRequired -eq $false })

    Write-Action -What ("Local accounts: {0} ({1} enabled)" -f $userCount, $enabledCount) -Kind ok
    Html-AddNote -Text ("Local accounts: {0} total, {1} enabled" -f $userCount, $enabledCount) -Kind info

    if ($noPasswordReq.Count -gt 0) {
        Write-Action -What ("{0} enabled account(s) do not require a password" -f $noPasswordReq.Count) -Kind bad
        Html-AddNote -Text ("{0} enabled account(s) do not require a password" -f $noPasswordReq.Count) -Kind bad `
            -KbUrl "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements" -KbTitle "Password complexity requirements"
    }

    $userRows = $userList | ForEach-Object {
        [pscustomobject]@{
            Name             = $_.Name
            Enabled          = $_.Enabled
            PasswordRequired = $_.PasswordRequired
            LastLogon        = if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
            PasswordLastSet  = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Never" }
            Description      = $_.Description
        }
    }

    Html-StartDetails -Summary ("Accounts ({0})" -f $userCount) -Open
    Html-AddTable -Items $userRows -Columns @(
        @{ Header="Name";              Property="Name" },
        @{ Header="Enabled";           Property="Enabled" },
        @{ Header="Password Required"; Property="PasswordRequired" },
        @{ Header="Last Logon";        Property="LastLogon" },
        @{ Header="Password Last Set"; Property="PasswordLastSet" },
        @{ Header="Description";       Property="Description" }
    ) -RowClass {
        param($r)
        if ($r.Enabled -eq $false) { return '' }
        if ($r.PasswordRequired -eq $false) { return 'sev-bad' }
        return 'sev-good'
    }
    Html-EndDetails
}
else {
    Write-Action -What "Local user accounts query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve local user accounts." -Kind warn
}

Html-EndSection

# ============================================================
# [10] STARTUP PROGRAMS
# ============================================================
Write-Step -Index 10 -Total 13 -Title "Enumerating startup programs..."
Write-Action -What "Running: Startup programs (Registry Run keys + WMI)" -Kind run
Html-StartSection "Startup Programs"

$startupItems = Safe-Invoke {
    $items = [System.Collections.Generic.List[object]]::new()

    # Registry Run keys (machine + current user)
    $runKeys = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';     Scope = 'Machine' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'Machine (RunOnce)' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';     Scope = 'Current User' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'Current User (RunOnce)' }
    )

    foreach ($rk in $runKeys) {
        try {
            $props = Get-ItemProperty -Path $rk.Path -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                    $items.Add([pscustomobject]@{
                        Name    = $_.Name
                        Command = [string]$_.Value
                        Source  = "Registry"
                        Scope   = $rk.Scope
                    })
                }
            }
        } catch { }
    }

    # WMI StartupCommand (broader coverage including Startup folder shortcuts)
    try {
        Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | ForEach-Object {
            $items.Add([pscustomobject]@{
                Name    = $_.Name
                Command = $_.Command
                Source  = "WMI"
                Scope   = $_.Location
            })
        }
    } catch { }

    @($items)
} "Startup Programs"

if ($startupItems -ne "Error" -and $startupItems) {
    # Deduplicate by Name+Command (registry and WMI often overlap)
    $startupList = @($startupItems) | Sort-Object Name, Command -Unique | Sort-Object Name
    $startupCount = $startupList.Count

    Write-Action -What ("Startup items found: {0}" -f $startupCount) -Kind ok
    Html-AddNote -Text ("Startup items found: {0}" -f $startupCount) -Kind info

    Html-StartDetails -Summary ("Startup Items ({0})" -f $startupCount) -Open
    Html-AddTable -Items $startupList -Columns @(
        @{ Header="Name";    Property="Name" },
        @{ Header="Command"; Property="Command" },
        @{ Header="Source";  Property="Source" },
        @{ Header="Scope";   Property="Scope" }
    )
    Html-EndDetails
}
elseif ($startupItems -eq "Error") {
    Write-Action -What "Startup programs query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve startup program information." -Kind warn
}
else {
    Write-Action -What "No startup items found." -Kind info
    Html-AddNote -Text "No startup items found." -Kind info
}

Html-EndSection

# ============================================================
# [11] EVENT LOG HEALTH
# ============================================================
Write-Step -Index 11 -Total 13 -Title "Checking event log health..."
Write-Action -What "Running: Event log configuration (Get-WinEvent)" -Kind run
Html-StartSection "Event Log Health"

$eventLogs = Safe-Invoke {
    $logNames = @('Application', 'Security', 'System', 'Setup', 'Windows PowerShell')
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($logName in $logNames) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $results.Add([pscustomobject]@{
                LogName       = $log.LogName
                Enabled       = $log.IsEnabled
                MaxSizeMB     = [math]::Round($log.MaximumSizeInBytes / 1MB, 1)
                CurrentSizeMB = [math]::Round($log.FileSize / 1MB, 1)
                RecordCount   = $log.RecordCount
                RetentionMode = if ($log.LogMode -eq 'Circular') { "Circular (overwrites)" } else { [string]$log.LogMode }
                IsFull        = ($log.FileSize -ge ($log.MaximumSizeInBytes * 0.95))
            })
        } catch {
            $results.Add([pscustomobject]@{
                LogName       = $logName
                Enabled       = "Error"
                MaxSizeMB     = "N/A"
                CurrentSizeMB = "N/A"
                RecordCount   = "N/A"
                RetentionMode = "N/A"
                IsFull        = $false
            })
        }
    }

    @($results)
} "Event Log Health"

if ($eventLogs -ne "Error" -and $eventLogs) {
    $logList      = @($eventLogs)
    $fullLogs     = @($logList | Where-Object { $_.IsFull -eq $true -and $_.RetentionMode -ne 'Circular (overwrites)' })
    $disabledLogs = @($logList | Where-Object { $_.Enabled -eq $false })

    if ($fullLogs.Count -gt 0) {
        Write-Action -What ("{0} event log(s) near capacity" -f $fullLogs.Count) -Kind warn
        Html-AddNote -Text ("{0} event log(s) at or near maximum capacity" -f $fullLogs.Count) -Kind warn
    }
    if ($disabledLogs.Count -gt 0) {
        Write-Action -What ("{0} event log(s) disabled" -f $disabledLogs.Count) -Kind warn
        Html-AddNote -Text ("{0} critical event log(s) disabled" -f $disabledLogs.Count) -Kind bad `
            -KbUrl "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor" -KbTitle "Windows event log monitoring"
    }
    if ($fullLogs.Count -eq 0 -and $disabledLogs.Count -eq 0) {
        Write-Action -What "All monitored event logs healthy" -Kind ok
        Html-AddNote -Text "All monitored event logs are enabled and within capacity." -Kind good
    }

    Html-AddTable -Items $logList -Columns @(
        @{ Header="Log";            Property="LogName" },
        @{ Header="Enabled";        Property="Enabled" },
        @{ Header="Max Size (MB)";  Property="MaxSizeMB" },
        @{ Header="Current (MB)";   Property="CurrentSizeMB" },
        @{ Header="Records";        Property="RecordCount" },
        @{ Header="Retention Mode"; Property="RetentionMode" }
    ) -RowClass {
        param($r)
        if ($r.Enabled -eq $false -or $r.Enabled -eq "Error") { return 'sev-bad' }
        if ($r.IsFull -eq $true -and $r.RetentionMode -ne 'Circular (overwrites)') { return 'sev-warn' }
        return 'sev-good'
    }
}
else {
    Write-Action -What "Event log query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve event log information." -Kind warn
}

Html-EndSection

# ============================================================
# [12] MICROSOFT ENTRA ID JOIN STATUS
# ============================================================
Write-Step -Index 12 -Total 13 -Title "Checking Microsoft Entra ID join status..."
Write-Action -What "Running: dsregcmd /status parse" -Kind run
Html-StartSection "Microsoft Entra ID Join Status"

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
        "Entra ID Joined" = $aadInfo.Joined
        "Tenant ID"       = $aadInfo.TenantId
        "Tenant Name"     = $aadInfo.TenantName
    })

    if ($aadInfo.Joined) {
        Write-Action -What "Entra ID Joined: Yes" -Kind ok
        Html-AddNote -Text ("Device is joined to Microsoft Entra ID (Tenant: {0})." -f $(if ($aadInfo.TenantName -ne "N/A") { $aadInfo.TenantName } else { $aadInfo.TenantId })) -Kind good
    } else {
        Write-Action -What "Entra ID Joined: No" -Kind warn
        Html-AddNote -Text "Device is not joined to Microsoft Entra ID. Most managed environments require Entra ID join for policy enforcement and conditional access." -Kind warn `
            -KbUrl "https://learn.microsoft.com/en-us/entra/identity/devices/overview" -KbTitle "Microsoft Entra device identity"
    }
}
else {
    Write-Action -What "Entra ID join status query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve Microsoft Entra ID join status." -Kind warn
}

Html-EndSection

# ============================================================
# [13] ESSENTIAL EIGHT ASSESSMENT
# ============================================================
Write-Step -Index 13 -Total 13 -Title "Performing Essential Eight assessment..."
Write-Action -What "Running: ASD Essential Eight Maturity Model checks" -Kind run
Html-StartSection "Essential Eight Assessment"
Html-AddNote -Text "Assessment based on the ASD Essential Eight Maturity Model. This tool performs read-only detection only; results reflect observed endpoint configuration and cannot substitute for a formal E8 assessment." -Kind info

# Scorecard accumulator - entries added after each E8 check, rendered at the end
$e8Scores = [System.Collections.Generic.List[object]]::new()
$e8ScorecardInsertPos     = $Html.Length
$e8ScorecardInsertPosHudu = $HuduHtml.Length

# ---- E8-1: Application Control ----
Html-Add "<h3>1. Application Control</h3>"

$appLocker = Safe-Invoke {
    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $ruleCount = ($policy.RuleCollections | Measure-Object).Count
    [pscustomobject]@{
        Configured = ($ruleCount -gt 0)
        RuleCount  = $ruleCount
        Detail     = if ($ruleCount -gt 0) { "AppLocker policy active ($ruleCount rule collection(s))" } else { "No AppLocker policy detected" }
    }
} "AppLocker Policy"

$wdac = Safe-Invoke {
    $ciConfig = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction SilentlyContinue
    $ciPolicy = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'  -ErrorAction SilentlyContinue
    $found = ($null -ne $ciConfig) -or ($null -ne $ciPolicy)
    [pscustomobject]@{
        Configured = $found
        Detail     = if ($found) { "WDAC Code Integrity policy registry key present" } else { "No WDAC policy registry key detected" }
    }
} "WDAC Detection"

$appLockOk = ($appLocker -ne "Error") -and $appLocker -and $appLocker.Configured
$wdacOk    = ($wdac      -ne "Error") -and $wdac      -and $wdac.Configured
$acStatus  = if ($appLockOk -or $wdacOk) { "Detected" } else { "Not detected" }
$acClass   = if ($appLockOk -or $wdacOk) { "sev-good" } else { "sev-bad" }

Html-Add "<table class='kv-table'><tbody>"
Html-Add ("<tr class='{0}'><th>AppLocker</th><td>{1}</td></tr>" -f $acClass, (Html-Enc $(if ($appLocker -ne "Error" -and $appLocker) { $appLocker.Detail } else { "Query failed" })))
Html-Add ("<tr class='{0}'><th>WDAC / Code Integrity</th><td>{1}</td></tr>" -f $acClass, (Html-Enc $(if ($wdac -ne "Error" -and $wdac) { $wdac.Detail } else { "Query failed" })))
Html-Add ("<tr class='{0}'><th>Overall</th><td><span class='badge {1}'>{2}</span></td></tr>" -f $acClass, $(if ($appLockOk -or $wdacOk) { "good" } else { "bad" }), $acStatus)
Html-Add "</tbody></table>"
Write-Action -What ("Application Control: {0}" -f $acStatus) -Kind $(if ($appLockOk -or $wdacOk) { "ok" } else { "warn" })
$e8Scores.Add([pscustomobject]@{ Control = "Application Control"; Status = $acStatus; Badge = if ($appLockOk -or $wdacOk) { "good" } else { "bad" } })

# ---- E8-2: Patch Applications ----
Html-Add "<h3>2. Patch Applications</h3>"
Html-AddNote -Text "Full application inventory is in Section 2 (Installed Software). Full hotfix list is in Section 3 (Patches)." -Kind info

$lastHotfix = Safe-Invoke {
    # Reuse $patches from Section 3 when available, otherwise query fresh
    $hf = if ($patches -ne "Error" -and $patches) {
        @($patches | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    } else {
        @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    }
    if ($hf.Count -gt 0) {
        $days = ([datetime]::Now - [datetime]$hf[0].InstalledOn).Days
        [pscustomobject]@{ HotFixID = $hf[0].HotFixID; InstalledOn = ($hf[0].InstalledOn).ToString("yyyy-MM-dd"); DaysAgo = $days }
    } else {
        [pscustomobject]@{ HotFixID = "N/A"; InstalledOn = "N/A"; DaysAgo = $null }
    }
} "Last Hotfix Date"

$wuAU = Safe-Invoke {
    $au = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    if ($au -and $au.AUOptions) {
        $desc = switch ($au.AUOptions) {
            2 { "Notify before download" }
            3 { "Auto-download, notify before install" }
            4 { "Auto-download and schedule install" }
            5 { "Allow local admin to choose" }
            default { "Option $($au.AUOptions)" }
        }
        [pscustomobject]@{ AUOptions = $au.AUOptions; Description = $desc; NoAutoUpdate = $au.NoAutoUpdate }
    } else {
        [pscustomobject]@{ AUOptions = $null; Description = "Not configured via policy (uses defaults)"; NoAutoUpdate = $null }
    }
} "WU Auto-Update Policy"

$patchDays = if ($lastHotfix -ne "Error" -and $lastHotfix -and $null -ne $lastHotfix.DaysAgo) { $lastHotfix.DaysAgo } else { $null }
$patchClass = if ($null -eq $patchDays) { "sev-warn" } elseif ($patchDays -le 14) { "sev-good" } elseif ($patchDays -le 30) { "sev-warn" } else { "sev-bad" }

Html-Add "<table class='kv-table'><tbody>"
if ($lastHotfix -ne "Error" -and $lastHotfix) {
    Html-Add ("<tr class='{0}'><th>Most Recent Hotfix</th><td>{1}</td></tr>" -f $patchClass, (Html-Enc $lastHotfix.HotFixID))
    Html-Add ("<tr class='{0}'><th>Installed On</th><td>{1}</td></tr>"      -f $patchClass, (Html-Enc $lastHotfix.InstalledOn))
    Html-Add ("<tr class='{0}'><th>Days Since Last Patch</th><td>{1}</td></tr>" -f $patchClass, (Html-Enc $(if ($null -ne $patchDays) { "$patchDays days" } else { "Unknown" })))
} else {
    Html-Add "<tr class='sev-warn'><th>Most Recent Hotfix</th><td>Could not retrieve</td></tr>"
}
if ($wuAU -ne "Error" -and $wuAU) {
    Html-Add ("<tr><th>Windows Update Policy</th><td>{0}</td></tr>" -f (Html-Enc $wuAU.Description))
}
if ($wuPolicy -ne "Error" -and $wuPolicy) {
    if ($wuPolicy.DeferQualityUpdates -eq 1 -and $null -ne $wuPolicy.DeferQualityUpdatesPeriodInDays) {
        Html-Add ("<tr class='sev-warn'><th>Quality Update Deferral</th><td>{0} days (WUfB)</td></tr>" -f (Html-Enc $wuPolicy.DeferQualityUpdatesPeriodInDays))
    }
    if ($wuPolicy.DeferFeatureUpdates -eq 1 -and $null -ne $wuPolicy.DeferFeatureUpdatesPeriodInDays) {
        Html-Add ("<tr><th>Feature Update Deferral</th><td>{0} days (WUfB)</td></tr>" -f (Html-Enc $wuPolicy.DeferFeatureUpdatesPeriodInDays))
    }
}
Html-Add "</tbody></table>"
Write-Action -What ("Patch currency: {0}" -f $(if ($null -ne $patchDays) { "$patchDays days since last hotfix" } else { "date unavailable" })) -Kind $(if ($patchClass -eq "sev-good") { "ok" } elseif ($patchClass -eq "sev-warn") { "warn" } else { "bad" })
$e8PatchStatus = if ($patchClass -eq "sev-good") { "Current" } elseif ($patchClass -eq "sev-warn") { "Needs attention" } else { "Overdue" }
$e8Scores.Add([pscustomobject]@{ Control = "Patch Applications"; Status = $e8PatchStatus; Badge = if ($patchClass -eq "sev-good") { "good" } elseif ($patchClass -eq "sev-warn") { "warn" } else { "bad" } })

# ---- E8-3: Restrict Microsoft Office Macros ----
Html-Add "<h3>3. Restrict Microsoft Office Macros</h3>"

$officeApps    = @('Word', 'Excel', 'PowerPoint', 'Outlook', 'Access')
$officeResults = [System.Collections.Generic.List[object]]::new()

foreach ($app in $officeApps) {
    $polPath  = "HKLM:\Software\Policies\Microsoft\Office\16.0\$app\Security"
    $userPath = "HKCU:\Software\Microsoft\Office\16.0\$app\Security"

    $polVal  = Safe-Invoke { (Get-ItemProperty -Path $polPath  -Name VBAWarnings -ErrorAction SilentlyContinue).VBAWarnings } "Office Macro Policy $app"
    $userVal = Safe-Invoke { (Get-ItemProperty -Path $userPath -Name VbaWarnings -ErrorAction SilentlyContinue).VbaWarnings } "Office Macro User $app"

    $effective = $null
    $source    = "Not configured"
    if ($polVal -ne "Error" -and $null -ne $polVal) {
        $effective = $polVal; $source = "Group Policy"
    } elseif ($userVal -ne "Error" -and $null -ne $userVal) {
        $effective = $userVal; $source = "User setting"
    }

    if ($null -ne $effective) {
        $label = switch ($effective) {
            1 { "Enable all macros (insecure)" }
            2 { "Disable with notification" }
            3 { "Signed macros only" }
            4 { "Disable all macros" }
            default { "Unknown value ($effective)" }
        }
        $officeResults.Add([pscustomobject]@{
            Application = $app
            Setting     = $effective
            Description = $label
            Source      = $source
        })
    }
}

if ($officeResults.Count -gt 0) {
    Html-AddTable -Items $officeResults -Columns @(
        @{ Header = "Application"; Property = "Application" },
        @{ Header = "Macro Setting"; Property = "Description" },
        @{ Header = "Source"; Property = "Source" }
    ) -RowClass {
        param($r)
        switch ($r.Setting) {
            1 { "sev-bad"  }
            2 { "sev-warn" }
            3 { "sev-good" }
            4 { "sev-good" }
            default { "sev-warn" }
        }
    }
    Write-Action -What ("Office macro settings found for {0} application(s)" -f $officeResults.Count) -Kind info
} else {
    Html-AddNote -Text "No Microsoft Office 2016/2019/365 macro settings detected. Office may not be installed, or no macro policy has been configured." -Kind info
    Write-Action -What "No Office macro settings detected" -Kind info
}
$e8MacroOk = ($officeResults.Count -gt 0) -and (@($officeResults | Where-Object { $_.Setting -eq 1 }).Count -eq 0)
$e8MacroStatus = if ($officeResults.Count -eq 0) { "Not configured" } elseif ($e8MacroOk) { "Restricted" } else { "Insecure" }
$e8MacroBadge  = if ($officeResults.Count -eq 0) { "warn" } elseif ($e8MacroOk) { "good" } else { "bad" }
$e8Scores.Add([pscustomobject]@{ Control = "Restrict Office Macros"; Status = $e8MacroStatus; Badge = $e8MacroBadge })

# ---- E8-4: User Application Hardening ----
Html-Add "<h3>4. User Application Hardening</h3>"

$mpPref = Safe-Invoke { Get-MpPreference -ErrorAction Stop } "Defender Preferences"

$cfa = if ($mpPref -ne "Error" -and $mpPref) { $mpPref.EnableControlledFolderAccess } else { "Error" }
# 0=Disabled, 1=Enabled, 2=Audit Mode
$cfaLabel = switch ($cfa) { 0 { "Disabled" } 1 { "Enabled" } 2 { "Audit mode" } default { if ($cfa -eq "Error") { "Query failed" } else { "Unknown ($cfa)" } } }
$cfaClass = switch ($cfa) { 1 { "sev-good" } 2 { "sev-warn" } default { "sev-bad" } }

$np = if ($mpPref -ne "Error" -and $mpPref) { $mpPref.EnableNetworkProtection } else { "Error" }
# 0=Disabled, 1=Enabled, 2=Audit Mode
$npLabel = switch ($np) { 0 { "Disabled" } 1 { "Enabled" } 2 { "Audit mode" } default { if ($np -eq "Error") { "Query failed" } else { "Unknown ($np)" } } }
$npClass = switch ($np) { 1 { "sev-good" } 2 { "sev-warn" } default { "sev-bad" } }

$asrIds = if ($mpPref -ne "Error" -and $mpPref) { $mpPref.AttackSurfaceReductionRules_Ids } else { "Error" }
$asrCount = if ($asrIds -ne "Error" -and $asrIds) { @($asrIds).Count } else { 0 }
$asrClass = if ($asrCount -gt 0) { "sev-good" } else { "sev-warn" }

# PS v2: elevation-gated; fall back to unknown when not admin
$psv2Class = "sev-warn"; $psv2Label = "Could not determine (run as administrator for full check)"
if ($IsElevated) {
    $psv2 = Safe-Invoke {
        $f = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue
        if ($f) { $f.State } else { "NotPresent" }
    } "PowerShell v2 Feature"
    if ($psv2 -ne "Error") {
        $psv2Label = if ($psv2 -eq "Disabled" -or $psv2 -eq "NotPresent") { "Disabled / Not installed (good)" } else { "Enabled ($psv2)" }
        $psv2Class = if ($psv2 -eq "Disabled" -or $psv2 -eq "NotPresent") { "sev-good" } else { "sev-bad" }
    }
}

# IE: check registry for IE executable or capability
$iePresent = Safe-Invoke {
    $ieExe = Test-Path "$env:ProgramFiles\Internet Explorer\iexplore.exe" -ErrorAction SilentlyContinue
    $ieExe32 = Test-Path "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe" -ErrorAction SilentlyContinue
    $ieExe -or $ieExe32
} "Internet Explorer Detection"
$ieLabel = if ($iePresent -eq "Error") { "Query failed" } elseif ($iePresent) { "Present (should be disabled/removed)" } else { "Not detected (good)" }
$ieClass  = if ($iePresent -eq "Error" -or $iePresent) { "sev-warn" } else { "sev-good" }

Html-Add "<table class='kv-table'><tbody>"
Html-Add ("<tr class='{0}'><th>Controlled Folder Access</th><td>{1}</td></tr>"     -f $cfaClass,  (Html-Enc $cfaLabel))
Html-Add ("<tr class='{0}'><th>Network Protection</th><td>{1}</td></tr>"           -f $npClass,   (Html-Enc $npLabel))
Html-Add ("<tr class='{0}'><th>ASR Rules Configured</th><td>{1}</td></tr>"         -f $asrClass,  (Html-Enc "$asrCount rule(s) found"))
Html-Add ("<tr class='{0}'><th>PowerShell v2</th><td>{1}</td></tr>"                -f $psv2Class, (Html-Enc $psv2Label))
Html-Add ("<tr class='{0}'><th>Internet Explorer</th><td>{1}</td></tr>"            -f $ieClass,   (Html-Enc $ieLabel))
Html-Add "</tbody></table>"
Write-Action -What "User application hardening checks complete" -Kind info
$e8HardenCount = @($cfaClass, $npClass, $asrClass, $psv2Class, $ieClass) | Where-Object { $_ -eq 'sev-good' } | Measure-Object | Select-Object -ExpandProperty Count
$e8HardenStatus = if ($e8HardenCount -ge 4) { "Hardened" } elseif ($e8HardenCount -ge 2) { "Partial" } else { "Weak" }
$e8HardenBadge  = if ($e8HardenCount -ge 4) { "good" } elseif ($e8HardenCount -ge 2) { "warn" } else { "bad" }
$e8Scores.Add([pscustomobject]@{ Control = "User Application Hardening"; Status = $e8HardenStatus; Badge = $e8HardenBadge })

# ---- E8-5: Restrict Administrative Privileges ----
Html-Add "<h3>5. Restrict Administrative Privileges</h3>"
Html-AddNote -Text "Full local administrator group membership is in Section 8 (Security Baseline)." -Kind info

$uacLua = Safe-Invoke {
    (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA
} "UAC EnableLUA"
$uacLuaLabel = if ($uacLua -eq "Error") { "Query failed" } elseif ($uacLua -eq 1) { "Enabled" } elseif ($uacLua -eq 0) { "Disabled" } else { "Unknown ($uacLua)" }
$uacLuaClass = if ($uacLua -eq 1) { "sev-good" } elseif ($uacLua -eq 0) { "sev-bad" } else { "sev-warn" }

$uacBehavior = Safe-Invoke {
    (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -ErrorAction Stop).ConsentPromptBehaviorAdmin
} "UAC ConsentPromptBehaviorAdmin"
$uacBehaviorLabel = switch ($uacBehavior) {
    0 { "Elevate without prompting (insecure)" }
    1 { "Prompt for credentials on secure desktop" }
    2 { "Prompt for consent on secure desktop" }
    3 { "Prompt for credentials" }
    4 { "Prompt for consent" }
    5 { "Prompt for consent for non-Windows binaries (default)" }
    default { if ($uacBehavior -eq "Error") { "Query failed" } else { "Unknown ($uacBehavior)" } }
}
$uacBehaviorClass = switch ($uacBehavior) {
    { $_ -in @(1,2,5) } { "sev-good" }
    { $_ -in @(3,4)   } { "sev-warn" }
    0                    { "sev-bad"  }
    default              { "sev-warn" }
}

# Reuse $admins from Section 8 when available, otherwise query fresh
$adminMembers = if ($admins -ne "Error" -and $admins) { @($admins) } else { Safe-Invoke { @(Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop) } "Local Admin Members" }
$adminCount   = if ($adminMembers -ne "Error" -and $adminMembers) { $adminMembers.Count } else { $null }
$adminClass   = if ($null -eq $adminCount) { "sev-warn" } elseif ($adminCount -le 2) { "sev-good" } elseif ($adminCount -le 4) { "sev-warn" } else { "sev-bad" }

Html-Add "<table class='kv-table'><tbody>"
Html-Add ("<tr class='{0}'><th>UAC Enabled (EnableLUA)</th><td>{1}</td></tr>"                   -f $uacLuaClass,      (Html-Enc $uacLuaLabel))
Html-Add ("<tr class='{0}'><th>UAC Admin Consent Prompt</th><td>{1}</td></tr>"                  -f $uacBehaviorClass, (Html-Enc $uacBehaviorLabel))
Html-Add ("<tr class='{0}'><th>Local Administrator Count</th><td>{1}</td></tr>"                 -f $adminClass,       (Html-Enc $(if ($null -ne $adminCount) { "$adminCount member(s)" } else { "Could not retrieve" })))
Html-Add "</tbody></table>"
Write-Action -What ("UAC: {0} | Admin members: {1}" -f $uacLuaLabel, $(if ($null -ne $adminCount) { $adminCount } else { "unknown" })) -Kind info
$e8AdminOk = ($uacLua -eq 1) -and ($null -ne $adminCount) -and ($adminCount -le 4)
$e8AdminStatus = if ($e8AdminOk) { "Restricted" } elseif ($uacLua -eq 1) { "Partial" } else { "Weak" }
$e8AdminBadge  = if ($e8AdminOk) { "good" } elseif ($uacLua -eq 1) { "warn" } else { "bad" }
$e8Scores.Add([pscustomobject]@{ Control = "Restrict Admin Privileges"; Status = $e8AdminStatus; Badge = $e8AdminBadge })

# ---- E8-6: Patch Operating Systems ----
Html-Add "<h3>6. Patch Operating Systems</h3>"
Html-AddNote -Text "Pending Windows Updates are detailed in Section 4." -Kind info

$osBuild = Safe-Invoke {
    $rv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    # Registry ProductName is unreliable on Windows 11 (often still says "Windows 10").
    # Prefer the CIM Caption from Section 1; fall back to registry with build-number correction.
    $prodName = $rv.ProductName
    if ($os -ne "Error" -and $os -and $os.Caption) {
        $prodName = $os.Caption
    } elseif ($rv.CurrentBuild -and [int]$rv.CurrentBuild -ge 22000 -and $prodName -match 'Windows 10') {
        $prodName = $prodName -replace 'Windows 10', 'Windows 11'
    }
    [pscustomobject]@{
        ProductName    = $prodName
        DisplayVersion = if ($rv.DisplayVersion) { $rv.DisplayVersion } else { $rv.ReleaseId }
        CurrentBuild   = $rv.CurrentBuild
        UBR            = $rv.UBR
    }
} "OS Build Info"

$wuSvc = Safe-Invoke {
    $s = Get-Service -Name wuauserv -ErrorAction Stop
    [pscustomobject]@{ Status = $s.Status; StartType = $s.StartType }
} "Windows Update Service"

$wuSvcClass = if ($wuSvc -ne "Error" -and $wuSvc) {
    if ($wuSvc.StartType -eq 'Disabled') { 'sev-bad' }
    elseif ($wuSvc.Status -eq 'Running') { 'sev-good' }
    else { 'sev-warn' }
} else { 'sev-warn' }

Html-Add "<table class='kv-table'><tbody>"
if ($osBuild -ne "Error" -and $osBuild) {
    Html-Add ("<tr><th>OS</th><td>{0}</td></tr>"             -f (Html-Enc $osBuild.ProductName))
    Html-Add ("<tr><th>Feature Version</th><td>{0}</td></tr>" -f (Html-Enc $osBuild.DisplayVersion))
    Html-Add ("<tr><th>Build Number</th><td>{0}.{1}</td></tr>" -f (Html-Enc $osBuild.CurrentBuild), (Html-Enc $osBuild.UBR))
}
if ($lastHotfix -ne "Error" -and $lastHotfix -and $lastHotfix.HotFixID -ne "N/A") {
    Html-Add ("<tr class='{0}'><th>Most Recent Patch</th><td>{1} (installed {2}, {3} days ago)</td></tr>" -f $patchClass, (Html-Enc $lastHotfix.HotFixID), (Html-Enc $lastHotfix.InstalledOn), (Html-Enc $lastHotfix.DaysAgo))
} else {
    Html-Add "<tr class='sev-warn'><th>Most Recent Patch</th><td>Could not determine</td></tr>"
}
if ($wuSvc -ne "Error" -and $wuSvc) {
    Html-Add ("<tr class='{0}'><th>Windows Update Service</th><td>{1} (startup: {2})</td></tr>" -f $wuSvcClass, (Html-Enc $wuSvc.Status), (Html-Enc $wuSvc.StartType))
}
if ($muEnabled -ne "Error") {
    $muE8Class = if ($muEnabled) { 'sev-good' } else { 'sev-warn' }
    Html-Add ("<tr class='{0}'><th>Microsoft Update</th><td>{1}</td></tr>" -f $muE8Class, (Html-Enc $(if ($muEnabled) { 'Enabled' } else { 'Disabled (non-OS Microsoft products excluded)' })))
}
Html-Add "</tbody></table>"
Write-Action -What ("OS: {0} | WU Service: {1}" -f $(if ($osBuild -ne "Error" -and $osBuild) { "$($osBuild.ProductName) $($osBuild.DisplayVersion)" } else { "unknown" }), $(if ($wuSvc -ne "Error" -and $wuSvc) { $wuSvc.Status } else { "unknown" })) -Kind info
$e8OsPatchOk = ($wuSvc -ne "Error" -and $wuSvc -and $wuSvc.Status -eq "Running" -and $wuSvc.StartType -ne 'Disabled') -and ($patchClass -ne "sev-bad")
$e8OsStatus  = if ($e8OsPatchOk -and $patchClass -eq "sev-good") { "Current" } elseif ($e8OsPatchOk) { "Needs attention" } else { "Overdue" }
$e8OsBadge   = if ($e8OsPatchOk -and $patchClass -eq "sev-good") { "good" } elseif ($e8OsPatchOk) { "warn" } else { "bad" }
$e8Scores.Add([pscustomobject]@{ Control = "Patch Operating Systems"; Status = $e8OsStatus; Badge = $e8OsBadge })

# ---- E8-7: Multi-Factor Authentication ----
Html-Add "<h3>7. Multi-Factor Authentication</h3>"
Html-AddNote -Text "Endpoint MFA signals only. Whether MFA is actually enforced by an identity provider (Entra ID, AD FS, etc.) cannot be verified from the endpoint alone." -Kind info

$wh4bPolicy = Safe-Invoke {
    $p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -ErrorAction SilentlyContinue
    if ($p -and $null -ne $p.Enabled) { $p.Enabled } else { $null }
} "Windows Hello for Business Policy"
$wh4bLabel = if ($wh4bPolicy -eq "Error") { "Query failed" } elseif ($wh4bPolicy -eq 1) { "Enabled via policy" } elseif ($wh4bPolicy -eq 0) { "Disabled via policy" } else { "Not configured via policy" }
$wh4bClass = if ($wh4bPolicy -eq 1) { "sev-good" } elseif ($wh4bPolicy -eq 0) { "sev-bad" } else { "sev-warn" }

# Detect Windows Hello PIN provider (presence suggests Hello is set up for at least one user)
$helloDetected = Safe-Invoke {
    $ngcPath = "$env:WINDIR\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
    Test-Path $ngcPath -ErrorAction SilentlyContinue
} "Windows Hello NGC Path"
$helloLabel = if ($helloDetected -eq "Error") { "Query failed" } elseif ($helloDetected) { "NGC store present (Windows Hello likely configured)" } else { "NGC store not found" }
$helloClass = if ($helloDetected -eq $true) { "sev-good" } else { "sev-warn" }

$smartcards = Safe-Invoke {
    @(Get-PnpDevice -Class SmartCardReader -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' })
} "Smartcard Readers"
$scCount = if ($smartcards -ne "Error" -and $smartcards) { $smartcards.Count } else { 0 }
$scLabel = if ($smartcards -eq "Error") { "Query failed" } elseif ($scCount -gt 0) { "$scCount reader(s) detected: $(($smartcards | Select-Object -ExpandProperty FriendlyName) -join '; ')" } else { "No smartcard readers detected" }
$scClass = if ($scCount -gt 0) { "sev-good" } else { "sev-warn" }

$cachedCreds = Safe-Invoke {
    (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -ErrorAction SilentlyContinue).CachedLogonsCount
} "Cached Logon Count"
$cachedLabel = if ($cachedCreds -eq "Error") { "Query failed" } elseif ($null -ne $cachedCreds) { "$cachedCreds cached credential(s) stored" } else { "Not set (Windows default applies)" }
$cachedClass = if ($cachedCreds -eq "Error" -or $null -eq $cachedCreds) { "sev-warn" } elseif ([int]$cachedCreds -eq 0) { "sev-good" } elseif ([int]$cachedCreds -le 2) { "sev-warn" } else { "sev-bad" }

Html-Add "<table class='kv-table'><tbody>"
Html-Add ("<tr class='{0}'><th>Windows Hello for Business Policy</th><td>{1}</td></tr>" -f $wh4bClass,    (Html-Enc $wh4bLabel))
Html-Add ("<tr class='{0}'><th>Windows Hello (NGC store)</th><td>{1}</td></tr>"          -f $helloClass,   (Html-Enc $helloLabel))
Html-Add ("<tr class='{0}'><th>Smartcard Readers</th><td>{1}</td></tr>"                  -f $scClass,      (Html-Enc $scLabel))
Html-Add ("<tr class='{0}'><th>Cached Domain Credentials</th><td>{1}</td></tr>"          -f $cachedClass,  (Html-Enc $cachedLabel))
Html-Add "</tbody></table>"
Write-Action -What ("MFA signals: WH4B policy=$wh4bLabel | Smartcards=$scCount") -Kind info
$e8MfaOk = ($wh4bPolicy -eq 1) -or ($helloDetected -eq $true) -or ($scCount -gt 0)
$e8MfaStatus = if ($e8MfaOk) { "Signals present" } else { "Not detected" }
$e8MfaBadge  = if ($e8MfaOk) { "good" } else { "warn" }
$e8Scores.Add([pscustomobject]@{ Control = "Multi-Factor Authentication"; Status = $e8MfaStatus; Badge = $e8MfaBadge })

# ---- E8-8: Regular Backups ----
Html-Add "<h3>8. Regular Backups</h3>"

$shadowCopies = Safe-Invoke { @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop) } "VSS Shadow Copies"
$scCopies     = if ($shadowCopies -ne "Error" -and $shadowCopies) { $shadowCopies } else { @() }
$scClass8     = if ($scCopies.Count -gt 0) { "sev-good" } else { "sev-warn" }

$newestShadow = if ($scCopies.Count -gt 0) {
    ($scCopies | Sort-Object InstallDate -Descending | Select-Object -First 1).InstallDate
} else { $null }

$fileHistory = Safe-Invoke {
    $fhKey = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileHistory' -ErrorAction SilentlyContinue
    if ($fhKey -and $null -ne $fhKey.Enabled) { $fhKey.Enabled } else { $null }
} "File History"
$fhLabel = if ($fileHistory -eq "Error") { "Query failed" } elseif ($fileHistory -eq 1) { "Enabled" } elseif ($fileHistory -eq 0) { "Disabled" } else { "Not configured" }
$fhClass = if ($fileHistory -eq 1) { "sev-good" } else { "sev-warn" }

$backupTasks = Safe-Invoke {
    @(Get-ScheduledTask -TaskPath '\Microsoft\Windows\Backup\' -ErrorAction SilentlyContinue |
        Select-Object TaskName, State, @{ N = "LastRunTime"; E = { $_.LastRunTime } })
} "Backup Scheduled Tasks"

$oneDriveRunning = Safe-Invoke {
    $null -ne (Get-Process -Name OneDrive -ErrorAction SilentlyContinue)
} "OneDrive Process"
$odLabel = if ($oneDriveRunning -eq "Error") { "Query failed" } elseif ($oneDriveRunning) { "Running" } else { "Not running" }
$odClass = if ($oneDriveRunning -eq $true) { "sev-good" } else { "sev-warn" }

Html-Add "<table class='kv-table'><tbody>"
Html-Add ("<tr class='{0}'><th>VSS Shadow Copies</th><td>{1}</td></tr>" -f $scClass8, (Html-Enc "$($scCopies.Count) snapshot(s) found$(if ($newestShadow) { '; newest: ' + $newestShadow } else { '' })"))
Html-Add ("<tr class='{0}'><th>File History</th><td>{1}</td></tr>"      -f $fhClass,  (Html-Enc $fhLabel))
Html-Add ("<tr class='{0}'><th>OneDrive</th><td>{1}</td></tr>"           -f $odClass,  (Html-Enc $odLabel))
Html-Add "</tbody></table>"

if ($backupTasks -ne "Error" -and $backupTasks -and @($backupTasks).Count -gt 0) {
    Html-AddTable -Items $backupTasks -Columns @(
        @{ Header = "Task";      Property = "TaskName"    },
        @{ Header = "State";     Property = "State"       },
        @{ Header = "Last Run";  Property = "LastRunTime" }
    )
}
Write-Action -What ("Backups: VSS copies=$($scCopies.Count) | File History=$fhLabel | OneDrive=$odLabel") -Kind $(if ($scCopies.Count -gt 0) { "ok" } else { "warn" })
$e8BackupOk = ($scCopies.Count -gt 0) -or ($fileHistory -eq 1) -or ($oneDriveRunning -eq $true)
$e8BackupStatus = if ($e8BackupOk) { "Detected" } else { "Not detected" }
$e8BackupBadge  = if ($e8BackupOk) { "good" } else { "warn" }
$e8Scores.Add([pscustomobject]@{ Control = "Regular Backups"; Status = $e8BackupStatus; Badge = $e8BackupBadge })

# ---- E8 Summary Scorecard (inserted at top of section) ----
$scorecardHtml = New-Object System.Text.StringBuilder
[void]$scorecardHtml.AppendLine("<h3>Summary Scorecard</h3>")
[void]$scorecardHtml.AppendLine("<table><thead><tr><th>#</th><th>Control</th><th>Status</th></tr></thead><tbody>")
$e8Num = 1
foreach ($s in $e8Scores) {
    $badgeHtml = "<span class='badge {0}'>{1}</span>" -f (Html-Enc $s.Badge), (Html-Enc $s.Status)
    $rowClass  = switch ($s.Badge) { 'good' { 'sev-good' }; 'warn' { 'sev-warn' }; 'bad' { 'sev-bad' }; default { '' } }
    [void]$scorecardHtml.AppendLine(("<tr class='{0}'><td>{1}</td><td>{2}</td><td>{3}</td></tr>" -f $rowClass, $e8Num, (Html-Enc $s.Control), $badgeHtml))
    $e8Num++
}
[void]$scorecardHtml.AppendLine("</tbody></table>")

# ---- E8 Issues Summary ----
$e8BadItems  = @($e8Scores | Where-Object { $_.Badge -eq 'bad' })
$e8WarnItems = @($e8Scores | Where-Object { $_.Badge -eq 'warn' })
[void]$scorecardHtml.AppendLine("<h3>Issues Requiring Attention</h3>")
if ($e8BadItems.Count -eq 0 -and $e8WarnItems.Count -eq 0) {
    [void]$scorecardHtml.AppendLine("<div class='callout callout-good'>All Essential Eight controls are compliant. No critical issues or warnings identified.</div>")
} else {
    if ($e8BadItems.Count -gt 0) {
        [void]$scorecardHtml.AppendLine("<div class='callout callout-bad'>")
        [void]$scorecardHtml.AppendLine("<strong>Critical Issues</strong><ul>")
        foreach ($item in $e8BadItems) {
            [void]$scorecardHtml.AppendLine(("<li><strong>{0}</strong> &mdash; {1}</li>" -f (Html-Enc $item.Control), (Html-Enc $item.Status)))
        }
        [void]$scorecardHtml.AppendLine("</ul></div>")
    }
    if ($e8WarnItems.Count -gt 0) {
        [void]$scorecardHtml.AppendLine("<div class='callout callout-warn'>")
        [void]$scorecardHtml.AppendLine("<strong>Warnings</strong><ul>")
        foreach ($item in $e8WarnItems) {
            [void]$scorecardHtml.AppendLine(("<li><strong>{0}</strong> &mdash; {1}</li>" -f (Html-Enc $item.Control), (Html-Enc $item.Status)))
        }
        [void]$scorecardHtml.AppendLine("</ul></div>")
    }
}

# Push E8 non-compliant controls to the global findings accumulator with KB links
$e8KbMap = @{
    'Application Control'        = @{ Url = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/'; Title = 'App Control for Business' }
    'Patch Applications'         = @{ Url = 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview'; Title = 'Windows Update overview' }
    'Restrict Office Macros'     = @{ Url = 'https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked'; Title = 'Office macro security' }
    'User Application Hardening' = @{ Url = 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction'; Title = 'Attack Surface Reduction' }
    'Restrict Admin Privileges'  = @{ Url = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/'; Title = 'User Account Control' }
    'Patch Operating Systems'    = @{ Url = 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview'; Title = 'Windows Update overview' }
    'Multi-Factor Authentication'= @{ Url = 'https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/'; Title = 'Windows Hello for Business' }
    'Regular Backups'            = @{ Url = 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service'; Title = 'Volume Shadow Copy Service' }
}
foreach ($item in (@($e8BadItems) + @($e8WarnItems))) {
    $kb = $e8KbMap[$item.Control]
    $script:GlobalFindings.Add([pscustomobject]@{
        Section   = $script:CurrentSectionTitle
        SectionId = $script:CurrentSectionId
        Message   = ("{0} - {1}" -f $item.Control, $item.Status)
        Kind      = $item.Badge
        KbUrl     = if ($kb) { $kb.Url } else { $null }
        KbTitle   = if ($kb) { $kb.Title } else { $null }
    })
}
[void]$Html.Insert($e8ScorecardInsertPos, $scorecardHtml.ToString())

# Also insert into HuduHtml with inline styles
$huduScorecard = New-Object System.Text.StringBuilder
[void]$huduScorecard.AppendLine((Convert-ToHuduInline "<h3>Summary Scorecard</h3>"))
[void]$huduScorecard.AppendLine((Convert-ToHuduInline "<table><thead><tr><th>#</th><th>Control</th><th>Status</th></tr></thead><tbody>"))
$e8Num2 = 1
foreach ($s in $e8Scores) {
    $badgeHtml2 = "<span class='badge {0}'>{1}</span>" -f (Html-Enc $s.Badge), (Html-Enc $s.Status)
    $rowClass2  = switch ($s.Badge) { 'good' { 'sev-good' }; 'warn' { 'sev-warn' }; 'bad' { 'sev-bad' }; default { '' } }
    [void]$huduScorecard.AppendLine((Convert-ToHuduInline ("<tr class='{0}'><td>{1}</td><td>{2}</td><td>{3}</td></tr>" -f $rowClass2, $e8Num2, (Html-Enc $s.Control), $badgeHtml2)))
    $e8Num2++
}
[void]$huduScorecard.AppendLine("</tbody></table>")

# ---- Hudu E8 Issues Summary (flat <p> per item - avoids ActionText block-element restructuring) ----
[void]$huduScorecard.AppendLine((Convert-ToHuduInline "<h3>Issues Requiring Attention</h3>"))
if ($e8BadItems.Count -eq 0 -and $e8WarnItems.Count -eq 0) {
    [void]$huduScorecard.AppendLine((Convert-ToHuduInline "<div class='callout callout-good'>All Essential Eight controls are compliant. No critical issues or warnings identified.</div>"))
} else {
    if ($e8BadItems.Count -gt 0) {
        [void]$huduScorecard.AppendLine((Convert-ToHuduInline "<div class='callout callout-bad'>"))
        [void]$huduScorecard.AppendLine("<strong>Critical Issues</strong>")
        foreach ($item in $e8BadItems) {
            [void]$huduScorecard.AppendLine(("<p style='margin:4px 0;'><strong>{0}</strong> &mdash; {1}</p>" -f (Html-Enc $item.Control), (Html-Enc $item.Status)))
        }
        [void]$huduScorecard.AppendLine("</div>")
    }
    if ($e8WarnItems.Count -gt 0) {
        [void]$huduScorecard.AppendLine((Convert-ToHuduInline "<div class='callout callout-warn'>"))
        [void]$huduScorecard.AppendLine("<strong>Warnings</strong>")
        foreach ($item in $e8WarnItems) {
            [void]$huduScorecard.AppendLine(("<p style='margin:4px 0;'><strong>{0}</strong> &mdash; {1}</p>" -f (Html-Enc $item.Control), (Html-Enc $item.Status)))
        }
        [void]$huduScorecard.AppendLine("</div>")
    }
}
[void]$HuduHtml.Insert($e8ScorecardInsertPosHudu, $huduScorecard.ToString())

# Set section health from E8 scorecard results
foreach ($s in $e8Scores) {
    if ($s.Badge -eq 'bad') { Set-SectionHealth -Status bad }
    elseif ($s.Badge -eq 'warn') { Set-SectionHealth -Status warn }
}

Html-EndSection

# ============================================================
# Save HTML Report
# ============================================================
Write-Host "[Final] Saving HTML report: $HtmlReportPath" -ForegroundColor Cyan
try {
    $generated = Get-Date
    $elevText = if ($IsElevated) { "Yes" } else { "No" }

    # Pre-encode values interpolated into the HTML template
    $safeComputerName  = Html-Enc $ComputerName
    $safeCustomerName  = if ($CustomerName) { Html-Enc $CustomerName } else { $null }
    $safeReportTitle   = if ($safeCustomerName) { "$safeCustomerName - $safeComputerName" } else { $safeComputerName }
    $safeReportPath    = Html-Enc $HtmlReportPath
    $safeLogPath       = Html-Enc $LogPath
    $safeVersion       = Html-Enc $ScriptVersion

    # Build update notice for the report header (if an update was detected)
    $updateNoticeHtml = ""
    if ($UpdateInfo -and $UpdateInfo.UpdateAvailable) {
        $safeLatest = Html-Enc $UpdateInfo.LatestVersion
        $safeUrl    = Html-Enc $UpdateInfo.ReleaseUrl
        $updateNoticeHtml = "<div class='update-notice'>Update available: v$safeVersion &rarr; $safeLatest &mdash; <a href='$safeUrl'>Download</a></div>"
    }

    # Build sidebar navigation (replaces old TOC)
    $sidebarHtml = ""
    if ($Toc -and $Toc.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("<nav class='sidebar' id='sidebar'>")
        [void]$sb.AppendLine("<div class='sidebar-header'><h2>Audit Navigation</h2><span class='version'>v$safeVersion</span></div>")
        [void]$sb.AppendLine("<ul class='sidebar-nav'>")
        foreach ($t in $Toc) {
            $id    = Html-Enc $t.Id
            $tt    = Html-Enc $t.Title
            $health = if ($SectionHealth.ContainsKey($t.Id)) { $SectionHealth[$t.Id] } else { 'good' }
            [void]$sb.AppendLine(("<li><a href='#{0}' data-section='{0}'><span class='nav-num'>{1}</span><span class='nav-label'>{2}</span><span class='health-dot {3}'></span></a></li>" -f $id, $t.Number, $tt, $health))
        }
        [void]$sb.AppendLine("</ul>")
        [void]$sb.AppendLine("</nav>")
        $sidebarHtml = $sb.ToString()
    }

    # Build system health score card (replaces TOC position in main content)
    $scoreCardHtml = ""
    if ($Toc -and $Toc.Count -gt 0) {
        $goodCount = @($SectionHealth.Values | Where-Object { $_ -eq 'good' }).Count
        $warnCount = @($SectionHealth.Values | Where-Object { $_ -eq 'warn' }).Count
        $badCount  = @($SectionHealth.Values | Where-Object { $_ -eq 'bad'  }).Count
        $totalCount = $goodCount + $warnCount + $badCount
        $score = if ($totalCount -gt 0) { [math]::Round(($goodCount * 1.0 + $warnCount * 0.5) / $totalCount * 10, 1) } else { 0 }

        $scoreColor = if ($score -ge 7) { 'var(--good)' } elseif ($score -ge 4) { 'var(--warn)' } else { 'var(--bad)' }
        $scoreClass = if ($score -ge 7) { 'good' } elseif ($score -ge 4) { 'warn' } else { 'bad' }

        # SVG ring parameters
        $circumference = [math]::Round(2 * [math]::PI * 52, 2)
        $offset = [math]::Round($circumference * (1 - $score / 10), 2)
        $scoreDisplay = $score.ToString("0.0")

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("<div class='score-card'>")
        [void]$sb.AppendLine("<div class='score-ring'>")
        [void]$sb.AppendLine("<svg viewBox='0 0 120 120'><circle class='bg' cx='60' cy='60' r='52'/><circle class='fg' cx='60' cy='60' r='52' stroke='$scoreColor' stroke-dasharray='$circumference' stroke-dashoffset='$offset'/></svg>")
        [void]$sb.AppendLine("<div class='score-value'><span class='num' style='color:$scoreColor'>$scoreDisplay</span><span class='label'>out of 10</span></div>")
        [void]$sb.AppendLine("</div>")
        [void]$sb.AppendLine("<div class='score-breakdown'>")
        [void]$sb.AppendLine("<h2>System Health Score</h2>")
        [void]$sb.AppendLine("<p class='score-desc'>Based on $totalCount audit modules. Each module contributes to the overall score based on its health status.</p>")
        [void]$sb.AppendLine("<div class='score-stats'>")
        [void]$sb.AppendLine("<div class='score-stat'><span class='dot good'></span><strong>$goodCount</strong> Healthy</div>")
        [void]$sb.AppendLine("<div class='score-stat'><span class='dot warn'></span><strong>$warnCount</strong> Warning</div>")
        [void]$sb.AppendLine("<div class='score-stat'><span class='dot bad'></span><strong>$badCount</strong> Critical</div>")
        [void]$sb.AppendLine("</div>")
        [void]$sb.AppendLine("</div>")
        [void]$sb.AppendLine("</div>")
        $scoreCardHtml = $sb.ToString()
    }

    # Build report-wide issues summary (bad/warn findings that have KB links)
    $globalSummaryHtml = ""
    if ($GlobalFindings.Count -gt 0) {
        $gBad  = @($GlobalFindings | Where-Object { $_.Kind -eq 'bad' })
        $gWarn = @($GlobalFindings | Where-Object { $_.Kind -eq 'warn' })
        if ($gBad.Count -gt 0 -or $gWarn.Count -gt 0) {
            $gSb = New-Object System.Text.StringBuilder
            [void]$gSb.AppendLine("<div class='issues-summary'>")
            [void]$gSb.AppendLine("<h2>Issues Requiring Attention</h2>")
            if ($gBad.Count -gt 0) {
                [void]$gSb.AppendLine("<div class='callout callout-bad'><strong>Critical Issues</strong><ul>")
                foreach ($f in $gBad) {
                    $kbLink  = if ($f.KbUrl) { " &rarr; <a href='{0}' target='_blank'>{1}</a>" -f (Html-Enc $f.KbUrl), (Html-Enc $f.KbTitle) } else { "" }
                    $secLink = "<a href='#{0}'>{1}</a>" -f (Html-Enc $f.SectionId), (Html-Enc $f.Section)
                    [void]$gSb.AppendLine(("<li><strong>{0}:</strong> {1}{2}</li>" -f $secLink, (Html-Enc $f.Message), $kbLink))
                }
                [void]$gSb.AppendLine("</ul></div>")
            }
            if ($gWarn.Count -gt 0) {
                [void]$gSb.AppendLine("<div class='callout callout-warn'><strong>Warnings</strong><ul>")
                foreach ($f in $gWarn) {
                    $kbLink  = if ($f.KbUrl) { " &rarr; <a href='{0}' target='_blank'>{1}</a>" -f (Html-Enc $f.KbUrl), (Html-Enc $f.KbTitle) } else { "" }
                    $secLink = "<a href='#{0}'>{1}</a>" -f (Html-Enc $f.SectionId), (Html-Enc $f.Section)
                    [void]$gSb.AppendLine(("<li><strong>{0}:</strong> {1}{2}</li>" -f $secLink, (Html-Enc $f.Message), $kbLink))
                }
                [void]$gSb.AppendLine("</ul></div>")
            }
            [void]$gSb.AppendLine("</div>")
            $globalSummaryHtml = $gSb.ToString()
        }
    }

$htmlContent = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System Audit Report - $safeReportTitle</title>
<style>
:root{
  --bg:#f0f4f8; --card:#ffffff; --text:#1e293b; --muted:#64748b;
  --accent:#1e3a5f; --accent-light:#2E5C6E; --border:#e2e8f0;
  --good:#059669; --good-bg:#ecfdf5; --good-border:#a7f3d0;
  --warn:#d97706; --warn-bg:#fffbeb; --warn-border:#fde68a;
  --bad:#dc2626;  --bad-bg:#fef2f2;  --bad-border:#fecaca;
}
*{ box-sizing:border-box; }
body{ font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:24px 24px 24px 284px; line-height:1.5; }
.container{ max-width:1100px; margin:0 auto; }

/* ---- Header ---- */
.header{
  background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);
  border-radius:14px; padding:28px 32px; color:#fff;
  box-shadow:0 4px 12px rgba(30,58,95,.15);
}
h1{ margin:0; color:#fff; font-size:26px; font-weight:700; letter-spacing:-0.3px; }
.header .subtitle{ font-size:15px; opacity:0.85; margin-top:4px; font-weight:400; }
.header .meta-bar{
  display:flex; flex-wrap:wrap; gap:6px 18px; margin-top:14px; padding-top:14px;
  border-top:1px solid rgba(255,255,255,.2); font-size:12px; opacity:0.8;
}
.header .meta-bar span{ white-space:nowrap; }
.header .update-notice{
  margin-top:10px; padding:8px 14px; border-radius:8px;
  background:rgba(255,255,255,.15); font-size:13px;
}
.header .update-notice a{ color:#fde68a; }

/* ---- Sidebar ---- */
.sidebar{
  position:fixed; left:0; top:0; width:260px; height:100vh; background:var(--card);
  border-right:1px solid var(--border); overflow-y:auto; padding:0; z-index:100;
  box-shadow:2px 0 8px rgba(0,0,0,.04); display:flex; flex-direction:column;
}
.sidebar-header{
  padding:20px 20px 16px; border-bottom:1px solid var(--border); flex-shrink:0;
}
.sidebar-header h2{ margin:0; font-size:15px; color:var(--accent); font-weight:700; }
.sidebar-header .version{ font-size:11px; color:var(--muted); }
.sidebar-nav{ list-style:none; padding:8px 0; margin:0; overflow-y:auto; flex:1; }
.sidebar-nav li{ margin:0; }
.sidebar-nav a{
  display:flex; align-items:center; gap:10px; padding:9px 20px;
  text-decoration:none; color:var(--text); font-size:13px;
  transition:background .15s, border-color .15s; border-left:3px solid transparent;
}
.sidebar-nav a:hover{ background:var(--bg); }
.sidebar-nav a.active{ background:var(--bg); border-left-color:var(--accent); font-weight:600; }
.nav-num{
  display:inline-flex; align-items:center; justify-content:center;
  min-width:22px; height:22px; border-radius:6px; background:var(--bg);
  font-size:11px; font-weight:700; flex-shrink:0; color:var(--muted);
}
.nav-label{ flex:1; line-height:1.3; }
.health-dot{ width:8px; height:8px; border-radius:50%; flex-shrink:0; }
.health-dot.good{ background:var(--good); }
.health-dot.warn{ background:var(--warn); }
.health-dot.bad{ background:var(--bad); }
.sidebar-toggle{
  display:none; position:fixed; bottom:20px; left:20px; z-index:200;
  width:48px; height:48px; border-radius:50%; background:var(--accent); color:#fff;
  border:none; cursor:pointer; font-size:22px; box-shadow:0 2px 10px rgba(0,0,0,.2);
  align-items:center; justify-content:center;
}
.sidebar-overlay{
  display:none; position:fixed; inset:0; background:rgba(0,0,0,.3); z-index:99;
}
.sidebar-overlay.open{ display:block; }
@media(max-width:900px){
  .sidebar{ transform:translateX(-100%); transition:transform .25s ease; }
  .sidebar.open{ transform:translateX(0); }
  .sidebar-toggle{ display:flex; }
  body{ padding-left:24px !important; }
}

/* ---- Score Card ---- */
.score-card{
  margin-top:16px; background:var(--card); border:1px solid var(--border); border-radius:14px;
  padding:28px 32px; box-shadow:0 1px 3px rgba(0,0,0,.04);
  display:flex; align-items:center; gap:32px;
}
.score-ring{ position:relative; width:120px; height:120px; flex-shrink:0; }
.score-ring svg{ width:120px; height:120px; transform:rotate(-90deg); }
.score-ring .bg{ fill:none; stroke:var(--border); stroke-width:8; }
.score-ring .fg{ fill:none; stroke-width:8; stroke-linecap:round; }
.score-value{
  position:absolute; inset:0; display:flex; flex-direction:column;
  align-items:center; justify-content:center;
}
.score-value .num{ font-size:32px; font-weight:700; line-height:1; }
.score-value .label{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.5px; margin-top:2px; }
.score-breakdown{ flex:1; }
.score-breakdown h2{ margin:0 0 6px; font-size:18px; color:var(--accent); font-weight:700; }
.score-desc{ margin:0 0 14px; font-size:13px; color:var(--muted); }
.score-stats{ display:flex; flex-wrap:wrap; gap:16px 28px; }
.score-stat{ display:flex; align-items:center; gap:8px; font-size:14px; }
.score-stat .dot{ width:12px; height:12px; border-radius:50%; flex-shrink:0; }
.score-stat .dot.good{ background:var(--good); }
.score-stat .dot.warn{ background:var(--warn); }
.score-stat .dot.bad{ background:var(--bad); }
@media(max-width:600px){
  .score-card{ flex-direction:column; text-align:center; gap:20px; padding:20px; }
  .score-stats{ justify-content:center; }
}

/* ---- Issues Summary ---- */
.issues-summary{
  background:var(--card); border-radius:12px; padding:24px 28px;
  border:1px solid var(--border); box-shadow:0 1px 3px rgba(0,0,0,.04);
  margin:24px 0;
}
.issues-summary h2{ font-size:18px; font-weight:700; color:var(--accent); margin:0 0 14px; }
.issues-summary .callout ul{ margin:6px 0 0 18px; padding:0; }
.issues-summary .callout li{ margin:4px 0; font-size:13px; line-height:1.5; }
.issues-summary .callout a{ color:inherit; text-decoration:none; font-weight:600; border-bottom:1px solid currentColor; }
.issues-summary .callout a:hover{ opacity:0.8; }

/* ---- Sections ---- */
.section{
  margin-top:16px; background:var(--card); border:1px solid var(--border); border-radius:14px;
  padding:20px 24px; box-shadow:0 1px 3px rgba(0,0,0,.04); overflow:hidden;
}
.section-details{ width:100%; }
.section-summary{
  position:sticky; top:0; z-index:10; background:var(--card);
  margin:0 -24px; padding:12px 24px; color:var(--accent);
  border-bottom:2px solid var(--border); font-size:18px; font-weight:700;
  display:flex; align-items:center; gap:10px;
  cursor:pointer; user-select:none; list-style:none;
}
.section-summary::-webkit-details-marker{ display:none; }
.section-summary::marker{ display:none; content:''; }
.section-summary::after{
  content:''; display:block; width:8px; height:8px; margin-left:auto; flex-shrink:0;
  border-right:2px solid currentColor; border-bottom:2px solid currentColor;
  transform:rotate(45deg); transition:transform 0.2s; opacity:0.4;
}
.section-details[open] > .section-summary::after{ transform:rotate(-135deg); }
.section-summary:hover{ opacity:0.8; }
.sec-num{
  display:inline-flex; align-items:center; justify-content:center;
  min-width:28px; height:28px; border-radius:8px;
  background:var(--accent); color:#fff; font-size:13px; font-weight:700; flex-shrink:0;
}
.section h3{ margin:20px 0 10px; color:#334155; font-size:15px; font-weight:600; }

/* ---- Callout / Note bars ---- */
.callout{
  padding:10px 14px; border-radius:8px; font-size:13px; margin:10px 0;
  border-left:4px solid var(--border); background:var(--bg); color:var(--text);
}
.callout-good{ border-left-color:var(--good); background:var(--good-bg); }
.callout-warn{ border-left-color:var(--warn); background:var(--warn-bg); }
.callout-bad{  border-left-color:var(--bad);  background:var(--bad-bg); }
.callout-info{ border-left-color:var(--accent-light); }

/* ---- Key-value grids ---- */
.kv{ display:grid; grid-template-columns:240px 1fr; gap:6px 12px; font-size:14px; }
.kv div.key{ color:var(--muted); font-weight:500; }
.kv-table{ margin-top:6px; table-layout:auto; }
.kv-table th{ width:280px; }

/* ---- Details / collapsible ---- */
details{ margin-top:12px; }
summary{
  cursor:pointer; user-select:none; font-weight:600; color:var(--accent);
  padding:8px 0; font-size:14px;
}
summary:hover{ text-decoration:underline; }

/* ---- Tables ---- */
table{ width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; table-layout:fixed; }
th,td{ border:1px solid var(--border); padding:8px 10px; vertical-align:top; overflow-wrap:break-word; word-break:break-word; }
th{ background:#eef3f7; text-align:left; position:sticky; top:0; z-index:1; font-weight:600; color:#334155; font-size:12px; text-transform:uppercase; letter-spacing:0.3px; }
tr:nth-child(even) td{ background:#f8fafc; }
tbody tr:hover td{ background:#eef3f7 !important; }
tr.sev-good td{ background:var(--good-bg) !important; }
tr.sev-warn td{ background:var(--warn-bg) !important; }
tr.sev-bad td{ background:var(--bad-bg) !important; }
tr.sev-good:hover td{ background:#d1fae5 !important; }
tr.sev-warn:hover td{ background:#fef3c7 !important; }
tr.sev-bad:hover td{ background:#fee2e2 !important; }

/* ---- Badges ---- */
.badge{
  display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600;
  border:1px solid var(--border); background:#f9fafb; color:var(--muted);
}
.badge.good{ background:var(--good-bg); border-color:var(--good-border); color:var(--good); }
.badge.warn{ background:var(--warn-bg); border-color:var(--warn-border); color:var(--warn); }
.badge.bad{  background:var(--bad-bg);  border-color:var(--bad-border);  color:var(--bad); }

/* ---- Filter box ---- */
.filter-box{
  width:100%; padding:10px 14px; margin:10px 0 6px; border:1px solid var(--border);
  border-radius:8px; font-size:14px; font-family:inherit; outline:none; background:var(--bg);
}
.filter-box:focus{ border-color:var(--accent); box-shadow:0 0 0 3px rgba(30,58,95,.1); background:#fff; }

/* ---- Utility ---- */
.small{ font-size:12px; color:var(--muted); }
.code{ font-family:Consolas,'Courier New',monospace; font-size:12px; }

/* ---- Footer ---- */
.footer{
  margin-top:24px; padding-top:16px; border-top:1px solid var(--border);
  color:var(--muted); font-size:12px; text-align:center;
}

/* ---- Print ---- */
@media print{
  .sidebar,.sidebar-toggle,.sidebar-overlay{ display:none !important; }
  body{ background:#fff; padding:0 !important; font-size:11px; }
  .container{ max-width:none; }
  .header{ background:var(--accent) !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .section,.score-card{ box-shadow:none; border:1px solid #ccc; break-inside:avoid; }
  .score-ring svg{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .section-summary{ position:static; }
  .section-summary::after{ display:none; }
  details[open] summary:not(.section-summary){ display:none; }
  details > *{ display:block !important; }
  summary{ page-break-after:avoid; }
  .filter-box,.small#sw-filter-count{ display:none; }
  table{ font-size:10px; }
  th{ position:static; }
  tbody tr:hover td{ background:inherit !important; }
  .footer{ border-top:1px solid #ccc; }
  a{ color:var(--accent) !important; text-decoration:none; }
}
</style>
</head>
<body>
$sidebarHtml
<button class="sidebar-toggle" id="sidebar-toggle" aria-label="Toggle navigation">&#9776;</button>
<div class="sidebar-overlay" id="sidebar-overlay"></div>
<div class="container">
  <div class="header">
    <h1>System Audit Report</h1>
    <div class="subtitle">$safeReportTitle</div>
    <div class="meta-bar">
      <span>Generated: $generated</span>
      <span>Elevated: $elevText</span>
      <span>Version: v$safeVersion</span>
    </div>
$updateNoticeHtml
  </div>

$scoreCardHtml

$globalSummaryHtml

$($Html.ToString())

  <div class="footer">
    Windows Audit Tool v$safeVersion &bull; Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')
  </div>
</div>
<script>
(function(){
  var toggle=document.getElementById('sidebar-toggle');
  var sidebar=document.getElementById('sidebar');
  var overlay=document.getElementById('sidebar-overlay');
  if(toggle&&sidebar){
    toggle.addEventListener('click',function(){sidebar.classList.toggle('open');overlay.classList.toggle('open')});
    overlay.addEventListener('click',function(){sidebar.classList.remove('open');overlay.classList.remove('open')});
  }
  var links=document.querySelectorAll('.sidebar-nav a');
  var sections=document.querySelectorAll('.section');
  if(sections.length&&links.length){
    var observer=new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if(entry.isIntersecting){
          var s=entry.target.querySelector('summary[id]');
          if(!s)return;
          links.forEach(function(l){l.classList.toggle('active',l.getAttribute('data-section')===s.id)});
        }
      });
    },{rootMargin:'-10% 0px -80% 0px'});
    sections.forEach(function(s){observer.observe(s)});
    links.forEach(function(l){
      l.addEventListener('click',function(e){
        e.preventDefault();
        var t=document.getElementById(this.getAttribute('data-section'));
        if(t){var d=t.closest('details');if(d)d.setAttribute('open','');t.scrollIntoView({behavior:'smooth',block:'start'});}
        if(sidebar)sidebar.classList.remove('open');
        if(overlay)overlay.classList.remove('open');
      });
    });
  }
  window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.setAttribute('open','')})});
})();
</script>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $HtmlReportPath -Force -Encoding utf8
    Write-Host "HTML report saved to $HtmlReportPath" -ForegroundColor Green
    Log "HTML report written to $HtmlReportPath"

    # ---- Hudu-compatible report (only when -HuduReport is enabled) ----
    if ($HuduReport -and $HuduValid) {
    # Hudu's ActionText sanitizer restructures nested <div> containers around block elements.
    # All layouts here use <table> instead of nested divs to survive sanitization intact.
    Write-Host "[Final] Building Hudu report..." -ForegroundColor Cyan

    # Hudu header - table layout prevents ActionText from splitting container around h1
    $huduUpdateLine = ""
    if ($UpdateInfo -and $UpdateInfo.UpdateAvailable) {
        $huduUpdateLine = "<p style='margin:10px 0 0; padding:8px 14px; border-radius:8px; background:rgba(255,255,255,.15); font-size:13px; color:#fff;'>Update available: v$safeVersion &rarr; $safeLatest &mdash; <a href='$safeUrl' style='color:#fde68a;'>Download</a></p>"
    }
    $huduHeaderHtml = @"
<table style='width:100%; border-collapse:collapse; border-radius:14px; overflow:hidden;'>
<tr><td style='background:linear-gradient(135deg, #1e3a5f 0%, #2E5C6E 100%); padding:28px 32px; color:#fff;'>
<h1 style='margin:0; color:#fff; font-size:26px; font-weight:700; letter-spacing:-0.3px;'>System Audit Report</h1>
<p style='font-size:15px; opacity:0.85; margin:4px 0 0; color:#fff;'>$safeReportTitle</p>
<p style='font-size:12px; opacity:0.8; margin:14px 0 0; padding-top:14px; border-top:1px solid rgba(255,255,255,.2); color:#fff;'>Generated: $generated &nbsp;&bull;&nbsp; Elevated: $elevText &nbsp;&bull;&nbsp; Version: v$safeVersion</p>
$huduUpdateLine
</td></tr>
</table>
"@

    # Hudu score card - table layout instead of nested flexbox divs
    $huduScoreCardHtml = ""
    if ($Toc -and $Toc.Count -gt 0) {
        $scoreColor2 = if ($score -ge 7) { '#059669' } elseif ($score -ge 4) { '#d97706' } else { '#dc2626' }
        $huduScoreCardHtml = @"
<table style='width:100%; border-collapse:collapse; margin-top:16px; border:1px solid rgba(128,128,128,0.2); border-radius:14px; overflow:hidden;'>
<tr>
<td style='text-align:center; padding:28px 20px; width:120px; vertical-align:middle;'>
<span style='font-size:42px; font-weight:700; color:$scoreColor2; line-height:1;'>$scoreDisplay</span><br>
<span style='font-size:11px; opacity:0.6; text-transform:uppercase; letter-spacing:0.5px;'>out of 10</span>
</td>
<td style='padding:28px 32px 28px 12px; vertical-align:middle;'>
<strong style='font-size:18px;'>System Health Score</strong><br>
<span style='font-size:13px; opacity:0.6;'>Based on $totalCount audit modules. Each module contributes to the overall score based on its health status.</span><br><br>
<span style='font-size:14px;'><span style='display:inline-block; width:12px; height:12px; border-radius:50%; background:#059669; vertical-align:middle;'></span> <strong>$goodCount</strong> Healthy &nbsp;&nbsp;<span style='display:inline-block; width:12px; height:12px; border-radius:50%; background:#d97706; vertical-align:middle;'></span> <strong>$warnCount</strong> Warning &nbsp;&nbsp;<span style='display:inline-block; width:12px; height:12px; border-radius:50%; background:#dc2626; vertical-align:middle;'></span> <strong>$badCount</strong> Critical</span>
</td>
</tr>
</table>
"@
    }

    # Hudu TOC - flat structure, no wrapping div (Hudu would split a div around the h2)
    $huduTocHtml = ""
    if ($Toc -and $Toc.Count -gt 0) {
        $tocSb = New-Object System.Text.StringBuilder
        [void]$tocSb.AppendLine("<h2 style='margin:24px 0 12px; font-size:18px; font-weight:700;'>Audit Navigation</h2>")
        [void]$tocSb.AppendLine("<ul style='margin:0; padding-left:8px; font-size:14px; line-height:2; list-style:none;'>")
        foreach ($t in $Toc) {
            $id    = Html-Enc $t.Id
            $tt    = Html-Enc $t.Title
            $health = if ($SectionHealth.ContainsKey($t.Id)) { $SectionHealth[$t.Id] } else { 'good' }
            $dotColor = switch ($health) { 'good' { '#059669' }; 'warn' { '#d97706' }; 'bad' { '#dc2626' }; default { '#059669' } }
            [void]$tocSb.AppendLine(("<li><a href='#{0}' style='text-decoration:none; color:inherit;'>{3}. <span style='color:{2}; font-size:10px;'>&#9679;</span> {1}</a></li>" -f $id, $tt, $dotColor, $t.Number))
        }
        [void]$tocSb.AppendLine("</ul>")
        $huduTocHtml = $tocSb.ToString()
    }

    # Hudu report-wide issues summary (uses <p> not <ul><li> - ActionText sanitizer restructures block elements inside divs)
    $huduGlobalSummaryHtml = ""
    if ($GlobalFindings.Count -gt 0) {
        $gBad2  = @($GlobalFindings | Where-Object { $_.Kind -eq 'bad' })
        $gWarn2 = @($GlobalFindings | Where-Object { $_.Kind -eq 'warn' })
        if ($gBad2.Count -gt 0 -or $gWarn2.Count -gt 0) {
            $gHuduSb = New-Object System.Text.StringBuilder
            [void]$gHuduSb.AppendLine((Convert-ToHuduInline "<h2>Issues Requiring Attention</h2>"))
            if ($gBad2.Count -gt 0) {
                [void]$gHuduSb.AppendLine((Convert-ToHuduInline "<div class='callout callout-bad'>"))
                [void]$gHuduSb.AppendLine("<strong>Critical Issues</strong>")
                foreach ($f in $gBad2) {
                    $kbLink2 = if ($f.KbUrl) { " &rarr; <a href='{0}' target='_blank'>{1}</a>" -f (Html-Enc $f.KbUrl), (Html-Enc $f.KbTitle) } else { "" }
                    [void]$gHuduSb.AppendLine(("<p style='margin:4px 0;'><strong>{0}:</strong> {1}{2}</p>" -f (Html-Enc $f.Section), (Html-Enc $f.Message), $kbLink2))
                }
                [void]$gHuduSb.AppendLine("</div>")
            }
            if ($gWarn2.Count -gt 0) {
                [void]$gHuduSb.AppendLine((Convert-ToHuduInline "<div class='callout callout-warn'>"))
                [void]$gHuduSb.AppendLine("<strong>Warnings</strong>")
                foreach ($f in $gWarn2) {
                    $kbLink2 = if ($f.KbUrl) { " &rarr; <a href='{0}' target='_blank'>{1}</a>" -f (Html-Enc $f.KbUrl), (Html-Enc $f.KbTitle) } else { "" }
                    [void]$gHuduSb.AppendLine(("<p style='margin:4px 0;'><strong>{0}:</strong> {1}{2}</p>" -f (Html-Enc $f.Section), (Html-Enc $f.Message), $kbLink2))
                }
                [void]$gHuduSb.AppendLine("</div>")
            }
            $huduGlobalSummaryHtml = $gHuduSb.ToString()
        }
    }

    # Build Hudu HTML body fragment (used for both file preview and API upload)
    $huduBodyFragment = @"
$huduHeaderHtml

$huduScoreCardHtml

$huduGlobalSummaryHtml

$huduTocHtml

$($HuduHtml.ToString())

<hr style='border:none; border-top:1px solid rgba(128,128,128,0.2); margin:24px 0 0;'>
<p style='opacity:0.6; font-size:12px; text-align:center; padding-top:16px;'>
  Windows Audit Tool v$safeVersion &bull; Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')
</p>
"@

    # Write Hudu HTML preview file
    $huduContent = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System Audit Report - $safeReportTitle (Hudu)</title>
</head>
<body style="font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif; margin:0; padding:24px; line-height:1.5;">

$huduBodyFragment

</body>
</html>
"@

    $huduContent | Out-File -FilePath $HuduHtmlReportPath -Force -Encoding utf8
    Write-Host "Hudu HTML preview saved to $HuduHtmlReportPath" -ForegroundColor Green
    Log "Hudu HTML preview written to $HuduHtmlReportPath"

    # ---- Upload to Hudu via API ----
    Write-Host "[Hudu] Uploading report to Hudu..." -ForegroundColor Yellow
    Log "STEP Hudu: Uploading report to Hudu"
    $huduAssetDate = Get-Date -Format 'dd/MM/yyyy'
    $huduAssetName = "$ComputerName - $huduAssetDate"
    # Strip null bytes and control characters (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F) - they are
    # invalid in JSON strings (RFC 8259) and cause Rails to return 500 with no error detail.
    # These can originate from registry software entries containing embedded null bytes.
    $huduBodyFragment = $huduBodyFragment -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    $huduResult = Publish-HuduAsset `
        -LayoutName     $HuduAssetLayoutName `
        -AssetName      $huduAssetName `
        -HtmlContent    $huduBodyFragment `
        -AttachmentPath $HtmlReportPath
    if ($huduResult.AssetCreated) {
        Write-Host "  Hudu upload complete: $huduAssetName" -ForegroundColor Green
        if ($huduResult.FileAttached) {
            # Both report content and file attachment succeeded - local copies are redundant
            Remove-Item -LiteralPath $HtmlReportPath     -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $HuduHtmlReportPath -Force -ErrorAction SilentlyContinue
            Write-Action -What "Local report files removed (content preserved in Hudu)" -Kind ok
            Log "Hudu: local report files deleted after successful upload and attachment"
        } else {
            Write-Action -What "Attachment upload failed - local report files retained" -Kind warn
            Log "Hudu: local report files retained (attachment did not succeed)"
        }
    } else {
        Write-Host "  Hudu upload failed. The local HTML report is still available." -ForegroundColor Yellow
    }
    } # end if ($HuduReport -and $HuduValid)
}
catch {
    Write-Host "Failed to write HTML report: $_" -ForegroundColor Red
    Log "Failed to write HTML report: $_"
    exit 3
}

Write-Host "=== Audit Completed for $ComputerName ===" -ForegroundColor Green
Log "Audit completed for $ComputerName"

if (-not $Silent) {
    Write-Host ""
    Write-Host "Audit complete. Press ENTER to exit..." -ForegroundColor Cyan
    [void][System.Console]::ReadLine()
}

exit 0

} catch {
    $msg = "FATAL: Unhandled exception - $($_.Exception.Message)"
    Write-Host $msg -ForegroundColor Red
    try { Log $msg } catch { }
    try { Log-ExceptionDetail -Context "Top-level" -ErrorRecord $_ } catch { }
    exit 1
}
