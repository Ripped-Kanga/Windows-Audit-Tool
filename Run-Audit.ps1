<#
    Run-Audit.ps1
    System Audit Script with progress output + security baseline.

    Output:
      - HTML report written to C:\Temp\<COMPUTER>-Audit.html
      - Operational log written to C:\Windows\Temp\AuditLog.txt
#>

param(
    # Suppress UAC elevation prompt and final interactive pause.
    # Intended for unattended deployment via RMM/MDM tools (Atera, Intune, etc.)
    # where the script is always launched in an already-elevated context.
    [switch]$Silent,

    # Update switches - download newer release assets from GitHub then run the audit.
    [Alias('update-all')]    [switch]$UpdateAll,
    [Alias('update-script')] [switch]$UpdateScript,
    [Alias('update-exe')]    [switch]$UpdateExe
)

$ErrorActionPreference = "Stop"

# ------------------------- #
# Version                   #
# ------------------------- #
$ScriptVersion = "1.1.0"

# ------------------------- #
# Paths (per computer)      #
# ------------------------- #
$ComputerName = $env:COMPUTERNAME
if (-not $ComputerName -or $ComputerName -eq "") {
    $ComputerName = "UnknownComputer"
}

$HtmlReportPath = "C:\Temp\${ComputerName}-Audit.html"
$LogPath        = "C:\Windows\Temp\AuditLog.txt"

# Ensure directories exist
try {
    New-Item -ItemType Directory -Path "C:\Temp" -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Host "FATAL: Could not create C:\Temp - $_" -ForegroundColor Red
    exit 2
}

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

    $silentArg = if ($Silent) { " -Silent" } else { "" }

    if ($PSCommandPath) {
        # Running as a .ps1 script - relaunch via powershell.exe
        $psi.FileName  = "powershell.exe"
        $psi.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`"$silentArg"
    }
    else {
        # Likely running as a PS2EXE-compiled executable
        $exePath = Convert-Path -LiteralPath ([Environment]::GetCommandLineArgs()[0])
        $psi.FileName  = $exePath
        $psi.Arguments = $silentArg.TrimStart()
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

    $updates = [System.Collections.Generic.List[object]]::new()

    $updates.Add([pscustomobject]@{
        Title          = "<META>"
        KB             = "N/A"
        Categories     = ("ResultCode={0}; Criteria={1}; Count={2}" -f $result.ResultCode, $criteria, $result.Updates.Count)
        Downloaded     = $false
        Mandatory      = $false
        RebootRequired = $false
        EulaAccepted   = $true
    })

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

        $updates.Add([pscustomobject]@{
            Title          = $u.Title
            KB             = $kb
            Categories     = $cats
            Downloaded     = $u.IsDownloaded
            Mandatory      = $u.IsMandatory
            RebootRequired = $u.RebootRequired
            EulaAccepted   = $u.EulaAccepted
        })
    }

    return @($updates)
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
            # Don't pass flags that older winget builds reject
            $raw = & $winget.Source "list" "--disable-interactivity" "--accept-source-agreements" 2>&1
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
$Html = New-Object System.Text.StringBuilder
$Toc = New-Object System.Collections.Generic.List[object]
$SectionIdCounts = @{}

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

function Html-Add {
    param([string]$Line)
    [void]$Html.AppendLine($Line)
}

function Html-StartSection {
    param([string]$Title)
    $id = New-SectionId -Title $Title
    $Toc.Add([pscustomobject]@{ Title = $Title; Id = $id }) | Out-Null
    Html-Add "<div class='section'>"
    Html-Add ("<h2 id='{0}'>{1}</h2>" -f (Html-Enc $id), (Html-Enc $Title))
}

function Html-EndSection { Html-Add "</div>" }

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

    # Determine the directory containing the running script/exe
    $scriptDir = $null
    $runningAsExe = $false
    if ($PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
    } else {
        $exePath = Convert-Path -LiteralPath ([Environment]::GetCommandLineArgs()[0])
        $scriptDir = Split-Path -Parent $exePath
        $runningAsExe = $true
    }

    if (-not $scriptDir) {
        Log "Self-update: could not determine script directory"
        Write-Action -What "Update failed: could not determine script directory" -Kind warn
        return $false
    }

    $updated = $false

    # Download .ps1
    if ($IncludeScript -and $UpdateInfo.Ps1DownloadUrl) {
        $ps1Target = Join-Path $scriptDir "Run-Audit.ps1"
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
        $exeTarget = Join-Path $scriptDir "Run-Audit.exe"
        $exeTemp   = Join-Path $scriptDir "Run-Audit.exe.update"

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
    $scriptDir = $null
    if ($PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
    } else {
        $exePath = Convert-Path -LiteralPath ([Environment]::GetCommandLineArgs()[0])
        $scriptDir = Split-Path -Parent $exePath
    }

    if (-not $scriptDir) { return }

    $pending = Join-Path $scriptDir "Run-Audit.exe.update"
    $target  = Join-Path $scriptDir "Run-Audit.exe"

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
# Start                     #
# ------------------------- #
try {

Write-Host "=== Windows Audit Tool v$ScriptVersion ===" -ForegroundColor Cyan
Write-Host "=== Starting System Audit for $ComputerName ===" -ForegroundColor Cyan
Log "Audit started for $ComputerName (v$ScriptVersion)"

# Apply any pending .exe update from a prior run
Invoke-PendingExeSwap

# Determine if the user requested an update
$WantUpdate       = $UpdateAll -or $UpdateScript -or $UpdateExe
$WantUpdateScript = $UpdateAll -or $UpdateScript
$WantUpdateExe    = $UpdateAll -or $UpdateExe

# Check for updates
$UpdateInfo = Test-ForUpdate
if ($UpdateInfo -and $UpdateInfo.UpdateAvailable) {
    if ($WantUpdate -or $Silent) {
        # Explicit update request, or -Silent mode (auto-update script only)
        $doScript = $WantUpdateScript -or $Silent
        $doExe    = $WantUpdateExe

        Write-Host ("    Updating: {0} -> {1}" -f $UpdateInfo.CurrentVersion, $UpdateInfo.LatestVersion) -ForegroundColor Cyan
        Log ("Performing update: {0} -> {1}" -f $UpdateInfo.CurrentVersion, $UpdateInfo.LatestVersion)

        $didUpdate = Invoke-SelfUpdate -UpdateInfo $UpdateInfo -IncludeScript:$doScript -IncludeExe:$doExe
        if ($didUpdate -and $doScript -and $PSCommandPath -and $UpdateInfo.Ps1DownloadUrl) {
            # .ps1 was replaced - re-launch the updated script (without update flags) and exit
            Write-Host "    Restarting with updated script..." -ForegroundColor Cyan
            Log "Self-update: re-launching updated .ps1"
            $silentArg = if ($Silent) { " -Silent" } else { "" }
            $relaunchArgs = "-ExecutionPolicy Bypass -File `"$PSCommandPath`"$silentArg"
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

# ============================================================
# [1] SYSTEM INFORMATION
# ============================================================
Write-Step -Index 1 -Total 10 -Title "Collecting system information..."
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
Write-Step -Index 2 -Total 10 -Title "Collecting installed software..."
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

    $open = $false
    if ($appCount -le 200) { $open = $true }

    Html-StartDetails -Summary ("Applications ({0})" -f $appCount) -Open:($open)
    Html-AddTable -Items $appsList -Columns @(
        @{ Header="Name";      Property="DisplayName" },
        @{ Header="Version";   Property="DisplayVersion" },
        @{ Header="Publisher"; Property="Publisher" },
        @{ Header="Scope";     Property="Scope" },
        @{ Header="Sources";   Property="Sources" }
    )
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
Write-Step -Index 3 -Total 10 -Title "Collecting installed Windows patches..."
Write-Action -What "Running: Installed patches/hotfixes (Get-HotFix)" -Kind run
Html-StartSection "Windows Patches / Hotfixes"

$patches = Safe-Invoke { Get-HotFix | Sort-Object InstalledOn -Descending } "Windows Patches"

if ($patches -ne "Error" -and $patches) {
    $patchList  = @($patches) | Sort-Object InstalledOn -Descending
    $patchCount = $patchList.Count

    Write-Action -What ("Patches found: {0}" -f $patchCount) -Kind ok
    Html-AddNote -Text ("Patches found: {0}" -f $patchCount) -Kind info

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
Write-Step -Index 4 -Total 10 -Title "Checking pending Windows Updates..."
Write-Action -What "Running: Pending updates (WUA API)" -Kind run
Html-StartSection "Pending Windows Updates"

$pendingUpdates = Safe-Invoke { Get-PendingWindowsUpdatesWUA } "Pending Windows Updates (WUA API)"

if ($pendingUpdates -eq "Error") {
    Write-Action -What "Pending updates query failed." -Kind bad
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
        Write-Action -What "No pending updates found." -Kind ok
        Html-AddNote -Text "No pending updates found." -Kind good
    }
    else {
        $count = @($real).Count
        Write-Action -What ("Pending updates: {0}" -f $count) -Kind warn
        Html-AddNote -Text ("Pending updates: {0}" -f $count) -Kind warn

        $updateRows = @($real) | ForEach-Object {
            [pscustomobject]@{
                KB             = $_.KB
                Title          = $_.Title
                Categories     = $_.Categories
                Downloaded     = $_.Downloaded
                Mandatory      = $_.Mandatory
                RebootRequired = $_.RebootRequired
            }
        }

        Html-StartDetails -Summary ("Updates ({0})" -f $count) -Open
        Html-AddTable -Items $updateRows -Columns @(
            @{ Header="KB";         Property="KB" },
            @{ Header="Title";      Property="Title" },
            @{ Header="Categories"; Property="Categories" },
            @{ Header="Downloaded"; Property="Downloaded" },
            @{ Header="Mandatory";  Property="Mandatory" },
            @{ Header="Reboot";     Property="RebootRequired" }
        ) -RowClass {
            param($r)
            if ($r.RebootRequired -eq $true -or $r.Mandatory -eq $true) { return 'sev-bad' }
            return 'sev-warn'
        }
        Html-EndDetails
    }
}

Html-EndSection

# ============================================================
# [5] NETWORK ADAPTERS
# ============================================================
Write-Step -Index 5 -Total 10 -Title "Gathering network information..."
Write-Action -What "Running: Network adapters + primary config" -Kind run
Html-StartSection "Network"

$nets = Safe-Invoke { Get-NetAdapter | Select-Object Name, Status, MacAddress } "Network Adapters"

if ($nets -ne "Error" -and $nets) {
    $netList = @($nets) | Sort-Object Name
    Write-Action -What ("Adapters found: {0}" -f $netList.Count) -Kind ok

    Html-StartDetails -Summary ("Network Adapters ({0})" -f $netList.Count) -Open
    Html-AddTable -Items $netList -Columns @(
        @{ Header="Name";        Property="Name" },
        @{ Header="Status";      Property="Status" },
        @{ Header="MAC Address"; Property="MacAddress" }
    )
    Html-EndDetails
}
else {
    Write-Action -What "Network adapter query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve network adapter information." -Kind warn
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

        Write-Action -What ("Primary: {0} | IPv4 {1} | GW {2}" -f $name, $ip4, $gw4) -Kind info

        Html-Add ("<h3>{0}</h3>" -f (Html-Enc ("Primary Configuration: " + $name)))
        Html-AddKV -Pairs ([ordered]@{
            "IPv4"    = $ip4
            "Gateway" = $gw4
            "DNS"     = $dns
        })
    }
}

Html-EndSection

# ============================================================
# [6] SMB SHARES
# ============================================================
Write-Step -Index 6 -Total 10 -Title "Gathering SMB shares..."
Write-Action -What "Running: SMB shares (Get-SmbShare)" -Kind run
Html-StartSection "SMB Shares"

$shares = Safe-Invoke { Get-SmbShare | Select-Object Name, Path } "SMB Shares"

if ($shares -ne "Error" -and $shares) {
    $shareList = @($shares) | Sort-Object Name
    $nonAdmin = $shareList | Where-Object { $_.Name -notmatch '^\w\$$' -and $_.Name -notin @('ADMIN$', 'C$', 'IPC$') }

    if ($nonAdmin -and $nonAdmin.Count -gt 0) {
        Write-Action -What ("Non-admin SMB shares found: {0}" -f $nonAdmin.Count) -Kind warn
        Html-AddNote -Text ("Non-admin SMB shares found: {0}" -f $nonAdmin.Count) -Kind warn
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
Write-Step -Index 7 -Total 10 -Title "Gathering printers..."
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
Write-Step -Index 8 -Total 10 -Title "Performing security baseline checks..."
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
            Write-Action -What ("BitLocker: {0} volume(s) not protected" -f $off.Count) -Kind warn
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
            @{ Header="Profile";                 Property="Profile" },
            @{ Header="Enabled";                 Property="Enabled"; Raw=$true },
            @{ Header="Default Inbound Action";  Property="Inbound" },
            @{ Header="Default Outbound Action"; Property="Outbound" }
        )
    }
    else {
        Write-Action -What "Firewall profile query failed." -Kind warn
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
        Write-Action -What "Defender status query failed." -Kind warn
        Html-AddNote -Text "Could not retrieve Defender status." -Kind warn
    }


    # --- Anti-Virus Products ---
    Html-Add "<h3>Anti-Virus Products</h3>"
    $av = Safe-Invoke {
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
            Select-Object displayName, productState
    } "AntiVirus Products"

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
                Product    = $_.displayName
                Status     = $statusBadge
                Engine     = $engine
                Signatures = if ($sig -eq "UpToDate") { "<span class='badge good'>Up-to-date</span>" }
                             elseif ($sig -eq "OutOfDate") { "<span class='badge warn'>Out-of-date</span>" }
                             else { "<span class='badge warn'>Unknown</span>" }
                State      = ("0x{0:X6}" -f [int]$state)
            }
        }


        Html-AddTable -Items $avRows -Columns @(
            @{ Header="Product";    Property="Product" },
            @{ Header="Status";     Property="Status"; Raw=$true },
            @{ Header="Engine";     Property="Engine" },
            @{ Header="Signatures"; Property="Signatures"; Raw=$true },
            @{ Header="State";      Property="State" }
        )
    }
    else {
        Write-Action -What "Anti-Virus product query failed." -Kind warn
        Html-AddNote -Text "Could not retrieve Anti-Virus products (Security Center)." -Kind warn
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
# [9] AZURE AD JOIN STATUS
# ============================================================
Write-Step -Index 9 -Total 10 -Title "Checking Azure AD join status..."
Write-Action -What "Running: dsregcmd /status parse" -Kind run
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
        "Tenant ID"       = $aadInfo.TenantId
        "Tenant Name"     = $aadInfo.TenantName
    })

    Write-Action -What ("Azure AD Joined: {0}" -f $(if($aadInfo.Joined){"Yes"} else {"No"})) -Kind info
}
else {
    Write-Action -What "Azure AD join status query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve Azure AD join status." -Kind warn
}

Html-EndSection

# ============================================================
# [10] ESSENTIAL EIGHT ASSESSMENT
# ============================================================
Write-Step -Index 10 -Total 10 -Title "Performing Essential Eight assessment..."
Write-Action -What "Running: ASD Essential Eight Maturity Model checks" -Kind run
Html-StartSection "Essential Eight Assessment"
Html-AddNote -Text "Assessment based on the ASD Essential Eight Maturity Model. This tool performs read-only detection only; results reflect observed endpoint configuration and cannot substitute for a formal E8 assessment." -Kind info

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
Html-Add "</tbody></table>"
Write-Action -What ("Patch currency: {0}" -f $(if ($null -ne $patchDays) { "$patchDays days since last hotfix" } else { "date unavailable" })) -Kind $(if ($patchClass -eq "sev-good") { "ok" } elseif ($patchClass -eq "sev-warn") { "warn" } else { "bad" })

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

$wuSvcClass = if ($wuSvc -ne "Error" -and $wuSvc -and $wuSvc.Status -eq "Running") { "sev-good" } else { "sev-warn" }

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
Html-Add "</tbody></table>"
Write-Action -What ("OS: {0} | WU Service: {1}" -f $(if ($osBuild -ne "Error" -and $osBuild) { "$($osBuild.ProductName) $($osBuild.DisplayVersion)" } else { "unknown" }), $(if ($wuSvc -ne "Error" -and $wuSvc) { $wuSvc.Status } else { "unknown" })) -Kind info

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
    $safeReportPath    = Html-Enc $HtmlReportPath
    $safeLogPath       = Html-Enc $LogPath
    $safeVersion       = Html-Enc $ScriptVersion

    # Build update notice for the report header (if an update was detected)
    $updateNoticeHtml = ""
    if ($UpdateInfo -and $UpdateInfo.UpdateAvailable) {
        $safeLatest = Html-Enc $UpdateInfo.LatestVersion
        $safeUrl    = Html-Enc $UpdateInfo.ReleaseUrl
        $updateNoticeHtml = "<div class='meta' style='color:#b45309;'>Update available: v$safeVersion -&gt; $safeLatest &mdash; <a href='$safeUrl' style='color:#b45309;'>Download</a></div>"
    }

    # Build Table of Contents (from Html-StartSection calls)
    $tocHtml = ""
    if ($Toc -and $Toc.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("<div class='toc'>")
        [void]$sb.AppendLine("<h2>Contents</h2>")
        [void]$sb.AppendLine("<ol>")
        foreach ($t in $Toc) {
            $id = Html-Enc $t.Id
            $tt = Html-Enc $t.Title
            [void]$sb.AppendLine(("<li><a href='#{0}'>{1}</a></li>" -f $id, $tt))
        }
        [void]$sb.AppendLine("</ol>")
        [void]$sb.AppendLine("</div>")
        $tocHtml = $sb.ToString()
    }

$htmlContent = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System Audit Report - $safeComputerName</title>
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
.toc{
  margin-top:16px; background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:16px 18px; box-shadow:0 1px 2px rgba(0,0,0,.04);
}
.toc h2{ margin:0 0 10px; color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:8px; font-size: 20px; }
.toc ol{ margin:0; padding-left: 18px; columns: 2; column-gap: 28px; }
.toc li{ break-inside: avoid; padding: 2px 0; }
.toc a{ color: var(--accent); text-decoration: none; }
.toc a:hover{ text-decoration: underline; }
.kv{ display:grid; grid-template-columns: 240px 1fr; gap:6px 12px; font-size: 14px; }
.kv div.key{ color:var(--muted); }
.kv-table{ margin-top:6px; }
.kv-table th{ width:280px; }
.small{ font-size:12px; color:var(--muted); }
.code{ font-family: Consolas, 'Courier New', monospace; }
details{ margin-top:10px; }
summary{ cursor:pointer; user-select:none; font-weight:600; color:#334155; padding:6px 0; }
table{ width:100%; border-collapse: collapse; margin-top:10px; font-size: 13px; }
th,td{ border:1px solid var(--border); padding:8px 10px; vertical-align: top; }
th{ background:#eef3f7; text-align:left; position:sticky; top:0; z-index:1; }
tr:nth-child(even) td{ background:#fafbfd; }
tr.sev-good td{ background:#ecfdf5 !important; }
tr.sev-warn td{ background:#fffbeb !important; }
tr.sev-bad td{ background:#fef2f2 !important; }
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
    <h1>System Audit Report - $safeComputerName</h1>
    <div class="meta">Generated: $generated &bull; Elevated: $elevText &bull; Version: v$safeVersion</div>
    <div class="meta">Report: <span class="code">$safeReportPath</span> &bull; Log: <span class="code">$safeLogPath</span></div>
$updateNoticeHtml
  </div>

$tocHtml

$($Html.ToString())

  <div class="footer">
    <div>Windows Audit Tool v$safeVersion &bull; Note: Large tables may take a moment to render in the browser.</div>
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
