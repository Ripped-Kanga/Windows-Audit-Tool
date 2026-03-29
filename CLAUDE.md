# CLAUDE.md — Windows-Audit-Tool

This file provides context for AI assistants working on this codebase.

---

## Project Overview

**Windows-Audit-Tool** is a self-contained PowerShell script that performs a comprehensive point-in-time audit of a single Windows machine and produces a portable, single-file HTML report.

**Design philosophy:**
- Partial data is better than no data — every section fails independently
- Zero-touch execution — no user prompts, no configuration needed
- Operator clarity — color-coded console output focused on progress and outcomes
- Report portability — single self-contained HTML file with embedded CSS

**Target environment:** Windows 10+, PowerShell 5.1+, local administrator access recommended.

---

## Repository Structure

```
Windows-Audit-Tool/
├── Run-Audit.ps1          # Primary source — the entire tool
├── Run-Audit.exe          # PS2EXE compiled binary — build artifact, never edited directly
├── RMM-Atera-Deploy.ps1   # Static Atera deploy wrapper — manages cached Run-Audit.ps1 on endpoints
├── README.md              # User-facing documentation
└── LICENSE                # MIT 2025
```

**`Run-Audit.ps1` is the primary file to edit.** The `.exe` is regenerated manually with PS2EXE after changes. `RMM-Atera-Deploy.ps1` is uploaded once to Atera and only updated when its own deploy logic changes — it does not need recompiling.

---

## Codebase Architecture

`Run-Audit.ps1` is organized into distinct logical regions, top-to-bottom:

### 1. Bootstrap / Global Setup
- Defines `$ScriptVersion` (e.g. `"1.1.0"`) — used for update checks and displayed in console + HTML report
- Sets `$ErrorActionPreference = "Stop"` globally
- Defines `$ComputerName` and bootstrap `$LogPath` (`C:\Windows\Temp\AuditLog.txt` — used only until `$ScriptDir` is resolved inside the main try block)
- Final `$LogPath`, `$ReportDir`, `$HtmlReportPath`, and `$HuduHtmlReportPath` are set in the Output Directory Routing block after `$IsRmmMode` is determined

### 2. Core Helper Functions

| Function | Purpose |
|---|---|
| `Log` | Appends timestamped messages to `$LogPath`; swallows its own errors |
| `Log-ExceptionDetail` | Logs full exception type, message, position, and stack trace |
| `Safe-Invoke` | Wraps a `[scriptblock]` in try/catch; returns `"Error"` on failure, never throws |
| `Test-IsElevated` | Returns `$true` if running as local Administrator |
| `Start-SelfElevate` | Relaunches the script/exe via `runas` verb; exits current process on success |
| `Write-Step` | Prints `[N/Total] Title` in yellow; used once per audit section |
| `Write-Action` | Prints a color-coded action line under the current step |
| `Write-PrivilegedGate` | Checks elevation and prints skip/run; returns `$true` if elevated |
| `Test-ForUpdate` | Queries the GitHub Releases API for a newer version; returns update info with asset URLs or `$null` on failure |
| `Invoke-SelfUpdate` | Downloads `.ps1` and/or `.exe` release assets into the script directory; accepts `-IncludeScript` / `-IncludeExe` switches |
| `Invoke-PendingExeSwap` | At startup, renames any `Run-Audit.exe.update` left by a prior locked-exe update into `Run-Audit.exe` |

### 3. Data Collection Functions

| Function | Purpose |
|---|---|
| `Get-PendingWindowsUpdatesWUA` | Queries the Windows Update Agent (WUA) COM API for pending updates; includes a `<META>` row with result code and count |
| `Get-InstalledSoftwareInventory` | Merges software from HKLM/HKCU/HKU registry uninstall keys, offline NTUSER.DAT hives, AppX/Store packages, and Winget; normalises and deduplicates |
| `Remove-SoftwareDuplicates` | Two-pass dedup: drops N/A-version rows when a real version exists; collapses exact name+version duplicates while merging `Scope` and `Sources` fields |

### 4. HTML Builder Infrastructure

All HTML is accumulated in `$Html` (a `System.Text.StringBuilder`). A parallel `$Toc` list drives the Table of Contents.

| Function | Purpose |
|---|---|
| `New-SectionId` | Slugifies a title to a unique anchor ID (e.g. `security-baseline-checks`) |
| `Html-Enc` | HTML-encodes a value; returns `"N/A"` for null/blank |
| `Html-Add` | Appends a raw HTML line to `$Html` |
| `Html-StartSection` / `Html-EndSection` | Wraps content in `<div class='section'>` with an `<h2>` anchor and TOC entry |
| `Html-AddNote` | Adds a styled notice paragraph (info / warn / bad) |
| `Html-AddKV` | Renders an `[ordered]@{}` dictionary as a key-value grid |
| `Html-AddTable` | Renders a list of objects as an HTML table with specified column headers and optional per-row CSS class callback |
| `Html-StartDetails` / `Html-EndDetails` | Wraps content in a `<details>`/`<summary>` collapsible block |

### 5. Main Execution Sequence

The script runs 13 sequential audit sections, each introduced with `Write-Step`:

| # | Section | Key APIs |
|---|---|---|
| 1 | System Information | `Get-CimInstance Win32_OperatingSystem`, `Win32_Processor`, `Win32_PhysicalMemory`, `Win32_DiskDrive`; registry `CurrentVersion` |
| 2 | Installed Software | `Get-InstalledSoftwareInventory` + `Remove-SoftwareDuplicates` |
| 3 | Patches / Hotfixes | `Get-HotFix` |
| 4 | Pending Windows Updates | `Get-PendingWindowsUpdatesWUA` (WUA COM API) |
| 5 | Network Adapters | `Get-NetAdapter`, `Get-NetIPConfiguration` |
| 6 | SMB Shares | `Get-SmbShare` with exposure classification (IPC$, ADMIN$, drive shares, custom) |
| 7 | Printers | `Get-Printer` |
| 8 | Security Baseline | `Get-BitLockerVolume`, `Get-Tpm`, `Confirm-SecureBootUEFI`, `Get-NetFirewallProfile`, `Get-MpComputerStatus`, WMI `AntiVirusProduct`, `net localgroup Administrators` — **admin-only** |
| 9 | Local User Accounts | `Get-LocalUser` — enumerates all local accounts, flags disabled/no-password-required |
| 10 | Startup Programs | Registry `Run`/`RunOnce` keys (HKLM + HKCU), `Get-CimInstance Win32_StartupCommand` |
| 11 | Event Log Health | `Get-WinEvent -ListLog` for Application, Security, System, Setup, PowerShell — checks enabled status, capacity, retention |
| 12 | Microsoft Entra ID Join Status | `dsregcmd.exe /status` output parsing |
| 13 | Essential Eight Assessment | `Get-AppLockerPolicy`, `Get-MpPreference` (CFA/NP/ASR), `Get-WindowsOptionalFeature`, `Get-PnpDevice`, `Get-CimInstance Win32_ShadowCopy`, `Get-ScheduledTask`, registry (UAC, Office macros, WH4B, WU policy); includes summary scorecard |

### 6. Report Generation

After all sections run, the script assembles the final HTML document:
- Builds the TOC from the `$Toc` list
- Wraps the `$Html` StringBuilder output in a full `<!doctype html>` page with embedded CSS
- Writes to `$HtmlReportPath` with `-Encoding utf8`
- Logs success or failure

---

## Output Paths

Output paths are determined at runtime based on deployment context (`$IsRmmMode`), not elevation:

| Context | `$ReportDir` | `$LogPath` |
|---|---|---|
| RMM/Silent OR running from `C:\Program Files\...` | `C:\Program Files\Windows Audit Tool\Results` | `C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt` |
| Interactive (non-silent, not in Program Files) | `<script-dir>\Windows Audit Tool\` | `<script-dir>\Windows Audit Tool\AuditLog.txt` |
| With `-CustomerName` | same as above | `<CustomerName> - <ComputerName>-Audit.html` |

`$IsRmmMode` is `$true` when `-Silent` is passed OR when `$ScriptDir` starts with `C:\Program Files`. Both `$ScriptDir` and `$IsRmmMode` are resolved early in the main `try` block. `$LogPath` starts as a bootstrap path (`C:\Windows\Temp\AuditLog.txt`) for the first few log lines, then is updated to its final value after the output directory routing block. `$HtmlReportPath` and `$HuduHtmlReportPath` are derived from `$ReportDir`. Do not add configuration file support or additional path parameters.

---

## Code Conventions

### Naming
- **Functions:** `PascalCase` with verb-noun or category-noun pattern (e.g., `Safe-Invoke`, `Html-Add`, `Get-InstalledSoftwareInventory`, `Write-PrivilegedGate`)
- **Significant variables:** `$PascalCase` (e.g., `$HtmlReportPath`, `$IsElevated`)
- **Local/loop variables:** `$camelCase` (e.g., `$nets`, `$blRows`)
- **Section dividers:** `# ============================================================` for major sections, `# ------------------------- #` for function groups

### Error Handling Pattern
Every data-gathering call uses `Safe-Invoke`:
```powershell
$result = Safe-Invoke { <# data collection code #> } "Descriptive Context Name"
if ($result -ne "Error" -and $result) {
    # process data
} else {
    Write-Action -What "Query failed." -Kind warn
    Html-AddNote -Text "Could not retrieve X." -Kind warn
}
```
**Never** let a section failure stop the audit. The string `"Error"` is the sentinel return value from `Safe-Invoke`.

### Console Output Severity Colors
| Color | Kind parameter | Meaning |
|---|---|---|
| `Cyan` | `run` | Starting an operation |
| `Green` | `ok` | Success |
| `Yellow` | `warn` | Non-fatal issue |
| `Red` | `bad` | Serious problem |
| `DarkYellow` | `skip` | Skipped due to lack of elevation |
| `Gray` | `info` | Informational |

### HTML Severity Classes
| Row class | Badge class | Meaning |
|---|---|---|
| `sev-good` | `badge good` | Healthy / compliant (green tint) |
| `sev-warn` | `badge warn` | Needs attention (yellow tint) |
| `sev-bad` | `badge bad` | Problem / risk (red tint) |

### PowerShell Patterns
- Wrap CIM/WMI results with `@()` to force array: `$items = @(Get-CimInstance ...)`
- Use `[pscustomobject]@{...}` for structured data rows
- Use `[ordered]@{}` for key-value pairs passed to `Html-AddKV`
- Use `[System.Collections.Generic.List[object]]` for mutable accumulation
- Gate admin-only sections with `Write-PrivilegedGate -IsElevated:$IsElevated -What "..."`

---

## Development Workflow

### Running the Script
The script **must be run on a real Windows 10+ machine** — it uses live Windows APIs that do not exist on Linux/macOS.

```powershell
# Option 1: Right-click the .ps1 → "Run with PowerShell"

# Option 2: From an elevated PowerShell prompt
powershell -ExecutionPolicy Bypass -File .\Run-Audit.ps1

# Option 3: Unattended deployment via RMM/MDM (Atera, Intune, etc.)
# Script must already be running elevated — UAC prompt and final pause are suppressed.
powershell -ExecutionPolicy Bypass -File .\Run-Audit.ps1 -Silent
# Or via the compiled binary:
.\Run-Audit.exe -Silent
```

The script auto-requests elevation via UAC if not already admin. If the user declines, it continues in limited mode (security baseline section is skipped). When `-Silent` is passed the UAC step is skipped entirely, script updates are applied automatically, and the process exits cleanly without waiting for input.

**Update switches:**
```powershell
.\Run-Audit.ps1 -UpdateAll       # download .ps1 + .exe, then run audit
.\Run-Audit.ps1 -UpdateScript    # download .ps1 only, then run audit
.\Run-Audit.ps1 -UpdateExe       # download .exe only, then run audit
```

**Check outputs (interactive mode, run from e.g. Desktop):**
- HTML report: `<script-dir>\Windows Audit Tool\<ComputerName>-Audit.html`
- Operational log: `<script-dir>\Windows Audit Tool\AuditLog.txt`

### Recompiling the .exe
**The `.exe` is compiled automatically by GitHub Actions** — no manual PS2EXE step is ever required. The workflow (`.github/workflows/release.yml`) compiles and attaches the binary when a `v*` tag is pushed. Do not run PS2EXE locally or flag missing recompilation as a TODO.

### Testing
There is **no automated test suite**. All validation is manual:
1. Run the script on a Windows machine with admin rights
2. Check the HTML report for completeness and correct formatting
3. Check `AuditLog.txt` for any unexpected errors
4. Run without admin rights and verify graceful degradation

### Git Workflow
- Branch from `main`
- Keep commits focused; only `Run-Audit.ps1` needs to be committed — the `.exe` is produced by CI
- PRs used for significant features or changes

### Release Workflow
When cutting a new version:
1. Bump `$ScriptVersion` in `Run-Audit.ps1` to match the branch/tag name exactly (e.g. branch `v1.3.2` → `$ScriptVersion = "1.3.2"`)
2. Commit, push branch, open PR, merge to main
3. Push an annotated tag with a brief change summary — the Action creates the release and compiles the `.exe`:
   ```
   git tag -a v1.3.2 -m "Brief summary of changes" && git push origin refs/tags/v1.3.2
   ```

> **Never use `gh release create`** — the Action creates the release automatically from the tag. A manually created release will conflict and break the workflow.

The workflow validates that `$ScriptVersion` matches the tag before compiling, so a version mismatch will fail the build.

> **For AI assistants:** `$ScriptVersion` must **always** match the branch version. When working on branch `vX.Y.Z`, ensure `$ScriptVersion = "X.Y.Z"` before any PR is merged. This is non-negotiable — the GitHub Actions release workflow will reject a mismatched version.

### Versioning Convention

Use standard three-part semver: `major.minor.patch` (e.g. `1.3.2`).

**For hotfix / sub-releases, use a fourth digit: `major.minor.patch.hotfix`** (e.g. `1.3.2.1`).

Do **not** use hyphenated suffixes like `v1.3.2-1`. The self-update mechanism and `RMM-Atera-Deploy.ps1` both use `[System.Version]` for version comparison, which only accepts up to four numeric components (`major.minor.build.revision`). A hyphen causes a parse failure and falls back to unreliable string comparison.

| Format | Example | `[System.Version]` | Notes |
|---|---|---|---|
| Three-part | `1.3.2` | ✅ | Standard release |
| Four-part | `1.3.2.1` | ✅ | Hotfix / sub-release |
| Hyphenated | `1.3.2-1` | ❌ | Do not use |

The self-update mechanism looks for `.ps1` and `.exe` assets attached to the latest GitHub Release.

---

## Constraints for AI Assistants

These are non-negotiable design decisions. Do not work around them:

1. **No external dependencies.** The script uses only built-in Windows cmdlets and standard COM APIs. Do not add `Install-Module`, `Import-Module`, or any external tool dependency.

2. **Permitted parameters are limited to operational switches.** The tool is zero-config by design. The permitted parameters are:
   - `-Silent` — suppresses the UAC elevation prompt, the final interactive pause, and auto-applies script updates for unattended RMM/MDM deployment
   - `-UpdateAll` / `-UpdateScript` / `-UpdateExe` — explicit update switches that download release assets from GitHub before running the audit
   - `-CustomerName "Name"` — customer/business name included in the report title and filename; prompted interactively when not using `-Silent`
   Do not add configuration parameters such as `-Verbose`, `-OutputPath`, or `-SkipSection`.

3. **Preserve graceful degradation.** Every data-gathering call must use `Safe-Invoke` and handle the `"Error"` return gracefully. A broken section must never stop the audit.

4. **Preserve the elevation model.** Admin-only operations must go through `Write-PrivilegedGate`. Do not add unconditional admin-required code.

5. **Keep the HTML self-contained.** No `<link>` or `<script src="...">` tags. All CSS is inline in the `$htmlContent` here-string. The report must open correctly with no internet access and no external files.

6. **No configuration files.** Output paths are hardcoded intentionally. Do not add JSON/XML/INI config support.

7. **The `.exe` is a build artifact.** Never edit `Run-Audit.exe` directly. Only update it by recompiling from `Run-Audit.ps1` with PS2EXE.

8. **Maintain the `[1/13]`…`[13/13]` step count.** If you add a new section, update the `$Total` value in all `Write-Step` calls and add a matching entry in the audit sections table above.

9. **Use `Html-Enc` for all user-derived data.** Never interpolate raw system values directly into HTML strings — always pass through `Html-Enc` to prevent HTML injection from unexpected characters in computer names, software names, etc.
