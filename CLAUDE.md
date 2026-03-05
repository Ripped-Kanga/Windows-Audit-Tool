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
├── Run-Audit.ps1   # Primary source — the entire tool (1,598 lines)
├── Run-Audit.exe   # PS2EXE compiled binary — build artifact, never edited directly
├── README.md       # User-facing documentation
└── LICENSE         # MIT 2025
```

**The `.ps1` is the only file you should ever edit.** The `.exe` is regenerated manually with PS2EXE after changes to the script.

---

## Codebase Architecture

`Run-Audit.ps1` is organized into distinct logical regions, top-to-bottom:

### 1. Bootstrap / Global Setup (lines 1–10)
- Sets `$ErrorActionPreference = "Stop"` globally
- Defines `$ComputerName`, `$HtmlReportPath` (`C:\Temp\<ComputerName>-Audit.html`), `$LogPath` (`C:\Windows\Temp\AuditLog.txt`)
- Creates `C:\Temp\` if it does not exist

### 2. Core Helper Functions (lines 29–180)

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

### 3. Data Collection Functions (lines 184–710)

| Function | Purpose |
|---|---|
| `Get-PendingWindowsUpdatesWUA` | Queries the Windows Update Agent (WUA) COM API for pending updates; includes a `<META>` row with result code and count |
| `Get-InstalledSoftwareInventory` | Merges software from HKLM/HKCU/HKU registry uninstall keys, offline NTUSER.DAT hives, AppX/Store packages, and Winget; normalises and deduplicates |
| `Remove-SoftwareDuplicates` | Two-pass dedup: drops N/A-version rows when a real version exists; collapses exact name+version duplicates while merging `Scope` and `Sources` fields |

### 4. HTML Builder Infrastructure (lines 713–840)

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

### 5. Main Execution Sequence (lines ~840–1481)

The script runs 10 sequential audit sections, each introduced with `Write-Step`:

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
| 9 | Azure AD Join Status | `dsregcmd.exe /status` output parsing |
| 10 | Essential Eight Assessment | `Get-AppLockerPolicy`, `Get-MpPreference` (CFA/NP/ASR), `Get-WindowsOptionalFeature`, `Get-PnpDevice`, `Get-CimInstance Win32_ShadowCopy`, `Get-ScheduledTask`, registry (UAC, Office macros, WH4B, WU policy) |

### 6. Report Generation (lines ~1700–1820)

After all sections run, the script assembles the final HTML document:
- Builds the TOC from the `$Toc` list
- Wraps the `$Html` StringBuilder output in a full `<!doctype html>` page with embedded CSS
- Writes to `$HtmlReportPath` with `-Encoding utf8`
- Logs success or failure

---

## Hardcoded Paths

| Path | Purpose |
|---|---|
| `C:\Temp\<ComputerName>-Audit.html` | HTML report output |
| `C:\Windows\Temp\AuditLog.txt` | Append-only operational log |
| `C:\Temp\` | Working directory (auto-created) |

These paths are **intentionally hardcoded** for predictability. Do not add configuration file support.

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
```

The script auto-requests elevation via UAC if not already admin. If the user declines, it continues in limited mode (security baseline section is skipped).

**Check outputs:**
- HTML report: `C:\Temp\<ComputerName>-Audit.html`
- Operational log: `C:\Windows\Temp\AuditLog.txt`

### Recompiling the .exe
After editing `Run-Audit.ps1`, regenerate the binary:
```powershell
# Install PS2EXE if not already present
Install-Module ps2exe -Scope CurrentUser

# Compile
Invoke-ps2exe .\Run-Audit.ps1 .\Run-Audit.exe
```
Commit both `Run-Audit.ps1` and `Run-Audit.exe` together.

### Testing
There is **no automated test suite**. All validation is manual:
1. Run the script on a Windows machine with admin rights
2. Check the HTML report for completeness and correct formatting
3. Check `AuditLog.txt` for any unexpected errors
4. Run without admin rights and verify graceful degradation

### Git Workflow
- Branch from `main`
- Keep commits focused; commit both `.ps1` and `.exe` when the binary is updated
- PRs used for significant features or changes

---

## Constraints for AI Assistants

These are non-negotiable design decisions. Do not work around them:

1. **No external dependencies.** The script uses only built-in Windows cmdlets and standard COM APIs. Do not add `Install-Module`, `Import-Module`, or any external tool dependency.

2. **No parameters or switches.** The tool is zero-config by design. Do not add `-Verbose`, `-OutputPath`, `-SkipSection`, or similar parameters.

3. **Preserve graceful degradation.** Every data-gathering call must use `Safe-Invoke` and handle the `"Error"` return gracefully. A broken section must never stop the audit.

4. **Preserve the elevation model.** Admin-only operations must go through `Write-PrivilegedGate`. Do not add unconditional admin-required code.

5. **Keep the HTML self-contained.** No `<link>` or `<script src="...">` tags. All CSS is inline in the `$htmlContent` here-string. The report must open correctly with no internet access and no external files.

6. **No configuration files.** Output paths are hardcoded intentionally. Do not add JSON/XML/INI config support.

7. **The `.exe` is a build artifact.** Never edit `Run-Audit.exe` directly. Only update it by recompiling from `Run-Audit.ps1` with PS2EXE.

8. **Maintain the `[1/10]`…`[10/10]` step count.** If you add a new section, update the `$Total` value in all `Write-Step` calls and add a matching entry in the audit sections table above.

9. **Use `Html-Enc` for all user-derived data.** Never interpolate raw system values directly into HTML strings — always pass through `Html-Enc` to prevent HTML injection from unexpected characters in computer names, software names, etc.
