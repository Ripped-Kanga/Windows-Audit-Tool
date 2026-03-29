# Windows-Audit-Tool

A self-contained PowerShell script that audits a single Windows machine and produces a portable, single-file HTML report. No external modules required. Optional Hudu integration uploads the report directly to your documentation platform.

---

## Quick Start

**Download the script:**
```powershell
curl -o Run-Audit.ps1 https://github.com/Ripped-Kanga/Windows-Audit-Tool/releases/latest/download/Run-Audit.ps1
```

**Option 1 — Right-click the script or executable:**
- `Run-Audit.ps1` → right-click → *Run with PowerShell*
- `Run-Audit.exe` → double-click (no PowerShell window needed — launches automatically)

**Option 2 — From an elevated PowerShell prompt:**
```powershell
powershell -ExecutionPolicy Bypass -File .\Run-Audit.ps1
```

**Option 3 — Unattended via RMM/MDM (Atera, Intune, etc.):**
```powershell
powershell -ExecutionPolicy Bypass -File .\Run-Audit.ps1 -Silent -CustomerName "Acme Corp"
# or
.\Run-Audit.exe -Silent -CustomerName "Acme Corp"
```

**Option 3a — Atera with `RMM-Atera-Deploy.ps1` (recommended for Atera):**

Upload `RMM-Atera-Deploy.ps1` once to Atera. It automatically downloads and caches the latest `Run-Audit.ps1` from GitHub Releases on each run, so you never need to update the Atera script when a new version is released.

```powershell
# Atera script body — no arguments needed for a basic run:
# (RMM-Atera-Deploy.ps1 injects -Silent automatically)

# With Hudu integration:
-HuduReport -HuduAPIKey "your-api-key" -HuduBaseURL "https://your-instance.huducloud.com" -HuduCompanySlug "Hex String" -HuduAssetLayoutName "Audit Reports"
```

Set the Atera script execution policy to `Bypass` and the timeout to **600 seconds**. See [`RMM-Atera-Deploy.ps1`](RMM-Atera-Deploy.ps1) for full setup notes.

**Option 4 — With Hudu integration (upload report directly to Hudu):**
```powershell
.\Run-Audit.ps1 -HuduReport `
    -HuduAPIKey "your-api-key" `
    -HuduBaseURL "https://your-instance.huducloud.com" `
    -HuduCompanySlug "Hex String" `
    -HuduAssetLayoutName "Audit Reports"
```

The `-Silent` switch suppresses the UAC elevation prompt and the "Press ENTER to exit" pause, allowing the process to exit cleanly in non-interactive contexts. In `-Silent` mode, script updates from GitHub are applied automatically before the audit runs. Use this when deploying through endpoint management software that already runs the script in an elevated context (e.g. Atera agent as SYSTEM, Intune Win32 app with `runAsAccount = system`).

The script will request administrator privileges via UAC automatically in interactive mode. If elevation is declined it continues in limited mode, skipping admin-only checks and noting what was skipped in the report.

**Customer name:** In interactive mode the script prompts for a customer/business name after startup. Press ENTER to skip. In `-Silent` mode, pass `-CustomerName "Name"` to include it. When provided, the name appears in the report title, HTML heading, and output filename. When using `-HuduReport`, the customer name is automatically resolved from the Hudu company slug, so `-CustomerName` is not required.

**Outputs:**

Output paths are determined by deployment context, not elevation level.

**RMM / Silent mode** (when `-Silent` is passed, or the script runs from `C:\Program Files\...`):
| File | Path |
|---|---|
| HTML report | `C:\Program Files\Windows Audit Tool\Results\<ComputerName>-Audit.html` |
| HTML report (with customer name) | `C:\Program Files\Windows Audit Tool\Results\<CustomerName> - <ComputerName>-Audit.html` |
| Hudu preview (when `-HuduReport` used) | `C:\Program Files\Windows Audit Tool\Results\<ComputerName>-Audit-Hudu.html` |
| Operational log | `C:\Program Files\Windows Audit Tool\Logs\AuditLog.txt` |

**Interactive mode** (run from any other location):
| File | Path |
|---|---|
| HTML report | `<script-dir>\Windows Audit Tool\<ComputerName>-Audit.html` |
| HTML report (with customer name) | `<script-dir>\Windows Audit Tool\<CustomerName> - <ComputerName>-Audit.html` |
| Hudu preview (when `-HuduReport` used) | `<script-dir>\Windows Audit Tool\<ComputerName>-Audit-Hudu.html` |
| Operational log | `<script-dir>\Windows Audit Tool\AuditLog.txt` |

> The first few log entries written before the output directory is resolved always land in `C:\Windows\Temp\AuditLog.txt` (the bootstrap log). Once the deployment context is determined, logging continues at the final path above. The `Windows Audit Tool` output subdirectory is created automatically if it does not exist.

> When using `RMM-Atera-Deploy.ps1`, the script is cached at `C:\Program Files\Windows Audit Tool\Scripts\Run-Audit.ps1` and runs from that path, so RMM mode is activated automatically.

---

## Self-Update

The script checks the [GitHub Releases](https://github.com/Ripped-Kanga/Windows-Audit-Tool/releases) API on every run to detect newer versions.

**Interactive mode (default):** If an update is found, the script pauses and recommends updating before continuing:

```
    Update available: 1.1.0 -> v1.2.0
    It is recommended you update before continuing.
    Restart the script with one of the following switches:
      .\Run-Audit.ps1 -UpdateAll       # update script + binary
      .\Run-Audit.ps1 -UpdateScript    # update script only
      .\Run-Audit.ps1 -UpdateExe       # update binary only

    Press ENTER to continue with the current version...
```

| Switch | What it downloads |
|---|---|
| `-UpdateAll` | Both `Run-Audit.ps1` and `Run-Audit.exe` from the release assets |
| `-UpdateScript` | `Run-Audit.ps1` only |
| `-UpdateExe` | `Run-Audit.exe` only |

After updating the `.ps1`, the script automatically re-launches the new version and runs the audit.

**Silent mode (`-Silent`):** The update check is skipped entirely. No GitHub API call is made and no update is applied. To update during a Silent deployment, pass an explicit update switch alongside `-Silent` (e.g. `.\Run-Audit.ps1 -Silent -UpdateScript` or `.\Run-Audit.ps1 -Silent -UpdateAll`). The banner is also suppressed in Silent mode — no console output is rendered until the audit sections begin.

**No internet / GitHub unreachable:** The update check silently fails and the audit proceeds with the current version. Update failures never block the audit.

> **Note for releases:** Attach both `Run-Audit.ps1` and `Run-Audit.exe` as assets to each GitHub Release. The updater looks for files ending in `.ps1` and `.exe` in the release assets.

---

## Hudu Integration

The script can upload audit reports directly to [Hudu](https://www.huducloud.com/) as a new asset. Enable this with the `-HuduReport` switch and four required parameters:

| Parameter | Description |
|---|---|
| `-HuduReport` | Enable Hudu integration |
| `-HuduAPIKey` | Your Hudu API key (generate from Admin > API Keys in Hudu) |
| `-HuduBaseURL` | Your Hudu instance URL (e.g. `https://your-instance.huducloud.com`) |
| `-HuduCompanySlug` | The hex slug from your Hudu company URL (e.g. `0297b67dbba7` from `https://instance.huducloud.com/c/0297b67dbba7`) |
| `-HuduAssetLayoutName` | The name of the asset layout to create the asset under (e.g. `Audit Reports`) |

**Example:**
```powershell
.\Run-Audit.ps1 -HuduReport `
    -HuduAPIKey "your-api-key" `
    -HuduBaseURL "https://your-instance.huducloud.com" `
    -HuduCompanySlug "Hex String" `
    -HuduAssetLayoutName "Audit Reports"
```

**How it works:**
1. The script resolves the company name from the slug via the Hudu API and uses it as the customer name in the report (no need to pass `-CustomerName` separately)
2. All audit HTML is transformed in real-time into Hudu-compatible inline-styled HTML (Hudu's ActionText editor strips `<style>` blocks)
3. After the audit completes, a new asset is created under the specified company and layout with the report content embedded in the first RichText field
4. The full standalone HTML report is attached to the asset as a downloadable file
5. A local Hudu preview file is also saved for reference

**Asset layout requirements:** The target asset layout must have at least one RichText field. The script automatically detects and uses the first RichText field in the layout.

**Graceful degradation:** If any Hudu parameter is missing, the API is unreachable, or the company slug cannot be resolved, the script logs the issue and continues the audit normally. Hudu failures never block the local report.

**RMM/MDM deployment with Hudu:**
```powershell
.\Run-Audit.ps1 -Silent -HuduReport `
    -HuduAPIKey "your-api-key" `
    -HuduBaseURL "https://your-instance.huducloud.com" `
    -HuduCompanySlug "Hex String" `
    -HuduAssetLayoutName "Audit Reports"
```

---

## What It Collects

The audit runs 13 sequential sections. Each section fails independently — a problem in one area never stops the rest.

### 1. System Information
Operating system, edition, build number, install date, uptime, CPU model and core count, total RAM, and attached disk drives with size and model.

### 2. Installed Software
Merged inventory from all available sources: HKLM and HKCU uninstall registry keys (both 64-bit and WOW6432Node), per-user registry hives including offline NTUSER.DAT files, AppX/Store packages, and Winget. Automatically deduplicates across sources, merging scope and origin metadata. Includes an interactive search/filter bar in the report.

### 3. Patches / Hotfixes
All installed Windows hotfixes and cumulative updates via `Get-HotFix`, sorted by install date.

### 4. Pending Windows Updates
Queries the Windows Update Agent (WUA) COM API directly — no PSWindowsUpdate module required. Reports update title, KB number, size, and severity for all pending updates.

### 5. Network Adapters
All physical and virtual adapters with connection status, MAC address, link speed, media type, driver version, driver date, and manufacturer. For each connected adapter: IPv4 address with prefix length, IPv6 addresses (global and link-local), default gateways, DNS servers, DHCP status, DHCP server address, lease obtained/expires dates, and network profile (Public/Private/Domain).

### 6. SMB Shares
All network shares with path, description, and an exposure classification: system shares (IPC$, ADMIN$), administrative drive shares (C$), and custom shares that expose data to the network.

### 7. Printers
Installed printers with driver name, port, and whether they are shared.

### 8. Security Baseline *(requires administrator)*
| Check | Details |
|---|---|
| BitLocker | Volume protection status and lock state per drive |
| TPM | Presence, version, and ready state |
| Secure Boot | UEFI Secure Boot enabled/disabled |
| Windows Firewall | Domain, Private, and Public profile state |
| Windows Defender | Real-time protection, signature version, last scan times |
| Anti-Virus Products | All SecurityCenter2-registered AV products with engine and signature status; deduplicated by product name so multi-component suites (e.g. Sophos Intercept X) appear as a single entry |
| Local Administrators | All members of the local Administrators group |

### 9. Local User Accounts
All local user accounts with enabled/disabled status, password requirements, last logon time, password age, and description. Accounts that don't require a password are flagged.

### 10. Startup Programs
Programs configured to run at startup from registry Run/RunOnce keys (HKLM and HKCU) and WMI `Win32_StartupCommand`, with automatic deduplication across sources.

### 11. Event Log Health
Checks the five core Windows event logs (Application, Security, System, Setup, PowerShell) for enabled status, current size vs. maximum capacity, record count, and retention mode. Warns when logs are near full or disabled.

### 12. Microsoft Entra ID Join Status
Parses `dsregcmd /status` output to report Entra ID (formerly Azure AD) join state, tenant name, and tenant ID.

### 13. Essential Eight Assessment
Read-only checks mapped to all eight ASD Essential Eight mitigation strategies, with a **summary scorecard** at the top showing pass/warn/fail status for each control at a glance:

| Strategy | Checks performed |
|---|---|
| Application Control | AppLocker effective policy rule count; WDAC Code Integrity registry key presence |
| Patch Applications | Days since most recent hotfix; Windows Update automatic update policy |
| Restrict Office Macros | `VbaWarnings` registry value per Office app (Word, Excel, PowerPoint, Outlook, Access) — reads Group Policy setting first, user setting as fallback |
| User Application Hardening | Controlled Folder Access state; Network Protection state; ASR rule count; PowerShell v2 optional feature status; Internet Explorer presence |
| Restrict Admin Privileges | UAC `EnableLUA` flag; `ConsentPromptBehaviorAdmin` level; local administrator count |
| Patch Operating Systems | OS build and feature version; days since last patch; Windows Update service state |
| Multi-Factor Authentication | Windows Hello for Business policy; NGC credential store presence; smartcard reader detection; cached domain credential count |
| Regular Backups | VSS shadow copy count and newest snapshot date; File History registry flag; Windows Backup scheduled tasks; OneDrive process detection |

---

## Output Format

The report is a **single self-contained HTML file** with embedded CSS and minimal inline JavaScript. No external stylesheets, no external scripts, no internet access needed to view it. It opens correctly in any browser and can be attached to emails, uploaded to ticketing systems, or archived as-is.

Report features:
- **Professional header** with customer name branding and gradient accent banner
- **Numbered table of contents** with clickable navigation
- **Numbered section headings** that stick when scrolling for easy orientation
- **Color-coded severity** — green/amber/red callout bars, row highlighting, and badges throughout
- **Interactive search** on the installed software table for quick filtering
- **Collapsible detail sections** for long tables (auto-expanded when printing)
- **Print-ready** — `Ctrl+P` produces a clean PDF with all sections expanded and UI elements hidden

---

## Requirements

- Windows 10 or later
- PowerShell 5.1 or later
- Local administrator access recommended (required for security baseline and Essential Eight checks; script continues without it)
- No external PowerShell modules required
- Internet access required for: self-update checks against the GitHub Releases API; Hudu integration (optional)

---

## Intended Use Cases

- ICT audits for small and medium businesses
- Pre-migration environment discovery and documentation
- Baseline snapshots for inherited or unmanaged systems
- Essential Eight compliance evidence gathering
- Client-facing technical reports with minimal manual effort

---

## Design Principles

**Partial data beats no data.** Every section is independent. A failed WMI query, blocked command, or missing privilege produces a visible warning in the report rather than crashing the audit.

**Minimal configuration.** No configuration files or external modules to install. Basic usage requires no setup at all. Hudu integration requires API credentials passed as parameters.

**Self-contained output.** The HTML report is a single file. No viewer software, no server, no dependencies.

**No permanent changes.** The script is read-only. It does not install software, modify configuration, or alter any system state. Execution policy is relaxed for the current process only and reverts when the script exits.

---

## Limitations

- Audits a single machine per run
- Results are a point-in-time snapshot only
- Admin-only sections are skipped gracefully when elevation is unavailable
- Essential Eight checks detect configuration signals only and do not constitute a formal E8 assessment
- MFA checks reflect endpoint-observable signals; identity provider enforcement cannot be verified from the local machine
