# Windows-Audit-Tool

A self-contained PowerShell script that audits a single Windows machine and produces a portable, single-file HTML report. No modules. No configuration. No internet access required.

---

## Quick Start

**Option 1 — Right-click the script or executable:**
- `Run-Audit.ps1` → right-click → *Run with PowerShell*
- `Run-Audit.exe` → double-click (no PowerShell required)

**Option 2 — From an elevated PowerShell prompt:**
```powershell
powershell -ExecutionPolicy Bypass -File .\Run-Audit.ps1
```

The script will request administrator privileges via UAC automatically. If elevation is declined it continues in limited mode, skipping admin-only checks and noting what was skipped in the report.

**Outputs:**
| File | Path |
|---|---|
| HTML report | `C:\Temp\<ComputerName>-Audit.html` |
| Operational log | `C:\Windows\Temp\AuditLog.txt` |

---

## What It Collects

The audit runs 10 sequential sections. Each section fails independently — a problem in one area never stops the rest.

### 1. System Information
Operating system, edition, build number, install date, uptime, CPU model and core count, total RAM, and attached disk drives with size and model.

### 2. Installed Software
Merged inventory from all available sources: HKLM and HKCU uninstall registry keys (both 64-bit and WOW6432Node), per-user registry hives including offline NTUSER.DAT files, AppX/Store packages, and Winget. Automatically deduplicates across sources, merging scope and origin metadata.

### 3. Patches / Hotfixes
All installed Windows hotfixes and cumulative updates via `Get-HotFix`, sorted by install date.

### 4. Pending Windows Updates
Queries the Windows Update Agent (WUA) COM API directly — no PSWindowsUpdate module required. Reports update title, KB number, size, and severity for all pending updates.

### 5. Network Adapters
All physical and virtual adapters with connection status, MAC address, IP addresses, default gateway, and DNS servers.

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

### 9. Azure AD Join Status
Parses `dsregcmd /status` output to report Azure AD join state, tenant name, and tenant ID.

### 10. Essential Eight Assessment
Read-only checks mapped to all eight ASD Essential Eight mitigation strategies:

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

The report is a **single self-contained HTML file** with embedded CSS. No external stylesheets, no JavaScript, no internet access needed to view it. It opens correctly in any browser and can be attached to emails, uploaded to ticketing systems, or archived as-is.

The report includes a linked table of contents, color-coded severity badges (green/amber/red), and collapsible detail sections for long tables.

---

## Requirements

- Windows 10 or later
- PowerShell 5.1 or later
- Local administrator access recommended (required for security baseline and Essential Eight checks; script continues without it)
- No internet access required
- No external PowerShell modules required

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

**Zero-touch execution.** No prompts, no configuration, no prerequisites to install. Run it and collect the report.

**Self-contained output.** The HTML report is a single file. No viewer software, no server, no dependencies.

**No permanent changes.** The script is read-only. It does not install software, modify configuration, or alter any system state. Execution policy is relaxed for the current process only and reverts when the script exits.

---

## Limitations

- Audits a single machine per run
- Results are a point-in-time snapshot only
- Admin-only sections are skipped gracefully when elevation is unavailable
- Essential Eight checks detect configuration signals only and do not constitute a formal E8 assessment
- MFA checks reflect endpoint-observable signals; identity provider enforcement cannot be verified from the local machine
