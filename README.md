# Windows-Audit-Tool
## This has been almost entirely vibe coded, I don't care one bit. 

# Run-Audit.ps1 — System Audit Tool

## Overview

Run-Audit.ps1 is a self-contained Windows system audit script designed for small to medium environments where fast, repeatable, and human-readable technical assessments are required. It gathers a broad snapshot of a Windows machine’s configuration and operational state, producing both live console feedback and a structured Markdown report suitable for client delivery or long-term records.

The script is intentionally pragmatic rather than theoretical. It assumes real-world conditions: restricted execution policies, missing PowerShell modules, inconsistent privilege levels, and systems that have been touched by many hands over many years. Where possible, it fails gracefully, records what it can, and clearly reports what could not be collected.

This project exists to answer a simple but deceptively hard question:

“What does this machine actually look like right now?”

## Design Goals

The script is built around a few guiding principles:

Reliability over perfection. Partial data is better than no data, as long as failures are explicit.

Zero-touch execution. Once started, the script should not require user input, even when installing prerequisites.

Operator clarity. Console output is concise, color-coded, and focused on progress and outcomes, not raw data dumps.

Report portability. The primary output is Markdown, chosen for readability, version control friendliness, and easy conversion to formats such as DOCX or PDF using Pandoc.

Security awareness. Administrative privileges are requested only when required, and execution policy workarounds are scoped to the current process.

## What the Script Collects

Run-Audit.ps1 gathers a wide range of system information, including but not limited to:

• Operating system details and build information
• Hardware overview (CPU, memory, storage)
• Disk layout and free space
• Network configuration and adapters
• SMB shares and local file-sharing exposure
• Installed software inventory
• Windows Update status (via PSWindowsUpdate)
• Security-relevant configuration signals

Each section is executed independently. A failure in one area does not halt the entire audit.

## Output

The script produces two primary forms of output:

Console output
Designed for the operator running the audit. Progress is shown section-by-section with clear success or failure indicators. Verbosity is intentionally limited to avoid drowning signal in noise.

Markdown report
A structured Markdown (.md) file is generated per machine. The report uses consistent headings and formatting so it can be:

• Read directly in GitHub or a Markdown viewer
• Converted to DOCX or PDF via Pandoc
• Archived for compliance or historical comparison

File naming is computer-specific to avoid accidental overwrites during batch audits.

## Execution Model

The script is intended to be run locally on the target machine.

When launched:

1. It checks for administrative privileges and relaunches itself elevated if required.
2. It temporarily bypasses execution policy restrictions for the current process only.
3. It verifies required modules and installs them automatically if missing.
4. It executes audit sections sequentially, capturing both data and errors.
5. It writes the final Markdown report to disk.

No permanent system configuration changes are made.

## Error Handling Philosophy

PowerShell scripts often fail loudly or silently. This project aims for a third path: honest failure.

All major data-gathering calls are wrapped in a controlled execution function. If a section fails:

• The failure is logged in the report
• The console shows a clear warning
• The script continues with the next section

This ensures that a single missing WMI class, disabled service, or blocked command does not invalidate the entire audit.

## Intended Use Cases

• ICT audits for small businesses
• Pre-migration environment discovery
• Baseline documentation for unmanaged systems
• Troubleshooting unknown or inherited machines
• Generating client-facing technical reports with minimal manual effort

This tool is not intended to replace full enterprise management platforms. It is a sharp, portable instrument for situations where speed, clarity, and independence matter.

## Requirements

• Windows 10 or later
• PowerShell 5.1 or newer
• Local administrator access (recommended for full data collection)
• Internet access (optional, only required for module installation)

## Limitations

• The script audits a single machine per run
• Results reflect point-in-time state only
• Some data may be unavailable on heavily locked-down systems
• Accuracy depends on the integrity of Windows management interfaces

These limitations are deliberate trade-offs in favor of simplicity and reliability.

## Project Philosophy

This project treats system audits as a scientific observation, not a guess. The script reports what it can directly measure, avoids inference where possible, and documents uncertainty where it exists.

Computers are messy. This tool acknowledges that mess, maps it carefully, and writes it down in a form humans can actually read.

