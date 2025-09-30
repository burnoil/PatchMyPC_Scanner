## PatchMyPC Update Checker - Help

VERSION: 2.0 Enhanced

---

## Features

- Check Windows software for security updates from PatchMyPC catalog
- Filter updates by type (All/Security/Feature)
- Track new updates with visual highlighting (RED = New)
- Acknowledge items you've handled (YELLOW = Acknowledged)
- Export results to CSV format
- Load software lists from text files

---

## How to Use

1. Enter software names (one per line) or load from a file
2. Set the number of days back to check
3. Choose a filter type (All/Security Only/Feature Only)
4. Click 'Check Updates' to scan PatchMyPC catalog
5. NEW updates will be highlighted in RED
6. Select one or MORE items (Ctrl+Click or Shift+Click) and click 'Acknowledge' to mark as handled (turns YELLOW)
7. Export results using the 'Export Results' button

---

## Understanding Architecture Types

The architecture types describe the software's design, installer packaging, and installation method.

Core Concept: x64 Architecture

x64 refers to 64-bit architecture that powers modern computers. Compared to 32-bit (x86), x64 processors handle more data simultaneously and access significantly more RAM.

Installer Packages: EXE vs MSI

EXE-x64: A 64-bit executable file (.exe). Flexible installers common for consumer applications with custom interfaces.

MSI-x64: A 64-bit Microsoft Installer file (.msi). Uses Windows Installer service for reliable, predictable installations. Ideal for corporate/automated deployments.

Installation Context: User vs System

User-x64: Installs ONLY for the current user (e.g., AppData folder). Does NOT require administrator privileges.

System (x64/EXE-x64/MSI-x64): System-wide installation for all users (e.g., Program Files). Requires administrator privileges.

---

## Update Type Classification

Security: Updates that address CVEs or contain security fixes/patches
Feature/Bug Fix: Standard updates that add features or fix non-security bugs

---

## File Format

Software list files should be plain text (.txt) with one software name per line.

Example:
Google Chrome
Mozilla Firefox
7-Zip

---

## Troubleshooting

- If no updates appear, try increasing the days back value
- Use 'Test Feed' to verify PatchMyPC catalog connectivity
- Use 'Debug Feed' to test basic internet connection
- Clear history to reset the new update highlighting

---

Data Source: PatchMyPC Catalog (https://patchmypc.com)
Created with PowerShell and Windows Forms
