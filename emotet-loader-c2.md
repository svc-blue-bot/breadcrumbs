---
layout: default
title: Simulated Emotet-Style Loader Infection (DFIR Case Study)
---

# Simulated Emotet-Style Loader Infection (2025)  
*A step-by-step forensic investigation of a safe, controlled malware simulation created by me.*

---

## 🧪 1. Introduction

This project documents a **fully controlled, safe, offline simulation** of a modern Emotet-style intrusion chain.  
I created this lab environment myself for the purpose of:

- practicing DFIR workflows  
- documenting artefacts left behind during staged malware activity  
- showcasing forensic methodology  
- understanding modern loader behaviour  

This is **not real malware** — all components were written by me, contain *zero malicious code*, and run only inside an isolated VM.

The infection flow I simulated mirrors *post-macro Emotet campaigns* commonly observed after Microsoft disabled Office macros by default in 2022:

1. Phishing email (`.eml`)  
2. ZIP attachment  
3. LNK masquerading as a PDF  
4. PowerShell-based loader  
5. Dropped Stage 2  
6. Scheduled Task persistence  
7. Localhost “C2” beacon attempts  

Every stage produces **real forensic artefacts**, which I collected and documented below.

---

## 🛠️ 2. Tools Used

| Tool | Purpose |
|------|---------|
| **Windows Explorer / 7-Zip** | Extract the ZIP & observe user artefacts |
| **Event Viewer** | Process creation, PowerShell, ScriptBlock logs |
| **LECmd** | LNK parsing (metadata, target command, timestamps) |
| **MFTECmd** | `$MFT` timeline reconstruction |
| **UsnJrnl2Csv** | `$UsnJrnl` activity during file creation |
| **PECmd** | Prefetch analysis |
| **Autoruns** | Reviewing persistence entries |
| **RegRipper / RECmd** | Registry analysis |
| **PowerShell (CLI)** | Inspecting file creation & logs |

> *These tools collectively reveal how each stage of the chain touches the filesystem, registry, network stack, and user activity logs.*

---

## 📧 3. Delivery Stage — Phishing Email

The infection begins with a crafted phishing email containing a ZIP archive (`Invoice_2025.zip`) meant to resemble common Emotet delivery lures.

### Screenshot: Email preview  
*Add screenshot here*  
`![Phishing Email](images/phish_email.png)`

Extraction produced the following folder:
Invoice_2025
├── Invoice.pdf.lnk
└── Documents
└── invoice_data.dat.ps1


### Forensic Artefacts Identified
- `.eml` message metadata (timestamp, sender spoofing)
- Attachment extraction recorded in:
  - `$MFT`  
  - `$UsnJrnl`  
  - Jump Lists  
  - Explorer view artefacts  
  - `Zone.Identifier` ADS  

### Screenshot: ZIP Extraction  
`![ZIP Extraction](images/zip_extract.png)`

---

## 🧷 4. Execution Stage — LNK Masquerading as “Invoice.pdf”

The user opens **Invoice.pdf.lnk**, a shortcut disguised with a PDF icon.

Using **LECmd**, I extracted metadata:
LECmd.exe -f "Invoice.pdf.lnk" -q


### Key Findings from LNK Metadata
- LNK points to PowerShell  
- Target file: `invoice_data.dat.ps1`  
- Working directory of the shortcut  
- File timestamps (creation/access)  
- Link flags showing it was manually created  

### Screenshot: LNK Metadata  
`![LNK Metadata](images/lnk_metadata.png)`

### LNK Target Command
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "%USERPROFILE%\Downloads\Invoice_2025\Documents\invoice_data.dat.ps1"

### Artefacts Generated
- `UserAssist` entry for the LNK  
- MUI Cache entries  
- Prefetch file for `POWERSHELL.EXE`  
- Event ID **4688** (process creation)  
- Jump List entry under *Recent Documents*  

---

## 📜 5. Stage 1 Loader — `invoice_data.dat.ps1`

Once executed, the disguised script:

1. Logs its execution
2. Creates a working directory:  
   `%APPDATA%\WinUpdate\`
3. Drops Stage 2 (`stage2.ps1`)
4. Creates Scheduled Task persistence  
5. Executes Stage 2 immediately

### Screenshot: Loader Script Execution Log  
`![Loader Log](images/loader_log.png)`

### Loader Output Files
- `loader_log.txt` in the Invoice folder  
- `stage2.ps1` dropped in WinUpdate directory  

### Artefacts Observed
- `$MFT` entries for directory & file creation  
- `$UsnJrnl` added rows for Stage 2 drop  
- ScriptBlock logs (Event ID 4104) showing full command  
- PowerShell Operational logs (4103, 4105)

### Screenshot: `$MFT` Timeline Evidence  
`![MFT Timeline](images/mft_timeline.png)`

---

## ⚙️ 6. Stage 2 — Simulated C2 Beacon

Stage 2 attempts harmless web requests to localhost:
Invoke-WebRequest http://127.0.0.1/ping


These are logged by PowerShell.

### Screenshot: Stage 2 Log  
`![Stage2 Log](images/stage2_log.png)`

### Artefacts Generated
- ScriptBlock logging (Event 4104)
- Network attempt logged in SRUM database
- Timestamped log file confirming beacon attempt
- Additional PowerShell prefetch entries  

---

## 🗓️ 7. Persistence — Scheduled Task

The loader created a Scheduled Task named **WindowsUpdateMonitor** that executes Stage 2 every 30 minutes.

### Task File Location:
C:\Windows\System32\Tasks\WindowsUpdateMonitor

### Relevant Registry Keys:
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\


### Screenshot: Scheduled Task  
`![Scheduled Task](images/scheduled_task.png)`

### Artefacts
- Task creation in Event Log (ID 106)
- MFT timestamp for the XML task file
- USN journal records for filesystem activity

---

## 📚 8. Forensic Artefact Summary

### 🔹 File System
- ZIP extraction logs  
- LNK creation & execution  
- loader.ps1 & stage2.ps1 creation  
- Prefetch for PowerShell & schtasks  

### 🔹 Registry
- TaskCache entries  
- MUICache and UserAssist  
- RecentApps  

### 🔹 PowerShell Logs
- ScriptBlock logs  
- Module & pipeline logs  
- Process creation logs  

### 🔹 Email Artefacts
- EML metadata  
- Attachment temp files  

### 🔹 Network
- Localhost “C2” activity visible in SRUM  

### 🔹 Timeline Reconstruction
Combining:
- MFT  
- USN journal  
- Event logs  
- Script logs  
- Prefetch  
…produces a complete, minute-by-minute forensic timeline.

---

## 🧩 9. Conclusions

This simulation provides a realistic, safe demonstration of a **modern post-macro Emotet-style intrusion chain**.  
Each step leaves behind traces that defenders can detect, and analysts can reconstruct:

- Initial access  
- Execution  
- Persistence  
- Post-execution activity  

---



