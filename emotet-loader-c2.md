---
layout: default
title: Simulated Emotet-Style Loader Infection (DFIR Case Study)
---

# Simulated Emotet-Style Loader Infection (DFIR Case Study)

---
## 1. Executive Summary

This report documents a **controlled, self-authored simulation** of a modern Emotet-style intrusion chain executed inside a Windows virtual machine (VM). The goals of this exercise are to:

- Understand how a contemporary loader behaves on a Windows endpoint
    
- Observe artefacts left at each stage (delivery, execution, persistence, “C2”)

No real malware was used at any point.  
All scripts, loaders, and “C2” activity were written specifically for this lab and executed only inside an isolated VM.

High-level flow:

1. User receives a phishing email with `Invoice_2025.zip` attached.
    
2. User saves and extracts the ZIP.
    
3. User opens a malicious LNK (`Invoice.pdf.lnk`) masquerading as a PDF.
    
4. LNK executes a PowerShell loader script (`invoice_data.dat.ps1`).
    
5. Loader drops a second-stage script (`stage2.ps1`) into `%APPDATA%\WinUpdate`.
    
6. Loader creates Scheduled Task persistence (`WindowsUpdateMonitor`).
    
7. Stage 2 simulates C2 activity by attempting HTTP requests to `http://127.0.0.1/ping` and logging its execution.
    

All of these stages leave observable artefacts in the filesystem, registry, event logs, PowerShell logs, SRUM, and user activity (LNK metadata, shellbags, Jump Lists, etc.).

---

## 2. Scope & Environment

### 2.1 Environment

- **Host:** Windows machine running VMware
    
- **Guest VM:** Windows 10/11 (lab system)
    
- **Hypervisor:** VMware Workstation / Player
    
- **Execution:**
    
    - Infection executed inside the VM
        
    - Snapshot taken post-detonation
        
    - VM disk (snapshot) mounted on host for offline analysis
        

### 2.2 Tools Used

|Category|Tools|
|---|---|
|Disk & Filesystem|FTK Imager, Arsenal Image Mounter / OSFMount|
|Timelines|MFTECmd (MFT), UsnJrnl2Csv (USN Journal)|
|Shortcuts / LNK|LECmd|
|Prefetch|PECmd|
|Registry|RECmd, Registry Explorer, RegRipper|
|Event Logs|EvtxECmd, Windows Event Viewer|
|Shellbags|SBECmd|
|Jump Lists|JLECmd|
|SRUM|SrumECmd|
|Text / Code|Notepad++, VS Code|

---

## 3. Attack Scenario Overview

This lab simulates a **post-macro Emotet-style loader campaign**:

1. **Delivery:** Phishing email with ZIP (`Invoice_2025.zip`).
    
2. **User Action:** Victim manually saves and extracts the ZIP.
    
3. **Execution:** Victim opens `Invoice.pdf.lnk`, which launches PowerShell.
    
4. **Stage 1 Loader:** PowerShell script `invoice_data.dat.ps1`:
    
    - Logs execution
        
    - Creates `%APPDATA%\WinUpdate`
        
    - Drops `stage2.ps1`
        
    - Creates Scheduled Task (`WindowsUpdateMonitor`)
        
    - Executes Stage 2
        
5. **Stage 2:** Simulated beacon to `http://127.0.0.1/ping`, logging outcome.
    

The remainder of this report reconstructs the infection using artefacts only.

---

## 4. Timeline of Events
4. Timeline of Events

2025-11-29 04:10:12 – Phishing email containing Invoice_2025.zip is received in the Windows Mail client.

2025-11-29 04:15:51 – Windows Mail caches a copy of Invoice_2025.zip in its internal attachments directory, indicating the user opened or interacted with the attachment in the Mail app.

2025-11-29 04:17:03 – A invoice-2025.lnk entry appears under AppData\Roaming\Microsoft\Windows\Recent, showing the user accessed the Invoice_2025 attachment via the shell.

2025-11-29 04:22:22 – Invoice_2025.zip and its :Zone.Identifier ADS are created in C:\Users\TestVM\Downloads, confirming the user saved the ZIP from the Mail client and that Windows marked it as originating from an untrusted zone.

2025-11-29 04:22:40 – The C:\Users\TestVM\Downloads\Invoice_2025 directory is created, indicating the ZIP was extracted and the embedded files (Invoice.pdf.lnk, Documents\invoice_data.dat.ps1) became accessible.

2025-11-29 04:22:41 – Shellbags record the user browsing into Downloads\Invoice_2025, confirming the folder was opened in Explorer.

2025-11-29 04:23:09 – UserAssist and Prefetch show the user executed Invoice.pdf.lnk, which launched powershell.exe with invoice_data.dat.ps1 as the script.

2025-11-29 04:23:12 – $MFT shows stage2.ps1 created under %APPDATA%\WinUpdate, and Stage 2 logging begins in stage2_log.txt, confirming second-stage execution.

(Further timestamps from the USN Journal, Scheduled Task artefacts, and logs to be added)

---

## 5. Detailed Forensic Findings
    
### 5.1 $MFT Entries
User opened / interacted with the email (.eml)
- Evidence: $MFT entry for invoice_2025.eml.lnk under AppData\Roaming\Microsoft\Windows\Recent.
- Interpretation: Indicates the user opened the phishing email via the Mail client.

Email client cached the ZIP attachment
- Evidence: $MFT entries under AppData\Local\Packages\microsoft.windowscommunicationsapps_...\LocalState\Files\S0\*\Attachments\Invoice_2025[...].zip.
- Interpretation: Shows the ZIP was received and cached by the Windows Mail app.

User downloaded Invoice_2025.zip to Downloads
- Evidence: $MFT entry for C:\Users\TestVM\Downloads\Invoice_2025.zip and its ADS Invoice_2025.zip:Zone.Identifier.
- Interpretation: Confirms the user manually saved the attachment from Mail to the Downloads folder and that Windows considered it untrusted content.

ZIP extracted, creating Invoice_2025 directory
- Evidence: $MFT entry for directory C:\Users\TestVM\Downloads\Invoice_2025 with Created timestamps consistent with extraction.
- Interpretation: Confirms archive extraction and creation of the working folder.

Extracted malicious LNK present (Invoice.pdf.lnk)
- Evidence: $MFT entry for C:\Users\TestVM\Downloads\Invoice_2025\Invoice.pdf.lnk.
- Interpretation: Confirms the fake PDF shortcut was present in the extracted folder.

Extracted Stage-1 loader present (invoice_data.dat.ps1)
- Evidence: $MFT entry for C:\Users\TestVM\Downloads\Invoice_2025\Documents\invoice_data.dat.ps1.
- Interpretation: Confirms Stage-1 payload was extracted and available on disk.

<img width="1675" height="673" alt="image" src="https://github.com/user-attachments/assets/de661715-4e47-4781-bcd3-5863b7c75818" />

Stage-2 script present (stage2.ps1)
Evidence: $MFT entry for C:\Users\TestVM\AppData\Roaming\WinUpdate\stage2.ps1 with creation time around 2025-11-29 04:23:12.
Interpretation: Confirms Stage-1 successfully dropped the Stage-2 script into the WinUpdate staging directory.

<img width="1504" height="134" alt="image" src="https://github.com/user-attachments/assets/724e009d-aec0-4467-adf9-72bd12cc711c" />

### 5.2 ShellBags 
User opened the extracted folder Invoice_2025
Evidence: Shellbag path Desktop\My Computer\Downloads\Invoice_2025.
Interpretation: Shows the user browsed into the extracted directory after unzipping.

User viewed the ZIP file inside Downloads
Evidence: Shellbag path Desktop\My Computer\Downloads\Invoice_2025.zip.
Interpretation: Confirms the ZIP itself was selected/viewed in Explorer.

User opened the inner Documents subfolder
Evidence: Shellbag path Desktop\My Computer\Downloads\Invoice_2025\Documents (or equivalent).
Interpretation: Indicates the user navigated into the subfolder containing the Stage-1 script.

Email client attachment folder was accessed
Evidence: Shellbag entries under
...\AppData\Local\Packages\microsoft.windowscommunicationsapps_...\LocalState\Files\S0\*\Attachments\.
Interpretation: Explorer accessed the Mail app’s attachment storage, consistent with viewing the ZIP in the email client.

User viewed the extracted payload path inside the ZIP (Invoice_2025.zip\Invoice_2025)
Evidence: Shellbag path Desktop\Invoice_2025.zip\Invoice_2025.
Interpretation: Indicates the user inspected the ZIP contents in Explorer before / during extraction.

<img width="1680" height="739" alt="image" src="https://github.com/user-attachments/assets/89e7c51c-c5d2-4645-9896-936bdeb95c81" />

### 5.3 UserAssist

User executed malicious LNK (Invoice.pdf.lnk)
Evidence: UserAssist entry for
C:\Users\TestVM\Downloads\Invoice_2025\Invoice.pdf.lnk
with Last Executed ≈ 2025-11-29 04:23:09.
Interpretation: Confirms the LNK was launched from Explorer by the logged-on user (GUI action, not scripted).

<img width="424" height="148" alt="image" src="https://github.com/user-attachments/assets/32c6c916-0d96-4d20-8515-2a9dff8c57fa" />

### 5.4 Prefetch

PowerShell executed following LNK click
Evidence: POWERSHELL.EXE-*.pf prefetch file showing:
Last Run Time ≈ 2025-11-29 04:23:09–04:23:12.
Low run count consistent with a fresh lab VM.
Interpretation: Confirms powershell.exe was executed in the infection window, aligning with the execution of Invoice.pdf.lnk.

<img width="1623" height="137" alt="image" src="https://github.com/user-attachments/assets/a00150b5-8deb-45c7-96ba-52ad5aa58f2a" />


---


## 7. Conclusion

This controlled simulation demonstrates how a relatively simple PowerShell-based loader chain can leave a **rich, multi-surface forensic footprint** across:

- Filesystem (MFT, USN, dropped scripts, logs)
    
- Registry (UserAssist, TaskCache, MUICache)
    
- Event logs (Security, PowerShell Operational)
    
- Application telemetry (Prefetch, SRUM)
    
- User artefacts (LNK, shellbags, Jump Lists)
    
    

The same methodology can be applied to real-world loader intrusions, with this lab serving as a safe training and demonstration baseline.
