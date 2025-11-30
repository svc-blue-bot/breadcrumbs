<img width="221" height="24" alt="image" src="https://github.com/user-attachments/assets/d197133a-42b1-4264-8406-1de9990e35ac" />---
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

**2025-11-29 04:10:12**  
The victim receives a phishing email containing `Invoice_2025.zip` as an attachment.

**2025-11-29 04:15:51**  
The victim saves `Invoice_2025.zip` from the email to their `Downloads` directory:

**YYYY-MM-DD HH:MM:SS**  
The victim extracts `Invoice_2025.zip`, creating:

`C:\Users\<User>\Downloads\Invoice_2025\     Invoice.pdf.lnk     Documents\         invoice_data.dat.ps1`

The victim browses into the `Invoice_2025` folder and the `Documents` subfolder using Explorer.

**T3 – YYYY-MM-DD HH:MM:SS**  
The victim double-clicks `Invoice.pdf.lnk` believing it to be a PDF invoice.

- The LNK launches `powershell.exe` with arguments that target `invoice_data.dat.ps1` in the `Documents` subfolder.

**T4 – YYYY-MM-DD HH:MM:SS**  
PowerShell executes `invoice_data.dat.ps1`:

- Writes an execution log (`loader_log.txt`) into the `Invoice_2025` folder.
    
- Creates working directory `%APPDATA%\WinUpdate`.
    
- Writes Stage 2 script `stage2.ps1` into `%APPDATA%\WinUpdate`.
    
- Creates Scheduled Task `WindowsUpdateMonitor` configured to run Stage 2 at intervals.
    
- Immediately executes `stage2.ps1`.

**T5 – YYYY-MM-DD HH:MM:SS**  
`stage2.ps1` runs:

- Logs its execution to `stage2_log.txt` in the `Invoice_2025` folder.
    
- Attempts an HTTP request to `http://127.0.0.1/ping`.
    
- Records failure (expected in an offline lab) and exits after a short delay.    

---

## 5. Detailed Forensic Findings

For each phase, artefacts are grouped as:

- **Evidence** – where it was found and how it was extracted
    
- **Explanation** – what it proves or supports
    
- **Screenshot** – placeholder for report images
    
### 5.1 $MFT Entries

User opened/interacted with the email (.eml)
Evidence: $MFT entry for invoice_2025.eml.lnk under AppData\Roaming\Microsoft\Windows\Recent.
Indicates the user opened the phishing email.

Email client cached the ZIP attachment
Evidence: $MFT entries under
AppData\Local\Packages\microsoft.windowscommunicationsapps_...\Attachments
for Invoice_2025[...].zip.
Indicates the ZIP was received via the Mail app.

User downloaded Invoice_2025.zip to Downloads
Evidence: $MFT entry for Invoice_2025.zip in
C:\Users\TestVM\Downloads.
Confirms the ZIP was manually saved by the user.

ZIP was extracted, creating Invoice_2025 directory
Evidence: $MFT entry for directory Invoice_2025 with timestamps consistent with extraction.
Confirms ZIP extraction.

Extracted malicious LNK present (Invoice.pdf.lnk)
Evidence: $MFT entry in Downloads\Invoice_2025\ for Invoice.pdf.lnk.
Confirms the fake PDF shortcut existed in the extracted folder.

Extracted Stage-1 loader present (invoice_data.dat.ps1)
Evidence: $MFT entry in Downloads\Invoice_2025\Documents\ for invoice_data.dat.ps1.
Confirms Stage-1 payload was extracted by the user.

![Alt text](MFT.png)

### 5.2 ShellBags 
User opened the extracted folder Invoice_2025
Shellbag entry: Desktop\My Computer\Downloads\Invoice_2025
Shows the user browsed into the extracted directory after unzipping.
(Screenshot)
[Shellbags_InvoiceFolder.png]

User viewed the ZIP file inside Downloads

Shellbag entry: Desktop\My Computer\Downloads\Invoice_2025.zip

Confirms the ZIP was selected/viewed in Explorer.
(Screenshot)
[Shellbags_ZIP_View.png]

User opened the inner Documents subfolder

Shellbag entry: Desktop\My Computer\Documents\Invoice_2025\Documents

Indicates the user navigated into the subfolder containing the Stage-1 script.
(Screenshot)
[Shellbags_Documents_Subfolder.png]

Email client attachment folder was accessed

Multiple Shellbag entries under:
…\AppData\Local\Packages\microsoft.windowscommunicationsapps_...\LocalState\Files\$0\3\Attachments\

Indicates Explorer accessed the Mail app’s attachment storage, consistent with viewing the ZIP in the email client.
(Screenshot)
[Shellbags_AttachmentCache.png]

User viewed the extracted payload path inside the ZIP (Invoice_2025.zip\Invoice_2025)

Shellbag entry: Desktop\Invoice_2025.zip\Invoice_2025

Indicates the user inspected contents of the ZIP in Explorer before or during extraction.
(Screenshot)
[Shellbags_ZIP_Internal_View.png]

System and application directories shown due to normal OS browsing

Shellbag entries for Program Files, System32, WindowsPowerShell, etc.

Non-malicious baseline activity; included automatically by Explorer navigation.
(Screenshot)
[Shellbags_OS_Baseline.png]
---


## 7. Conclusion

This controlled simulation demonstrates how a relatively simple PowerShell-based loader chain can leave a **rich, multi-surface forensic footprint** across:

- Filesystem (MFT, USN, dropped scripts, logs)
    
- Registry (UserAssist, TaskCache, MUICache)
    
- Event logs (Security, PowerShell Operational)
    
- Application telemetry (Prefetch, SRUM)
    
- User artefacts (LNK, shellbags, Jump Lists)
    
    

The same methodology can be applied to real-world loader intrusions, with this lab serving as a safe training and demonstration baseline.
