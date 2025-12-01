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
2. 
3. User saves and extracts the ZIP.
    
4. User opens a malicious LNK (`Invoice.pdf.lnk`) masquerading as a PDF.
    
5. LNK executes a PowerShell loader script (`invoice_data.dat.ps1`).
    
6. Loader drops a second-stage script (`stage2.ps1`) into `%APPDATA%\WinUpdate`.
    
7. Loader creates Scheduled Task persistence (`WindowsUpdateMonitor`).
    
8. Stage 2 simulates C2 activity by attempting HTTP requests to `http://127.0.0.1/ping` and logging its execution.
    

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

### 5.1 $MFT (Master File Table)

#### 5.1.1 Phishing email & attachment interaction

- Evidence: $MFT entry for invoice_2025.eml.lnk under C:\Users\TestVM\AppData\Roaming\Microsoft\Windows\Recent.
- Interpretation: Indicates the user opened the phishing email (invoice_2025.eml) via the Mail client.

#### 5.1.2 Mail app cached ZIP attachment
- Evidence: $MFT entries under C:\Users\TestVM\AppData\Local\Packages\microsoft.windowscommunicationsapps_...\LocalState\Files\S0\3\Attachments\Invoice_2025[...].zip.
- Interpretation: Confirms Invoice_2025.zip was received and cached by the Windows Mail application.

#### 5.1.3 ZIP downloaded to Downloads
- Evidence:
    - $MFT entry for C:\Users\TestVM\Downloads\Invoice_2025.zip.
    - $MFT entry for C:\Users\TestVM\Downloads\Invoice_2025.zip:Zone.Identifier (extension .Identifier).
- Interpretation: Confirms the ZIP was manually saved to Downloads and marked as Internet-sourced content.

#### 5.1.4 Extraction of Invoice_2025 directory
- Evidence: $MFT entry for directory C:\Users\TestVM\Downloads\Invoice_2025 with Created ≈ 2025-11-29 04:22:40.
- Interpretation: Indicates the ZIP was extracted, creating the working folder.

#### 5.1.5 Malicious LNK present (Invoice.pdf.lnk)
- Evidence: $MFT entry for C:\Users\TestVM\Downloads\Invoice_2025\Invoice.pdf.lnk.
- Interpretation: Confirms a fake PDF shortcut existed in the extracted folder.

<img width="1675" height="673" alt="image" src="https://github.com/user-attachments/assets/de661715-4e47-4781-bcd3-5863b7c75818" />

#### 5.1.6 Stage-1 loader present (invoice_data.dat.ps1)
- Evidence: $MFT entry for C:\Users\TestVM\Downloads\Invoice_2025\Documents\invoice_data.dat.ps1 (and ADS invoice_data.dat.ps1:Zone.Identifier if present).
- Interpretation: Confirms the Stage-1 PowerShell loader was present in the Documents subfolder.

#### 5.1.7 Stage-2 script written (stage2.ps1)
- Evidence: $MFT entry for C:\Users\TestVM\AppData\Roaming\WinUpdate\stage2.ps1 with creation time ≈ 2025-11-29 04:23:12.
- Interpretation: Confirms Stage-1 successfully wrote the Stage-2 beacon script to %APPDATA%\WinUpdate.

<img width="1504" height="134" alt="image" src="https://github.com/user-attachments/assets/724e009d-aec0-4467-adf9-72bd12cc711c" />

#### 5.1.8 Loader & Stage-2 text logs

- Evidence:
    - C:\Users\TestVM\Downloads\Invoice_2025\loader_log.txt
    - C:\Users\TestVM\Downloads\Invoice_2025\stage2_log.txt
- Interpretation: Presence and modification times of these files prove invoice_data.dat.ps1 and stage2.ps1 executed.

<img width="758" height="175" alt="image" src="https://github.com/user-attachments/assets/e99de59f-b0a9-4d01-aba5-3dfc133176aa" />

<img width="832" height="205" alt="image" src="https://github.com/user-attachments/assets/64cb5656-a0b4-4417-9b4e-023340508104" />


#### 5.1.9 Scheduled Task file on disk
- Evidence: $MFT entry for C:\Windows\System32\Tasks\WindowsUpdateMonitor.
- Interpretation: Shows the loader created a Scheduled Task for persistence.

<img width="1661" height="109" alt="image" src="https://github.com/user-attachments/assets/7e801fcd-885f-451e-988f-595aecfe7394" />

### 5.2 Shellbags (Explorer Folder Navigation)
#### 5.2.1 User browses Mail attachment path
- Evidence: Shellbag paths like Desktop\My Computer\C:\Users\TestVM\AppData\Local\Packages\microsoft.windowscommunicationsapps_...\LocalState\Files\S0\0\Attachments\Invoice_2025[4688].zip.
- Interpretation: The user navigated into the Mail app’s internal attachments folder, consistent with viewing the attachment from Mail.

#### 5.2.2 User views ZIP & extraction target
- Evidence:
    - Desktop\My Computer\Downloads\Invoice_2025.zip
    - Desktop\Invoice_2025.zip\Invoice_2025
- Interpretation: Confirms the ZIP and its internal Invoice_2025 folder were browsed in Explorer prior to/while extracting.

#### 5.2.3 User opens Downloads\Invoice_2025
- Evidence: Shellbag path Desktop\My Computer\Downloads\Invoice_2025 with last write around 04:22:41.
- Interpretation: Shows the extracted folder was opened.

#### 5.2.4 User opens inner Documents subfolder
- Evidence: Shellbag path Desktop\My Computer\Downloads\Invoice_2025\Documents (or equivalent).
- Interpretation: Indicates navigation into the folder containing the Stage-1 script.

<img width="1680" height="739" alt="image" src="https://github.com/user-attachments/assets/89e7c51c-c5d2-4645-9896-936bdeb95c81" />


### 5.3 UserAssist (GUI Execution)
#### 5.3.1 Execution of Invoice.pdf.lnk
- Evidence: UserAssist entry in NTUSER.DAT for C:\Users\TestVM\Downloads\Invoice_2025\Invoice.pdf.lnk, with Last Executed ≈ 2025-11-29 04:23:09.
- Interpretation: Confirms the malicious shortcut was launched via the Explorer GUI by the logged-on user.

<img width="424" height="148" alt="image" src="https://github.com/user-attachments/assets/32c6c916-0d96-4d20-8515-2a9dff8c57fa" />

### 5.4 Prefetch
#### 5.4.1 powershell.exe execution
- Evidence: POWERSHELL.EXE-*.pf prefetch file (parsed with PECmd) showing:
Last Run Time around 2025-11-29 04:23:09–04:23:12.
- Interpretation: Confirms powershell.exe ran in the same window as the LNK execution and loader activity.
Screenshot placeholder:
<img width="1623" height="137" alt="image" src="https://github.com/user-attachments/assets/a00150b5-8deb-45c7-96ba-52ad5aa58f2a" />

### 5.5 USN Journal – [TODO]
Use this section to summarise high-resolution file operations once you’ve parsed $UsnJrnl.
Evidence (expected):
- USN entries for:
    - Creation of Invoice_2025 directory.
    - Creation of Invoice.pdf.lnk.
    - Creation of invoice_data.dat.ps1.
    - Creation of %APPDATA%\WinUpdate\stage2.ps1.
    - Writes to loader_log.txt and stage2_log.txt.
    - Creation/updates of WindowsUpdateMonitor task file.
- Interpretation: Provides precise ordering of Stage-1 -> Stage-2 -> persistence operations.

<img width="1677" height="606" alt="image" src="https://github.com/user-attachments/assets/ccd705b5-609c-41c1-91dd-68e14bd2a083" />

<img width="1062" height="631" alt="image" src="https://github.com/user-attachments/assets/27f96f42-4193-42a4-a755-3c8fc02f0347" />

<img width="1065" height="630" alt="image" src="https://github.com/user-attachments/assets/35b50b5b-c37f-4d3d-b5c2-bdf8bac800c9" />

<img width="1066" height="328" alt="image" src="https://github.com/user-attachments/assets/013ae0e1-0149-4f15-9749-35e521ab20c8" />

<img width="1064" height="166" alt="image" src="https://github.com/user-attachments/assets/7bad9808-4020-47dd-8624-bc1aadaa030f" />

<img width="1063" height="233" alt="image" src="https://github.com/user-attachments/assets/a29c80d8-29fc-48a4-9142-848355acd975" />


### 5.6 Registry – Persistence & MRU Keys

#### 5.6.1 Scheduled Task TaskCache entries
Evidence:
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WindowsUpdateMonitor
- Interpretation:
Confirms creation of a Scheduled Task named WindowsUpdateMonitor pointing to powershell.exe and stage2.ps1.

<img width="695" height="182" alt="image" src="https://github.com/user-attachments/assets/8f8c5cb8-aa66-4416-a4bc-4a1c11e63d5c" />
<img width="1336" height="320" alt="image" src="https://github.com/user-attachments/assets/750cab3e-83ac-479f-96e9-3a148d48c4e9" />

---

## 6. TTPs

---

## 7. MITRE ATT&CK

---

## 8. Components Used

---

## 8. Conclusion

This controlled simulation demonstrates how a relatively simple PowerShell-based loader chain can leave a **rich, multi-surface forensic footprint** across:

- Filesystem (MFT, USN, dropped scripts, logs)
    
- Registry (UserAssist, TaskCache, MUICache)
    
- Event logs (Security, PowerShell Operational)
    
- Application telemetry (Prefetch, SRUM)
    
- User artefacts (LNK, shellbags, Jump Lists)
        
---
