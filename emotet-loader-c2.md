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
    
- Practice reconstructing a forensic timeline from disk and log evidence
    
- Produce a public DFIR-style write-up suitable for education and portfolio use
    

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
    

The remainder of this report reconstructs the infection using artefacts only, as if it were a real investigation.

---

## 4. Timeline of Events (Narrative)

> Replace `YYYY-MM-DD HH:MM:SS` with actual times from your artefacts (MFT, Security logs, PowerShell logs, etc).

### 4.1 Delivery & Initial User Interaction

**T0 – YYYY-MM-DD HH:MM:SS**  
The victim receives a phishing email containing `Invoice_2025.zip` as an attachment.

- The email (e.g. `Invoice-2025.eml`) is saved locally by the user.
    

**T1 – YYYY-MM-DD HH:MM:SS**  
The victim saves `Invoice_2025.zip` from the email to their `Downloads` directory:

- `Invoice_2025.zip` appears in `C:\Users\<User>\Downloads\`.
    

**T2 – YYYY-MM-DD HH:MM:SS**  
The victim extracts `Invoice_2025.zip`, creating:

`C:\Users\<User>\Downloads\Invoice_2025\     Invoice.pdf.lnk     Documents\         invoice_data.dat.ps1`

The victim browses into the `Invoice_2025` folder and the `Documents` subfolder using Explorer.

---

### 4.2 LNK Execution (Initial Code Execution)

**T3 – YYYY-MM-DD HH:MM:SS**  
The victim double-clicks `Invoice.pdf.lnk` believing it to be a PDF invoice.

- The LNK launches `powershell.exe` with arguments that target `invoice_data.dat.ps1` in the `Documents` subfolder.
    

---

### 4.3 Stage 1 Loader

**T4 – YYYY-MM-DD HH:MM:SS**  
PowerShell executes `invoice_data.dat.ps1`:

- Writes an execution log (`loader_log.txt`) into the `Invoice_2025` folder.
    
- Creates working directory `%APPDATA%\WinUpdate`.
    
- Writes Stage 2 script `stage2.ps1` into `%APPDATA%\WinUpdate`.
    
- Creates Scheduled Task `WindowsUpdateMonitor` configured to run Stage 2 at intervals.
    
- Immediately executes `stage2.ps1`.
    

---

### 4.4 Stage 2 & Simulated C2

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
    

Assume the mounted VM disk is visible on the host as drive `X:\`.

---

### 5.1 Delivery & ZIP Extraction

#### 5.1.1 Evidence: ZIP Saved from Email

- **Location:**  
    `X:\Users\<User>\Downloads\Invoice_2025.zip`
    
- **How extracted:**
    
    - Mounted post-detonation VM snapshot as `X:`.
        
    - Browsed `X:\Users\<User>\Downloads\` via FTK Imager or Explorer.
        

**Explanation:**  
Confirms the user manually saved `Invoice_2025.zip` from the email client into their `Downloads` directory at approximately T1.

**Screenshot:**  
`![Invoice_2025.zip in Downloads](images/evidence_zip_in_downloads.png)`

---

#### 5.1.2 Evidence: Zone.Identifier ADS (Optional)

- **Location:**  
    `X:\Users\<User>\Downloads\Invoice_2025.zip:Zone.Identifier` (if present)
    
- **How extracted (live example):**
    

`more < "C:\Users\<User>\Downloads\Invoice_2025.zip:Zone.Identifier"`

- For offline image: export the file and inspect ADS on a lab host.
    

**Explanation:**  
A `ZoneId=3` entry indicates Windows treated the file as originating from an untrusted zone (Internet), supporting the narrative that this came from an email or external source.

**Screenshot:**  
`![Zone.Identifier for ZIP](images/evidence_zip_zoneid.png)`

---

#### 5.1.3 Evidence: ZIP Extraction – MFT / USN

- **Location:**
    
    - MFT: `X:\$MFT`
        
    - USN Journal: `X:\$Extend\$UsnJrnl`
        
- **How extracted:**
    

`MFTECmd.exe -f X:\$MFT --csv mft.csv UsnJrnl2Csv.exe -f X:\$Extend\$UsnJrnl -o usn.csv`

- Filter `mft.csv` & `usn.csv` for:
    
    - `\Users\<User>\Downloads\Invoice_2025\`
        
    - `Invoice.pdf.lnk`
        
    - `invoice_data.dat.ps1`
        

**Explanation:**  
Shows creation of the folder `Invoice_2025`, its child LNK, and the loader script, confirming ZIP extraction at around T2.

**Screenshot:**  
`![MFT timeline for ZIP extraction](images/evidence_mft_zip_extraction.png)`

---

### 5.2 User Browsing: Shellbags & Jump Lists

#### 5.2.1 Evidence: Shellbags – Folder Viewed in Explorer

- **Location (user hives):**
    
    - `X:\Users\<User>\NTUSER.DAT`
        
    - `X:\Users\<User>\AppData\Local\Microsoft\Windows\UsrClass.dat`
        
- **How extracted:**
    

`SBECmd.exe -d "X:\Users\<User>\AppData\Local\Microsoft\Windows" --csv sbecmd_out`

**Explanation:**  
Shellbag entries show that the `Downloads\Invoice_2025` folder (and possibly `Documents`) was opened in Explorer. Timestamps close to T2–T3 corroborate user browsing prior to execution.

**Screenshot:**  
`![Shellbag entry for Invoice_2025 folder](images/evidence_shellbag_invoice_folder.png)`

---

#### 5.2.2 Evidence: Jump List – Recent Folder / File

- **Location:**  
    `X:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`
    
- **How extracted:**
    

`JLECmd.exe -d "X:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv jl.csv`

**Explanation:**  
Jump List entries referencing `Invoice_2025` or the ZIP indicate that the user opened the folder or file via Explorer, reinforcing the manual nature of the interaction.

**Screenshot:**  
`![Jump list entry for Invoice_2025](images/evidence_jump_list_invoice.png)`

---

### 5.3 LNK Execution (Invoice.pdf.lnk)

#### 5.3.1 Evidence: LNK Metadata

- **Location:**  
    `X:\Users\<User>\Downloads\Invoice_2025\Invoice.pdf.lnk`
    
- **How extracted:**
    

`LECmd.exe -f "X:\Users\<User>\Downloads\Invoice_2025\Invoice.pdf.lnk" --csv lnk.csv`

**Explanation:**  
The LNK metadata reveals:

- Target: `powershell.exe`
    
- Arguments: `-WindowStyle Hidden -ExecutionPolicy Bypass -File "%USERPROFILE%\Downloads\Invoice_2025\Documents\invoice_data.dat.ps1"`
    

Timestamps align with T3, confirming when the shortcut was last executed.

**Screenshot:**  
`![LECmd output for Invoice.pdf.lnk](images/evidence_lecmd_invoice_lnk.png)`

---

#### 5.3.2 Evidence: UserAssist – LNK Launched via GUI

- **Location (user hive):**  
    `X:\Users\<User>\NTUSER.DAT`
    
- **How extracted:**
    
    - Using RECmd or RegRipper on UserAssist keys:
        
        - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`
            

**Explanation:**  
UserAssist entries (after ROT13 decoding of value names) show that `Invoice.pdf.lnk` was executed via Explorer, not via script or command line. This backs the user-driven execution narrative at T3.

**Screenshot:**  
`![UserAssist entry for Invoice.pdf.lnk](images/evidence_userassist_invoice_lnk.png)`

---

### 5.4 Loader Execution (invoice_data.dat.ps1)

#### 5.4.1 Evidence: Loader Script Contents

- **Location:**  
    `X:\Users\<User>\Downloads\Invoice_2025\Documents\invoice_data.dat.ps1`
    
- **How extracted:**
    
    - Exported from the mounted image and opened in Notepad++ / VS Code.
        

**Explanation:**  
The loader script encodes the Stage 1 behaviour:

- Logging execution to `loader_log.txt`
    
- Creating `%APPDATA%\WinUpdate`
    
- Dropping `stage2.ps1`
    
- Creating Scheduled Task (`WindowsUpdateMonitor`)
    
- Executing Stage 2 immediately
    

This mirrors modern loader behaviour in a safe, controlled way.

**Screenshot:**  
`![Loader script contents](images/evidence_loader_script.png)`

---

#### 5.4.2 Evidence: Loader Execution Log

- **Location:**  
    `X:\Users\<User>\Downloads\Invoice_2025\loader_log.txt`
    
- **How extracted:**
    
    - Viewed directly in a text editor.
        

**Explanation:**  
Confirms the loader was executed at T4, often including timestamp and hostname/environment. This provides a strong pivot point for correlating with PowerShell and Security logs.

**Screenshot:**  
`![loader_log.txt contents](images/evidence_loader_log.png)`

---

#### 5.4.3 Evidence: Stage 2 Dropped (stage2.ps1)

- **Location:**  
    `X:\Users\<User>\AppData\Roaming\WinUpdate\stage2.ps1`
    
- **How extracted:**
    
    - Located under the user’s `AppData\Roaming\WinUpdate` directory.
        
    - Timelined via MFTECmd on `$MFT`.
        

**Explanation:**  
Demonstrates that the loader wrote a second-stage script into a directory named to resemble Windows update or maintenance activity, a common staging pattern in real malware.

**Screenshot:**  
`![WinUpdate directory with stage2.ps1](images/evidence_winupdate_stage2.png)`

---

### 5.5 Persistence (Scheduled Task: WindowsUpdateMonitor)

#### 5.5.1 Evidence: Task File on Disk

- **Location:**  
    `X:\Windows\System32\Tasks\WindowsUpdateMonitor`
    
- **How extracted:**
    
    - Opened in a text editor (XML-format scheduled task definition).
        

**Explanation:**  
Shows:

- Task name: `WindowsUpdateMonitor`
    
- Action: `powershell.exe` executing `stage2.ps1`
    
- Schedule: interval (e.g., every 30 minutes)
    
- User context and trigger configuration
    

This is concrete evidence of Scheduled Task-based persistence created by the loader.

**Screenshot:**  
`![WindowsUpdateMonitor task XML](images/evidence_task_xml.png)`

---

#### 5.5.2 Evidence: TaskCache Registry Entries

- **Location (SYSTEM hive):**  
    `X:\Windows\System32\config\SYSTEM`
    
    - Keys of interest:
        
        - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}`
            
        - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WindowsUpdateMonitor`
            
- **How extracted:**
    
    - Parsed in Registry Explorer or RECmd using appropriate profiles.
        

**Explanation:**  
TaskCache registry entries link the logical task name (`WindowsUpdateMonitor`) to its GUID and filesystem representation, forming part of the task scheduler’s internal index. They serve as registry confirmation of the persistence mechanism.

**Screenshot:**  
`![TaskCache registry entries](images/evidence_taskcache_registry.png)`

---

#### 5.5.3 Evidence: Process Creation (schtasks.exe)

- **Location:**  
    `X:\Windows\System32\winevt\Logs\Security.evtx`
    
- **How extracted:**
    
    - Parsed with EvtxECmd or viewed in Event Viewer.
        
    - Filtered for Event ID 4688 (process creation) where `NewProcessName` = `schtasks.exe`.
        

**Explanation:**  
Shows `schtasks.exe` invoked with `/create` parameters that include `WindowsUpdateMonitor` and the command to execute `stage2.ps1`. This ties the persistence creation directly back to the loader’s activity window.

**Screenshot:**  
`![4688 event for schtasks.exe](images/evidence_4688_schtasks.png)`

---

### 5.6 Stage 2 Execution & Simulated C2

#### 5.6.1 Evidence: Stage 2 Log

- **Location:**  
    `X:\Users\<User>\Downloads\Invoice_2025\stage2_log.txt`
    
- **How extracted:**
    
    - Viewed directly in a text editor.
        

**Explanation:**  
Confirms Stage 2 executed at T5, and logs:

- Activation time
    
- Attempted HTTP request to `http://127.0.0.1/ping`
    
- Failure message (expected due to no listener)
    

This is controlled “C2-like” behaviour suitable for offline labs.

**Screenshot:**  
`![stage2_log.txt contents](images/evidence_stage2_log.png)`

---

#### 5.6.2 Evidence: PowerShell ScriptBlock Logs

- **Location:**  
    `X:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`
    
- **How extracted:**
    
    - Parsed with EvtxECmd or Event Viewer.
        
    - Filtered for Event ID 4104 (ScriptBlockLogging).
        

**Explanation:**  
ScriptBlock log entries reveal the code passed to PowerShell, including:

- Loader behaviour
    
- The `Invoke-WebRequest "http://127.0.0.1/ping"` call in Stage 2
    

These logs are extremely valuable for IR as they expose actual script contents even if the files are later deleted.

**Screenshot:**  
`![4104 ScriptBlock event with Invoke-WebRequest](images/evidence_4104_stage2.png)`

---

#### 5.6.3 Evidence: SRUM Execution/Network Telemetry (Optional)

- **Location:**  
    `X:\Windows\System32\sru\SRUDB.dat`
    
- **How extracted:**
    

`SrumECmd.exe -f "X:\Windows\System32\sru\SRUDB.dat" --csv srum.csv`

**Explanation:**  
SRUM can record execution and basic network-related statistics for `powershell.exe`. Entries near T4–T5 help confirm when PowerShell ran in relation to the infection chain.

**Screenshot:**  
`![SRUM entry for PowerShell](images/evidence_srum_powershell.png)`

---

### 5.7 Execution Traces: Prefetch & Amcache

#### 5.7.1 Evidence: Prefetch (POWERSHELL.EXE / SCHTASKS.EXE)

- **Location:**
    
    - `X:\Windows\Prefetch\POWERSHELL.EXE-*.pf`
        
    - `X:\Windows\Prefetch\SCHTASKS.EXE-*.pf`
        
- **How extracted:**
    

`PECmd.exe -f "X:\Windows\Prefetch\POWERSHELL.EXE-*.pf" --csv ps_pf.csv PECmd.exe -f "X:\Windows\Prefetch\SCHTASKS.EXE-*.pf" --csv sch_pf.csv`

**Explanation:**  
Prefetch records show:

- That `powershell.exe` and `schtasks.exe` executed
    
- Their last run times (expected around T3–T5)
    
- Run counts and related metadata
    

These traces corroborate script and persistence activity even if logs are incomplete.

**Screenshot:**  
`![PECmd output for POWERSHELL prefetch](images/evidence_prefetch_powershell.png)`

---

#### 5.7.2 Evidence: Amcache (Optional)

- **Location:**  
    `X:\Windows\AppCompat\Programs\Amcache.hve`
    
- **How extracted:**
    
    - Parsed with RECmd or dedicated Amcache parser.
        

**Explanation:**  
Amcache entries can record program execution and associated file paths. Entries for `powershell.exe` (and potentially associated script paths) provide long-lived execution evidence.

**Screenshot:**  
`![Amcache entry for powershell.exe](images/evidence_amcache_powershell.png)`

---

## 6. Detection & Hunting Opportunities

This simulation highlights several reliable detection angles:

- **LNK launching PowerShell with script path**
    
    - Look for command lines where `powershell.exe` is invoked by a `.lnk` target, especially with `-ExecutionPolicy Bypass` and `-File` arguments.
        
- **PowerShell writing and executing scripts in unusual locations**
    
    - Scripts dropped and run from `%APPDATA%\WinUpdate` or similar non-standard directories.
        
- **Scheduled Task persistence invoking PowerShell scripts**
    
    - Task names that mimic legit services (e.g. `WindowsUpdateMonitor`) but execute `.ps1` files.
        
- **PowerShell ScriptBlock logs containing suspicious web requests**
    
    - `Invoke-WebRequest` or `Invoke-RestMethod` with non-corporate domains or unexpected endpoints.
        
- **User activity correlation**
    
    - UserAssist, shellbags, Jump Lists showing that user interaction (double-clicking a LNK) preceded the script execution.
        

These patterns can be translated into Sigma rules, KQL queries, or other detection logic for SIEM and EDR platforms.

---

## 7. Conclusion

This controlled simulation demonstrates how a relatively simple PowerShell-based loader chain can leave a **rich, multi-surface forensic footprint** across:

- Filesystem (MFT, USN, dropped scripts, logs)
    
- Registry (UserAssist, TaskCache, MUICache)
    
- Event logs (Security, PowerShell Operational)
    
- Application telemetry (Prefetch, SRUM)
    
- User artefacts (LNK, shellbags, Jump Lists)
    

By walking through these artefacts step-by-step, an analyst can:

- Reconstruct the user’s actions from saving the ZIP to executing the LNK.
    
- Attribute loader and Stage 2 activity to specific processes, times, and artefacts.
    
- Confirm persistence mechanisms and their configuration.
    
- Understand how script-based activity appears in multiple logging surfaces.
    

The same methodology can be applied to real-world loader intrusions, with this lab serving as a safe training and demonstration baseline.
