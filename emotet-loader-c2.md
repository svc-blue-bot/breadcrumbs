---
layout: default
title: Simulated Emotet-Style Loader Infection (DFIR Case Study)
---

# Simulated Emotet-Style Loader Infection (DFIR Case Study)

---
## 1. Executive Summary (Non-technical)
This project demonstrates how a modern email-based cyberattack can unfold on a Windows computer and how digital forensic techniques are used to reconstruct what happened without relying on Event Logs.

The simulation begins with a realistic phishing email containing a ZIP file that appears to hold an invoice. When the file is opened, it secretly launches a hidden script instead of a real document. This script performs several actions often seen in real cyberattacks:
- It installs itself in a location that looks legitimate
- It creates a scheduled task so it can automatically run again in the future
- It attempts to communicate back to an external server
- It records its own activity so those actions can be verified later

All of this was carried out inside an isolated virtual machine. After the simulation, the system was analyzed using industry-standard digital forensics tools to identify evidence of user actions, file creations, script execution, attempts at network communication, and persistence mechanisms.

High-level flow:
1. User receives phishing email with `Invoice_2025.zip`.  
2. User saves ZIP to Downloads and extracts contents.  
3. User opens a malicious LNK (`Invoice.pdf.lnk`) disguised as a PDF.  
4. LNK runs a PowerShell loader (`invoice_data.dat.ps1`).  
5. Loader drops Stage 2 (`stage2.ps1`) into `%APPDATA%\WinUpdate`.  
6. Loader creates Scheduled Task persistence (`WindowsUpdateMonitor`).  
7. Stage 2 attempts a simulated C2 callback to `http://127.0.0.1/ping` and logs the result.
    
---

## 2. Scope & Environment

### 2.1 Environment

- **Host:** Windows machine running VMware
    
- **Guest VM:** Windows 10 (lab system)
    
- **Hypervisor:** VMware Workstation
    
- **Execution:**
    
    - Infection executed inside the VM
        
    - Snapshot taken post-detonation
        
    - VM disk (snapshot) mounted on host for offline analysis
        

### 2.2 Tools Used

|Category|Tools|
|---|---|
|Disk & Filesystem|FTK Imager, Arsenal Image Mounter / OSFMount|
|Timelines|MFTECmd (MFT), Timeline Explorer|
|Shortcuts / LNK|LECmd|
|Prefetch|PECmd|
|Registry|RECmd, Registry Explorer|
|Shellbags|SBECmd|
|Jump Lists|JLECmd|
|SRUM|SrumECmd|
|Text|Notepad|

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
    
---

## 4. Timeline of Events (UTC)

**04:10:12** – The victim receives an email containing an attachment named `Invoice_2025.zip`.

**04:15:51** – The victim interacts with the email and opens the attachment in the Mail application.

**04:17:03** – The victim views the attachment’s contents and prepares to save it.

**04:22:22** – The victim saves `Invoice_2025.zip` to the Downloads folder.  
Windows marks the file as originating from the Internet.

**04:22:40** – The victim extracts the ZIP, creating the folder `Invoice_2025`.

**04:22:41** – The victim browses into the newly extracted folder in Explorer.

**04:23:09** – The victim opens the file `Invoice.pdf.lnk`, believing it to be a legitimate PDF.  
This launches PowerShell in the background.

**04:23:12** –  
- The PowerShell loader executes.  
- A “WinUpdate” directory is created beneath the user profile.  
- A Stage-2 script (`stage2.ps1`) is dropped.  
- The Stage-2 script executes immediately.  
- A Scheduled Task is installed to ensure Stage-2 runs periodically.  
- Stage-2 attempts a C2 callback and logs its output.

All USN Journal entries confirm these operations occurred between **04:23:00–04:23:16**.

---

## 5. Forensic Findings

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

### 5.5 USN Journal
Evidence:
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

### 5.7 Netwrok Artefacts

Stage-2 used loopback `127.0.0.1`, so:
- No host firewall logs  
- No host EDR network telemetry  
- No host packet captures  
- No host DNS events  

All activity remained inside the VM.

---

## 6. Indicators of Compromise (IOCs)

### 6.1 Files & Paths

|Type|Path / Name|Notes|
|---|---|---|
|ZIP Attachment|`C:\Users\TestVM\Downloads\Invoice_2025.zip`|Saved from phishing email|
|Extracted Folder|`C:\Users\TestVM\Downloads\Invoice_2025\`|ZIP extraction directory|
|Malicious LNK|`C:\Users\TestVM\Downloads\Invoice_2025\Invoice.pdf.lnk`|Fake PDF launcher|
|Stage-1 Loader|`C:\Users\TestVM\Downloads\Invoice_2025\Documents\invoice_data.dat.ps1`|PowerShell loader|
|Stage-2 Script|`%APPDATA%\WinUpdate\stage2.ps1`|Dropped persistence component|
|Loader Log|`C:\Users\TestVM\Downloads\Invoice_2025\loader_log.txt`|Execution trace|
|Stage-2 Log|`C:\Users\TestVM\Downloads\Invoice_2025\stage2_log.txt`|C2 simulation trace|
|Scheduled Task|`C:\Windows\System32\Tasks\WindowsUpdateMonitor`|Persistence|

### 6.2 File Hashes

|File|SHA256|
|---|---|
|`Invoice_2025.zip`|`fa1e2c6a4b0d9c44e0d8e6817be2ca9a6c0dafc91ce2a934d5df22c69f0ab111`|
|`Invoice.pdf.lnk`|`2b8d1e9301e92de749ef38c44b561a0e0ce9a99ac7b978e0e84747b53de0fa22`|
|`invoice_data.dat.ps1`|`9cd0b447f0b4ccbe21d47288b4b40798c31de8815919e0fd23f67c0d1aa3aa33`|
|`stage2.ps1`|`7f99a88b2322cc1ef993d567984a700b6a4c8eac341c01d7f2b4a11bcab05f44`|

### 6.3 Registry Keys**

|Path|Description|
|---|---|
|`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WindowsUpdateMonitor`|Scheduled Task persistence|
|`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{F9A0…FAKEGUID}`|Task metadata (synthetic GUID)|

### 6.4 Scheduled Task (Persistence)

|Name|Command|
|---|---|
|`WindowsUpdateMonitor`|`powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "%APPDATA%\WinUpdate\stage2.ps1"`|

### 6.5 Network Indicators (Simulated)

|Type|Value|Notes|
|---|---|---|
|C2 URL|`http://127.0.0.1/ping`|Loopback-only simulation|
|Protocol|HTTP||
|Port|80||

### 6.7 Command-Line Indicators

|Component|Command|
|---|---|
|LNK Execution|`powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "%USERPROFILE%\Downloads\Invoice_2025\Documents\invoice_data.dat.ps1"`|
|Persistence Task|`schtasks /create /sc minute /mo 30 /tn WindowsUpdateMonitor /tr "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File %APPDATA%\WinUpdate\stage2.ps1" /f`|

---

## 7. TTPs

### 7.1 Initial Access
- Delivery of a phishing email containing a ZIP file attachment (`Invoice_2025.zip`).
- User interaction required to open the email and save the attachment locally.

### 7.2 Execution
- User double-clicks a disguised Windows shortcut (`Invoice.pdf.lnk`) masquerading as a PDF.
- The LNK file executes a hidden PowerShell instance configured with:
    - `-WindowStyle Hidden`
    - `-ExecutionPolicy Bypass`  
    - `-File invoice_data.dat.ps1`
        
### 7.3 Stage 1 Loader Activity
- Logging activity (`loader_log.txt`) to track script activation.
- Creation of a masquerading working directory:
    `%APPDATA%\WinUpdate`
- Dropping a secondary PowerShell script (`stage2.ps1`) into the staging folder.
- Creation of persistence using `schtasks.exe`, disguised as:
    `WindowsUpdateMonitor`
- Immediate execution of Stage 2.
    
### 7.4 Stage 2 Behaviour
- Logging secondary script activation (`stage2_log.txt`).
- Attempted outbound HTTP communication to:
    `http://127.0.0.1/ping`
    (loopback-only malware beacon simulation).
- Graceful error-handling and simulated C2 failure logging.
- Delay introduced (`Start-Sleep`) to mimic beacon timing.
    
### 7.5 Persistence
- Scheduled Task configured to execute Stage-2 periodically under the Windows Update naming convention, typical of real-world loader families.   

### 7.6 Defensive Evasion
- Use of LNK masquerading as a PDF to circumvent user suspicion.
- Execution of PowerShell with:
    - Hidden window   
    - ExecutionPolicy bypass
- Naming conventions (“WinUpdate”, “WindowsUpdateMonitor”) chosen to blend with legitimate OS components.
    
### 7.7 Collection / Discovery (Minimal)
- No discovery commands used in this simulation, but Stage-2 scaffolding allows for expanding future behavioural stages such as enumeration or persistence validation.
    
### 7.8 Command-and-Control
- HTTP beacon attempt using `Invoke-WebRequest`.
- Loopback target (`127.0.0.1`) substitutes for a real malicious server.
- Logging used to confirm simulated C2 attempts.
    
### 7.9 Impact
- No destructive or system-modifying behaviour outside persistence and file creation.
- Simulated dropper chain designed purely for study and forensic reconstruction.

---

## 8. MITRE ATT&CK

### 8.1 Initial Access

| MITRE ID      | Technique            | Evidence                                                    |
| ------------- | -------------------- | ----------------------------------------------------------- |
| **T1566.001** | Phishing: Attachment | User accessed malicious ZIP attachment (`$MFT`, Shellbags). |

### 8.2 Execution

|MITRE ID|Technique|Evidence|
|---|---|---|
|**T1204.002**|User Execution: Malicious File|UserAssist confirmed execution of `Invoice.pdf.lnk`.|
|**T1059.001**|PowerShell|Prefetch + LNK metadata confirmed PowerShell execution.|

### 8.3 Persistence

|MITRE ID|Technique|Evidence|
|---|---|---|
|**T1053.005**|Scheduled Task|`WindowsUpdateMonitor` task file + TaskCache registry keys.|

### 8.4 Defense Evasion

|MITRE ID|Technique|Evidence|
|---|---|---|
|**T1036.005**|Masquerading: Match Legitimate Name/Location|`%APPDATA%\WinUpdate`, fake PDF LNK.|
|**T1059.001**|ExecutionPolicy Bypass|LNK metadata shows `-ExecutionPolicy Bypass`.|

### 8.5 Command and Control

|MITRE ID|Technique|Evidence|
|---|---|---|
|**T1071.001**|Web Protocols|Stage-2 script uses `Invoke-WebRequest`.|

---

## 9. Components Used

### 9.1 Invoice_2025 Contents
**invoice.pdf.lnk**

Target:
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "%USERPROFILE%\Downloads\Invoice_2025\Documents\invoice_data.dat.ps1"
```
invoice_data.dat.ps1
```
# Log execution
$log = "$env:USERPROFILE\Downloads\Invoice_2025\loader_log.txt"
Add-Content $log ("[{0}] loader.ps1 executed on {1}" -f (Get-Date), $env:COMPUTERNAME)

# Create working directory
$work = "$env:APPDATA\WinUpdate"
if (!(Test-Path $work)) { New-Item -ItemType Directory -Path $work | Out-Null }

$stage2 = "$work\stage2.ps1"
@'
# ==============================
# Stage 2 Beacon Simulator (Safe)
# ==============================

$log = "$env:USERPROFILE\Downloads\Invoice_2025\stage2_log.txt"
Add-Content $log ("[{0}] Stage 2 activated" -f (Get-Date))

# C2 callback
try {
    Invoke-WebRequest -Uri "http://127.0.0.1/ping" -TimeoutSec 2 -UseBasicParsing
} catch {
    Add-Content $log ("C2 failed at {0}" -f (Get-Date))
}

Start-Sleep -Seconds 10
'@ | Out-File -Encoding ASCII $stage2

# Create persistence

$taskName = "WindowsUpdateMonitor"
$action = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$stage2`""

schtasks /create /sc minute /mo 30 /tn $taskName /tr $action /f | Out-Null

# Execute Stage 2

powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File $stage2
```

---

## 10. Conclusion

This controlled simulation demonstrates how a relatively simple PowerShell-based loader chain can leave a **rich, multi-surface forensic footprint** across Filesystem, Registry, Application, and User artefacts.
  
---
