---
layout: default
title: Simulated Emotet-Style Infection Chain (2025)
---

# Simulated Emotet-Style Infection Chain (2025)
*A safe, offline reconstruction of a modern Emotet-inspired attack chain.*

---

## 1. Overview

This investigation recreates a modern Emotet-style delivery chain:

1. Phishing email (`.eml`)
2. ZIP archive containing a disguised LNK dropper
3. LNK executes PowerShell Loader (Stage 1)
4. Loader drops Stage 2 payload
5. Loader establishes persistence via Scheduled Task
6. Stage 2 simulates C2 activity (to `127.0.0.1`)
7. Artefacts collected & analyzed

The goal is to document all artefacts left behind and examine how a modern loader behaves on a Windows system.

---

## 2. Delivery: Phishing Email

**Attachment:** `Invoice_2025.zip`  
**Payloads:**  
- `Invoice.pdf.lnk`  
- `loader.ps1`

The ZIP archive mimics post-macro Emotet campaigns which shifted to LNK-based loaders in response to Microsoft’s macro restrictions (2022).

### Artefacts
- `.eml` file metadata
- Attachment extraction temp paths
- RecentFiles / Jump Lists
- Shellbags

---

## 3. Execution: LNK Dropper

The user executes `Invoice.pdf.lnk`, which:

- Masquerades as a PDF document
- Executes embedded command:
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "%USERPROFILE%\Downloads\Invoice_2025\loader.ps1"


### Artefacts
- UserAssist entries
- LNK metadata (target path, timestamps)
- MUI Cache
- Prefetch entry for `POWERSHELL.EXE`

---

## 4. Loader (Stage 1)

`loader.ps1` performs:

- Logging its execution  
- Creating `WinUpdate` directory  
- Dropping Stage 2  
- Establishing Scheduled Task persistence  
- Executing Stage 2

### Dropped file:
`%APPDATA%\WinUpdate\stage2.ps1`

### Artefacts
- `$MFT` + `$UsnJrnl` timestamps
- Scheduled Task files
- PowerShell ScriptBlock logs
- AppCompatCache / Amcache entries

---

## 5. Stage 2: Fake C2 Beacon

Stage 2 simulates remote command-and-control:
Invoke-WebRequest http://127.0.0.1/ping


Generates reliable DFIR artefacts without any real network calls.

### Artefacts
- PowerShell network attempts
- SRUM DB entries
- stage2_log.txt

---

## 6. Persistence

A Scheduled Task named **WindowsUpdateMonitor** runs Stage 2 every 30 minutes.

### Location
- `C:\Windows\System32\Tasks\WindowsUpdateMonitor`

### Registry keys
- TaskCache entries under  
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`

---

## 7. DFIR Artefact Summary

### ✔ File System
- ZIP extraction paths  
- LNK execution  
- loader/stage2 creation  
- Working directory (`WinUpdate`)  

### ✔ Registry
- TaskCache  
- UserAssist  
- MUICache  
- RecentApps  

### ✔ PowerShell
- ScriptBlock logs  
- Operational logs  
- 4688 process creation events  

### ✔ Network
- Localhost callbacks (`127.0.0.1`)  
- SRUM entries  

### ✔ Email
- `.eml` metadata  
- Attachment temp extraction  

---

## 8. Detection Opportunities

### Sigma-style rules (pseudo):
```yaml
detection:
  selection:
    EventID: 4688
    Image: powershell.exe
    CommandLine|contains:
      - "ExecutionPolicy Bypass"
      - "WinUpdate"
      - "stage2.ps1"

Behaviour-based:
LNK launching PowerShell
PowerShell writing new PS files
Unexpected scheduled tasks
PowerShell to localhost
```
9. Conclusion
This simulation accurately reproduces the artefacts and behaviours of a modern post-macro Emotet-style loader, while remaining fully safe and offline. The chain produces a wide artefact footprint across filesystem, registry, PowerShell, scheduled tasks, and user activity.

