# ClickFix-Style Attack: Artefacts Left Behind (Experiment 1)

## Goal
Identify what Windows artefacts remain after running a “click-fix” style payload in a controlled environment.

## Method
- Windows 10 VM
- Logging: (Event Logs, PowerShell, SRUM)
- Action: User executes fake “update” EXE
- Artefact collection: KAPE + manual triage

## Ground Truth Timeline
- 14:02: File downloaded
- 14:03: User executed EXE
- 14:03: Dropper wrote file X
- 14:04: Reg key added
- 14:05: Shell launched payload

## Observed Artefacts
### File System
- MFT entry for clickfix.exe → created at 14:02
- USN entries for new DLL → 14:03

### Registry
- Run key added → HKCU\Software\Microsoft\Windows\CurrentVersion\Run

### Execution
- Prefetch entry: CLICKFIX.EXE-xxxxx.pf
- Amcache entry with SHA-1
- SRUM process execution record

### Network
- DNS cache entry  
- 5156/5158 Firewall logs if enabled

## Notes on Reliability
- Prefetch confirmed  
- Shimcache unreliable due to delayed writes  
- SRUM has ~1–3 minutes delay  
- Event Logs incomplete when logging is default  

## Next Steps
- Test persistence-only variant  
- Compare artefacts after reboot  

