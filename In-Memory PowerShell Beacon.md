# Simulated In-Memory PowerShell Beacon Artifact Lab

---
# 1. Executive Summary (Non-technical)

This project demonstrates how a memory-resident PowerShell script can generate forensic artefacts that are recoverable through memory acquisition and analysis.

Unlike traditional malware simulations that rely heavily on disk artefacts and registry persistence, this lab focuses on volatile artefacts that exist only while a process is running.

The simulation:
- Creates an encoded configuration in memory
- Allocates unmanaged memory
- Spawns a legitimate Windows process (notepad.exe)
- Attempts repeated local network connections
- Remains active to allow live memory capture

No external communication occurs.  
All activity remains inside an isolated virtual machine.

After execution, a full physical memory image is captured and analyzed using industry-standard memory forensic tools to identify:

- Process artefacts
- Heap allocations
- Network socket objects
- Parent/child relationships
- Encoded configuration remnants in memory

This lab demonstrates how volatile evidence can be reconstructed even when no traditional malware is written to disk.

---

# 2. Scope & Environment

## 2.1 Environment

Host: Windows system running VMware
Guest VM (Victim System): Windows 10 x64
Analysis VM: Ubuntu Linux
Hypervisor: VMware Workstation
Network: Host-only (no internet connectivity)
Execution Flow:
- PowerShell artefact script executed inside VM
- Script left running
- Full physical memory captured
- Memory image transferred to analysis system
- Volatile artefacts reconstructed using forensic tools

---

## 2.2 Tools Used

|Category|Tools|
|---|---|
|Memory Acquisition|WinPmem|
|Memory Analysis|Volatility 3|
|Strings Analysis|strings (Linux utility)|
|Hashing|sha256sum|
|VM Platform|VMware Workstation|

---

# 3. Simulation Overview

This lab simulates a memory-resident beacon-style script:

### Stage 1 – Configuration Handling

- A fake configuration string is created.
- The string is converted to bytes.
- A static XOR key (0xAA) encodes the configuration.
- The encoded byte array is copied into unmanaged memory.
### Stage 2 – Process Activity

- notepad.exe is spawned.
- Parent-child process relationship established.

### Stage 3 – Network Behaviour

- A loop repeatedly attempts connection to:
    - 127.0.0.1:4444
- If no listener is present, connection fails gracefully.
- Loop continues every 5 seconds.

### Stage 4 – Persistence in Memory Only

- No registry keys created.
- No scheduled tasks created.
- No files written to disk.
- Artefacts remain purely volatile.

---

# 4. Timeline of Events (UTC Example)

10:14:22 – PowerShell script executed manually.
10:14:23 – Configuration converted to byte array.
10:14:23 – XOR encoding loop completed.
10:14:23 – Unmanaged memory allocated and populated.
10:14:24 – notepad.exe spawned as child process.
10:14:25 – First TCP connection attempt to 127.0.0.1:4444.
10:14:30 – Second TCP attempt.
10:15:00 – Memory acquisition initiated.
10:17:40 – Memory image saved as memdump.raw.

---

# 5. Memory Forensic Findings

## 5.1 Process Enumeration

Command:
vol -f memdump.raw windows.pslist
Evidence:
- powershell.exe present
- notepad.exe present
- Parent-child relationship visible

Interpretation:
Confirms script execution and spawned process behaviour.

---

## 5.2 Process Tree

vol -f memdump.raw windows.pstree

Evidence:
powershell.exe  
└── notepad.exe

Interpretation:
Confirms child process was launched by PowerShell.

---

## 5.3 Network Artefacts

vol -f memdump.raw windows.netscan

Evidence:
- TCP entries referencing 127.0.0.1:4444
- State likely SYN_SENT or CLOSED

Interpretation:
Confirms repeated connection attempts from the running process.

---

## 5.4 Encoded Configuration in Memory

Strings search:
strings memdump.raw | grep C2_SERVER

If only encoded copy exists:
- Plaintext may not appear.

If decoded anywhere:
- Plaintext visible in memory.

To recover encoded blob:
- Dump powershell.exe memory region.
- Extract raw bytes.
- XOR with 0xAA to reconstruct original config.

Interpretation:
Demonstrates recovery of staged configuration from memory.

---

## 5.5 Unmanaged Memory Allocation

Command:
vol -f memdump.raw windows.vadinfo --pid powershell PID

Evidence
- Private memory regions
- PAGE_READWRITE protection
- Size matching encoded buffer

Interpretation:
Indicates unmanaged memory allocation via Marshal.AllocHGlobal.

---

## 5.6 No Disk Artefacts

Verification:
- No new files in filesystem
- No scheduled tasks
- No registry modifications

Interpretation:
All behaviour is volatile.

---

# 6. Indicators of Compromise (Simulation Only)

## 6.1 Memory Indicators

|Indicator|Description|
|---|---|
|Encoded blob|XOR-encoded config bytes|
|Powershell PID|Long-running process|
|notepad.exe child|Spawned from PowerShell|
|TCP 127.0.0.1:4444|Repeated connection attempts|
|Unmanaged allocation|Private heap region|

---

## 6.2 Network Indicators (Loopback Only)

|Type|Value|
|---|---|
|IP|127.0.0.1|
|Port|4444|
|Protocol|TCP|

No external C2.

---

# 7. TTP Simulation

## 7.1 Execution

- Manual script execution via PowerShell console.
## 7.2 In-Memory Configuration Staging

- Encoded config stored in heap.
- XOR obfuscation used.

## 7.3 Process Creation

- notepad.exe spawned via Start-Process.

## 7.4 Command-and-Control Simulation

- Repeated TCP connect attempts.
- Loopback only.

## 7.5 Persistence

- None (intentionally omitted).

---

# 8. MITRE ATT&CK Mapping (Simulation Context)

|MITRE ID|Technique|Evidence|
|---|---|---|
|T1059.001|PowerShell|Script execution|
|T1027|Obfuscated/Encrypted Config|XOR encoding|
|T1055 (conceptual)|Process Creation|notepad child|
|T1071|Application Layer Protocol|TCP connect attempts|

Note: No real injection performed.

---

# 9. Script Used

```
Write-Host "Starting pulse"

# Beacon Config
$config = @"
C2_SERVER=127.0.0.1
C2_PORT=4444
INTERVAL=5
NOTE=TRAINING_ARTIFACT_ONLY
"@

#XOR Key
$key = 0xAA

#Convert to bytes
$bytes = [System.Text.Encoding]::UTF8.GetBytes($config)

# XOR encode
for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = $bytes[$i] -bxor $key
}

Write-Host "Pulse hidden"

# Allocate unmanaged memory
$size = $bytes.Length
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $size)

Write-Host "Hidden pulse stored at $ptr"

# Spawn notepad 
$notepad = Start-Process notepad.exe -PassThru
Write-Host "[*] Spawned notepad.exe PID: $($notepad.Id)"

# Pulse connect loop
$interval = 5

while ($true) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect("127.0.0.1", 4444)
        Write-Host "Pulse connect"
        $client.Close()
    }
    catch {
        Write-Host "No reciever"
    }

    Start-Sleep -Seconds $interval
}
```

---

# 10. Conclusion

This lab demonstrates how even a simple PowerShell script can generate rich volatile artefacts observable through memory forensics.

Key learning outcomes:
- Difference between managed and unmanaged memory
- Identification of process relationships
- Recovery of encoded configuration from memory
- Correlation of socket artefacts with running processes
- Importance of capturing memory while process is active

Unlike disk-based malware simulations, this exercise highlights the importance of volatile evidence in incident response.

It reinforces that:

Even without persistence mechanisms or file-based payloads, memory analysis alone can reconstruct execution behaviour and intent.
