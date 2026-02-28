# Simulated In-Memory PowerShell Beacon

---
# 1. Summary

This lab demonstrates how a memory-resident PowerShell script can generate forensic artefacts that are recoverable through memory acquisition and analysis.

**The simulation:**
- Creates an encoded configuration in memory
- Allocates unmanaged memory
- Spawns a legitimate Windows process (notepad.exe)
- Attempts repeated local network connections
- Remains active to allow live memory capture

No external communication occurs and all activity remains inside an isolated virtual machine.

After execution, a full physical memory image is captured and analyzed using memory forensic tools to identify:
- Process artefacts
- Heap allocations
- Network socket objects
- Parent/child relationships
- Encoded configuration remnants in memory

---

# 2. Scope & Environment

## 2.1 Environment

**Guest VM (Victim System):** Windows 10 x64

**Analysis VM:** Custom FlareVM

**Hypervisor:** VMware Workstation

**Network:** Host-only (no internet connectivity)

**Execution Flow:**
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
|Strings Analysis|strings|
|Hashing|sha256sum|
|VM Platform|VMware Workstation|

## 2.3 Script Used

```
Write-Host "Starting pulse"

# Beacon Config
$config = @"
C2_SERVER=127.0.0.1
C2_PORT=4444
INTERVAL=5
NOTE=TRAINING_ARTEFACT_ONLY
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
Write-Host "Spawned notepad.exe PID: $($notepad.Id)"

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

# 3. Simulation Overview

This lab simulates a memory-resident beacon-style script:

### Stage 1 Configuration Handling
- A fake configuration string is created.
- The string is converted to bytes.
- A static XOR key (0xAA) encodes the configuration.
- The encoded byte array is copied into unmanaged memory.

### Stage 2 Process Activity
- notepad.exe is spawned.
- Parent-child process relationship established.

### Stage 3 Network Behaviour
- A loop repeatedly attempts connection to:
    - 127.0.0.1:4444
- If no listener is present, connection fails gracefully.
- Loop continues every 5 seconds.

### Stage 4 Persistence in Memory Only
- No registry keys created.
- No scheduled tasks created.
- No files written to disk.
- Artefacts remain purely volatile.

---

# 4. Memory Forensic Findings

## 4.1 Process Enumeration

Command: `vol -f memdump.raw windows.pslist`

**Evidence:**
<img width="1280" height="84" alt="image" src="https://github.com/user-attachments/assets/ee311633-9c2e-4b32-957b-ca0c099561bf" />

- powershell.exe present
- notepad.exe present
- Parent-child relationship visible (PID/PPID)

**Interpretation:**
Confirms script execution and spawned process behaviour.

## 4.2 Process Command Line

**Command:** `vol -f memdump.raw windows.cmdline`

**Evidence:**
<img width="1912" height="64" alt="image" src="https://github.com/user-attachments/assets/2a6d6a37-43ac-4e42-af94-3656447fea9f" />

**Identified Command-line:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\Lab\Desktop\beacon.ps1'"`

**Interpretation:**
The command-line arguments confirm that:
- PowerShell was launched using the -Command parameter.
- Execution policy was conditionally bypassed at the process scope.
- The script beacon.ps1 located on the user’s desktop was executed directly.
- This artefact provides strong evidence of script execution and execution context.

Command-line artefacts are often more reliable indicators of execution intent than memory structure alone. Even in the absence of network artefacts or persistence, command-line reconstruction can clearly demonstrate how a script was invoked.

---

## 4.3 Process Tree

**Command:** `vol -f memdump.raw windows.pstree`

**Evidence:**
<img width="2504" height="103" alt="image" src="https://github.com/user-attachments/assets/f27c9ba4-3085-4566-b065-1ed920f9973a" />

- explorer.exe
- powershell.exe  
- notepad.exe

**Interpretation:**
Confirms child process was launched by PowerShell, that was launched by explorer, which strongly suggest user interaction.

---

## 4.4 Network Artefacts

**Command:** `vol -f memdump.raw windows.netscan`

**Evidence:**
<img width="1285" height="742" alt="image" src="https://github.com/user-attachments/assets/cfea2cb4-edac-47fa-8bc8-30422ce826b4" />
<img width="982" height="335" alt="image" src="https://github.com/user-attachments/assets/c955e458-56e1-4911-a41b-53563c1f5a28" />

- No TCP entries referencing 127.0.0.1:4444 were observed.
- No active or recently closed sockets attributable to powershell.exe were identified at time of capture.

**Interpretation:**
The PowerShell script attempts a connection every 5 seconds. When no listener is present on port 4444, Windows immediately rejects the connection attempt. The TcpClient object is then closed almost instantly. As a result the TCP socket exists only for a very short duration, meaning the connection object may be destroyed before memory acquisition occurs, or if the memory capture happened during the script’s sleep interval, no active socket object would be present in memory.

This demonstrates an important DFIR principle, volatile artefacts are timing-dependent. Their absence in memory does not necessarily negate execution.

---

## 4.5 Unmanaged Memory Allocation (Structural Observation)

**Command:** `vol -f memdump.raw windows.vadinfo --pid=PID`

**Evidence:**
<img width="1378" height="310" alt="image" src="https://github.com/user-attachments/assets/12791f0c-92e4-4085-9158-adac39dc7b46" />

- Multiple private `PAGE_READWRITE` memory regions present
- No file-backed mapping associated with these regions

**Interpretation:**
Private read/write regions are consistent with normal heap allocations within a running process.

In this lab, unmanaged memory was allocated using `Marshal.AllocHGlobal`. However, such allocations are indistinguishable from standard heap memory without direct content validation, which highlights an important analytical limitation. Structural VAD analysis alone does not prove malicious behaviour: context is necesary.  

---

## 4.6 Script and Configuration Artefacts in Memory

**Method:** Process memory was dumped and inspected using string analysis.

**Commands:**
- `vol -f memdump.raw windows.memmap --pid --dump`
- `strings powershell.dump`

**Evidence:**

<img width="648" height="665" alt="image" src="https://github.com/user-attachments/assets/0f90c7bc-cafc-451b-bb34-1ae56db8ede8" />


**Interpretation:**
Although the configuration was XOR-encoded and copied into unmanaged memory, the original `$config` string variable was never removed, overwritten, or zeroed. As a result the plaintext configuration remains present in managed memory, content remains resident in process memory during execution, and encoding created an additional transformed copy but did not eliminate the original artefact.

    
This demonstrates an important forensic principle, encoding data in memory does not remove original artefacts unless the plaintext is explicitly destroyed.

The visibility of the configuration is consistent with normal PowerShell execution behaviour rather than the stealthy in-memory staging you'd typically see in the wild.

---

# 5. Conclusion

This lab demonstrates how even a simple PowerShell script can generate rich volatile artefacts observable through memory forensics. Unlike disk-based simulations, this highlights the importance of volatile evidence in incident response. It reinforces that even without persistence mechanisms or file-based payloads, memory analysis alone can reconstruct execution behaviour and intent.
