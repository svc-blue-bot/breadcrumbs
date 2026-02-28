# Simulated PowerShell Beacon (Runtime Memory Analysis)

---

# 1. Summary

This lab demonstrates how a PowerShell script executing in memory after being launched from disk can generate forensic artefacts that are recoverable through memory acquisition and analysis.

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
- Script and configuration artefacts recoverable from process memory

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
|VM Platform|VMware Workstation|

---

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

## 2.4 Analytic Scope

This lab represents controlled script execution in a user context.

It does not simulate:
- Code injection
- Reflective loading
- Memory-only payload staging
- Persistence mechanisms
- Anti-forensic techniques

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

---

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

*Command-line artefacts are often more reliable indicators of execution intent than memory structure alone. Even in the absence of network artefacts or persistence, command-line reconstruction can clearly demonstrate how a script was invoked.*

---

## 4.3 Process Tree

**Command:** `vol -f memdump.raw windows.pstree`

**Evidence:**
<img width="2504" height="103" alt="image" src="https://github.com/user-attachments/assets/f27c9ba4-3085-4566-b065-1ed920f9973a" />

- explorer.exe
- powershell.exe  
- notepad.exe

**Interpretation:**
Confirms child process was launched by PowerShell, that was launched by explorer, which strongly suggests execution within a user session context.

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

---

## 4.5 Unmanaged Memory Allocation (Structural Observation)

**Command:** `vol -f memdump.raw windows.vadinfo --pid=PID`

**Evidence:**
<img width="1378" height="310" alt="image" src="https://github.com/user-attachments/assets/12791f0c-92e4-4085-9158-adac39dc7b46" />

- Multiple private `PAGE_READWRITE` memory regions present
- No file-backed mapping associated with these regions

**Interpretation:**
Private read/write regions are consistent with normal heap allocations within a running process.

In this lab, unmanaged memory was allocated using `Marshal.AllocHGlobal`. However, such allocations are indistinguishable from standard heap memory without direct content validation. 

---

## 4.6 Script and Configuration Artefacts in Memory

**Method:** Process memory was dumped and inspected using string analysis.

**Commands:**
- `vol -f memdump.raw windows.memmap --pid --dump`
- `strings powershell.dump`

**Evidence:**

<img width="677" height="803" alt="image" src="https://github.com/user-attachments/assets/96f3deb9-407d-4152-b467-03e7dd3f32b0" />


**Interpretation:**
Although the configuration was XOR-encoded and copied into unmanaged memory, the original `$config` string variable was never removed, overwritten, or zeroed. As a result the plaintext configuration remains present in managed memory, the script content remains resident in process memory during execution, and encoding created an additional transformed copy but did not eliminate the original artefact.

---

# 5. Conclusion & Analytical Observations

This lab demonstrates how standard PowerShell execution produces recoverable volatile artefacts within process memory. Through memory acquisition and analysis, process hierarchy, command-line invocation, and runtime behaviour were reconstructed while the system remained active.

Several expected findings provided important forensic learning points:

- Encoding did not remove plaintext artefacts.
- Although the configuration was XOR-encoded and copied into unmanaged memory, the original $config string was never overwritten or zeroed. As a result, the plaintext configuration remained visible in process memory.

*Data transformation alone does not eliminate artefacts unless the original data is explicitly destroyed.*

- TCP artefacts were timing-dependent.
- No socket entries for 127.0.0.1:4444 were observed at acquisition time. Given that connections failed immediately and the script slept between attempts, the TCP objects likely existed only briefly.

*Volatile network artefacts may not persist long enough to be captured.*

- Unmanaged allocations were not inherently distinguishable.
- Private PAGE_READWRITE regions were consistent with normal heap behaviour. Without direct content validation, structural VAD analysis alone does not indicate malicious activity.

*Context and behavioural correlation are essential.*

The findings illustrate how memory evidence must be interpreted carefully, with attention to timing, execution context, and implementation details.
