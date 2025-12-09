---
title: Windows Memory Artifact Reference
layout: default
---

# Windows Memory Artifact Reference


# 1. Raw Physical Memory Dump (RAW)

## What you get

• Full RAM snapshot  
• Complete process tree and threads  
• Loaded DLLs and kernel drivers  
• Injected code, unpacked malware, in memory configs  
• Network sockets and structures  
• Tokens, handles, registry hives and cache structures

## What to be careful about

• Acquisition alters RAM slightly  
• Some tools do not capture device memory  
• Frameworks may lag behind new Windows builds  
• RAW dumps are best supported, crash dumps sometimes less so

## When to use

• High confidence analysis of malware presence  
• Kernel driver investigations  
• Credential theft and in memory C2 investigations

---

## Volatility 3 plugins to run first

### Process enumeration and anomalies

**windows.pslist**  
Shows active processes. Used to establish a baseline and spot unfamiliar executables.

**windows.pstree**  
Shows parent child hierarchy. Used to identify suspicious process chains such as explorer spawning cmd or powershell.

**windows.psscan**  
Scans memory for EPROCESS structures. Used to detect hidden, terminated or unlinked processes.

**windows.psxview**  
Compares multiple enumeration techniques. Used to identify tampering or DKOM hiding.

### DLLs, handles and injection

**windows.dlllist**  
Lists loaded DLLs. Used to spot unsigned, renamed or abnormal library loads.

**windows.handles**  
Shows open handles such as mutexes, files and registry keys. Useful for spotting malware indicators inside process handle tables.

**windows.malfind**  
Detects injected or suspicious executable pages. Primary detection plugin for malware injection and unpacked payloads.

**windows.vadinfo**  
Shows VAD tree entries with permissions. Used to find regions with RX or RWX permissions or large anonymous mappings typical of injected code.

### Network activity

**windows.netstat**  
Shows open network connections. Used to identify active C2 or lateral movement.

**windows.netscan**  
Scans memory for socket structures. Finds sockets that no longer appear in active tables and may expose stealthy connections.

### Kernel insight

**windows.modules**  
Lists kernel modules. Used to detect unsigned or non standard drivers.

**windows.driverscan**  
Scans for DRIVER_OBJECT structures. Used to find hidden or unlinked kernel drivers.

### User context and credentials

**windows.hashdump**  
Extracts NTLM hashes from memory resident SAM. Useful for determining credential exposure.

**windows.lsadump**  
Extracts secrets from LSASS. Used to detect credential theft.

**windows.cachedump**  
Extracts cached domain logons. Helps with offline identity analysis.

### Registry extraction

**windows.registry.hivelist**  
Locates registry hives in memory. Allows analysis of volatile registry content.

**windows.registry.printkey**  
Prints registry keys. Used to recover persistence or configuration entries not written to disk.

**windows.registry.userassist**  
Shows execution artifacts for GUI apps. Useful for linking user activity to processes.

**windows.registry.shimcache**  
Recovers AppCompatCache content from RAM. Helps retrieve presence data even if disk hive was modified.

### General triage

**windows.cmdline**  
Shows command line arguments. Very useful for identifying malicious execution parameters.

**windows.getservicesids**  
Maps services to SIDs. Helps identify suspicious or rogue services.

**windows.mutantscan**  
Finds mutexes. Malware often uses characteristic mutex names.

**windows.verinfo**  
Extracts PE version information. Used to detect mismatches, fake metadata or time forgery.

---

# 2. Windows Crash Dumps

(MEMORY.DMP, kernel.dmp, small dumps, WER process dumps)

## What you get

• Content varies by dump type  
• Kernel dumps contain kernel mode memory and crash context  
• WER dumps capture one crashing user mode process  
• Often includes malware in memory if that process or driver triggered the crash

## What to be careful about

• Coverage depends on dump type  
• Small dumps are limited  
• WER dumps include only one process

## When to use

• Suspected malicious drivers  
• Process specific failures  
• Crashes correlated with attacker behavior

---

## Volatility 3 plugins most effective

### For kernel dumps

**windows.modules**  
Detects loaded kernel drivers.

**windows.modscan**  
Scans for hidden or unlinked kernel modules.

**windows.driverscan**  
Finds DRIVER_OBJECT structures.

**windows.ssdt**  
Displays system call table entries. Used for detecting hooked SSDT entries.

**windows.mutantscan**  
Finds mutexes that may be associated with malware.

### For WER process dumps

**windows.vadinfo**  
Analyzes VADs for suspicious regions.

**windows.malfind**  
Very effective at detecting injected code in a single process dump.

**windows.dlllist**  
Shows modules loaded by the crashing process.

**windows.cmdline**  
Shows execution context leading to the crash.

### Crash oriented plugin

**windows.crashinfo**  
Extracts bugcheck and crash dump metadata.

---

# 3. Hibernation File

(hiberfil.sys)

## What you get

• Compressed RAM snapshot  
• Near full memory contents from hibernation time  
• Application state, keys and secrets  
• Good fallback source if RAM dump is missing

## What to be careful about

• Snapshot may not reflect incident time  
• Must be converted before analysis  
• Format varies between Windows releases

## When to use

• Machine is powered off  
• Evidence of earlier execution required  
• No RAM dump acquired

---

## Volatility 3 plugins to use after conversion

(Same workflow as raw memory)

Run in this order:

1. **windows.pslist**, **windows.pstree**  
    Establish the process baseline.
    
2. **windows.vadinfo**, **windows.malfind**  
    Identify injection and suspicious memory regions.
    
3. **windows.netstat**  
    Find network artifacts active at hibernation.
    
4. **windows.registry.hivelist**, **windows.registry.printkey**  
    Recover volatile registry content.
    
5. **windows.verinfo**, **windows.modscan**  
    Identify modules and hidden drivers.
    

Useful additional correlation:  
• **windows.userassist**  
• **windows.shimcache**  
• **windows.amcache**  
These often capture older state preserved in memory.

---

# 4. Pagefile (pagefile.sys)

## What you get

• Evicted memory pages  
• Strings, commands, URLs, credentials  
• Malware fragments not present in RAM anymore

## What to be careful about

• Not a real memory dump  
• Needs carving or strings analysis  
• Cannot be processed directly by Volatility

## When to use

• Supplemental memory in absence of RAM image  
• Recovering partial or fragmented evidence  
• Document or chat reconstruction

---

## Volatility alignment

Volatility cannot ingest pagefile directly.  
Use:  
• strings  
• bulk_extractor  
• YARA

Then feed carved PE or memory chunks into:  
• **windows.malfind** (to inspect extracted regions)  
• **windows.vadinfo** (for structural clues in reconstructed blocks)

---

# 5. Swapfile (swapfile.sys)

## What you get

• Paging for suspended UWP apps  
• Can hold memory from applications not represented in RAM

## What to be careful about

• Only UWP and certain modern apps populate it  
• Requires carving  
• Not usable as a full dump

## When to use

• Tablet or UWP heavy deployments  
• Malware abusing Windows Store apps

---

## Volatility usage

Same method as pagefile:  
• Carve  
• Extract  
• Feed to static or reconstructive analysis  
• Use malfind and vadinfo on any carved process memory

---

# 6. Volatility Guided Investigation Flow

(What to run, in what order, and why)

### Phase 1. System overview

Plugins  
• windows.info  
• windows.pslist  
• windows.pstree  
• windows.psscan

Objective  
Identify suspicious processes, hidden tasks and anomalies.

### Phase 2. Process inspection

Plugins  
• windows.cmdline  
• windows.dlllist  
• windows.handles  
• windows.vadinfo

Objective  
Identify abnormal DLLs, suspicious handles, RWX memory and odd command lines.

### Phase 3. Code injection and persistence

Plugins  
• windows.malfind  
• windows.apihooks  
• windows.ssdt  
• windows.getservicesids  
• windows.serviceenumeration

Objective  
Detect injected code, API hooking, SSDT tampering and rogue services.

### Phase 4. Credential and identity

Plugins  
• windows.lsadump  
• windows.hashdump  
• windows.cachedump  
• windows.tokenprivs

Objective  
Assess credential exposure, privilege escalation and impersonation.

### Phase 5. Network activity

Plugins  
• windows.netstat  
• windows.netscan

Objective  
Identify C2, backdoors, pivoting and lateral movement.

### Phase 6. Registry and configuration

Plugins  
• windows.registry.hivelist  
• windows.registry.printkey  
• windows.registry.userassist  
• windows.registry.shimcache  
• windows.registry.amcache

Objective  
Recover persistence keys, execution traces and volatile registry data.

### Phase 7. Kernel and driver analysis

Plugins  
• windows.modules  
• windows.modscan  
• windows.driverscan  
• windows.callbacks

Objective  
Find malicious drivers, kernel hooks and stealth rootkits.

