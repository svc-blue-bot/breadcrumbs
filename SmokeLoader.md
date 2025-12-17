
# SmokeLoader Style Loader Analysis

## Dofoil tagged sample deep dive (Static + Behavioral + Memory)

> Sample: `35bf9dfd223e02da2ee3d57ec493156787a3c2cecb8b655a583985a2f14cc6e3`  
> Lab: FLARE VM on VMware, fully isolated  
> Goal: show how a native loader behaves, how it hides intent, and how to extract defensible IOCs plus memory level indicators

---

## 0. Quick note on safety and scope

This post is written from a defender’s perspective. Everything happened in a contained lab with snapshots and no internet access. I’m focusing on analysis outcomes and repeatable methodology, not providing anything that helps operationalize malware.

---

## 1. Executive summary

This sample presents as a small native Windows executable associated with SmokeLoader style delivery. The core behavior looks like a loader, not a full-featured infostealer or ransomware. The interesting bit is how quickly it pivots from benign looking execution into memory-centric activity: API resolution, string decryption, and likely staged payload handling.

Even with no live C2 available, the sample still leaks enough signals to reconstruct what it is trying to do: how it resolves APIs, what artifacts it produces on disk, what it keeps purely in memory, and which hosts and URIs it appears to target.

**Key takeaways**

- The dropper stage is designed to keep high value strings and config material out of the static binary
    
- The loader uses runtime decoding and indirect API calls, so you need both static reversing and runtime tracing
    
- Memory inspection is not optional here, it is where the truth lives
    

---

## 2. Lab setup and guardrails

### Environment

- Host: VMware Workstation
    
- Guest: FLARE VM Windows 10 or 11
    
- Networking: isolated, optionally a host-only network for simulated services
    

### Tooling I used

Static triage:

- Detect It Easy (DIE) for packer and compiler hints
    
- PE Bear or CFF Explorer for PE structure sanity checks
    
- capa for capability-style hints
    

Reverse engineering:

- IDA (primary) for control flow and function-level reasoning
    
- x64dbg (secondary) for dynamic tracing and patching checks safely
    
- FLOSS for string decoding (useful when strings are stacked, XORed, or RC4 style)
    
- Ghidra optional for cross-checking decompilation
    

Behavioral and system visibility:

- Procmon for file and registry activity
    
- Process Explorer for trees, handles, and loaded modules
    
- FakeNet-NG or INetSim for controlled network simulation
    
- Wireshark for packet level truth if you simulate networking
    

Memory focus:

- pe-sieve or HollowsHunter to detect process hollowing and in-memory implants
    
- Volatility 3 if you capture RAM
    
- MemProcFS for quick browsing and carving if you captured RAM
    

### Screenshot callouts

Include one screenshot early showing:

- VM isolation settings and snapshot baseline
    
- This builds trust with DFIR readers immediately
    

---

## 3. Sample metadata and first impressions

### Hashes

- SHA256: `35bf...cc6e3`
    
- Add MD5 and SHA1 if you want, but SHA256 is usually enough for blogs
    

### File characteristics

- Architecture: [x86 or x64]
    
- Compilation timestamp: [if present, note if it looks plausible or obviously spoofed]
    
- Entropy: [high entropy can hint packing or encrypted blobs]
    

### Triage notes

What I usually write here:

- Does it look packed
    
- Is it .NET or native
    
- Does it have an overlay
    
- Does the import table look “thin” in a loader-like way
    

**Screenshot callout**

- DIE output showing architecture and packer hints
    
- PE header view showing suspicious traits, like very few imports or weird sections
    

---

## 4. Static analysis deep dive

This section is where you make DFIR folks happy by turning reversing into explanations they can operationalize.

### 4.1 PE structure and sections

Explain what you see:

- Odd section names
    
- High entropy sections
    
- Executable and writable sections
    
- TLS callbacks if any
    
- Export table if any, and why it matters for sideload style behavior
    

What to extract:

- Section hashes
    
- Any embedded blobs and their offsets
    
- Any resource section content
    

**Screenshot callout**

- IDA segments view or PE Bear section table with entropy
    

---

### 4.2 Imports and API strategy

Loaders often avoid a rich import table. Instead, they:

- resolve APIs dynamically
    
- hash API names
    
- walk the PEB for loaded modules
    
- call syscalls indirectly
    

Write this in plain language:

- “This binary imports very little, then resolves the rest at runtime”
    
- “That’s why static strings and imports do not tell the full story”
    

**Operational tie-in**  
Mention what defenders can hunt:

- GetProcAddress and LoadLibrary patterns
    
- PEB walking patterns
    
- API hashing routines
    

**Screenshot callout**

- Imports table with the “thin” footprint
    
- IDA pseudocode snippet of the resolver function
    

---

### 4.3 String encryption and configuration material

This is a signature move for loader families.

What to look for:

- loops that build strings byte-by-byte
    
- XOR with a repeating key
    
- RC4-like KSA and PRGA looking patterns
    
- Base64 blocks, though less common in native loaders
    

What to do:

- find the decode routine
    
- identify call sites
    
- dump decoded output at runtime
    

**High value blog content**  
Show your “string recovery workflow”:

- static attempt using FLOSS
    
- confirm by breakpointing the decode routine
    
- dump decoded buffers from memory
    

**Screenshot callout**

- IDA view of the decode function
    
- A small screenshot of decoded strings that are clearly meaningful, like module names, user agent strings, URLs, mutex names, registry paths
    

---

## 5. Dynamic analysis with intent

This section should read like you are driving the binary, not being driven by it.

### 5.1 Execution plan

Before executing:

- snapshot
    
- start Procmon capture with filters
    
- start FakeNet-NG if you want network simulation
    
- have Process Explorer open for the process tree
    

Explain the rationale:

- Procmon gives ground truth of file and registry access
    
- FakeNet gives controlled responses so you can observe “what it wanted to do”
    
- Process Explorer helps spot child processes, injections, suspicious handles
    

### 5.2 First run observations

Write it narratively:

- “On execution, the process quickly spawns [child]”
    
- “It touches registry keys related to [persistence or environment]”
    
- “It attempts outbound traffic to [domain or IP]”
    

Even without internet, you can still document:

- DNS queries
    
- connection attempts
    
- constructed HTTP requests
    

**Screenshot callout**

- Procmon filtered view showing the first interesting file or registry actions
    
- FakeNet showing attempted domains and URIs
    
- Process tree in Process Explorer
    

---

## 6. Unpacking or staged payload handling

This is where SmokeLoader style samples often get interesting.

Common patterns to check:

- process hollowing, like CreateProcess suspended then WriteProcessMemory then ResumeThread
    
- reflective loading patterns
    
- RWX memory allocations, VirtualAlloc then memcpy then execute
    
- shellcode execution via CreateThread or NtCreateThreadEx
    

Tools that help:

- pe-sieve or HollowsHunter to flag hollowing or replaced images
    
- x64dbg to break on VirtualAlloc, WriteProcessMemory, CreateRemoteThread
    
- API Monitor if you want call-level visibility, but be careful with noise
    

**Screenshot callout**

- pe-sieve results showing a suspicious region
    
- x64dbg showing the moment a buffer becomes executable
    

---

## 7. Memory analysis and carving

This is the part DFIR people love, because it bridges reversing and incident response.

### 7.1 What I expect to find in RAM

Explain what should exist in memory for a loader:

- decoded strings and config values
    
- C2 endpoints and URI patterns
    
- decrypted payload bytes, sometimes as a PE image, sometimes as shellcode
    
- injected regions in a child process
    
- network buffers and HTTP headers
    

### 7.2 If you capture RAM

State how you captured it in the lab, for example RamCapturer.

Then do a clean workflow:

Volatility 3:

- process list and tree
    
- command line
    
- network sockets
    
- malfind and VAD review
    
- dump suspicious regions and carve strings
    

MemProcFS:

- quick browse the process memory space
    
- search for recovered strings and endpoint patterns
    
- dump relevant regions for offline RE
    

**Screenshot callout**

- Volatility netscan showing process to remote mapping
    
- Volatility malfind output for the process of interest
    
- strings output showing the recovered C2 or markers
    

---

## 8. IOC extraction and defensive takeaways

Keep this tight and defensible.

### Network IOCs

- Domains
    
- IPs
    
- Ports
    
- URI paths
    
- User-Agent if you recover it
    

### Host IOCs

- Dropped files and paths
    
- Mutex names
    
- Registry keys accessed or created
    
- Scheduled tasks or services if present
    
- Module names resolved dynamically
    

### Behavioral detections

Write this in a defender-friendly way:

- What Sysmon events would catch this
    
- What EDR telemetry would show
    
- What common detection pitfalls exist, like “thin imports means little to no static signal”
    

**Screenshot callout**

- IOC tables
    
- One short section of “high confidence signals” and “needs corroboration”
    

---

## 9. MITRE ATT&CK mapping

Do conservative mapping only. If you did not observe it, say so.

Example mapping style:

- Execution: Native binary, possible process injection
    
- Defense evasion: string encryption, indirect API resolution
    
- Command and Control: HTTP based, DNS lookups, connection attempts
    
- Persistence: only if you actually saw it
    

---

## 10. Conclusion

Wrap it up like this:

- what the sample is most consistent with
    
- what analysis techniques mattered most
    
- what you would do next if you had more time, like deeper config extraction, full stage recovery, cluster by infrastructure, YARA rule drafting
