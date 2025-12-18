# SmokeLoader Style Loader Analysis

Sample: `35bf9dfd223e02da2ee3d57ec493156787a3c2cecb8b655a583985a2f14cc6e3`  
Environment: FLARE VM, fully isolated  
Time limit: 3 Hours (excluding this report)
Purpose: This write-up documents a time-boxed static and dynamic triage of a suspected staged malware loader. The goal was not full unpacking or payload recovery, but to rapidly classify behavior, validate execution staging, and assess anti-analysis intent under realistic analyst constraints. Analysis was intentionally stopped once Loader characteristics were confirmed, Dynamic capability expansion was observed, Anti-analysis behavior materially interfered with debugging. Deeper reverse engineering (patching, dumping, or bypassing execution guards) was considered out of scope to reflect real-world prioritization decisions. Conclusions are based on observable behavior, not exhaustive reconstruction.

---

# Part I: Static Analysis 
## 1. Initial triage and intent

Before opening the sample in a debugger or executing it, I wanted to answer three basic questions:

1. Is this a native binary or managed (.NET)?
    
2. Is it packed or obfuscated?
    
3. Does it look like a loader or a full payload?
    

Answering those upfront helps decide whether IDA, dnSpy, or dynamic tooling should be the primary path.

---

## 2. File identification with Detect It Easy (DIE)

Before executing or debugging the sample, I used Detect It Easy (DIE) to establish a few baseline facts that would shape the rest of the analysis:

- Is the binary native or managed?
- What architecture does it target?
- Does it look like a loader or a full payload?
    
Answering these early helps avoid committing to the wrong tooling or analysis path.

### Basic characteristics

<img width="863" height="582" alt="image" src="https://github.com/user-attachments/assets/849804b3-5ad4-4c6b-8aec-457bc167af1d" />


DIE identifies the sample as:
- Type: PE32
- Architecture: 32-bit (x86 / i386)
- Subsystem: GUI
- File size: ~277 KiB
- Image base: `0x00400000`
- Entry point: `0x00401A50`
    
The absence of any .NET metadata confirms this is a native Windows executable, ruling out managed analysis tools and pointing toward standard PE reversing and debugging workflows.

---

### Structural observations

Additional high-level observations:

- Sections: 4
- No overlay data
- No TLS callbacks
- No managed (.NET) components
    
The small, unremarkable section layout is consistent with compact loader binaries and does not resemble a full-featured application.

---

### Interim conclusion

From DIE alone, the sample can be confidently described as:

- A native 32-bit Windows executable 
- Likely a loader or staging component, not a complete payload
- Structurally minimal, with no immediate signs of embedded functionality
    
At this stage, DIE establishes constraints but not behavior. The next question is whether the executable contains meaningful code or deferred, packed content.

---

## 3. Section layout and entropy analysis

With the file identified as a native x86 executable, the next question was whether the code inside it was directly analyzable or staged for runtime unpacking. To answer that, I examined the section layout and entropy distribution.

---

### Entropy distribution

Entropy analysis reveals a clear split between regions:

- PE header entropy: ~2.4
- `.text` section entropy: ~6.95
    
Low entropy in the PE headers is expected, as they consist of structured metadata. The `.text` section, however, shows entropy approaching the upper bound typically seen in executables.

For context:
- Normal compiled x86 code usually falls in the 5.0–6.2 range
- Values near 7.0 indicate near-random data, commonly associated with compressed or encrypted content
    
Despite the tool heuristically labeling the file as “not packed,” the entropy profile tells a different story. High entropy concentrated almost entirely in `.text` is not consistent with plain compiler output.

---

### Interpretation

This pattern strongly suggests that:
- The `.text` section does not primarily contain readable machine code
- The executable includes a small loader stub
- The real logic is encrypted or compressed and reconstructed at runtime
    
Importantly, this also implies that static disassembly of `.text` is unlikely to be productive at this stage.

---

### Interim conclusion

Based on entropy alone, the sample appears to be:
- A staged loader, not a fully unpacked payload
- Designed to transform itself in memory before meaningful execution
- Intentionally resistant to static analysis
    
This confirms that static analysis should focus on capabilities and constraints, not instruction-level reversing.

---

## 4. Import table analysis

With entropy indicating staged content, the next step was to examine the import table to understand what the executable is capable of doing before any unpacking occurs. For loader-style malware, static imports define the hard limits of early execution behavior.

<img width="1987" height="1055" alt="image" src="https://github.com/user-attachments/assets/406e47ab-ff81-4119-8809-1abab37f65b2" />
<img width="1986" height="358" alt="image" src="https://github.com/user-attachments/assets/ec683db3-e1d9-4bd6-b6ee-c4f52e17ffb7" />

### Imported libraries

The sample statically imports the following DLLs:
- `KERNEL32.dll`
- `ADVAPI32.dll`
- `OLE32.dll`
- `GDIPLUS.dll`
- `WINHTTP.dll`
    
This is broader than a minimal stub and immediately rules out the idea that all functionality is resolved dynamically. In particular, the presence of WINHTTP suggests built-in networking capability, even before any runtime resolution occurs.

---

### Core functionality exposed

A review of imported functions shows several clear capability groups.

Memory allocation and execution control

- `VirtualAlloc`, `VirtualFree`
- `HeapAlloc`, `HeapCreate`, `HeapFree`
- `InterlockedIncrement`, `InterlockedDecrement`

These APIs are sufficient to implement a full in-memory unpacking routine and safely transition memory from writable to executable.

Process and environment awareness

- `GetCurrentProcessId`
- `GetModuleFileNameA/W`
- `GetStartupInfoA`
- `IsDebuggerPresent`
- `QueryPerformanceCounter`
    
This indicates awareness of execution context and timing, which is commonly used for environment checks (anti-analysis) or unpacking flow control.

Exception and control-flow handling

- `SetUnhandledExceptionFilter`
- `RtlUnwind`
    
These APIs are often used in loader stubs that rely on structured exception handling to redirect execution or obscure control flow.

File and console interaction

- `CreateFileA`, `ReadFile`, `WriteFile`
- `GetStdHandle`, `WriteConsoleA`, `AllocConsole`
    
Console-related imports are frequently leftover from development or debugging and do not necessarily indicate user-visible output.

---

### Networking capability

The static import of WINHTTP.dll is notable. Unlike loaders that defer all networking to later stages, this binary exposes HTTP capability directly. This suggests that:
- Network communication may occur early, or
- The loader is self-sufficient enough to retrieve additional stages without resolving APIs dynamically
    
At this stage, intent cannot be confirmed, but the capability is clearly present.

---

### What is notably absent

Despite the broad import set, several things are missing:
- No explicit process injection APIs
- No service control APIs
- No persistence-related registry functions
- No low-level NTDLL imports
    
This suggests that while the loader is capable, it is still likely a staging component, not a full payload.

---

### Interim conclusion

The import table reinforces earlier findings:
- The executable is a loader with non-trivial built-in capability
- It can allocate, transform, and execute memory internally
- It has native support for networking via WINHTTP
- It is not yet exhibiting full post-exploitation behavior
    
Static analysis has now reached diminishing returns. The next meaningful insights will only emerge during execution.

---

## 5. Strings and embedded IP context

Given the high entropy observed in the `.text` section, I did not expect extensive or high-quality string artifacts. Loader-style binaries typically minimize static strings, deferring meaningful values until runtime.

A limited strings pass yielded one notable Unicode value:
- String: `17.33.43.61`
- Type: Unicode
- Offset: `0x0003ED30`

<img width="1241" height="15" alt="image" src="https://github.com/user-attachments/assets/40ad3c9f-4651-4404-9d0a-dba6ee9427a4" />

This resembles a valid IPv4 address. While a single string is not evidence of network behavior, its presence is more interesting in this case because the binary statically imports WINHTTP, making network usage plausible even before unpacking.

A reputation check shows that this IP belongs to Apple (AS714, APPLE-ENGINEERING) and falls within the `17.0.0.0/9` range. The address itself is not inherently malicious, but it has appeared embedded in multiple other malware samples.

<img width="701" height="169" alt="image" src="https://github.com/user-attachments/assets/7fb5f888-34cb-4bc5-b0b7-b0870263183b" />

This creates a narrow but meaningful hypothesis: the IP may be used as a connectivity check, a decoy, or a benign-looking endpoint rather than a traditional command-and-control server. At this stage, however, there is no proof that the string is ever referenced or used during execution.

---

# Part II: Dynamic Analysis

## 6. Execution strategy

At this stage, static analysis suggests the sample is a staged loader: high entropy in `.text` and limited readable content indicate that meaningful code is likely reconstructed at runtime.

Because of that, I chose to begin with controlled execution rather than immediate reverse engineering. Disassembling the binary at this point would mostly involve encrypted or compressed data and provide little insight.

Controlled execution allows observation of:
- Memory allocation and protection changes
- The moment unpacking occurs
- Any early network or environment checks
    
Once the unpacked code becomes visible in memory, reverse engineering becomes both practical and meaningful.

---
## 7. Initial debugger interaction and control-flow friction

The sample was executed under x32dbg in a fully isolated FLARE VM. Breakpoints were placed on a small set of high-signal APIs commonly involved in loader staging and anti-analysis logic, including:

- `VirtualAlloc`
- `VirtualProtect`
- `LoadLibraryA/W`
- `GetProcAddress`
- `SetUnhandledExceptionFilter`
- Timing-related APIs (such as `GetTickCount`)

Early execution did not progress linearly. Instead, execution repeatedly returned to timing and comparison logic, exhibiting looping behaviour that materially interfered with straightforward single-stepping. This is consistent with guard logic that delays or gates progression based on runtime conditions.

<img width="1397" height="522" alt="loop" src="https://github.com/user-attachments/assets/4e0f8ee9-bb43-47b8-8553-23d1260ee6dd" />

At this stage, the behavior suggested intentional resistance to interactive debugging rather than a simple initialization routine.

---

## 8. Runtime memory staging via VirtualAlloc

Despite the control-flow friction, execution eventually reached a call to `VirtualAlloc`. The allocation parameters were observed directly from the stack at call time:

- `lpAddress`: `NULL`
- `dwSize`: ~0xA267 bytes (~41 KB)
- `flAllocationType`: `MEM_COMMIT`
- `flProtect`: `PAGE_EXECUTE_READWRITE`

The call returned a base address of `0x0019F634`.

<img width="2046" height="731" alt="e17fb96d-39db-4bd9-b14f-82223f5cdd2e" src="https://github.com/user-attachments/assets/3e423ff1-24f2-4b21-a444-0715464c0de4" />

This allocation created a private, RWX memory region not backed by any loaded module. Such allocations are uncommon in benign applications and are strongly associated with loader-style staging, where code or data is reconstructed in memory prior to execution.

---

## 9. Memory map confirmation

Inspection of the process memory map confirmed the presence of the newly allocated region:

- Type: Private
- Permissions: RWX
- Size: ~41 KB
- Base: `0x0019F634`

At the time of inspection, the region did not contain valid executable instructions and appeared either uninitialized or only partially populated.

This strongly suggests the region was intended as a staging buffer rather than a simple scratch allocation.

---

## 10. Dynamic API resolution phase

Following memory allocation, execution progressed into repeated calls to `GetProcAddress`. Observed resolutions included:

- `LoadLibraryA`
- `VirtualQuery`
- `MapViewOfFile`
- `atexit`

<img width="2048" height="984" alt="7bd2cd75-1e83-45fa-bc83-eac6d50a924e" src="https://github.com/user-attachments/assets/bb316287-f6e5-4d8c-b415-b4be141ec4cc" />

This behavior indicates a transition into a dynamic capability expansion phase, where required APIs are resolved at runtime rather than relied upon via the static import table. This is a common loader technique and aligns with earlier static observations.

Notably, resolution of `atexit` was observed shortly before process instability. Since `atexit` is a C runtime export rather than a kernel32 export, this resolution path is sensitive to module state and calling context.

---

## 11. Execution instability and termination under debugger

Shortly after resolving `atexit`, the process terminated with an access violation. No clean handoff into the previously allocated RWX region was observed prior to termination.

The termination path appeared to follow a normal runtime exit pattern rather than an explicit crash, consistent with guarded early-exit behavior under debugger conditions.

At this point, further progress would require stabilizing execution by patching indirect calls or bypassing guard logic—steps that fall outside the intended scope of this analysis.

---

## 12. Correlation with system-level telemetry (Procmon)

To validate debugger observations, the sample was also monitored using **Process Monitor**.

Observed behaviors:
- Successful loading of system DLLs, including `winhttp.dll`
- Registry queries related to:
    - Image File Execution Options
    - Compatibility settings
    - OLE and GDI initialization
- Short-lived thread creation
- Clean process termination

Notably absent:
- No dropped files
- No outbound network connections
- No registry persistence
- No service creation
- No child processes

<img width="1569" height="191" alt="image" src="https://github.com/user-attachments/assets/9f17a0a1-6c49-456d-ae30-020366849328" />

These observations align with a **self-contained loader that aborts early**, rather than a malfunctioning or incomplete sample.

---

## 13. Dynamic analysis conclusion

Dynamic analysis confirmed multiple loader-consistent behaviors:

- Guarded, timing-influenced control flow that impeded debugging
- Runtime allocation of a private RWX memory region suitable for staging
- Dynamic resolution of key APIs via `GetProcAddress`
- Early termination under debugger conditions before stable payload execution

While no final payload execution was observed, the combination of these behaviors is sufficient to classify the sample as a staged loader rather than a standalone payload.

---

# Final Conclusion

This analysis documents a time-boxed static and dynamic triage of a suspected SmokeLoader-style loader. Static analysis established that the binary is a compact, native x86 executable with high-entropy `.text` content and non-trivial built-in capability. Dynamic analysis demonstrated runtime staging behavior, dynamic API resolution, and deliberate resistance to interactive debugging.

The investigation was intentionally halted once loader characteristics and anti-analysis intent were confirmed. Full payload recovery or execution stabilization would require bypassing execution guards and exception-driven flow, which was considered out of scope to reflect realistic analyst prioritization.
