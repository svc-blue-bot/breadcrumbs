# SmokeLoader Style Loader Analysis

Sample: `35bf9dfd223e02da2ee3d57ec493156787a3c2cecb8b655a583985a2f14cc6e3`  
Environment: FLARE VM, fully isolated  
Objective: Understand loader behavior, staging logic, and memory-resident artifacts using static, dynamic, and memory-aware analysis

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

- `UnhandledExceptionFilter`
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

## 7. Debugger setup (IDA)

With static analysis suggesting a staged loader and early termination complicating external debugger attachment, I continued dynamic analysis using IDA’s built-in debugger.

While IDA is not ideal for heavy unpacking work, it is sufficient for observing early execution flow, API usage, and identifying the point at which the loader transitions into unpacked code.

### Debugger configuration
- Debugger: IDA local Windows debugger
- Architecture: 32-bit
- Execution state: Suspended at entry point
- Network: Isolated
    
### Initial breakpoints

Breakpoint selection was informed directly by the static import set. Rather than assuming full WinHTTP usage, breakpoints were placed only on APIs that are actually present or required for dynamic resolution:
- `VirtualAlloc`
- `LoadLibraryA/W`
- `GetProcAddress`
- `WinHttpAddRequestHeaders`
- 'UnhandledExceptionFilter'

Notably, VirtualProtect and most WinHTTP session APIs were absent from the import table, suggesting either direct allocation of executable memory or late-bound resolution via GetProcAddress.

The goal here was not to reverse logic immediately, but to identify when unpacking occurs and where execution is redirected once the staged code becomes active.

---

## 8. Early execution flow and control logic

Execution begins in `wWinMain`, which immediately delegates into a secondary routine responsible for environment setup and execution gating. Rather than proceeding directly into business logic, the sample performs a series of API calls related to time, process state, and execution context.

Observed calls include:

- `GetSystemTimeAsFileTime`
- `GetCurrentProcessId`
- `GetCurrentThreadId`
- `GetTickCount`
- `QueryPerformanceCounter`
    
These APIs are commonly used together in loader stubs to:
- Seed runtime values
- Detect abnormal execution timing
- Introduce conditional execution paths based on environment behavior
    
While none of these calls alone prove anti-analysis, the pattern and density strongly suggest execution conditioning rather than functional work:
<img width="768" height="820" alt="image2" src="https://github.com/user-attachments/assets/48d1fca8-a3ca-4bbd-a23d-1ff9c586a1a8" />


---

## 9. Structured exception handling and execution interference

During debugging, the loader repeatedly triggered access violations and exception-based execution paths. These manifested as:
- Writes to invalid or low memory addresses
- Execution landing inside undefined or partially defined instruction regions
- IDA warnings indicating self-modifying or runtime-altered code
    
This behavior aligns with intentional exception-driven control flow, a known technique in loader families to:
- Break debuggers
- Corrupt linear disassembly
- Force analysts into unstable execution states
    
Importantly, when exceptions were configured to pass through to the application, the process terminated cleanly rather than continuing execution. This indicates the exception paths are not error handling, but deliberate execution branches.

<img width="733" height="109" alt="image6" src="https://github.com/user-attachments/assets/bbe01ab4-8dfa-4a0d-be15-417b0b201cb1" />


---

## 10. Anti-analysis observations - practical

Rather than attempting to classify every anti-analysis technique in isolation, the following observable behaviors were confirmed during runtime:
- Execution stalls or exits when stepped instruction-by-instruction
- Loader behaves differently depending on exception handling configuration
- Debugger-visible execution paths lead into corrupted or non-linear instruction blocks
- Normal execution flow does not reliably reach later-stage logic under debugger control
    
At this point, deeper analysis would require:
- Patch-based bypassing of execution guards
- Runtime memory dumping after successful unpacking
- Instrumented execution outside IDA

Those steps exceed the scope of this analysis by design.

---

## 11. Dynamic library loading and staged capability expansion

One meaningful execution milestone was the successful breakpoint hit on `LoadLibraryA`, confirming that:
- The loader dynamically expands functionality at runtime
- Additional capabilities are conditionally enabled post-environment checks

The presence of `WINHTTP.dll` at this stage reinforces earlier static conclusions: networking is intended, but only after execution conditions are satisfied.

No outbound connections were observed during controlled execution, suggesting either:
- Network logic is gated behind failed checks, or
- This sample represents an early-stage loader awaiting tasking
    

---

## 12. Why analysis stopped here (intentionally)
At this point, continuing would require shifting analysis goals:
- From loader triage > full unpacking
- From behavioral observation > manual bypass and patching
- From time-boxed analysis > multi-hour reverse engineering
    
That was not the objective.

The purpose of this analysis was to:
- Identify loader characteristics
- Validate staging behavior
- Confirm anti-analysis intent
- Establish realistic analyst decision-making under time pressure
    
From that perspective, the sample has already been sufficiently classified.

---

# Part III: Analyst Assessment

## 13. Final assessment

Based on combined static and dynamic observations, this sample can be confidently described as:
- A SmokeLoader-style staged loader
- Designed to resist debugging and linear analysis
- Capable of dynamic capability expansion
- Likely dependent on runtime conditions or tasking for payload delivery
    
Key traits include:
- High-entropy `.text` section
- Early execution gating
- Exception-driven control flow
- Conditional library loading
- Deferred network behavior
    
No evidence suggests this binary is a standalone payload.

---

## 14. What could be done next (but wasn’t)

For completeness, the following steps would be logical continuations in a deeper investigation:
- Bypassing timing and exception checks  
- Memory dumping after successful execution
- API tracing outside IDA
- Network simulation to trigger stage retrieval
    
These were intentionally excluded to maintain scope discipline.

---

## 15. Conclusion
This analysis demonstrates a realistic loader triage workflow under time constraints:
- Static analysis to establish intent
- Dynamic execution to validate staging
- Controlled stopping point once classification is achieved
    
Not every sample needs to be fully unpacked to be understood. In real-world analysis, knowing when to stop is as important as knowing how to continue.

This loader was designed to consume analyst time. It succeeded—up to the point where its purpose became clear.
