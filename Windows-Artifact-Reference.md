---
layout: default
title: Windows Artifact Reference
---

# Windows Artifact Reference 
Summary of what you get, what to be careful about, and when to use each artifact.

## Prefetch (.pf)

**What you get**  
• Evidence that an executable launched at least once  
• Up to 8 last execution times on Windows 8 plus  
• Run count  
• Referenced files and directories accessed during first ~10 seconds  
• Path-hash indicating original execution path

**What to be careful about**  
• Prefetch can be disabled on servers or by policy  
• Limited retention (up to ~1024 files on modern Windows)  
• Presence does not prove full execution, only that the launch began  
• Hash reversal is not trivial  
• Self-contamination risk during live analysis

**When to use**  
• Reconstruct execution timelines  
• Identify unusual tool usage and execution paths  
• Validate malware execution in absence of process logs

---

## ShimCache (AppCompatCache)

**What you get**  
• Evidence a file existed on the system  
• Full path of binary  
• File last modified timestamp  
• Possible execution flag only on older Windows versions

**What to be careful about**  
• Does not reliably prove execution  
• Written only on shutdown or reboot in many versions  
• Timestamp reflects file modify time, not run time  
• Cache size limited  
• Susceptible to tampering or clearing

**When to use**  
• Detect presence of deleted malware  
• Build existence maps of suspicious binaries  
• Supplement Prefetch and Amcache when prefetch is disabled

---

## AmCache (Amcache.hve)

**What you get**  
• Evidence of binary presence and sometimes first-run metadata  
• SHA-1 hash of first ~30 MB  
• File size, path, publisher, compile dates  
• Driver, executable, and link file records

**What to be careful about**  
• SHA-1 does not cover large files completely  
• Entries may show presence rather than execution  
• Hive can be deleted or replaced by attacker  
• Timestamps vary in meaning depending on entry type

**When to use**  
• Identify deleted or cleaned-up malware  
• Validate binary integrity using hash  
• Correlate with Prefetch to confirm execution  
• Support timeline building when Prefetch is absent

---

## Program Compatibility Assistant (PCA)

**What you get**  
• Per-user record of executed binaries  
• Path, execution time, exit code, ProgramId

**What to be careful about**  
• Only records user-level launches monitored by PCA  
• Coverage is incomplete and not designed as an execution log

**When to use**  
• Strengthen per-user attribution  
• Tie AmCache ProgramId to an actual execution event

---

## MUICache

**What you get**  
• Application friendly names extracted from metadata  
• Evidence of user interactions with GUI programs

**What you should be careful about**  
• No timestamps  
• Shows metadata-based names, which may differ after renaming  
• Does not confirm execution

**When to use**  
• Detect program renaming  
• Support attribution of GUI interactions

---

## UserAssist

**What you get**  
• Per-user evidence of GUI application launches  
• Run count and last execution timestamps  
• ROT13 encoded values

**What to be careful about**  
• Known inconsistencies in run count and timestamps  
• Can show false positives  
• Does not record command-line executions

**When to use**  
• Attribute execution to a logged-in user  
• Confirm GUI-based execution of apps or links  
• Validate suspicious user behaviors

---

## SRUM (SRUDB.dat)

**What you get**  
• Application usage metadata including foreground/background use  
• Network usage per application  
• User SID and timestamps  
• Resource consumption patterns

**What to be careful about**  
• Not all processes are captured  
• Very short-lived processes may not appear  
• SRUM is not an explicit execution log  
• Parsers vary in completeness

**When to use**  
• Show that malware communicated over the network  
• Link execution to a user based on resource records  
• Provide behavioral context beyond simple presence

---

## LNK Files

**What you get**  
• Path to target file  
• Creation timestamp for shortcut  
• Last accessed and target file metadata  
• Volume information and drive serial data

**What to be careful about**  
• LNK creation time reflects shortcut creation, not execution  
• Target file timestamps may be updated externally  
• Not all executions generate LNK files

**When to use**  
• Attribute user interaction with files  
• Recover deleted file paths  
• Establish initial use of a file or tool by a user

---

## Jumplists

**What you get**  
• Collections of LNK-like entries associated with specific apps  
• MRU order, pinned entries, interaction counts  
• Hostname and MAC address in metadata

**What to be careful about**  
• Only for applications using the Windows jump list API  
• AutomaticDestinations and CustomDestinations differ in behavior  
• Can be cleared or reset

**When to use**  
• Attribute user interaction with documents or executables  
• Identify high-frequency access patterns  
• Support timelines of document or tool usage

---

## Registry MRU Keys (NTUSER.dat and UsrClass.dat)

**What you get**  
• Evidence of recently opened or saved files  
• Run dialog history  
• Explorer typed paths  
• Folder browsing artifacts (ShellBags)  
• Recent file dialogs and search history

**What to be careful about**  
• MRU values have no timestamps  
• Last write timestamps exist on keys only  
• Can be influenced by applications, not only user actions

**When to use**  
• Map user navigation through the file system  
• Identify removable media interactions  
• Correlate with file access or exfiltration activity

---

## USB Artifacts (Enum USB, USBSTOR, MountedDevices, MountPoints2)

**What you get**  
• USB vendor, product ID, and serial  
• First install time, last connect, last removal  
• Assigned drive letters and volume GUIDs  
• Volume serial number history  
• Friendly name

**What to be careful about**  
• Times vary across Windows versions  
• Formatting a USB creates new volume serial numbers  
• Some artifacts require cross-correlation for accuracy

**When to use**  
• Investigate data exfiltration via removable media  
• Determine when a device was connected or removed  
• Attribute USB usage to specific users or sessions

---

## TimeZone, ComputerName, Shares, Network Info, NLA Profiles

**What you get**  
• Environment context for the system during an incident  
• Network profiles, SSIDs, gateway MACs, timestamps  
• Share configurations and access points

**What to be careful about**  
• Primarily environmental, not execution evidence  
• Some keys change only when environments change  
• Requires pairing with logs for deeper meaning

**When to use**  
• Establish system identity and baseline  
• Determine network movement and exposure  
• Investigate lateral movement or rogue profiles

---

## Registry Transaction Logs (.LOG1, .LOG2)

**What you get**  
• Ability to replay uncommitted registry transactions  
• Recovery of recently changed keys

**What to be careful about**  
• Requires specialized tooling  
• Not all operations can be recovered  
• Logs may be overwritten quickly

**When to use**  
• Retrieve recently added or deleted registry entries  
• Investigate persistence or tampering attempts  
• Confirm whether a registry-based payload existed briefly

---

## Practical Correlation Strategy

**Always combine artifacts.**
Execution evidence is strongest when at least two independent artifacts agree.
Preferred combinations:
- Prefetch plus AmCache
- AmCache plus SRUM for network-aware malware
- ShimCache plus LNK or Jumplists for deleted binaries
- UserAssist plus MRUs for user-driven execution
- Prefetch plus Event Logs for high-confidence timelines
- ShimCache plus LNK or Jumplists for deleted binaries  
- UserAssist plus MRUs for user-driven execution  
- Prefetch plus Event Logs for high-confidence timelines
