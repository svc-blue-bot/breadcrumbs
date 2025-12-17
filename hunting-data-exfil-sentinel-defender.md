# Hunting data exfiltration in Microsoft Sentinel + Defender
Microsoft gives you the raw ingredients for a defensible exfiltration story across multiple surfaces, but they live across different tables and in a real incident you win by pivoting cleanly between them. The tables below are all part of the Microsoft Defender XDR advanced hunting schema and/or common Microsoft Sentinel Log Analytics tables.

---

# A quick note on “Sentinel vs Defender” KQL

- **Defender XDR Advanced Hunting** tables typically use `Timestamp`.
    
- **Sentinel / Log Analytics** tables typically use `TimeGenerated`.
    

Most queries below are written in a way you can port with minimal edits.

---

# Defender XDR: endpoint exfil signals (Device* tables)

Below are primarily your hands-on-keyboard (HOK) + data staging sources.

## DeviceProcessEvents: exfil tooling & staging commands

Hunt for common “get data out” tooling (rclone, scp/sftp, cloud CLIs) and staging tools (7zip, WinRAR, GPG, OpenSSL).

```
let timeframe = 7d;
let Keywords = dynamic(["rclone", "winscp", "putty", "pscp", "plink", "ssh", "scp", "sftp", "rsync", "ftp", "lftp", "tftp", "ncftp", "filezilla", "cyberduck", "mobaxterm", "curl", "wget", "aria2c", "httpie", "bitsadmin", "certutil", "powershell", "pwsh", "az", "azcopy", "aws", "s3cmd", "s5cmd", "gcloud", "gsutil", "oci", "ibmcloud", "openstack", "swift", "mc", "megacmd", "mega-put", "mega-get", "megasync", "dropbox", "onedrive", "googledrivefs", "boxdrive", "nextcloud", "owncloud", "syncthing", "resilio", "duplicati", "restic", "borg", "kopia", "7z", "7za", "winrar", "rar", "zip", "tar", "gzip", "bzip2", "xz", "zstd", "gpg", "openssl", "age", "sops", "stunnel", "socat", "netcat", "ncat", "ngrok", "cloudflared", "git", "gh", "glab"]);
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where ProcessCommandLine has_any (Keywords) or FileName has_any (Keywords)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

Why it matters: exfil almost always requires tooling and staging, even if the final transfer happens over what could be considered normal HTTPS.

---

## DeviceFileEvents: staging artifacts (archives, dumps, exports)

Look for archive creation or suspicious bulk file activity in staging folders.

```
let timeframe = 7d;
let ArchiveExt = dynamic([".zip",".7z",".rar",".tar",".gz",".tgz",".iso",".pst"]);
DeviceFileEvents
| where Timestamp > ago(timeframe)
| where FileName has_any (ArchiveExt)
| summarize Files=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
  by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
     FolderPath, FileName
| order by Files desc
```

What you’re looking for is a new burst of archives in `Downloads`, `Temp`, user profile roots, or masqueraded paths.

---

## DeviceNetworkEvents: suspicious egress destinations + process attribution

This is your fastest way to discover Which process talked to what.

```
let timeframe = 7d;
let exfildomains = dynamic(["dropbox.com", "dropboxapi.com", "db.tt", "dropboxusercontent.com", "dl.dropboxusercontent.com", "dl.dropbox.com", "drive.google.com", "*.drive.google.com", "drive.usercontent.google.com", "drive-data-export.usercontent.google.com", "docs.google.com", "*.docs.google.com", "sheets.google.com", "slides.google.com", "takeout.google.com", "*.googleusercontent.com", "*.googleapis.com", "apis.google.com", "onedrive.com", "*.onedrive.com", "onedrive.live.com", "*.onedrive.live.com", "*.files.1drv.com", "storage.live.com", "*.storage.live.com", "login.live.com", "*.sharepoint.com", "*.my.sharepoint.com", "<tenant>-my.sharepoint.com", "1drv.ms", "*.box.com", "*.app.box.com", "*.box.net", "*.boxcdn.net", "*.boxcloud.com", "*.services.box.com", "upload.box.com", "upload.box.net", "upload.app.box.com", "upload.ent.box.com", "mega.nz", "mega.io", "pastebin.com", "gist.github.com", "slack.com", "*.slack.com", "discord.com", "cdn.discordapp.com", "media.discordapp.net"]);
DeviceNetworkEvents
| where Timestamp > ago(timeframe)
| where RemoteUrl has_any (exfildomains) or RemoteIPType == "Public"
| summarize Connections=count(),
          FirstSeen=min(Timestamp),
          LastSeen=max(Timestamp)
  by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
     RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Connections desc
```


---

## DeviceRegistryEvents: persistence or config for transfer tools

This is useful when attackers install or configure a tool.

```
let timeframe = 14d;
let Tools = dynamic(["rclone","winscp","filezilla","putty","pscp","plink"]);
DeviceRegistryEvents
| where Timestamp > ago(timeframe)
| where RegistryKey has_any (Tools) or RegistryValueData has_any (Tools)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

---

## DeviceEvents: odd security events that correlate with exfil

Find anything that hints at removable media or security-control events and then pivot.

```
let timeframe = 7d;
DeviceEvents
| where Timestamp > ago(timeframe)
| where ActionType has_any ("Usb","Removable","DeviceControl","Dlp")
| project Timestamp, DeviceName, AccountName, ActionType, AdditionalFields
| order by Timestamp desc
```

---

# Defender XDR: SaaS exfil signals (CloudAppEvents)

CloudAppEvents is one of the best sources for bulk download / bulk share / unusual access patterns if Defender for CloudApps is connected.

## CloudAppEvents: bulk downloads / shares

```
let timeframe = 7d;
CloudAppEvents
| where Timestamp > ago(timeframe)
| where ActionType has_any ("Download","Share","Upload")
| summarize Actions=count(),
          DistinctObjects=dcount(ObjectId),
          Apps=make_set(Application, 10),
          Countries=make_set(CountryCode, 10),
          UserAgents=make_set(UserAgent, 5)
  by AccountDisplayName, AccountId, ActionType
| where Actions > 200 or DistinctObjects > 100
| order by Actions desc
```

## CloudAppEvents: anonymous proxy access (provides additional context)

```
let timeframe = 14d;
CloudAppEvents
| where Timestamp > ago(timeframe)
| where IsAnonymousProxy == true
| summarize Events=count(), Apps=make_set(Application, 10), Actions=make_set(ActionType, 10)
  by AccountDisplayName, AccountId, IPAddress, CountryCode, City
| order by Events desc
```

---

# Defender XDR: DLP / insider-risk-grade exfil (DataSecurityEvents)

Purview insider risk signals into Defender XDR, DataSecurityEvents is basically exfil telemetry with labels attached.

## DataSecurityEvents: exfil to cloud / removable / file share

```
let timeframe = 30d;
DataSecurityEvents
| where Timestamp > ago(timeframe)
| extend Destination =
  case(DeviceDestinationLocationType == 3, "Removable",
       DeviceDestinationLocationType == 4, "Cloud",
       DeviceDestinationLocationType == 5, "FileShare",
       DeviceDestinationLocationType == 2, "Remote",
       tostring(DeviceDestinationLocationType))
| where Destination in ("Removable","Cloud","FileShare","Remote")
| summarize Events=count(),
          TotalBytes=sum(ObjectSize),
          TopTargets=make_set(TargetUrlDomain, 10),
          Policies=make_set(DlpPolicyMatchInfo, 10)
  by AccountUpn, Destination
| order by TotalBytes desc
```

## DataSecurityEvents: removable media exfil (device serial correlation)

```
let timeframe = 30d;
DataSecurityEvents
| where Timestamp > ago(timeframe)
| where DeviceDestinationLocationType == 3 or isnotempty(RemovableMediaSerialNumber)
| summarize TotalBytes=sum(ObjectSize),
          Files=dcount(ObjectId),
          Devices=make_set(DeviceName, 10)
  by AccountUpn, RemovableMediaManufacturer, RemovableMediaModel, RemovableMediaSerialNumber
| order by TotalBytes desc
```

This is the kind of query that is both measurable (bytes, files, device serials) and attributable (account + device), which is the perfect recipe for an incident report.

---

# Defender XDR: Graph API as an exfil path (GraphApiAuditEvents)

Graph can be a quiet exfil channel with pull mail, pull OneDrive/SharePoint, enumerate org data via API.

## GraphApiAuditEvents: high-volume read patterns

```
let timeframe = 7d;
GraphApiAuditEvents
| where Timestamp > ago(timeframe)
| where RequestMethod == "GET"
| where RequestUri has_any ("/drive", "/messages", "/mailFolders", "/chats", "/teams", "/sites")
| summarize Requests=count(),
          DistinctUris=dcount(RequestUri),
          StatusCodes=make_set(ResponseStatusCode, 10)
  by ApplicationId, AccountObjectId, IPAddress
| order by Requests desc
```

## GraphApiAuditEvents: suspicious scopes (broad permissions)

```
let timeframe = 14d;
GraphApiAuditEvents
| where Timestamp > ago(timeframe)
| where Scopes has_any ("Mail.Read", "Files.Read", "Files.Read.All", "Sites.Read.All", "User.Read.All")
| summarize Requests=count(), Uris=make_set(RequestUri, 10)
  by ApplicationId, AccountObjectId, IPAddress, Scopes
| order by Requests desc
```

---

# Defender XDR: Azure Storage, data-out evidence (CloudStorageAggregatedEvents)

CloudStorageAggregatedEvents gives you aggregated read activity including "TotalResponseLength" which is a very useful proxy for data pulled.

## CloudStorageAggregatedEvents: large reads + suspicious network context

```
let timeframe = 7d;
CloudStorageAggregatedEvents
| where Timestamp > ago(timeframe)
| where TotalResponseLength > 100000000  // 100MB in the aggregation window (tune)
| summarize TotalBytes=sum(TotalResponseLength),
          ReadOps=sum(SuccessfulReadOperations),
          Ops=sum(OperationsCount)
  by StorageAccount, StorageContainer, ServiceType,
     AccountUpn, IpAddress, CountryName,
     AuthenticationType, IsTorExitNode, IsKnownSuspiciousIp
| order by TotalBytes desc
```

## CloudStorageAggregatedEvents: unexpected auth types for quick wins

```
let timeframe = 14d;
let ExpectedAuth = dynamic(["AccountKey","SAS","Oauth"]);
CloudStorageAggregatedEvents
| where Timestamp > ago(timeframe)
| where not(AuthenticationType in (ExpectedAuth))
| summarize Ops=sum(OperationsCount) by StorageAccount, AuthenticationType, ServiceType
| order by Ops desc
```

---

# Defender XDR: email as an exfil channel (Email* + UrlClickEvents)

These tables are populated by Defender for Office 365.

## EmailAttachmentInfo: attachments sent to external recipients

Because "EmailAttachmentInfo" includes "FileSize", you can rank by total bytes.

```
let timeframe = 7d;
let OrgDomains = dynamic(["yourcompany.com"]); // add your real domains
EmailAttachmentInfo
| where Timestamp > ago(timeframe)
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@")[1])
| where RecipientDomain !in~ (OrgDomains)
| summarize TotalAttachmentBytes=sum(FileSize),
          Attachments=count(),
          UniqueHashes=dcount(SHA256),
          Messages=dcount(NetworkMessageId)
  by SenderFromAddress, RecipientEmailAddress
| order by TotalAttachmentBytes desc
```

## EmailAttachmentInfo: suspicious container file types to external domains

```
let timeframe = 14d;
let OrgDomains = dynamic(["<insert company domain here>"]);
let SuspiciousTypes = dynamic(["zip","7z","rar","iso","pst","csv"]);
EmailAttachmentInfo
| where Timestamp > ago(timeframe)
| where FileType in~ (SuspiciousTypes)
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@")[1])
| where RecipientDomain !in~ (OrgDomains)
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, FileSize, SHA256, NetworkMessageId
| order by Timestamp desc
```

## EmailUrlInfo: emails containing links to common exfil destinations

```
let timeframe = 14d;
let ExfilDomains = dynamic(["dropbox.com","drive.google.com","mega.nz","transfer.sh","box.com"]);
EmailUrlInfo
| where Timestamp > ago(timeframe)
| where UrlDomain has_any (ExfilDomains)
| summarize Hits=count(), Senders=make_set(SenderFromAddress, 10)
  by UrlDomain, Url
| order by Hits desc
```

## UrlClickEvents: users clicking through to risky links (can be used as supporting evidence)

This provides excellent context if an account is suspected.

```
let timeframe = 14d;
UrlClickEvents
| where Timestamp > ago(timeframe)
| where ActionType in ("ClickAllowed","ClickThrough")
| project Timestamp, AccountUpn, Workload, Url, IsClickedThrough, IPAddress, ThreatTypes, NetworkMessageId
| order by Timestamp desc
```

---

# Microsoft Sentinel: network and tenant activity (Log Analytics tables)

Sentinel is where you prove or disprove exfil with bytes-out and service audit logs.

## CommonSecurityLog: firewall / proxy bytes out

This query tries to be resilient by using `column_ifexists()` so it doesn’t break when a vendor maps fields differently.

```
let timeframe = 24h;
CommonSecurityLog
| where TimeGenerated > ago(timeframe)
| extend OutBytes =
    tolong(column_ifexists("SentBytes", 0)) +
    tolong(column_ifexists("BytesSent", 0)) +
    tolong(column_ifexists("BytesOut", 0))
| extend SrcIp = tostring(column_ifexists("SourceIP", "")),
         DstIp = tostring(column_ifexists("DestinationIP", "")),
         Url   = tostring(column_ifexists("RequestURL", ""))
| where isnotempty(SrcIp) and isnotempty(DstIp)
| summarize TotalOutBytes=sum(OutBytes),
          Sessions=count(),
          DstCount=dcount(DstIp),
          SampleUrls=make_set(Url, 5)
  by SrcIp, DeviceVendor, DeviceProduct
| order by TotalOutBytes desc
```

## DnsEvents: DNS tunneling heuristics 

DnsEvents is another great quick win table.

```
let timeframe = 24h;
DnsEvents
| where TimeGenerated > ago(timeframe)
| extend Q = tostring(column_ifexists("Name", column_ifexists("QueryName","")))
| where isnotempty(Q)
| extend FirstLabel = tostring(split(Q, ".")[0])
| where strlen(FirstLabel) > 25
| summarize Queries=count(), UniqueQueries=dcount(Q) by ClientIP=tostring(column_ifexists("ClientIP","")), Q
| order by Queries desc
```

You can layer in `QueryType` (TXT) and NXDOMAIN rates if your connector populates those fields.

---

## OfficeActivity: SharePoint/OneDrive/Teams audit trail for mass download / share

### OfficeActivity: mass download pattern

```
let timeframe = 7d;
OfficeActivity
| where TimeGenerated > ago(timeframe)
| extend Op = tostring(column_ifexists("Operation","")),
         User = tostring(column_ifexists("UserId","")),
         Workload = tostring(column_ifexists("Workload", column_ifexists("OfficeWorkload","")))
| where Op has "Download"
| summarize Downloads=count(),
          Sites=dcount(tostring(column_ifexists("Site_Url",""))),
          ClientIPs=make_set(tostring(column_ifexists("ClientIP","")), 10)
  by User, Workload
| where Downloads > 200
| order by Downloads desc
```

### OfficeActivity: external/anonymous sharing pattern

```
let timeframe = 14d;
OfficeActivity
| where TimeGenerated > ago(timeframe)
| extend Op = tostring(column_ifexists("Operation","")),
         User = tostring(column_ifexists("UserId",""))
| where Op has_any ("AnonymousLink","Sharing","External","Invite")
| summarize Events=count(), Ops=make_set(Op, 20) by User
| order by Events desc
```

---

## SecurityEvent: process creation evidence when MDE isn’t your only source

SecurityEvent holds Windows security events collected into Sentinel.

### SecurityEvent 4688: exfil/staging commandline detections

```
let timeframe = 7d;
let Indicators = dynamic(["rclone", "winscp", "putty", "pscp", "plink", "ssh", "scp", "sftp", "rsync", "ftp", "lftp", "tftp", "ncftp", "filezilla", "cyberduck", "mobaxterm", "curl", "wget", "aria2c", "httpie", "bitsadmin", "certutil", "powershell", "pwsh", "az", "azcopy", "aws", "s3cmd", "s5cmd", "gcloud", "gsutil", "oci", "ibmcloud", "openstack", "swift", "mc", "megacmd", "mega-put", "mega-get", "megasync", "dropbox", "onedrive", "googledrivefs", "boxdrive", "nextcloud", "owncloud", "syncthing", "resilio", "duplicati", "restic", "borg", "kopia", "7z", "7za", "winrar", "rar", "zip", "tar", "gzip", "bzip2", "xz", "zstd", "gpg", "openssl", "age", "sops", "stunnel", "socat", "netcat", "ncat", "ngrok", "cloudflared", "git", "gh", "glab"]);
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4688
| extend Cmd = tostring(column_ifexists("CommandLine","")),
         NewProc = tostring(column_ifexists("NewProcessName",""))
| where Cmd has_any (Indicators) or NewProc has_any (Indicators)
| project TimeGenerated, Computer, Account=tostring(column_ifexists("Account","")),
          NewProc, Cmd
| order by TimeGenerated desc
```

---

### Example and Closing notes
A clean exfil chain look may look like:

- Device staged `7z` archives > process executed `rclone copy` > network connections to a new cloud endpoint > CloudAppEvents shows bulk download/share > DataSecurityEvents flags DLP match and object size.
    
This is also why exfil isn’t always as simple as one table / logset, it emerges when you correlate signals across them.

---
