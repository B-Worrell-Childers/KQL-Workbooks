# Connection from a Recently Downloaded Executable File

## Description

This query is designed to be used in a Sentinel Workbook for threat hunting purposes. 

Detects if an executable file downloaded from a web browser makes a successful connection within a time period given.

This query tends to catch a lot of Microsoft Store installer files, you may want to exclude it if you trust it (I wouldn't)

## Sentinel (Workbook)
<details>
<summary> Query </summary>
<br>
  
``` KQL
DeviceFileEvents
| where ActionType != "FileDeleted"
| where PreviousFileName endswith ".part" or PreviousFileName endswith ".crdownload" // Commonly Associated Browser Download Files
| where AdditionalFields has_any ("PortableExecutable", "Unknown", "Error") // From personal experience, the File Type for executables sometimes errors out, so Unknown and Error is included for safety
| where FileName !endswith ".crdownload" and FileName !endswith ".part" // We don't want to see the original download file, just what is created after
// URL Exclusions here (Authorized Sources)
| where FileOriginUrl !contains "INSERT URL HERE"
// End URL Exclusions
| where isnotempty(SHA1) // Makes sure that the hash is there so joining works.
| join kind=innerunique (DeviceNetworkEvents
    | where ActionType == "ConnectionSuccess"
) on $left.SHA1 == $right.InitiatingProcessSHA1, DeviceName
| summarize 
FileNames = make_set(FileName),
OriginUrls = make_set(FileOriginUrl),
ReferrerUrls = make_set(FileOriginReferrerUrl),
Folderpaths = make_set(FolderPath),
Hashes = make_set(SHA1),
ConnectedIPs = make_set(RemoteIP),
ConnectedUrls = make_set(RemoteUrl)
by DeviceName
```

</details>
