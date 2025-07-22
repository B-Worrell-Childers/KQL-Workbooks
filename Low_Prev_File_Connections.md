# Low Enterprise Prevalance File Connections (Company Names and No Company Names)

## Description

This query is designed to be used in a Sentinel Workbook for threat hunting purposes. 

This requires workbook variables "prevalenceThreshold" and "ConnectCount" to be set to work. Optionally, you can replace the workbook variables with desired numeric values.

Looks for files making successful connections that are below a set enterprise device count and below a certain connections count.

There is a version for files with a company name in their information and for files that don't have a company name in their info.

May require fine tuning to the enterprise due to the general nature of the queries.

## Sentinel (Workbook)
<details>
<summary> Query (Low Prevalance Files, Company Names) </summary>
<br>
  
``` KQL
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where isnotempty(InitiatingProcessVersionInfoCompanyName)
// Insert Exclusions Here
| where RemoteIP != "127.0.0.1"
| where not(RemoteUrl has_any ("googleapis", "windowsupdate", "microsoft", "microsoftonline", "officeapps", "google", "office", "office365"))
// End Exclusions
| summarize 
    Devices = makeset(DeviceName),
    DeviceCount = dcount(DeviceName),
    ObservedIPs = makeset(RemoteIP),
    ObservedURLs = makeset(RemoteUrl),
    ObservedFileNames = makeset(InitiatingProcessFileName),
    ObservedFolderPaths = makeset(InitiatingProcessFolderPath),
    ObservedHashes = makeset(InitiatingProcessSHA1),
    FileCount = dcount(InitiatingProcessSHA1),
    count() by InitiatingProcessVersionInfoCompanyName
| project-rename Connections = count_ 
| where DeviceCount <= {prevalenceThreshold} and Connections <= {ConnectCount}
```

</details>

<details>
<summary> Query (Low Prevalance Files, No Company Names) </summary>
<br>
  
``` KQL
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where isempty(InitiatingProcessVersionInfoCompanyName)
// Insert Exclusions Here
| where RemoteIP != "127.0.0.1"
| where not(RemoteUrl has_any ("googleapis", "windowsupdate", "microsoft", "microsoftonline", "officeapps", "google", "office", "office365"))
// End Exclusions
| summarize 
    Devices = makeset(DeviceName),
    DeviceCount = dcount(DeviceName),
    ObservedIPs = makeset(RemoteIP),
    ObservedURLs = makeset(RemoteUrl),
    ObservedHashes = makeset(InitiatingProcessSHA1),
    ObservedFolderPaths = makeset(InitiatingProcessFolderPath),
    FileCount = dcount(InitiatingProcessSHA1),
    count() by InitiatingProcessFileName
| project-rename Connections = count_ 
| where DeviceCount <= {prevalenceThreshold} and Connections <= {ConnectCount}
```

</details>
