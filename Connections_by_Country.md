# Successful Connections by Country

## Description

This query is designed to be used in a Sentinel Workbook for threat hunting purposes. 

Looks up the remote IP's of successful connections for their geographic location, then shows results based on chosen countries. Works only with IPv4 IP's

Requires a workbook variable "Countries". Optionally, you can manually input a list of country names.

## Sentinel (Workbook)
<details>
<summary> Query </summary>
<br>
  
``` KQL
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIP !contains "::" // No IPV6
/// URL FILTERS //
| where not (RemoteUrl has_any("windows", "microsoft", "windowsupdate", "bing.com", "ocsp", "office.net", "msftconnecttest", "azure"))
/// END URL FILTERS //
| extend LocationData = geo_info_from_ip_address(RemoteIP)
| extend Country = parse_json(LocationData).country
| where Country in ({Countries})
| join kind=leftanti ( // Checking to make sure the host isnt using the IP as its own.
    DeviceNetworkInfo
    | extend IPAddress = parse_json(IPAddresses).IPAddress
    | project tostring(IPAddress), DeviceName
) on DeviceName, $left.RemoteIP == $right.IPAddress
| summarize 
Observed_Countries = makeset(Country),
Connected_IPs = makeset(RemoteIP),
Connections = dcount(RemoteIP),
Processes = makeset(InitiatingProcessFileName),
Hashes = makeset(InitiatingProcessSHA1),
FolderPaths = makeset(InitiatingProcessFolderPath),
Parents = makeset(InitiatingProcessParentFileName),
Urls = makeset(RemoteUrl)
by DeviceName
```

</details>
