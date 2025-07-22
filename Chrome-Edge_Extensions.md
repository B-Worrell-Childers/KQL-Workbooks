# Chrome/Edge Extensions

## Description

This query is designed to be used in a Sentinel Workbook for threat hunting purposes. 

Looks for chrome/edge extension files ".crx" that have a chrome/edge webstore extension ID in the filename, extracts and appends the id to the respective links involving the 2 stores, and displays it for further analysis.

Use the "ExtensionWhitelist" to tune out known good extensions in your enterprise.

## Sentinel (Workbook)
<details>
<summary> Query </summary>
<br>
  
``` KQL
// Unusual .crx (Chrome Extension) files with ID's
let ExtensionWhitelist = dynamic([
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi", // Google Docs Offline
    "blpcfgokakmgnkcojhhkbfbldkacnbeo", // Youtube
    "gamjhjfeblghkihfjdpmbpajhlpmobbp", // Microsoft S/MIME
    "ljglajjnnkapghbckkcmodicjhacbfhk", // Microsoft Power Automate
    "kagpabjoboikccfdghpdlaaopmgpgfdc", // Microsoft Power Automate
    "aohghmighlieiainnegkcijnfilokake", // Google Docs
    "aapocclcgogkmnckokdopfmhonfmgoek", // Google Slides
    "felcaaldnbdncclmgdcncolpebgiejap" // Google Sheets
]);
DeviceFileEvents
| where ActionType != "FileDeleted"
| where FileName endswith ".crx"
| extend PotentialExtensionID = tolower(extract(@"^([A-Za-z]{32})_", 1, FileName))
| where PotentialExtensionID !in (ExtensionWhitelist) and isnotempty(PotentialExtensionID)
| extend PotentialChromeExtensionLink = iff(isnotempty(PotentialExtensionID), strcat("https://chromewebstore.google.com/detail/", PotentialExtensionID), "N/A")
| extend PotentialEdgeExtensionLink = iff(isnotempty(PotentialExtensionID), strcat("https://microsoftedge.microsoft.com/addons/detail/", PotentialExtensionID), "N/A")
| summarize
    DeviceCount = dcount(DeviceName),
    Devices = makeset(DeviceName),
    FolderPaths = makeset(FolderPath),
    Hashes = makeset(SHA1),
    FileNames = makeset(FileName)
by PotentialExtensionID, PotentialChromeExtensionLink, PotentialEdgeExtensionLink
```

</details>
