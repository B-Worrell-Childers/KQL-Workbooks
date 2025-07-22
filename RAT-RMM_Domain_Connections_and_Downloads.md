# Known RAT/RMM Domain Connections with Potential File Downloads

## Description

This query is designed to be used in a Sentinel Workbook for threat hunting purposes.

Looks for successful connections to domains associated with known Remote Access Software and also attempts to detect if any files associated with the specific software were downloaded in the time period.

External Lists Used: 
- https://github.com/jischell-msft/RemoteManagementMonitoringTools
- https://github.com/0x706972686f/RMM-Catalogue

## Sentinel (Workbook)
<details>
<summary> Query </summary>
<br>
  
``` KQL
let AuthedRMM = dynamic(["beyondtrust"]); // Approved RMM's go here to filter out. beyondtrust is bomgar.
let OnlineRMM = dynamic(["action1", "addigy", "atera", "chrome remote desktop", "connectwise", "LogMeIn", "ISL Online", "JumpCloud", "level.io", "meshcentral", "Ninja RMM", "panorama9", "pulseway", "screenmeet", "Simple-Help", "Splashtop", "teamviewer", "ZohoAssist"]); // List of Potentially Online RMM's
let skip = "skip"; // skip variable for iff statements
let RMMList=
    externaldata(URI: string, RMMTool: string)
    [h'https://raw.githubusercontent.com/jischell-msft/RemoteManagementMonitoringTools/refs/heads/main/Network%20Indicators/RMM_SummaryNetworkURI.csv'];
let RMMList2=
    externaldata(Software: string, Domain: string, Executables: string) 
    [h"https://raw.githubusercontent.com/0x706972686f/RMM-Catalogue/main/rmm.csv"];
let RMMDomains = RMMList | where URI != "URI" | project URI;
let RMMNames = RMMList | where RMMTool != "RMM_Tool" | project RMMTool;
let RMMDomains2 = RMMList2 | where isnotempty(Domain) and Domain != "Domain" | project Domain;
let RMMNames2 = RMMList2 | where Software != "Software" | project Software;
let RMMFileNames = RMMList2 | where isnotempty(Executables) and Executables != "Executables"  | project Executables;
let RMMCreationEvents =
    DeviceFileEvents
    | where ActionType != "FileDeleted"
    | where FileOriginUrl has_any (RMMDomains)
         or FileOriginUrl has_any (RMMDomains2)
         or FileOriginReferrerUrl has_any (RMMDomains)
         or FileOriginReferrerUrl has_any (RMMDomains2)
         or FileName has_any (RMMNames)
         or FileName has_any (RMMNames2)
         or FileName in (RMMFileNames)
;
DeviceNetworkEvents
| where ActionType == @"ConnectionSuccess"
| where RemoteUrl has_any(RMMDomains) or RemoteUrl has_any(RMMDomains2)
| extend RMM = case( // Appends the name of the RMM to the entries for easier sorting and analyzing
    //RMMList
    RemoteUrl has "action1.com", "action1",
    RemoteUrl has "prod.addigy.com", "addigy",
    RemoteUrl has "grtmprod.addigy.com", "addigy",
    RemoteUrl has "agents.addigy.com", "addigy",
    RemoteUrl has "aeroadmin.com", "aeroadmin",
    RemoteUrl has "alpemix.com", "alpemix",
    RemoteUrl has "teknopars.com", "alpemix",
    RemoteUrl has "ammyy.com", "ammyy",
    RemoteUrl has "anydesk.com", "anydesk",
    RemoteUrl has "api.playanext.com", "anydesk",
    RemoteUrl has "support.kastentornado.fi", "AnyplaceControl",
    RemoteUrl has "anyviewer.com", "anyviewer",
    RemoteUrl has "anyviewer.cn", "anyviewer",
    RemoteUrl has "aomeisoftware.com", "anyviewer",
    RemoteUrl has "aomeikeji.com", "anyviewer",
    RemoteUrl has "atera.com", "atera",
    RemoteUrl has "atera-agent-heartbeat", "atera",
    RemoteUrl has "aweray.com", "aweray",
    RemoteUrl has "aweray.net", "aweray",
    RemoteUrl has "awerayimg.com", "aweray",
    RemoteUrl has "awesun.app", "aweray",
    RemoteUrl has "barracudamsp.com", "barracuda rmm",
    RemoteUrl has "autoupdate.mikogo4.com", "beamyourscreen",
    RemoteUrl has "download.mikogo4.com", "beamyourscreen",
    RemoteUrl has "webdb.mikogo4.com", "beamyourscreen",
    RemoteUrl has "webdbmirror.mikogo4.com", "beamyourscreen",
    RemoteUrl has "license.bomgar.com", "beyondtrust",
    RemoteUrl has "bomgarcloud.com", "beyondtrust",
    RemoteUrl has "beyondtrustcloud.com", "beyondtrust",
    RemoteUrl has "remotedesktop-pa.googleapis.com", "chrome remote desktop",
    RemoteUrl has "remotedesktop.google.com", "chrome remote desktop",
    RemoteUrl has "myconnectwise.com", "connectwise",
    RemoteUrl has "connectwise.com", "connectwise",
    RemoteUrl has "screenconnect.com", "connectwise",
    RemoteUrl has "itsupport247.net", "connectwise / Continuum Managed",
    RemoteUrl has "beanywhere.com", "Dameware",
    RemoteUrl has "licenseserver.solarwinds.com", "Dameware",
    RemoteUrl has "swi-rc.com", "Dameware",
    RemoteUrl has "swi-tc.com", "Dameware",
    RemoteUrl has "dameware.com", "Dameware",
    RemoteUrl has "rmm.datto.com", "datto",
    RemoteUrl has "agent.centrastage.net", "datto",
    RemoteUrl has "audit.centrastage.net", "datto",
    RemoteUrl has "monitoring.centrastage.net", "datto",
    RemoteUrl has "agent-notifications.centrastage.net", "datto",
    RemoteUrl has "agent-comms.centrastage.net", "datto",
    RemoteUrl has "update.centrastage.net", "datto",
    RemoteUrl has "realtime.centrastage.net", "datto",
    RemoteUrl has "ts.centrastage.net", "datto",
    RemoteUrl has "datto.com", "datto",
    RemoteUrl has "nchuser.com", "desktopNow",
    RemoteUrl has "distantdesktop.com", "distantdesktop",
    RemoteUrl has "signalserver.xyz", "distantdesktop",
    RemoteUrl has "dwservice.net", "dwservice",
    RemoteUrl has "fleetdeck.io", "fleetdeck",
    RemoteUrl has "getscreen.me", "getscreen",
    RemoteUrl has "getscreen.ru", "getscreen",
    RemoteUrl has "iperius.com", "Iperius Remote",
    RemoteUrl has "iperiusremote.com", "Iperius Remote",
    RemoteUrl has "iperius-r1.com", "Iperius Remote",
    RemoteUrl has "iperius-r2.com", "Iperius Remote",
    RemoteUrl has "iperius-r3.com", "Iperius Remote",
    RemoteUrl has "iperius-r4.com", "Iperius Remote",
    RemoteUrl has "iperiusremote.de", "Iperius Remote",
    RemoteUrl has "entersrl.it", "Iperius Remote",
    RemoteUrl has "islonline.net", "ISL Online",
    RemoteUrl has "islonline.com", "ISL Online",
    RemoteUrl has "xmpp.itsm-us1.comodo.com", "Itarian",
    RemoteUrl has "xmpp.cmdm.comodo.com", "Itarian",
    RemoteUrl has "rmm-api.itsm-us1.comodo.com", "Itarian",
    RemoteUrl has "rmm-api.cmdm.comodo.com", "Itarian",
    RemoteUrl has "assist.jumpcloud.com", "JumpCloud",
    RemoteUrl has "api.jumpcloud.com", "JumpCloud",
    RemoteUrl has "kaseya.com", "Kaseya VSA",
    RemoteUrl has "stun.kaseya.com", "Kaseya VSA",
    RemoteUrl has "managedsupport.kaseya.net", "Kaseya VSA",
    RemoteUrl has "kaseya.net", "Kaseya VSA",
    RemoteUrl has "agents.level.io", "level.io",
    RemoteUrl has "online.level.io", "level.io",
    RemoteUrl has "builds.level.io", "level.io",
    RemoteUrl has "downloads.level.io", "level.io",
    RemoteUrl has "litemanager.ru", "LiteManager",
    RemoteUrl has "litemanager.com", "LiteManager",
    RemoteUrl has "update-cdn.logmein.com", "LogMeIn",
    RemoteUrl has "secure.logmein.com", "LogMeIn",
    RemoteUrl has "update.logmein.com", "LogMeIn",
    RemoteUrl has "logmeinrescue.com", "LogMeIn",
    RemoteUrl has "logmeinrescue.eu", "LogMeIn",
    RemoteUrl has "logmeinrescue-enterprise.com", "LogMeIn",
    RemoteUrl has "logmeinrescue-enterprise.eu", "LogMeIn",
    RemoteUrl has "remotelyanywhere.com", "LogMeIn",
    RemoteUrl has "gotoassist.com", "LogMeIn",
    RemoteUrl has "logmeininc.com", "LogMeIn",
    RemoteUrl has "logme.in", "LogMeIn",
    RemoteUrl has "getgo.com", "LogMeIn",
    RemoteUrl has "goto.com", "LogMeIn",
    RemoteUrl has "goto-rtc.com", "LogMeIn",
    RemoteUrl has "gotomypc.com", "LogMeIn",
    RemoteUrl has "gotohttp.com", "LogMeIn",
    RemoteUrl has "logmeincdn.http.internapcdn.net", "LogMeIn",
    RemoteUrl has "logmein-gateway.com", "LogMeIn",
    RemoteUrl has "meshcentral.com", "meshcentral",
    RemoteUrl has "mremoteng.org", "mRemoteNG",
    RemoteUrl has "rm.mspbackups.com", "MSP360",
    RemoteUrl has "client.rmm.mspbackups.com", "MSP360",
    RemoteUrl has "settings.services.mspbackups.com", "MSP360",
    RemoteUrl has "msp360.com", "MSP360",
    RemoteUrl has "foris.cloudberrylab.com", "MSP360",
    RemoteUrl has "remote.management", "N-Able",
    RemoteUrl has "logicnow.com", "N-Able",
    RemoteUrl has "logicnow.us", "N-Able",
    RemoteUrl has "system-monitor.com", "N-Able",
    RemoteUrl has "systemmonitor.eu.com", "N-Able",
    RemoteUrl has "systemmonitor.co.uk", "N-Able",
    RemoteUrl has "systemmonitor.us", "N-Able",
    RemoteUrl has "n-able.com", "N-Able",
    RemoteUrl has "solarwindsmsp.com", "N-Able",
    RemoteUrl has "rmm-host.com", "N-Able",
    RemoteUrl has "activate.netsupportsoftware.com", "NetSupport",
    RemoteUrl has "geo.netsupportsoftware.com", "NetSupport",
    RemoteUrl has "ninjarmm.com", "Ninja RMM",
    RemoteUrl has "ninjaone.com", "Ninja RMM",
    RemoteUrl has "opti-tune.com", "OptiTune",
    RemoteUrl has "optitune.us", "OptiTune",
    RemoteUrl has "panorama9.com", "panorama9",
    RemoteUrl has "kessel-ws.parsec.app", "parsec",
    RemoteUrl has "kessel-api.parsec.app", "parsec",
    RemoteUrl has "builds.parsec.app", "parsec",
    RemoteUrl has "builds.parsecgaming.com", "parsec",
    RemoteUrl has "public.parsec.app", "parsec",
    RemoteUrl has "parsecusercontent.com", "parsec",
    RemoteUrl has "stun.parsec.app", "parsec",
    RemoteUrl has "parsec.app", "parsec",
    RemoteUrl has "pcvisit.de", "pcvisit",
    RemoteUrl has "cloudflare-pcvisit.com", "pcvisit",
    RemoteUrl has "pdq.com", "pdq",
    RemoteUrl has "pdq.tools", "pdq",
    RemoteUrl has "pulseway.com", "pulseway",
    RemoteUrl has "activate.famatech.com", "RAdmin",
    RemoteUrl has "radminte.com", "RAdmin",
    RemoteUrl has "services.vnc.com", "realVNC",
    RemoteUrl has "update-check.realvnc.com", "realVNC",
    RemoteUrl has "remotepc.com", "remotepc",
    RemoteUrl has "rustdesk.com", "rustdesk",
    RemoteUrl has "screenmeet.com", "screenmeet",
    RemoteUrl has "server-eye.de", "server-eye",
    RemoteUrl has "showmypc.com", "ShowMyPC",
    RemoteUrl has "rmshelp.me", "Simple-Help",
    RemoteUrl has "splashtop.com", "Splashtop",
    RemoteUrl has "splashtop.eu", "Splashtop",
    RemoteUrl has "nanosystems.it", "SupRemo",
    RemoteUrl has "supremocontrol.com", "SupRemo",
    RemoteUrl has "syncromsp.com", "SynchroMSP",
    RemoteUrl has "servably.com", "SynchroMSP",
    RemoteUrl has "syncroapi.com", "SynchroMSP",
    RemoteUrl has "atled.syspectr.com", "Syspectr",
    RemoteUrl has "notify1.syspectr.com", "Syspectr",
    RemoteUrl has "cdn.syspectr.com", "Syspectr",
    RemoteUrl has "app.syspectr.com", "Syspectr",
    RemoteUrl has "tm.syspectr.com", "Syspectr",
    RemoteUrl has "console.syspectr.com", "Syspectr",
    RemoteUrl has "icanhazip.tacticalrmm.io", "TacticalRMM",
    RemoteUrl has "tacticalrmm.io", "TacticalRMM",
    RemoteUrl has "tacticalrmm.com", "TacticalRMM",
    RemoteUrl has "teamviewer.com", "TeamViewer",
    RemoteUrl has "teamviewer.cn", "TeamViewer",
    RemoteUrl has "fixme.it", "TechInline",
    RemoteUrl has "techinline.net", "TechInline",
    RemoteUrl has "set.me", "TechInline",
    RemoteUrl has "tsplus-remotesupport.com", "TSplus",
    RemoteUrl has "secure-download-file.com", "TSplus",
    RemoteUrl has "licenseapi.dl-files.com", "TSplus",
    RemoteUrl has "securityapi.dl-files.com", "TSplus",
    RemoteUrl has "monitoring.tsplus.net", "TSplus",
    RemoteUrl has "ultraviewer.com", "UltraViewer",
    RemoteUrl has "utraviewer.net", "UltraViewer",
    RemoteUrl has "xmreality.com", "XMReality",
    RemoteUrl has "assist.zoho.com", "ZohoAssist",
    RemoteUrl has "assist.zoho.eu", "ZohoAssist",
    RemoteUrl has "assist.zoho.com.au", "ZohoAssist",
    RemoteUrl has "assist.zoho.in", "ZohoAssist",
    RemoteUrl has "assist.zoho.jp", "ZohoAssist",
    RemoteUrl has "assist.zoho.uk", "ZohoAssist",
    RemoteUrl has "assistlab.zoho.com", "ZohoAssist",
    RemoteUrl has "downloads.zohocdn.com", "ZohoAssist",
    RemoteUrl has "download-accl.zoho.in", "ZohoAssist",
    RemoteUrl has "zohoassist.com", "ZohoAssist",
    RemoteUrl has "zohopublic.com", "ZohoAssist",
    RemoteUrl has "zohopublic.eu", "ZohoAssist",
    RemoteUrl has "meeting.zoho.com", "ZohoAssist",
    RemoteUrl has "meeting.zoho.eu", "ZohoAssist",
    RemoteUrl has "static.zohocdn.com", "ZohoAssist",
    RemoteUrl has "zohodl.com.cn", "ZohoAssist",
    RemoteUrl has "zohowebstatic.com", "ZohoAssist",
    RemoteUrl has "zohostatic.in", "ZohoAssist",
    //RMMist2
    RemoteUrl has "wangwang.taobao.com", "AliWangWang-remote-control",
    RemoteUrl has "auvik.com", "Auvik",
    RemoteUrl has "basecamp.com", "Basecamp",
    RemoteUrl has "beananywhere.en.uptodown.com/windows", "BeAnywhere",
    RemoteUrl has "cloudflare.com/products/tunnel/", "CloudFlare Tunnel",
    RemoteUrl has "one.comodo.com", "Comodo RMM",
    RemoteUrl has "crossloop.en.softonic.com", "CrossLoop",
    RemoteUrl has "crosstecsoftware.com/remote-control", "CrossTec Remote Control",
    RemoteUrl has "resources.doradosoftware.com/cruz-rmm", "Cruz",
    RemoteUrl has "deskday.ai", "DeskDay",
    RemoteUrl has "devolutions.net/remote-desktop-manager/", "Devolutions",
    RemoteUrl has "domotz.com", "Domotz",
    RemoteUrl has "ehorus.com", "eHorus",
    RemoteUrl has "electric.ai", "Electric",
    RemoteUrl has "emcosoftware.com", "EMCO Remote Console",
    RemoteUrl has "encapto.com", "Encapto",
    RemoteUrl has "ericom.com", "Ericom Connect/AccessNow",
    RemoteUrl has "eset.com/me/business/remote-management/remote-administrator/", "ESET Remote Administrator",
    RemoteUrl has "ezhelp.co.kr", "ezHelp",
    RemoteUrl has "fastviewer.com", "FastViewer",
    RemoteUrl has "fixme.it", "FixMe.it",
    RemoteUrl has "fortra.com", "Fortra",
    RemoteUrl has "gatherplace.com", "GatherPlace-desktop sharing",
    RemoteUrl has "goverlan.com", "Goverlan",
    RemoteUrl has "guacamole.apache.org", "Guacamole",
    RemoteUrl has "helpbeam.software.informer.com", "HelpBeam",
    RemoteUrl has "01com.com/imintouch-remote-pc-desktop", "I'm InTouch",
    RemoteUrl has "instanthousecall.com", "Instant Housecall",
    RemoteUrl has "intelliadmin.com/remote-control", "IntelliAdmin Remote Control",
    RemoteUrl has "jumpdesktop.com", "Jump Desktop",
    RemoteUrl has "repairtechsolutions.com/kabuto/", "Kabuto",
    RemoteUrl has "kickidler.com", "KickIdler",
    RemoteUrl has "ivanti.com", "LANDesk/RES Automation Manager",
    RemoteUrl has "everywhere.laplink.com", "Laplink Everywhere",
    RemoteUrl has "wen.laplink.com/product/laplink-gold", "Laplink Gold",
    RemoteUrl has "manageengine.com/remote-monitoring-management/", "ManageEngine RMM Central",
    RemoteUrl has "remoteassistance.support.services.microsoft.com", "Microsoft Quick Asssist",
    RemoteUrl has "mikogo.com", "Mikogo",
    RemoteUrl has "myivo-server.software.informer.com", "MyIVO",
    RemoteUrl has "naverisk.com", "Naverisk",
    RemoteUrl has "netreo.com", "Netreo",
    RemoteUrl has "ngrok.com", "ngrok",
    RemoteUrl has "nomachine.com", "NoMachine",
    RemoteUrl has "ocsinventory-ng.org", "OCS inventory",
    RemoteUrl has "parallels.com/products/ras/try", "Parallels Access",
    RemoteUrl has "au.pcmag.com/utilities/21470/webex-pcnow", "Pcnow",
    RemoteUrl has "soti.net/products/soti-pocket-controller", "Pocket Controller",
    RemoteUrl has "qq-messenger.en.softonic.com", "QQ IM-remote assistance",
    RemoteUrl has "www.quest.com/kace/", "Quest KACE Agent",
    RemoteUrl has "systemmanager.ru/dntu.en/rdp_view.htm", "RDPView",
    RemoteUrl has "github.com/stascorp/rdpwrap", "rdpwrap",
    RemoteUrl has "remobo.en.softonic.com", "Remobo",
    RemoteUrl has "donkz.nl", "Remote Desktop Plus",
    RemoteUrl has "remote.it", "Remote.it",
    RemoteUrl has "rmansys.ru", "Remote Manipulator System",
    RemoteUrl has "remotecall.com", "RemoteCall",
    RemoteUrl has "remotepass.com", "RemotePass",
    RemoteUrl has "content.rview.com", "RemoteView",
    RemoteUrl has "royalapps.com", "Royal Server/TS",
    RemoteUrl has "rport.io", "rport",
    RemoteUrl has "rudesktop.ru", "RuDesktop",
    RemoteUrl has "runsmart.io", "RunSmart",
    RemoteUrl has "seetrol.co.kr", "Seetrol",
    RemoteUrl has "senso.cloud", "Senso.cloud",
    RemoteUrl has "skyfex.com", "SkyFex",
    RemoteUrl has "site24x7.com/msp", "Site24x7",
    RemoteUrl has "community.sophos.com/on-premise-endpoint/f/sophos-endpoint-software/5725/sophos-remote-management-system", "Sophos-Remote Management System",
    RemoteUrl has "spyanywhere.com", "SpyAnywhere",
    RemoteUrl has "superops.ai", "SuperOps",
    RemoteUrl has "tailscale.com", "Tailscale",
    RemoteUrl has "tanium.com/products/tanium-deploy", "Tanium Deploy",
    RemoteUrl has "tele-desk.com", "TeleDesktop",
    RemoteUrl has "todesktop.com", "ToDesk",
    RemoteUrl has "acceo.com/turbomeeting/", "TurboMeeting",
    RemoteUrl has "realvnc.com/en/connect/download/vnc", "VNC",
    RemoteUrl has "github.com/Mikej81/WebRDP", "WebRDP",
    RemoteUrl has "weezo.en.softonic.com", "Weezo",
    RemoteUrl has "xeox.com", "XEOX",
    RemoteUrl has "zabbix.com", "Zabbix",
    RemoteUrl has "zerotier.com", "ZeroTier",
    // In either list but not updated in case  
    "Other"
)
| where RMM !in (AuthedRMM)
| extend CanBeWebBased = iff(RMM in (OnlineRMM), "Yes", "No")
| join kind = leftouter RMMCreationEvents on DeviceName, InitiatingProcessSHA1
| where iff(
    isnotempty(FileName)
    and not (FileOriginUrl has_any (RMMDomains)
    or FileOriginReferrerUrl has_any(RMMDomains)
    or FileOriginUrl has_any (RMMDomains2)
    or FileOriginReferrerUrl has_any (RMMDomains2)
    or FileName in (RMMFileNames)), 
FileName contains RMM, skip == "skip")
// Insert URL/File Specific Exclusions Here
| where AdditionalFields1 !contains "image"
    and FileName !endswith ".css"
    and FileName !endswith ".gif"
    and FileName !endswith ".pdf"
// End URL/File Specific Exclusions
| summarize 
    Device = makeset(DeviceName),
    DeviceCount = dcount(DeviceName),
    PotentialFileDownloads = makeset(FileName),
    PotentialFileDownloadHashes = makeset(SHA1),
    PotetntialFileDownloadLocations = makeset(FolderPath),
    FileOriginUrls = makeset(FileOriginUrl),
    FileOriginReferrerUrls = makeset(FileOriginReferrerUrl),
    InitProc = makeset(InitiatingProcessFileName),
    InitHash = makeset(InitiatingProcessSHA1),
    InitFolders = makeset(InitiatingProcessFolderPath),
    DownloadUrls = makeset(RemoteUrl)
by tostring(RMM), CanBeWebBased
| sort by DeviceCount desc
// Optional Render for Presenting Data
//| render barchart
```

</details>
