During the investigation of the incident **"Unauthorized TOR Usage"** , In ==DeviceFileEvents== table it was found that the user "ice" downloaded **"tor-browser-windows-x86_64-portable-15.0.10.exe"** on the device **"karan-mde-vm-win"** at this time : **2026-04-22T13:50:58.7246323Z** .
The tor application was silently installed on the device with the following command :
`"tor-browser-windows-x86_64-portable-15.0.10.exe" /S`.
The user also created a suspicious file **"tor-shopping-list.txt.txt"**.

```kql
DeviceFileEvents
| where DeviceName startswith "karan-mde-vm-"
| where TimeGenerated >= datetime(2026-04-22) and TimeGenerated < datetime(2026-04-23)
| where InitiatingProcessAccountName == "ice"
| where FileName has_any ("tor" , "firefox")
| project TimeGenerated , ActionType , DeviceName , InitiatingProcessAccountName , FileName , FolderPath , InitiatingProcessCommandLine ,InitiatingProcessFileName ,  InitiatingProcessFolderPath , InitiatingProcessParentFileName 
| sort by TimeGenerated asc 
```

---

Then i pivoted to ==DeviceProcessEvents== table and found that the user account **"ice"** on device **"karan-mde-vm-win"** initiated a process where **"tor.exe"**, launched from the Tor Browser directory, was executed by its parent process **"firefox.exe"** at time : **2026-04-22T13:52:55.4505233Z** with standard Tor configuration parameters including **SOCKS proxy on 127.0.0.1:9150 and ControlPort 9151** 

```kql
DeviceProcessEvents
| where DeviceName startswith "karan-mde-vm-"
| where TimeGenerated >= datetime(2026-04-22) and TimeGenerated < datetime(2026-04-23)
| where InitiatingProcessAccountName == "ice"
| where InitiatingProcessFileName has_any ("tor.exe" , "firefox.exe")
| sort by TimeGenerated asc
```

---

I looked into ==DeviceNetworkEvents== table and found that the user **"ice"** made connections to multiple tor sites using tor browser , from which some sites are listed below :

| **Remote IP**  | **Remote Port** | **Remote URL**                       |
| -------------- | --------------- | ------------------------------------ |
| 204.13.164.118 | 443             | https://www.hc366uexfmczfjamp3he.com |
| 192.42.116.70  | 443             | https://www.nvppurmethvcvp.com       |
| 192.87.28.82   | 9001            | https://www.w2cwj7.com               |
| 65.108.136.190 | 465             | https://www.a7kf3.com                |

```kql
DeviceNetworkEvents
| where DeviceName startswith "karan-mde-vm-"
| where TimeGenerated >= datetime(2026-04-22) and TimeGenerated < datetime(2026-04-23)
| where InitiatingProcessFileName has_any ("tor.exe" , "firefox.exe")
| where RemotePort in ("9050", "9150", "9051", "9151", "9001", "443", "465", "80", "9040", "9030", "9053")
| project TimeGenerated , DeviceName , InitiatingProcessAccountName , ActionType = "ConnectionSuccess" , InitiatingProcessFileName, InitiatingProcessCommandLine , InitiatingProcessParentFileName , LocalIP , LocalPort , RemoteIP , RemotePort ,RemoteUrl
| sort by TimeGenerated asc
```

---



