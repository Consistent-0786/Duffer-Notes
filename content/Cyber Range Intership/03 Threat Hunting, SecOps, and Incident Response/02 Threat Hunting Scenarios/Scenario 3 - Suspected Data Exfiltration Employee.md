
- We checked DeviceFileEvents for archive files like .zip, .rar, and .7z. 
- We found several cases where files were compressed and moved to backup folders, suggesting possible data staging.
```kql
DeviceFileEvents
| where DeviceName == "test-mde-vm-win"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith".rar"or FileName endswith ".tar" or FileName endswith".gz"
| sort by Timestamp desc
```
 
![[Pasted image 20260414191503.png|697]]

---

- To analyze in more depth we checked DeviceProcessEvents with the timespan when the zip file was created between 1 minute before and 1 minute after and found that a powershell script "exfiltratedata.ps1" was ran by the user "ice" at this timespan "2026-04-14T07:54:29.0963879Z"
- This powershell script installed the file archiver application named "7z2408-x64.exe" and converted the csv file named "employee-data-temp20260414075429.csv" to zip format "employee-data-20260414075429.zip"
```
let _StartTime = datetime(2026-04-14T07:54:29.0443917Z);
DeviceProcessEvents
| where DeviceName == "test-mde-vm-win"
| where Timestamp between ((_StartTime - 1m) .. (_StartTime + 1m) )
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId, InitiatingProcessId
| sort by Timestamp asc
```

![[Pasted image 20260414200251.png|697]]

---

- We checked DeviceNetworkEvents table to find that is outbound connection made by the powershell script 
- The powershell script made outbound connection with two ip addresses :
	- "20.60.181.193" (url = sacyberrange00.blob.core.windows.net) 
	- "20.60.133.132" (url = sacyberrangedanger.blob.core.windows.net)
```
let _StartTime = datetime(2026-04-14T07:54:29.0443917Z);
DeviceNetworkEvents
| where DeviceName == "test-mde-vm-win"
| where Timestamp between ((_StartTime - 1m) .. (_StartTime + 1m) )
| where InitiatingProcessCommandLine == "powershell.exe  -ExecutionPolicy Bypass -File C:\\programdata\\exfiltratedata.ps1"
| project Timestamp , DeviceName , RemoteIP , RemotePort , RemoteUrl , InitiatingProcessCommandLine
| sort by Timestamp asc
```
![[Pasted image 20260414202540.png]]

---

- I remotely login to the device to analyze the powershell script and to analyze the device
- After analyzing the script , i removed the script and also delete's the scheduled tasks related to the powershell script
- I also delete's the "employee-data" file from the device 

![[Pasted image 20260414203959.png|564]]

---

- **IOC's (Indicators of compromise)**
	-  File-Based IOCs :
		- `exfiltratedata.ps1` (PowerShell script executed on host)
		- `employee-data-temp20260414075429.csv`
		- `employee-data-20260414075429.zip`
		- `7z2408-x64.exe` (7-Zip installer used for compression)
	-  Network IOCs :
		- `20.60.181.193` → `sacyberrange00.blob.core.windows.net`
		- `20.60.133.132` → `sacyberrangedanger.blob.core.windows.net`
	- Host / User IOCs :
		- Device: `test-mde-vm-win`
		- User: `ice`
		- Execution path:
		    - `C:\ProgramData\exfiltratedata.ps1`
	- Process / Execution IOCs :
		- PowerShell execution with bypass flag :
		    - `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\exfiltratedata.ps1`
		- Compression activity using 7-Zip (`7z.exe` / installer execution)
	- Behavioral IOCs :
	- CSV file collected and compressed into ZIP archive
	- Data staging observed via archive creation (`.zip`, `.7z`)
	- Outbound HTTP/S connections to Azure Blob Storage endpoints
	- Possible scheduled task execution/removal linked to script activity

---

- **MITRE ATT&CK Mapping** 

| Observed Activity                                       | MITRE Technique                          | Technique ID |
| ------------------------------------------------------- | ---------------------------------------- | ------------ |
| Collection of CSV file (`employee-data-temp...csv`)     | Data from Local System                   | T1005        |
| Compressing data into `.zip/.7z/.rar` files             | Archive Collected Data                   | T1560.001    |
| Moving compressed files to backup/staging folders       | Data Staged for Exfiltration             | T1074.001    |
| Execution of PowerShell script (`exfiltratedata.ps1`)   | PowerShell                               | T1059.001    |
| PowerShell execution with `-ExecutionPolicy Bypass`     | Impair Defenses: Execution Policy Bypass | T1562.001    |
| Download/installation of 7-Zip (`7z2408-x64.exe`)       | Ingress Tool Transfer                    | T1105        |
| Outbound connections to Azure blob storage endpoints    | Exfiltration to Cloud Storage            | T1567.002    |
| Transfer of compressed employee data outside host       | Exfiltration Over Web Services           | T1567        |
| Use of scripted automation for data handling + transfer | Automated Collection                     | T1119        |
| Potential use of scheduled tasks (created/removed)      | Scheduled Task/Job                       | T1053.005    |

---

**Response :**
- This incident indicates potential data exfiltration activity involving the user **“ice”** on device **“test-mde-vm-win”**, where sensitive business data was staged and transferred externally.
- The affected endpoint was **immediately isolated** to prevent further data exposure.
- A malware scan was conducted; no additional malicious binaries were detected at the time of analysis.
- The suspicious PowerShell script (`exfiltratedata.ps1`) and related artifacts were removed from the system.
- The employee workstation was flagged for **re-imaging to ensure full eradication of any persistence or hidden components**.
- Outbound connections to identified malicious IPs/domains were blocked at the network level.
- The incident was escalated and reported to the relevant department head and security stakeholders for further action.

---

**Improvement :**
- Implement PowerShell security controls such as **Script Block Logging, AMSI integration, and constrained language mode** to improve detection of malicious scripts.
- Enforce **application allowlisting (e.g., blocking unauthorized installers like 7-Zip)** to prevent unauthorized tooling.
- Deploy **Data Loss Prevention (DLP) policies** to detect and prevent compression and transfer of sensitive CSV/employee data.
- Add monitoring rules for **mass file compression and archive creation behavior** as early indicators of staging activity.
- Apply **least privilege access controls** for user accounts to limit ability to execute system-level scripts and tools.

---

- **Lesson Learned :**
	- Need for improved detection of data staging behavior
	- Need for tighter control on scripting tools
	- Need for outbound traffic anomaly detection

---
