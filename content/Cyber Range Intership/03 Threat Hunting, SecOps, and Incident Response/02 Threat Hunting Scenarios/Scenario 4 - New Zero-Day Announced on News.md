- We checked for **DeviceFileEvents** for files extensions like "**.pwncrypt.**" 
- We found several files that were renamed by added "**.pwncrypt.**" extension  in "**test-mde-vm-win**" device
```
DeviceFileEvents
| where DeviceName == "test-mde-vm-win"
| where FileName contains "pwncrypt"
```

![[Pasted image 20260415185824.png]]

---

- On further analysis , we suspected that "**PwnCrypt**" ransomware specifically target files in "**desktop**" folder
- Several files has been encrypted in the "**desktop**" folder
```
DeviceFileEvents
| where DeviceName == "test-mde-vm-win"
| where FileName contains "pwncrypt"
| where FolderPath contains "Desktop"
|| project Timestamp , DeviceName , FileName , FolderPath , ActionType
| sort by Timestamp asc
```
![[Pasted image 20260415192445.png]]

---

- To analyze in-depth we checked **DeviceProcessEvents** with the timespan when the ransomware file was created between 1 minute before and 1 minute after and found that a file "**pwncrypt.ps1**" was executed by the user "**ice**" at timestamp -> "2026-04-15T13:00:37.0962466Z" with command -> ""**cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1**"
- The ransomware "**pwncrypt.ps1**" file size is "**454656**"  bytes
```
let _StartTime = datetime(2026-04-15T13:00:37.076653Z);
DeviceProcessEvents
| where DeviceName == "test-mde-vm-win"
| where Timestamp between ((_StartTime - 1m ) .. (_StartTime + 1m))
| where ProcessCommandLine contains "pwncrypt"
| project Timestamp , DeviceName , FileName , ProcessCommandLine , nitiatingProcessCommandLine , FileSize , AccountName
| sort by Timestamp asc
```
![[Pasted image 20260415194719.png]]

---

- We again checked the **DeviceFileEvents table** , we found that before encrypting the file's in desktop folder , the ransomware file "**pwncrypt.ps1**" created two more files i.e. "**PSScriptPolicyTest_3i0h2pqs.zmr.ps1**" and "**PSScriptPolicyTest_0bhkkfke.w3f.psm1**" 
```
let _StartTime = datetime(2026-04-15T13:00:37.076653Z);
DeviceFileEvents
| where DeviceName == "test-mde-vm-win"
| where Timestamp between ((_StartTime - 1m ) .. (_StartTime + 1m))
| project Timestamp , DeviceName , ActionType , FileName ,InitiatingProcessCommandLine , FolderPath , PreviousFolderPath , InitiatingProcessFolderPath
| sort by Timestamp asc
```
![[Pasted image 20260415201532.png]]

---

- We then checked **DeviceNetworkEvents** table in the same timespan format to analyze that the any outbound connection's were made by the ransomware file "**pwncrypt.ps1**"
- Based on the results we found **no outbound connection's** made by the ransomware file
```
let _StartTime = datetime(2026-04-15T13:00:37.076653Z);
DeviceNetworkEvents
| where DeviceName == "test-mde-vm-win"
| where Timestamp between ((_StartTime - 1m ) .. (_StartTime + 1m))
| where InitiatingProcessCommandLine contains "pwncrypt"
| sort by Timestamp asc
```

---

- **IOC's (Indicators of Compromise) :** 
	- File-Based IOCs :
		- `pwncrypt.ps1` (Ransomware PowerShell script executed on host)
		- `PSScriptPolicyTest_3i0h2pqs.zmr.ps1` (Temporary script file created)
		- `PSScriptPolicyTest_0bhkkfke.w3f.psm1` (Temporary module file created)
		- `*.pwncrypt` (Encrypted files with ransomware extension)
	- Network IOCs :
		- No outbound network connections observed

---

- **Events Timeline :**
	- Ransomware file "pwncrypt.ps1" was created at `->`` 2026-04-15T13:00:37.076653Z `
	- Ransomware sub created file :
		- First file "PSScriptPolicyTest_3i0h2pqs.zmr.ps1" was created at `->` `2026-04-15T13:00:37.2040911Z`
		- Second File "PSScriptPolicyTest_0bhkkfke.w3f.psm1" was created at `->` `2026-04-15T13:00:37.2043895Z`
	- Encrypted files in desktop folder happend from  
		- Start time `->` `2026-04-15T13:00:37.5003334Z` till End time `->` `2026-04-15T13:00:37.6070511Z`

---
- **MITRE ATT&CK Mapping** **:**

| Observed Activity                                      | MITRE Technique                               | Technique ID |
| ------------------------------------------------------ | --------------------------------------------- | ------------ |
| PowerShell script execution via cmd with bypass policy | Command and Scripting Interpreter: PowerShell | T1059.001    |
| Script executed by user `ice`                          | User Execution                                | T1204        |
| Use of ExecutionPolicy Bypass                          | PowerShell (Defense Evasion)                  | T1059.001    |
| Creation of PSScriptPolicyTest temporary script files  | Obfuscated/Compressed Files and Information   | T1027        |
| Targeting Desktop folder for file operations           | File and Directory Discovery                  | T1083        |
| File encryption with `.pwncrypt` extension             | Data Encrypted for Impact                     | T1486        |

---

**Response :**

- This incident indicates a **ransomware infection (PwnCrypt)** executed by user **“ice”** on device **“test-mde-vm-win”**, resulting in rapid file encryption within the Desktop directory.
- The affected endpoint was **immediately isolated** to prevent further spread or lateral movement.
- A full antivirus and EDR scan was conducted to identify any additional malicious artifacts or persistence mechanisms.
- The malicious PowerShell script (`pwncrypt.ps1`) along with associated temporary files were **identified and removed**.
- Encrypted files (`*.pwncrypt`) were contained, and recovery procedures (backup restoration if available) were initiated.
- Since no outbound communication was detected, risk of data exfiltration is **considered low**, but monitoring was continued.
- The system was marked for **full re-imaging** to ensure complete eradication of the ransomware.
- The incident was escalated to security stakeholders, and **preventive controls (PowerShell restrictions, execution policy enforcement, user awareness)** were recommended.

---

**Improvements :**

- Enforce **PowerShell Constrained Language Mode** and restrict use of `-ExecutionPolicy Bypass`.
- Implement **Application Control (e.g., allowlisting)** to block unauthorized script execution.
- Enable **Controlled Folder Access** to prevent unauthorized encryption of sensitive directories like Desktop.
- Apply **least privilege access** to limit user ability to execute scripts from sensitive paths (e.g., `ProgramData`).
- Maintain **regular, offline backups** to ensure quick recovery from ransomware incidents.
- Enhance **user awareness training** to reduce risk of malicious script execution.
- Monitor and alert on **suspicious file creation patterns** (e.g., `PSScriptPolicyTest_*` files).
- Implement **network segmentation** to reduce potential spread, even though no C2 was observed.

---

**Lessons Learned :**

- PowerShell misuse (bypass) is a key attack vector.
- Ransomware can encrypt files within seconds → need real-time detection.
- Monitor mass file changes and extension modifications.
- User-level access can cause major impact → enforce least privilege.
- No C2 does not mean low impact (offline ransomware).
- Backups are critical for recovery.

---
