- test-mde-vm-win local machine was found establishing failed connection attempts to remote ip ("10.0.0.198", "10.0.0.155")

- Overall fourty nine(49) failed attempts was performed by test-mde-vm-win on targeted remote ip

```

DeviceNetworkEvents

| where DeviceName == "test-mde-vm-win"

| where ActionType == "ConnectionFailed"

| summarize FailedConnectionAttempts = count() by DeviceName , ActionType , LocalIP , RemoteIP

| sort by FailedConnectionAttempts desc

  

```
![[Pasted image 20260414174459.png]]


---


- After further analysis , i discovered that test-mde-vm-win machine was performing port scanning on the remote ip ("10.0.0.198", "10.0.0.155")

- This port scanning occurred from Apr 12, 2026 2:45:20 PM till Apr 12, 2026 2:50:50 PM time

```

DeviceNetworkEvents

| where DeviceName == "test-mde-vm-win"

| where ActionType == "ConnectionFailed"

| where RemoteIP has_any ("10.0.0.198", "10.0.0.155")

```

---

- I pivoted to DeviceFileEvents table to find suspicious file executed at which the port scan started.

- I found that there was a suspicious file name = portscan.ps1 was executed at 2026-04-12T09:15:20.2380099Z timestamp

```

let _StartTime = datetime(2026-4-12T02:45:20);

DeviceFileEvents

| where DeviceName == "test-mde-vm-win"

| summarize Count = count() by Timestamp, DeviceName, FileName , InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath

| sort by Timestamp asc

```
![[Pasted image 20260414174505.png]]
 

---

- Then i logged in to the "test-mde-vm-win" suspected system and observed the powershell script named "portscan.ps1" that was used to perform port scan
![[Pasted image 20260414174510.png]]
  

---

- I observed that the port scan was launched by the "ice" account name , the system owner confirmed that this action was not performed by him and this is also not something that was setup by the Admin's

- This seems to be done by the "unknown entity**" that has compromised system account , so i isolate the device and ran a malware scan**

---

**- The malware scan output no results , so** **Cautiously i remained the device isolated and created a ticket to re-image the device**

---

**MITRE ATT&CK Mapping :**  
  
Tactic: Discovery  
Technique: T1046 - Network Service Scanning  
  
Tactic: Execution  
Technique: T1059.001 - Command and Scripting Interpreter: PowerShell  
  
Tactic: Initial Access / Persistence (Potential)  
Technique: T1078 - Valid Accounts (use of "ice" account by unknown entity)

---

- **Response** :**
- Containment :
	- Keep the affected host (test-mde-vm-win) isolated from the network
	- Disable or reset credentials for the "ice" account

- Eradication :
	- Remove the malicious script (portscan.ps1)
	- Perform full AV + EDR deep scan (including memory scan)
	- Check for persistence mechanisms (scheduled tasks, registry run keys, services)

- Investigation :
	- Review login activity for "ice" account (lateral movement / credential misuse)
	- Analyze PowerShell logs (ScriptBlockLogging, ModuleLogging)
	- Correlate with other hosts for similar scanning behavior

- Recovery :
	- Re-image the system 
	- Restore from a known clean backup if needed
	- Rejoin to domain with hardened configuration

- Hardening :
	- Enforce least privilege on user accounts
	- Enable PowerShell logging & attack surface reduction rules
	- Apply network segmentation to limit internal scanning

- Monitoring :
	- Set alerts for port scanning behavior (T1046)
	- Monitor failed connection spikes and abnormal scripting activity

---
