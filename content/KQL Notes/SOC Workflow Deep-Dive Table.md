# SOC Workflow Deep-Dive Table (Microsoft Accordingly)

- ==This Table covers **Detect → Investigate → Respond**, includes **specific tables**, **columns to check**, **MITRE ATT&CK mapping**, and **SOC analyst actions**==
- ==This will be a **practical reference for analysts**==

|Stage|Action / Purpose|Relevant Tables (KQL)|Key Columns to Check|MITRE ATT&CK Mapping|SOC Analyst Action / Example|
|---|---|---|---|---|---|
|**Detect**|Spot anomalies or suspicious activity|`SecurityAlert` (MDE)|`AlertName`, `Severity`, `DeviceName`, `Timestamp`|T1059, T1071, T1086, T1486|Identify high-severity malware or ransomware alerts|
|||`SigninLogs` (Entra ID)|`UserPrincipalName`, `ResultType`, `IPAddresses`|T1078, T1110|Detect impossible travel or brute-force login attempts|
|||`AzureActivity` (Mgmt Plane)|`OperationName`, `Caller`, `ResourceId`|T1078, T1087, T1484|Detect unexpected resource deletion, creation, or role changes|
|||`DeviceNetworkEvents` (MDE)|`RemoteIP`, `RemoteUrl`, `Protocol`|T1041, T1071|Detect unusual external connections / potential C2 communication|
|**Investigate**|Analyze and trace root cause|`DeviceProcessEvents` (MDE)|`ProcessName`, `ProcessCommandLine`, `InitiatingProcessFileName`|T1059, T1086, T1204|Trace suspicious processes; identify malware execution path|
|||`DeviceFileEvents` (MDE)|`FileName`, `FilePath`, `ActionType`|T1486, T1055|Find affected files or dropped malware|
|||`DeviceRegistryEvents` (MDE)|`RegistryKey`, `RegistryValueName`, `ActionType`|T1547, T1112|Check persistence mechanisms (auto-start entries, config changes)|
|||`DeviceImageLoadEvents` (MDE)|`FileName`, `DeviceName`, `InitiatingProcessFileName`|T1055|Detect DLL injections or suspicious binaries|
|||`AuditLogs` / `ServicePrincipalSignInLogs` / `NonInteractiveUserSignInLogs` (Entra ID)|`ActivityDisplayName`, `TargetResources`, `ResultType`|T1078, T1550|Detect privilege escalation, unauthorized app/service logins|
|||`AzureDiagnostics`, `KeyVaultLogs`, `StorageBlobLogs` (Azure Resource)|`OperationName`, `RequestStatus`, `ClientIP`|T1041, T1567, T1552, T1550|Trace which resources or secrets were accessed or modified|
|**Respond**|Contain threat and remediate|Actions based on findings from all tables|N/A|N/A|Quarantine infected endpoints; disable compromised accounts; restore deleted Azure resources; block malicious IPs; trigger SOAR playbooks|

---
# SOC Workflow Tree

**SOC Workflow: Detect → Investigate → Respond**

├── **Detect (Spot suspicious activity)**
│   ├── SecurityAlert (MDE) [T1059, T1071, T1086, T1486]
│   ├── SigninLogs (Entra ID) [T1078, T1110]
│   ├── AzureActivity (Mgmt Plane) [T1078, T1087, T1484]
│   └── DeviceNetworkEvents (MDE) [T1041, T1071]
│
├── **Investigate (Analyze & trace root cause)**
│   ├── DeviceProcessEvents (MDE) [T1059, T1086, T1204]
│   ├── DeviceFileEvents (MDE) [T1486, T1055]
│   ├── DeviceRegistryEvents (MDE) [T1547, T1112]
│   ├── DeviceImageLoadEvents (MDE) [T1055]
│   ├── AuditLogs (Entra ID) [T1078, T1098]
│   ├── ServicePrincipalSignInLogs (Entra ID) [T1078]
│   ├── NonInteractiveUserSignInLogs (Entra ID) [T1078, T1550]
│   ├── AzureDiagnostics (Azure Resource) [T1070, T1486]
│   ├── KeyVaultLogs (Azure Resource) [T1552, T1550]
│   └── StorageBlobLogs / StorageFileLogs (Azure Resource) [T1041, T1567]
│
└── **Respond (Contain & remediate)**
    ├── Quarantine infected endpoints
    ├── Disable compromised accounts
    ├── Restore deleted resources
    ├── Block malicious IPs
    └── Trigger automated playbooks (SOAR)

---
# ✅ How to Read This Tree :

1. **Detect :** 
	- Start with high-level alerts or anomalous activity
2. **Investigate :** 
	- Drill into **endpoint, identity, and Azure logs** to understand the full attack chain
3. **Respond :** 
	- Take **remediation actions** on endpoints, accounts, and cloud resources

---
