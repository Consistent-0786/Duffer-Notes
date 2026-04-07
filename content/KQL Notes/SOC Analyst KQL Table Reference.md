# SOC Analyst KQL Table Reference + MITRE ATT&CK Mapping

<iframe src="https://docs.google.com/spreadsheets/d/e/2PACX-1vSDOlf3cXzMBxoUQ3meHwwTpMXj-1s23IH19xdZGZ6awO9WYq89bKiU9Ce7sCTjJ-_Vauf1V1Hxo0yj/pubhtml?widget=true&amp;headers=false"></iframe>




| Source / Data Connector                   | Table Name                     | Purpose / Description                                                           | Key Columns (Examples)                                          | Common SOC Use Case                                      | MITRE ATT&CK Mapping       |
| ----------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------- | -------------------------- |
| **Microsoft Defender for Endpoint (MDE)** | `SecurityAlert`                | Aggregated alerts from MDE, combining suspicious events into actionable alerts. | `AlertName`, `Severity`, `DeviceName`, `Timestamp`, `Status`    | Triage incidents, detect malware/ransomware alerts       | T1059, T1071, T1486, T1086 |
|                                           | `DeviceProcessEvents`          | Tracks process creation and execution on endpoints.                             | `DeviceName`, `ProcessCommandLine`, `InitiatingProcessFileName` | Detect malware execution, suspicious PowerShell commands | T1059, T1086, T1204        |
|                                           | `DeviceFileEvents`             | File creation, modification, deletion events.                                   | `FileName`, `FilePath`, `ActionType`                            | Identify dropped malicious files, ransomware activity    | T1486, T1055               |
|                                           | `DeviceNetworkEvents`          | Endpoint network connections (inbound/outbound).                                | `RemoteUrl`, `RemoteIP`, `Protocol`                             | Detect C2 communication, data exfiltration               | T1041, T1071               |
|                                           | `DeviceLogonEvents`            | User logons on endpoints.                                                       | `AccountName`, `LogonType`, `DeviceName`                        | Investigate lateral movement, brute-force attempts       | T1078, T1021               |
|                                           | `DeviceRegistryEvents`         | Registry key modifications on endpoints.                                        | `RegistryKey`, `RegistryValueName`, `ActionType`                | Detect persistence or malware configuration changes      | T1547, T1112               |
|                                           | `DeviceImageLoadEvents`        | DLLs and binaries loaded into processes.                                        | `DeviceName`, `FileName`, `InitiatingProcessFileName`           | Detect DLL injection or suspicious binaries              | T1055                      |
|                                           | `DeviceEvents`                 | Catch-all for miscellaneous security events.                                    | Varies by event type                                            | General investigation, correlation with alerts           | T1059, T1043               |
| **Microsoft Entra ID (Azure AD)**         | `SigninLogs`                   | All user sign-in attempts (success/failure).                                    | `UserPrincipalName`, `ResultType`, `IPAddresses`                | Detect suspicious logins, impossible travel              | T1078, T1110               |
|                                           | `AuditLogs`                    | Tenant-wide directory changes (users, roles, apps).                             | `ActivityDisplayName`, `TargetResources`, `InitiatedBy`         | Detect privilege escalation, unauthorized changes        | T1078, T1098               |
|                                           | `NonInteractiveUserSignInLogs` | Background or token-based logins (apps/scripts).                                | `AppId`, `UserPrincipalName`, `ResultType`                      | Detect service account abuse, token theft                | T1078, T1550               |
|                                           | `ServicePrincipalSignInLogs`   | App/service logins.                                                             | `AppId`, `ResultType`, `CallerIpAddress`                        | Detect compromised apps                                  | T1078                      |
|                                           | `ManagedIdentitySignInLogs`    | Azure resource identity logins.                                                 | `AppId`, `ResourceId`, `ResultType`                             | Abuse of managed identities                              | T1078, T1550               |
| **Azure Management Plane**                | `AzureActivity`                | Management operations on Azure resources.                                       | `OperationName`, `Caller`, `ResourceId`                         | Track resource creation, deletion, permission changes    | T1078, T1087, T1484        |
| **Azure Resource Logs (Data Plane)**      | `AzureDiagnostics`             | Diagnostic logs from multiple Azure services.                                   | `Category`, `OperationName`, `Resource`                         | Investigate resource-specific events and anomalies       | T1070, T1486               |
|                                           | `StorageBlobLogs`              | Blob storage access and operation logs.                                         | `RequestStatus`, `AuthenticationType`, `ClientIP`               | Detect unauthorized data access or exfiltration          | T1041, T1567               |
|                                           | `StorageFileLogs`              | File storage access logs.                                                       | `RequestStatus`, `ClientIP`, `AuthenticationType`               | Detect suspicious file operations                        | T1041, T1567               |
|                                           | `KeyVaultLogs`                 | Access to Azure Key Vault secrets and keys.                                     | `OperationName`, `ResultType`, `CallerIpAddress`                | Detect suspicious secret retrieval attempts              | T1552, T1550               |
|                                           | `AppServiceHTTPLogs`           | HTTP request logs for App Services.                                             | `HttpStatus`, `RequestUri`, `ClientIp`                          | Detect web attacks, suspicious HTTP requests             | T1190, T1071               |
|                                           | `NetworkSecurityGroupEvent`    | NSG flow logs capturing network traffic flow data.                              | `SourceIP`, `DestinationIP`, `Action`                           | Analyze allowed/denied traffic for anomalies             | T1040, T1041               |
|                                           | `AzureFirewallLogs`            | Logs from Azure Firewall actions.                                               | `RuleName`, `SourceIP`, `DestinationIP`, `Action`               | Detect blocked or allowed suspicious traffic             | T1040, T1041               |

---

# **SOC Analyst KQL Table Tree** :

**SOC Analyst KQL Table Reference :**
```text

├── **Microsoft Defender for Endpoint (MDE)**
│   ├── SecurityAlert (T1059, T1071, T1086, T1486)
│   ├── DeviceProcessEvents (T1059, T1086, T1204)
│   ├── DeviceFileEvents (T1486, T1055)
│   ├── DeviceNetworkEvents (T1041, T1071)
│   ├── DeviceLogonEvents (T1078, T1021)
│   ├── DeviceRegistryEvents (T1547, T1112)
│   ├── DeviceImageLoadEvents (T1055)
│   └── DeviceEvents (T1059, T1043)
│
├── **Microsoft Entra ID (Azure AD)**
│   ├── SigninLogs (T1078, T1110)
│   ├── AuditLogs (T1078, T1098)
│   ├── NonInteractiveUserSignInLogs (T1078, T1550)
│   ├── ServicePrincipalSignInLogs (T1078)
│   └── ManagedIdentitySignInLogs (T1078, T1550)
│
├── **Azure Management Plane**
│   └── AzureActivity (T1078, T1087, T1484)
│
└── **Azure Resource Logs (Data Plane)**
    ├── AzureDiagnostics (T1070, T1486)
    ├── StorageBlobLogs (T1041, T1567)
    ├── StorageFileLogs (T1041, T1567)
    ├── KeyVaultLogs (T1552, T1550)
    ├── AppServiceHTTPLogs (T1190, T1071)
    └── NetworkSecurityGroup / AzureFirewallLogs (T1040, T1041)
```

---
