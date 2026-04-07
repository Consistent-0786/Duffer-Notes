# SOC Workflow Deep-Dive Action Table 

- This Table covers ==**Detect → Investigate → Respond**==, includes **specific tables**, **columns to check**, **MITRE ATT&CK mapping**, and **SOC analyst actions**

- This will be a **practical reference for analysts**

<div style="position: relative; width: 100%; height: 70vh;">

  <!-- Full View Button -->
  <a href="https://docs.google.com/spreadsheets/d/e/2PACX-1vSVb7B2Wxb2kIAiCRH6DAPy8Ti7l0GRcrb64VmWMCSdY9ax37cI6Ig0OdAFhhVzUcNwFfSBC-2X2K-f/pubhtml"
     target="_blank"
     style="position:absolute; top:10px; right:10px; z-index:10; 
            padding:8px 12px; background:#4CAF50; color:white; 
            text-decoration:none; border-radius:5px;">
    ⛶ Full View
  </a>

  <!-- Iframe -->
  <iframe 
    src="https://docs.google.com/spreadsheets/d/e/2PACX-1vSVb7B2Wxb2kIAiCRH6DAPy8Ti7l0GRcrb64VmWMCSdY9ax37cI6Ig0OdAFhhVzUcNwFfSBC-2X2K-f/pubhtml?widget=true&amp;headers=false"
    style="width:100%; height:100%; border:none;">
  </iframe>

</div>


---
# SOC Workflow Tree

**SOC Workflow: Detect → Investigate → Respond**

```text
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

```
---
# ✅ How to Read This Tree :

1. **Detect :** 
	- Start with high-level alerts or anomalous activity
2. **Investigate :** 
	- Drill into **endpoint, identity, and Azure logs** to understand the full attack chain
3. **Respond :** 
	- Take **remediation actions** on endpoints, accounts, and cloud resources

---
