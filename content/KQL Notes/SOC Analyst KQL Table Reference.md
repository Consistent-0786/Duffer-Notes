# SOC Analyst KQL Table Reference + MITRE ATT&CK Mapping


<div style="position: relative; width: 100%; height: 70vh;">

  <!-- Full View Button -->
  <a href="https://docs.google.com/spreadsheets/d/e/2PACX-1vSDOlf3cXzMBxoUQ3meHwwTpMXj-1s23IH19xdZGZ6awO9WYq89bKiU9Ce7sCTjJ-_Vauf1V1Hxo0yj/pubhtml"
     target="_blank"
     style="position:absolute; top:10px; right:10px; z-index:10; 
            padding:8px 12px; background:#4CAF50; color:white; 
            text-decoration:none; border-radius:5px;">
    ⛶ Full View
  </a>

  <!-- Iframe -->
  <iframe 
    src="https://docs.google.com/spreadsheets/d/e/2PACX-1vSDOlf3cXzMBxoUQ3meHwwTpMXj-1s23IH19xdZGZ6awO9WYq89bKiU9Ce7sCTjJ-_Vauf1V1Hxo0yj/pubhtml?widget=true&headers=false"
    style="width:100%; height:100%; border:none;">
  </iframe>

</div>


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
