# Detection and Analysis

- Three (3) virtual machines were targeted by brute-force login attempts originating from three (3) distinct external IP addresses.
- The observed activity consists of multiple failed authentication attempts (`LogonFailed`) within a short time window, indicating a likely brute-force or password-spraying attempt.

### Impacted Assets and Source IPs

- **tareq-linux-programmatic-fix.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net**  
    → Source IP: 116.34.14.135 (119 failed attempts)
- **ws-2927**  
    → Source IP: 185.156.73.69 (100 failed attempts)
- **flovmreal**  
    → Source IP: 217.154.234.156 (65 failed attempts)

### Failed Logon Activity

```
let _host_device_names = dynamic(["ws-2927", "tareq-linux-programmatic-fix", "flovmreal"]);  
let _malicious_remote_ip = dynamic (["217.154.234.156" , "185.156.73.69" , "116.34.14.135"]);  
DeviceLogonEvents  
| where TimeGenerated > ago(6h)  
| where ActionType == "LogonFailed"  
| where DeviceName has_any (_host_device_names)  
| where RemoteIP in (_malicious_remote_ip)  
| summarize Event_Count = count() by DeviceName , ActionType , RemoteIP  
| where Event_Count >= 10  
| sort by Event_Count desc 
```

- The query confirms repeated failed logon attempts from each malicious IP against the respective virtual machines.
- The volume and pattern are consistent with automated brute-force activity.

---

### Successful Logon Validation

To determine whether the attack resulted in a compromise, successful logon events were investigated.

```
let _host_device_names = dynamic(["ws-2927", "tareq-linux-programmatic-fix", "flovmreal"]);  
let _malicious_remote_ip = dynamic (["217.154.234.156" , "185.156.73.69" , "116.34.14.135"]);  
DeviceLogonEvents  
| where TimeGenerated > ago(6h)  
| where ActionType != "LogonFailed"  
| where DeviceName has_any (_host_device_names)  
| where RemoteIP in (_malicious_remote_ip)  
| summarize Event_Count = count() by DeviceName , ActionType , RemoteIP  
| where Event_Count >= 10  
| sort by Event_Count desc 
```

- No successful logon attempts were identified from the malicious IP addresses.
- This indicates that the brute-force attempts **did not result in unauthorized access** during the investigated timeframe.

---

# Containment

- The impacted virtual machines were isolated to prevent further unauthorized access attempts.
- Network Security Group (NSG) rules were updated to:
    - Block inbound access from the identified malicious IP addresses
    - Restrict RDP/SSH access to trusted IP ranges only
    - Enforce access via Azure Bastion where applicable
- A full antivirus/endpoint scan was conducted on all affected systems:
    - No malicious artifacts or post-compromise activity were detected

---

# Recommendations

- Enforce **Multi-Factor Authentication (MFA)** for all remote access (RDP/SSH).
- Implement **strong password policies**:
    - Minimum length (≥12 characters)
    - Complexity requirements
    - Account lockout after multiple failed attempts
- Avoid exposing RDP/SSH ports (3389/22) directly to the internet.
- Use :
    - Azure Bastion
    - VPN-based access
- Regularly review NSG rules for overly permissive access.
- Configure account lockout thresholds to mitigate brute-force attempts.

---

