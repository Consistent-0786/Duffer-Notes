# Zero Trust 

- Zero Trust is a security strategy , it is not a product or a service
- **There are 3 core principles of Zero Trust:**
	1. **Verify explicitly**
		- Always check who someone is and what they’re doing before giving access (don’t just trust them because they’re inside the network)
	2. **Use least-privilege access**
		- Give users only the minimum access they need to do their job, nothing more
	3. **Assume breach**
		- Act as if the system is already hacked; always monitor, detect, and limit damage quickly
---
# The Microsoft Security Cosmos (Universe)

![[Pasted image 20251026225645.png]]
## Microsoft Defender XDR

- **Purpose:** 
	- Protects *users, devices, apps, emails, and data* across your organization , both on-premises and in the cloud
	- It detects, investigates, and responds to threats automatically
###  Identities

* Protects user accounts and logins (through **Microsoft Defender for Identity**)
* Detects unusual sign-ins, credential theft, and suspicious behavior
* Works with **Microsoft Entra ID (Azure AD)**
### Endpoints

* Protects laptops, desktops, servers, and mobile devices (through **Defender for Endpoint**)
* Detects malware, ransomware, or risky behavior on devices
* Can isolate infected machines automatically
### Apps

* Protects productivity apps like **Microsoft 365**, **Teams**, **SharePoint**, and **OneDrive**
* Monitors for unsafe app activity or malicious file sharing
### Email

* Protects **Exchange Online** and other mail systems (via **Defender for Office 365**)
* Detects phishing, spam, and malicious attachments/links
### Documents

* Scans and protects files shared through SharePoint, OneDrive, and Teams (via **Defender for Office 365**) 
* Uses AI to detect data leaks or malicious file behavior
### Cloud Apps

* Managed by **Defender for Cloud Apps** (formerly Cloud App Security)
* Detects risky app usage, data movement between cloud services, and shadow IT (unapproved apps)

---

## Microsoft Defender for Cloud

- **Purpose:** 
	- Protects your **cloud infrastructure and workloads** (IaaS and PaaS),  whether in **Azure**, **AWS**, **Google Cloud**, or **on-premises**
### SQL Databases

* Monitors for suspicious SQL activity and vulnerabilities
* Protects data stored in cloud databases
### Server VMs (Virtual Machines)

* Secures both Windows and Linux VMs
* Detects malware or misconfigurations on servers
### Containers

* Secures containerized workloads (like **Kubernetes**)
* Detects insecure images or misconfigurations
### Network Traffic

* Monitors data moving between servers and the internet
* Detects unusual or malicious traffic patterns
### IoT Services

* Protects industrial devices and sensors connected to the network
* Detects suspicious behavior in IoT communications
### PaaS Services

* Secures Platform-as-a-Service components (like **App Services** or **Function Apps**)
* Detects code or configuration vulnerabilities

---
## Microsoft Sentinel

- **Purpose:** 
	- Cloud-native **SIEM + SOAR** platform for centralized monitoring, analytics, and automated response
### 1. Data Collection

* Gathers logs and alerts from **Defender XDR**, **Defender for Cloud**, firewalls, servers, and more
* Unifies data from on-premises and multi-cloud sources
### 2. Analytics & Correlation

* Uses built-in rules and **KQL queries** to detect suspicious patterns
* Correlates alerts from multiple sources into one meaningful incident
### 3. Investigation Tools

* Provides interactive dashboards and timelines to analyze attacks
* Lets analysts drill down to find the **root cause** and **affected resources**
### 4. Response & Automation

* Uses **playbooks** (powered by Logic Apps) to automate responses like:
	* Isolating a device
	* Disabling a user account
	* Blocking IPs
	* Enables manual or automatic remediation steps

---

## Integration & Data Flow

1. Collection from Data Sources
	* Data comes from **users, devices, servers, cloud apps**, and **networks**
	* These generate telemetry and logs continuously

2. Alerts & Incidents in XDR
	* Defender XDR analyzes all signals
	* Detects threats and groups related alerts into an **incident** (e.g., phishing + endpoint compromise)

3. Forwarding to Sentinel
	* Defender XDR sends these incidents and alerts to **Microsoft Sentinel**
	* Sentinel combines them with other security data sources

4. Investigation & Response in Sentinel
	* Analysts review incidents in Sentinel’s dashboard
	* Use **hunting queries**, **notebooks**, and **playbooks** for response
	* Responses and updates sync back to Defender XDR to keep both portals consistent
---
## Summary

| No. | Tool                             | Purpose                                                            |
| --- | -------------------------------- | ------------------------------------------------------------------ |
| 1   | **Microsoft Defender XDR**       | Protects users, endpoints, apps, and data.                         |
| 2   | **Microsoft Defender for Cloud** | Protects cloud infrastructure and workloads.                       |
| 3   | **Microsoft Sentinel**           | Collects data, analyzes threats, automates responses.              |
| 4   | **Integration Flow**             | Data & alerts flow upward; investigation & response flow downward. |


