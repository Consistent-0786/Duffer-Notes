# Typically data sources for SIEM

- **Microsoft Sentinel typically ingests data from :**
	- **Applications, Network, Operating Systems, Cloud platforms, and Security tools**  

- These give a SOC full visibility to detect and respond to threats effectively

## 1. Application Layer

- Application layer includes logs from **business applications** to track user activity and actions  
- **Examples :**
	- SAP (access logs, transactions)
	- ServiceNow
	- Workday

- It focuses on **application behavior**, not the server OS

## 2. Network Layer

- Network Layer includes logs that **show network traffic** and security events
- **Examples :**
	- Azure Firewall
	- Network Security Groups (NSGs)
	- Web Application Firewall (WAF)
	- On-prem firewalls and proxies
	- AWS/GCP network logs

## 3. Operating System Layer

- Operating System Layer includes logs from **servers and endpoints** for visibility into system activity
- **Examples :**
	- Windows Security Event Logs    
	- Linux Syslog    
	- macOS logs    

## 4. Cloud Platform 

- Cloud Platform includes logs that track changes and access to cloud resources
- **Examples :**
	- Microsoft Entra ID sign-in and audit logs    
	- Azure Activity Logs    
	- Also logs from **other cloud platforms** such as : 
		- AWS S3
		- CloudTrail logs

## 5. Security Solutions

- Security Solutions includes Alerts and logs from security tools
- **Examples :**
	- Microsoft Defender for Endpoint    
	- Defender for Cloud    
	- Microsoft Purview    
	- Third-party EDR or security tools

![[Pasted image 20260121152335.png]]

---

