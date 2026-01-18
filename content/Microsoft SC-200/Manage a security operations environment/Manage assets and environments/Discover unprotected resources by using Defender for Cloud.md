# Defender for Cloud

- Microsoft Defender for Cloud is a **unified [CNAPP (Cloud-Native Application Protection Platform)](https://share.google/aimode/7xk6O6Qn63Dign8kq)** security solution that protects cloud environments from code to runtime.
- It provides security **across the entire lifecycle of cloud applications** from development to production

- It also **support Multi-Cloud & Hybrid Support protection that includes :** 
	- Azure
	- AWS
	- Google Cloud (GCP)
	- On-premises servers
	- On-premises Kubernetes and databases
- All environments are managed from **one unified platform**

## Defender for Cloud implements CNAPP through 3 core pillars

### 1. DevSecOps Security

- Defender for Cloud integrates with :
	- GitHub    
	- Azure DevOps    
	- GitLab

- It Scans source code repositories    
- Detects misconfigurations in **Infrastructure as Code (IaC)**    
- Finds exposed secrets in code    
- Identifies vulnerable libraries and CVEs

	- **Example :**
		- A virtual machine defined with insecure settings in IaC
		- A Python package with a known vulnerability
		- A hardcoded secret in source code

- Issues are identified **before deployment**, reducing risk early

### 2. Cloud Security Posture Management (CSPM)

- Defender for Cloud continuously assesses **all existing cloud resources**
	- It Identifies misconfigurations in live environments
	- It Provides security recommendations and gives step-by-step remediation guidance
	- Improves ==Secure Score==

### 3. Cloud Workload Protection

- This pillar focuses on **active threat detection and response**
- It protects (Virtual Machines, Databases (e.g., Cosmos DB), App Services, Kubernetes clusters / Containers

- It Detects real-time threats    
- Monitors suspicious behavior    
- Alerts on active attacks   

- This is **reactive security**, focused on stopping threats during runtime

![[Pasted image 20260118192837.png]]