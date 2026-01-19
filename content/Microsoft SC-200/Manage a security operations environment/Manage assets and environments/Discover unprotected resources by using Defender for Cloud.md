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

---

# CSPM (Cloud Security Posture Management) | CWP (Cloud Workload Protection)

## CSPM (Cloud Security Posture Management)

- CSPM focuses on **_assessing and improving the security posture_** of your cloud environment across **Azure, AWS, and Google Cloud**
- It **continuously scans for :**
	- Misconfigurations
	- Compliance gaps vs security standards    
	- Risk exposures across cloud services and resources    
	- Secure Score    
	- Policy recommendations and prioritized remediation guidance
### CSPM Plans

- Microsoft Defender for Cloud offers **two CSPM tiers** :

|Plan|What You Get|Cost|
|---|---|---|
|**Foundational CSPM**|Continuous security posture assessment, Secure Score, recommendations, baseline compliance checks|**Free** (enabled by default) ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management?utm_source=chatgpt.com "What is Cloud Security Posture Management (CSPM) - Microsoft Defender for Cloud \| Microsoft Learn"))|
|**Defender CSPM (Paid)**|All foundational capabilities **plus** advanced posture features like agentless cloud vulnerability scanning, attack path analysis, risk prioritization, DevOps posture integration, cloud security graph insights|**Paid** (billed per billable resource) ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management?utm_source=chatgpt.com "What is Cloud Security Posture Management (CSPM) - Microsoft Defender for Cloud \| Microsoft Learn"))|

## CWP (Cloud Workload Protection)

- CWP focuses on **runtime threat protection** and **_active defense_** for ==cloud workloads such as Virtual Machines (VMs), Containers / Kubernetes, Databases, Storage, Serverless functions==    
- **It includes :**
	- Threat detection & response    
	- Anomaly detection    
	- Runtime vulnerability scanning    
	- Malware scanning    
	- Behavior analytics
### CWP Plans

- Defender for Cloud doesn’t have a single traditional “CWP plan” like CSPM, instead it offers **workload-specific paid plans**, such as :

| **CWP Workload Protection Plans**    | **Focus**                                                                                                               |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| **Defender for Servers Plan 1 (P1)** | Entry-level server protection with EDR via Microsoft Defender for Endpoint                                              |
| **Defender for Servers Plan 2 (P2)** | Full server protection: EDR, agentless vulnerability scanning, malware detection, JIT access, file integrity monitoring |
| **Defender for Containers**          | Security for Kubernetes & container workloads (image scanning + runtime threat detection)                               |
| **Defender for App Service**         | Runtime protection for Azure App Services (web app attack detection)                                                    |
| **Defender for Databases**           | Threat detection, anomaly detection, and SQL attack protection for databases                                            |
| **Defender for Storage**             | Malware scanning and suspicious access detection for storage accounts                                                   |
| **Defender for Key Vault**           | Protection for secrets, keys, and certificates with suspicious access alerts                                            |
| **Defender for Resource Manager**    | Control-plane protection: detects malicious deployments and ARM abuse                                                   |
| **Defender for APIs**                | API attack detection and abnormal API behavior monitoring                                                               |

---

# Defender For Cloud : RBAC 

- Defender for cloud **also comes with an RBAC (Role-Based Access Control) model**, meaning there are **pre-built RBAC roles** existing for defender for cloud environment
- We can also build our **Custom RBAC Model** apart from existing **pre-built RBAC roles**

- There are several **Pre-Built RBAC Roles** that are :

![[Pasted image 20260119160027.png]]

---

# Defender for Cloud : Asset Inventory

- **Asset Inventory** in **Microsoft Defender for Cloud** gives you a **centralized view of all cloud resources** across your environments
- It is a one dashboard to **see all cloud resources and their security risk**

- It lists **all cloud assets** like (**Azure, AWS, and GCP**) in one place 
- Helps understand **what we have**, **where it is**, and **its security state**

- In Asset Inventory **for each asset, we can view :**
	- Resource type (VM, storage, database, container, etc.)    
	- Cloud provider & subscription/account    
	- Security posture (secure / unhealthy)    
	- Open security recommendations    
	- Compliance status    
	- Tags and ownership info

# Demo : Asset Inventory

- To access **Asset Inventory**
- Go to [Azure Portal](https://portal.azure.com)
- Click on **Microsoft Defender for Cloud -> Inventory**

![[Pasted image 20260119210913.png]]

---

# Defender for Cloud : Security Recommendations

- Defender for Cloud checks your resources in **Azure, AWS, and GCP** against built-in **security best practices**
- If something is missing or misconfigured, it gives you **security recommendations**
- These recommendations are **enforced and managed using Azure Policy** to help keep resources secure

## Demo : Security Recommendations

- To access **Security Recommendations**
- Go to [Azure Portal](https://portal.azure.com)
- Click on **Microsoft Defender for Cloud -> Recommendations**
- Click on **Switch to classic view**

![[Pasted image 20260119212323.png]]

- Click on **All recommendations**

![[Pasted image 20260119212953.png]]

---

# Defender for Cloud – Secure Score Recommendations

- The entire purpose of Secure Score is to provide a number from 0 to 100 and this number tells us our various resources security score
- Secure score recommendations show **specific actions** you can take to **improve your security posture**
- Each recommendation adds points to your **Secure Score**, helping you track and prioritize security improvements

## Demo : Secure Score Recommendations

- Follow the Steps from  ==**Demo : Security Recommendations**== till "Click on **Switch to classic view** tab"
- Click on **Secure Score Recommendations**

![[Pasted image 20260119214216.png]]

---

# Defender for Cloud : Remediation

Security recommendations should be **fixed regularly**.  
Defender for Cloud explains **how to remediate** them and often provides a **Quick Fix** option.

⚠️ **Be careful using Quick Fix if :**
- If you manage resources with **Infrastructure as Code (IaC)**
- If you don’t fully understand the **workload**, 

- As **Automatic fixes** can **impact or break services**

## Demo : Remediation

### For Manual Remediation

- Follow the Steps from  ==**Demo : Security Recommendations**== till "Click on **Switch to classic view** tab"
- Click on **All recommendations**

![[Pasted image 20260119220124.png]]
- Click on **Name: "Microsoft Defender for App Service should be enabled"**
- It will open a **Remediation window**

![[Pasted image 20260119220610.png]]

### For Automatic Remediation

- Follow the Steps from  ==**Demo : Security Recommendations**== till "Click on **Switch to classic view** tab"
- Click on **All recommendations**
![[Pasted image 20260119221203.png]]

-  Click on **Name: "Machines should be configured ..."**
- It will open a **Remediation window**

![[Pasted image 20260119221633.png]]

---

# Defender for Cloud: DevOps Security

## DevOps Security

- **[DevOps Security](https://share.google/aimode/ip46siQRO8dvjw12s)** means **keeping applications safe while they are being built and run**
- We **check for security problems early**, while writing and deploying code, not **after** the application is already running

## DevOps Security life-cycle in Azure

- A **developer** writes code in **Azure DevOps** and uses **Azure Pipelines** to deploy it to  
    **ACR (Azure Container Registry)** and run it in **AKS (Azure Kubernetes Service)**

- **Defender for CSPM (Cloud Security Posture Management)** scans :
	- **Azure DevOps** and pipelines 
	- **IaC (Infrastructure as Code)** for misconfigurations
	- **Source code** for vulnerabilities (**CVEs – Common Vulnerabilities and Exposures**), outdated libraries, and hard-coded secrets 
	- **Container images** stored in ACR

- **Defender for Containers**:
	- Scans **container images**    
	- Monitors **AKS (Azure Kubernetes Service) workloads at runtime** for threats    
	- **Logs** from Defender and Azure services are sent to **Log Analytics**    

- **Microsoft Sentinel (SIEM – Security Information and Event Management)** uses these logs to give the **SOC (Security Operations Center)** full visibility
    
- **Result:** Security is built into the entire pipeline :
	- **code → containers → runtime → monitoring**

![[Pasted image 20260119223343.png]]

---

