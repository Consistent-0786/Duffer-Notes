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

- To Access Asset Inventory 
<div style="max-width: 100%; width: 800px; margin: 0 auto;"> <div style="display: none;"> <p style="display: none; text-align: center; margin-top: 10px;"> <i style="font-style: italic; font-weight: bold; color: #CCCCCC; font-size: 18px;">7 STEPS</i> </p> <p style='font-size: 15px; line-height: 136%; margin-top: 59px; margin-bottom: 51px;'> 1. The first step is to open <b style="font-weight:normal;color:#FF00D6">Home - Microsoft Azure</b> and click <b style="font-weight:normal;color:#FF00D6">Microsoft Azure</b> </p> <p style="text-align: center;"><img src="https://www.iorad.com/api/tutorial/stepScreenshot?tutorial_id=2670533&step_number=1&width=800&height=600&mobile_width=450&mobile_height=400&apply_resize=true&min_zoom=0.5" style="max-width: 100%;max-height: 100%;border: none;" alt="" /></p> <p style='font-size: 15px; line-height: 136%; margin-top: 59px; margin-bottom: 51px;'> 2. Click <b style="font-weight:normal;color:#FF00D6">Microsoft Defender for Cloud</b> </p> <p style="text-align: center;"><img src="https://www.iorad.com/api/tutorial/stepScreenshot?tutorial_id=2670533&step_number=2&width=800&height=600&mobile_width=450&mobile_height=400&apply_resize=true&min_zoom=0.5" style="max-width: 100%;max-height: 100%;border: none;" alt="" /></p> <p style='font-size: 15px; line-height: 136%; margin-top: 59px; margin-bottom: 51px;'> 3. Click <b style="font-weight:normal;color:#FF00D6">Inventory</b> </p> <p style="text-align: center;"><img src="https://www.iorad.com/api/tutorial/stepScreenshot?tutorial_id=2670533&step_number=3&width=800&height=600&mobile_width=450&mobile_height=400&apply_resize=true&min_zoom=0.5" style="max-width: 100%;max-height: 100%;border: none;" alt="" /></p> <p style='font-size: 15px; line-height: 136%; margin-top: 59px; margin-bottom: 51px;'> 4. Inventory page </p> <p style="text-align: center;"><img src="https://www.iorad.com/api/tutorial/stepScreenshot?tutorial_id=2670533&step_number=4&width=800&height=600&mobile_width=450&mobile_height=400&apply_resize=true&min_zoom=0.5" style="max-width: 100%;max-height: 100%;border: none;" alt="" /></p> <p style='font-size: 15px; line-height: 136%; margin-top: 59px; margin-bottom: 51px;'> 5. Click <b style="font-weight:normal;color:#FF00D6">laws-sentinal</b> </p> <p style="text-align: center;"><img src="https://www.iorad.com/api/tutorial/stepScreenshot?tutorial_id=2670533&step_number=5&width=800&height=600&mobile_width=450&mobile_height=400&apply_resize=true&min_zoom=0.5" style="max-width: 100%;max-height: 100%;border: none;" alt="" /></p> <p style='font-size: 15px; line-height: 136%; margin-top: 59px; margin-bottom: 51px;'> 6. We can see Resource Health, Recommendations, Alerts of our workspace </p> <p style="text-align: center;"><img src="https://www.iorad.com/api/tutorial/stepScreenshot?tutorial_id=2670533&step_number=6&width=800&height=600&mobile_width=450&mobile_height=400&apply_resize=true&min_zoom=0.5" style="max-width: 100%;max-height: 100%;border: none;" alt="" /></p> <p style='font-size: 15px; line-height: 136%; margin-top: 59px; margin-bottom: 51px;'> 7. That's it. You're done. </p> <p style="text-align: center;"><img src="https://www.iorad.com/api/tutorial/stepScreenshot?tutorial_id=2670533&step_number=7&width=800&height=600&mobile_width=450&mobile_height=400&apply_resize=true&min_zoom=0.5" style="max-width: 100%;max-height: 100%;border: none;" alt="" /></p> </div> </div> <h3 style="display: none; font-size: 18px; margin-top: 89px; margin-bottom: 15px;"> Here's an interactive tutorial </h3> <p style="display: none;"> <a href="https://www.iorad.com/player/2670533/Portal-Azure---How-to-access-Asset-Inventory-in-Microsoft-Defender-for-Cloud">https://www.iorad.com/player/2670533/Portal-Azure---How-to-access-Asset-Inventory-in-Microsoft-Defender-for-Cloud</a> </p> <p class="skiptranslate" style="border: 0; min-width: 100%; margin-bottom: 0; height: 501px;"><iframe src="https://www.iorad.com/player/2670533/Portal-Azure---How-to-access-Asset-Inventory-in-Microsoft-Defender-for-Cloud?src=iframe&oembed=1" width="100%" height="500px" style="width: 100%; height: 500px; " referrerpolicy="strict-origin-when-cross-origin" frameborder="0" webkitallowfullscreen="webkitallowfullscreen" mozallowfullscreen="mozallowfullscreen" allowfullscreen="allowfullscreen" allow="camera; microphone; clipboard-write;" sandbox="allow-scripts allow-forms allow-same-origin allow-presentation allow-downloads allow-modals allow-popups allow-popups-to-escape-sandbox allow-top-navigation allow-top-navigation-by-user-activation"></iframe></p> <div style="display: none;font-size: 18px; text-align: center;font-family: 'Libre Franklin', sans-serif;"> <br><br> <b style="font-weight: bold; color: #CCCCCC;"> Next step </b> <br><br> <div style="display: inline-block;"> <div style="display: table-row;"> <a style="display: table-cell;" href="http://ior.ad/live/bcJ7" target="_blank"> <img src="https://www.iorad.com/golive.svg" style="border: none;" alt="Go Live" /> </a> </div> </div> </div>

---

