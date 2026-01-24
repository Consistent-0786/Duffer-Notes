# Microsoft Defender for Containers

- **Microsoft Defender for Containers** is a **single security service** that protects **Kubernetes clusters**, no matter where they run
- It replaces older, separate plans (like _Defender for Kubernetes_) and works across clouds and on-prem
## Where can it be used?

Defender for Containers works with :
	- **AKS** (Azure Kubernetes Service)    
	- **EKS** (Amazon Elastic Kubernetes Service)    
	- **GKE** (Google Kubernetes Engine)    
	- **Any other Kubernetes** (via **Azure Arc**, e.g., OpenShift or on-prem clusters)    
## The 3 core benefits

1. **Environment Hardening**
	- Checks your cluster for **misconfigurations**    
	- Gives **security recommendations**    
	- Helps you secure Kubernetes proactively (since it’s complex)    

2. **Vulnerability Assessment**
	- Finds **vulnerabilities** :
	    - In **running containers**
	    - In **container images** (registries)
	- Helps you fix risks before attackers use them
    

3. **Runtime Threat Protection** (most important)
	- **Monitors containers while they’re running**    
	- Detects **active attacks or suspicious behavior**    
	- Sends alerts to **Defender for Cloud**    

## Defender for Containers - Architecture 

- **Working :**
	- In managed Kubernetes (AKS/EKS/GKE), the **control plane is managed by the cloud provider (Microsoft)**    
	- Defender focuses on **nodes and pods**    
	- Defender deploys **agent pods** into your cluster    
	
	- **These agents :**
    - Collect security data        
    - Detect threats & vulnerabilities        
    - Send everything to **Microsoft Defender for Cloud**
- ![[Pasted image 20260124182655.png]]

## Main components (Defender for Containers )

- All run in the **kube-system** namespace :

1.  **Defender Collector (DaemonSet)**
	- Runs on **every node**    
	- Collects inventory & security events
    

2. **Defender Collector (Deployment)**
	- Not tied to a node
	- Also collects inventory & security data

3. **Defender Publisher (DaemonSet)**
	- Sends collected data to Microsoft
	- Requires **outbound HTTPS (port 443)**
- ![[Pasted image 20260124182714.png]]

**In Simple :**
- Defender for Containers secures Kubernetes everywhere by hardening the environment, scanning for vulnerabilities, and detecting live attacks in running containers

---
