# Complexity and Cyber Security Challenges

Cyber Security Challenges : 

	1. Lack of Security 
	2. More sophisticated threats
	3. Lack of Automation		        
		- we can't introduce AI everywhere and still need human interaction
	4. Ton's of Data to access 	    	
		- it makes harder to find needed data 
	5. Many disconnected products	     	
		- unable to make inter-connectivity between security products
	6. Evolving Regulatory Landscape     	
	        - increasing volumes of Threats day by day
	7. Noisy alerts / false positive
	8. A lot of alerts are never really investigated
---

# What comes under SOC

SOC Analyst :
	
	1. Threat Intelligence 
		- try to identify all the tactics, techniques and procedures that adversaries (threat actors) are carrying out to their victims
	2. Threat Hunting 
		- trying to proactively identify active threats in your environment
	3. Log Management 
		- identifying data sources from *SIEM*
	4. Threat Detection
		- identifying threats in your environment by building rules in *SIEM* solution
		- eg = establishing a rule that whenever a new user has been created, *SIEM* will fire an alert so that someone from SOC can look at it
	5. Incident Response
		- identify the incident, minimize its effects 
		- analyze it and triage it correctly 
	6. Recovery and Remediation
		- restoring systems and preventing future attacks after a security incident
	7. Root cause investigation
		- identify the fundamental causes of a security event
		- what tactics, techniques and procedures were taken by adversaries (threat actors)
	8. Reducing Attack Surface
		- minimizing the number of potential entry points that an attacker could exploit
		- educate company employees on how they can get better
---

# SOC Model

| Tier | Focus Areas | Example Tasks | % of Alerts |
|------|--------------|---------------|--------------|
| **Tier 3** | - Advanced malware<br>- Hard tasks<br>- Proactive threat hunting<br>- Advanced forensics | Threat hunting, malware reverse engineering, complex incident response | **5%** |
| **Tier 2** | - Intermediate analysis<br>- Investigation of complex alerts<br>- Support to Tier 1 and Tier 3 | Deep-dive investigations, correlation analysis | **25%** |
| **Tier 1** | - Commodity malware<br>- Easier tasks that can or should not be automated | Initial triage, alert validation, escalation when needed | **70%** |
| **Automation** | - Commodity malware<br>- Repetitive tasks<br>- Mimics analyst steps in easy cases | Automated detection and response for low-complexity threats | *N/A* |

---

# Cyber Security Incident Response Process

![[Pasted image 20251025205150.png]]

---


# EDR, XDR, SIEM & SOAR

![[Pasted image 20251025210120.png]]