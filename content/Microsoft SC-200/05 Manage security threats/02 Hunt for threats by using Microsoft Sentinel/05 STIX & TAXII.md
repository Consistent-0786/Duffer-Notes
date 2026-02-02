# Cyber Threat Intelligence : STIX & TAXII

## Why STIX & TAXII Matter

- Enable **sharing threat intelligence** across the security community    
- Make CTI **standardized, automated, and scalable**    
- Used by tools like **Microsoft Sentinel**
## STIX (Structured Threat Information eXpression)

- **Standardized language** for cyber threat intelligence
- Built on **JSON**    
- Used to describe CTI data such as :    
    - IOCs (IPs, hashes, domains)        
    - Threat actors        
    - TTPs
- Purpose :    
    - **Consistent exchange of threat intelligence** between systems

➡️ Think of **STIX as the language / format**

## TAXII (Trusted Automated eXchange of Indicator Information)

- **Transport protocol** for threat intelligence    
- Used to **send and receive STIX data**    
- Connects :    
    - Threat intelligence platforms        
    - SIEMs like Sentinel        
    - External TAXII servers        

➡️ Think of **TAXII as the delivery mechanism**

## Threat Intelligence Usage in Microsoft Sentinel

Threat intelligence is used across **many Sentinel features** :

- **Analytic rules**    
    - Match logs against known IOCs
        
- **Threat hunting**    
    - Proactively search using IOCs
        
- **Workbooks**    
    - Visualize threat intelligence
        
- **Notebooks**    
    - Advanced CTI analysis (Python)
        
- **Playbooks**    
    - Automated response actions
        
- **Incidents**    
    - Enrich alerts with CTI context
        
## Why Threat Intelligence Is Critical in Sentinel

- Enriches detections and investigations    
- Improves accuracy of alerts    
- Enhances hunting and automation    
- Makes Sentinel more **context-aware**

> **In Simple :** 
	- STIX = **standardized CTI format (JSON)**    
	- TAXII = **protocol to exchange STIX**    
	- Used together to share threat intelligence    
	- Threat intelligence is used **everywhere in Sentinel**    
	- IOCs are central to rules, hunting, and investigations

---

