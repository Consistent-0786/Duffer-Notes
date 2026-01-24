# User and Entity Behavior Analytics (UEBA) in Microsoft Sentinel

- UEBA uses **machine learning** to analyze user and entity behavior, detect deviations from normal patterns, and identify early-stage suspicious activities (anomalies)
- UEBA focuses on **early detection** of suspicious behavior before alerts or incidents occur    
- It helps SOC analysts **find the needle in the haystack** by flagging unusual user/entity activity    
- **Anomalies** are a starting point for deeper investigation, not final alerts    
- Integrating **Entra ID** data is crucial for accurate detection
## UEBA Working

1. **Data Collection**
    - UEBA ingests **raw data** from multiple sources :        
        - SaaS applications            
        - On-premises systems            
        - Cloud providers            
	
	- Data flows into **Microsoft Sentinel** via Log Analytics
        
2. **Behavior Profiling & Baseline Creation**    
    - UEBA builds a baseline of typical behavior for each entity (user or resource), considering factors like :        
        - **User Resolution:** Identify specific users/entities            
        - **Geolocation:** Typical IP, city, country locations            
        - **User Blast Radius:** Impact scope if user is compromised (higher for privileged users)   
        - **Threat Indicators:** Known malicious IPs, domains, etc         
        - **Host-IP Data:** Link users to devices and network info            

3. **Integration with Entra ID**
    - UEBA uses **user and group information** from Entra ID to enrich context
    - This improves anomaly detection accuracy and relevance
        
4. **UEBA Engine Processing**    
    - Analyzes onboarded data and behavior profiles        
    - Detects **anomalies** deviations from starting that may indicate suspicious activity        
    - Anomalies are early warning signs (not necessarily malicious but worth investigating)
        
5. **Output to Sentinel**    
    - Anomalies are sent to Log Analytics and Microsoft Sentinel        
    - SOC teams use these insights to prioritize alerts and investigate incidents early

**In Simple :**
- UEBA in Microsoft Sentinel uses **behavior profiling, threat indicators, and Entra ID data** to **detect early anomalies in user and entity behavior**, providing actionable insights for proactive security monitoring
- ![[Pasted image 20260123193906.png]]
- ![[Pasted image 20260123193922.png]]

> To create **UEBA Demo :** [[03.1 Demo - UEBA]]

---

