# Threat Hunting

- **Proactive** search for cyber threats in your environment
- You **don’t wait for alerts** to fire    
- Analysts actively query logs to find suspicious activity
## Threat Hunting vs Analytic Rules

- **Analytic rules** :    
    - Run on a **schedule** (even near real-time = every minute)
    - Generate **alerts/incidents**
        
- **Threat hunting** :    
    - **Manual and proactive**
    - Analysts **search logs directly**
    - Looks for threats that rules may **miss**

### Why Threat Hunting is Important

- Detects **unknown or stealthy attacks**    
- Finds threats **before damage occurs**    
- Complements analytic rules in a SOC

## Threat Hunting Models

1. **Intelligence-Based Hunting :**
	- Based on **known indicators**
    - Uses **IOCs (Indicators of Compromise)** such as :   
	    - IP addresses        
	    - Domain names       
	    - File hashes
	- Data comes from **Threat Intelligence feeds**    
	- Example :    
	    - `Search logs for this malicious IP`

2. **Hypothesis-Based Hunting :**
	- Based on **attacker behavior**
	- Uses :    
	    - **IOAs** (Indicators of Attack)        
	    - **TTPs** (Tactics, Techniques, Procedures)
	- Focuses on **how attackers behave**, not exact values
	- Example :    
    - `Look for lateral movement behavior`

---
