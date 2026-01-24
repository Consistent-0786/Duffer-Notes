# What is Defender for Identity ?

- Defender for Identity helps protect your environment from **identity-related threats**
- It focuses on **three key areas**:
     1. **Proactive Posture Assessments**
		- Evaluates your identity security before threats happen
		- Provides **recommendations** to improve identity posture
		- Examples of issues found :
		    - Use of clear-text credentials
		    - Legacy insecure protocols
		    - Unsecure Kerberos delegation
		    - Unmonitored domain controllers
        
	2. **Threat Detection and Investigation**
		- Detects attacks like **pass the hash** and **pass the ticket**
		- Uses the **MDI sensor** installed on Domain Controllers and Active Directory Federation Services (ADFS)
		- Collects telemetry from network traffic, Windows security events, Active Directory events, and user behavior analytics
		- Integrated into Defender XDR for end-to-end threat visibility

	3. **Response**
		- Enables manual and automated responses in your Security Operations Center (SOC)
		- Actions include :
		    - Disabling compromised users
		    - Resetting passwords in Entra ID and Active Directory

## How does it work?

- The MDI sensor acts like an **agent streaming identity-related telemetry**
- Works in environments with on-premises Active Directory synced to Entra ID via Azure AD Connect
- Monitors identity objects such as users, devices, and applications

- **Example :**
	- 🚨 An adversary tries a pass-the-hash attack → Defender for Identity detects it  
	- ⚙️ You disable the compromised user and reset their password automatically

- **In Simple :**
	- Defender for Identity **protects user identities by spotting risky settings and detecting identity attacks early**
    - It provides **security recommendations, threat detection, and response tools**
    - Works on-premises and in hybrid environments with cloud integration
    
---

