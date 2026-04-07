>[!Important Information]
>**To View the official NIST 800-37 (RMF) 80 page**
>[Click HERE](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

# NIST 800-61: Computer Security Incident Handling Guide

- **NIST 800-61** provides guidance on how organizations should **detect, respond to, and recover from cybersecurity incidents**
- It explains the **process organizations should follow when a security incident occurs**
- In Simple :
    - A **framework for handling cybersecurity incidents in a structured way**
- A **security incident** is any event that threatens the **Confidentiality, Integrity, or Availability (CIA)** of systems or data

- **Examples of incidents :**
	- Lost or stolen laptop
	- Malware outbreak
	- Data breach
	- Account compromise
	- Natural disasters (flood, fire)

# NIST 800-61 Purpose

- The guide helps organizations :
	- Detect cybersecurity incidents
	- Analyze security breaches
	- Contain and remove threats
	- Recover systems
	- Improve incident response processes

- **Goal :**
	- Respond to incidents **quickly, effectively, and consistently**

---
# Incident Response Lifecycle (NIST 800-61)

- NIST defines **4 major phases** in the incident response lifecycle :
	1. **Preparation**
	2. **Detection and Analysis**
	3. **Containment, Eradication, and Recovery**
	4. **Post-Incident Activity**

![[Pasted image 20260331150250.png]]
# Phase 1 : Preparation

- This phase focuses on **getting the organization ready to respond to incidents**
- Activities include :
	- Creating an **Incident Response (IR) Plan**
	- Establishing **communication channels**
	- Training employees
	- Conducting security awareness programs
	- Preparing response tools and procedures

- The **Incident Response Plan** should include :
	- Detection procedures
	- Analysis procedures
	- Containment steps
	- Recovery steps
	- Post-incident processes
	- Roles and responsibilities
## Phase 1.1 : Communication Channels

- Organizations must establish **communication methods during incidents**

### Internal Communication

- Used to notify internal teams 
- **Examples :**
	- Email
	- Intranet
	- Internal chat systems
	- Phone calls
### External Communication

- Used to communicate with external stakeholders
- **Examples :**
	- Customers
	- Partners
	- Vendors

- Methods :
	- Email
	- Web portals
	- Phone communication
## Phase 1.2 : Emergency Notification Systems

- Organizations may also use :
	- Automated voice alerts
	- SMS alert systems
	- Manual alerts (sirens, alarms)
- These systems notify employees **when a security incident occurs**
## Phase 1.3 : Continuous Improvement (Preparation Phase)

- Organizations should continuously improve incident response through :
	- **Tabletop exercises**
	- **Security drills and simulations**
	- **Post-incident reviews**
	- **Metrics and KPIs**

- Important metrics include :
	- Time to detect incident
	- Time to contain incident
	- Time to recover systems

- Feedback and surveys help identify **weaknesses in the response process**


# Phase 2 : Detection and Analysis

- This phase involves **identifying and confirming security incidents**
- Incidents may be detected by :
	- SIEM systems
	- IDS / IPS systems
	- Security monitoring tools

- **Steps :**
	1. Identify suspicious activity
	2. Confirm the incident is a **true positive**
	3. Determine the **scope and impact**
	4. Start the **communication process**

# Phase 3 : Containment, Eradication, and Recovery

- This phase focuses on **stopping the attack and restoring systems**

## Containment

- **Goal :**
	- Stop the attack from spreading

- **Examples :**
	- Isolate infected systems
	- Disable compromised accounts
	- Disconnect affected devices
## Eradication

- **Goal** :
	- Remove the root cause of the incident

- **Examples :**
	- Remove malware
	- Patch vulnerabilities
	- Block attacker IP addresses
## Recovery

- **Goal :**
	- Restore normal operations

- **Examples :**
	- Re-image compromised systems
	- Restore backups
	- Validate system integrity

- Organizations should also implement **new security controls** to prevent future incidents
- **Examples** :
	- Deploy EDR solutions
	- Improve user training
	- Strengthen security policies

# Phase 4: Post-Incident Activity

- After the incident is resolved, organizations perform **post-incident analysis**
- Activities include :
	1. Reviewing what happened
	2. Documenting the incident response
	3. Identifying improvement areas
	4. Sharing lessons learned
	5. Updating incident response plans
	6. Improving security controls

- **Goal :**
	- Prevent similar incidents in the future

---

# Important Notes About Incident Response

- Incident response is a **complex process**
- Every incident is **different**
- Organizations should focus on understanding the **overall lifecycle**

- Key concepts to remember :
	- Detection
	- Containment
	- Eradication
	- Recovery

---
# NIST 800-61: Incident Response - Some Things to Keep in Mind

1. Creating an IR plan and executing on it is a huge process and you won’t be expected to create a plan or be the incident command or something like this

2. Focus on understanding the process at a high level and make sure you can articulate the incident lifecycle as **it pertains to NIST 800-61**

3. **All incidents will be very different, so “detection”, “containment”, “eradication”** and all of that will be handled different depending on what happened

---

