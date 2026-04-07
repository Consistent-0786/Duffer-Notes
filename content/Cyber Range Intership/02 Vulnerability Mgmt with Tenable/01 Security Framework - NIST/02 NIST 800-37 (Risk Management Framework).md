>[!Important Information]
>**To View the official NIST 800-37 (RMF) 183 page**
>[Click HERE](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf)

# # NIST 800-37: Risk Management Framework (RMF)

- **NIST 800-37** defines the **Risk Management Framework (RMF)** used to manage security risks in information systems.
- It provides a **structured process to identify, assess, and manage cybersecurity risks**
- In Simple :
    - A framework used to **identify risks in a system and reduce them to an acceptable level**
- A **system** in RMF can be :
    - The **entire organization**
    - A **software system or SaaS product**
    - A **single component or feature** inside a system

# # When To Use RMF

- RMF should be used whenever an organization needs to **protect sensitive information**
- **Examples :**
	- When **developing a new system**
	- When **procuring or implementing software**
	- After a **security breach**
	- When **making major system changes**
	- When systems handle **sensitive data**
		- Personal data
		- Financial data
		- Confidential business information

---
# # NIST RMF 6-Step Process

- NIST defines ==**6 steps to manage risk in systems**==
	1. **Categorize**
	2. **Select Security Controls**
	3. **Implement Security Controls**
	4. **Assess Security Controls**
	5. **Authorize Information System**
	6. **Monitor Security Controls**

- **Goal :**
	- Reduce risk to an **acceptable level for the system owner**

## RMF STEP 1 : Categorize

- You can categorize in terms of CIA Triad Requirements
- **Example :**
	- Imagine we are reviewing a non-mission-critical application our company is building that is solely for allowing city residents to look up public information. We might decide on the following categorization :
		- Confidentiality : LOW (public information)
		- Integrity : MED (info needs to be accurate, but easy to correct/reconcile)
		- Availability : LOW (not mission critical)
### STEP 1.1 : Categorize

- Organizations must identify **regulated data** stored or processed by the system
- **Examples :**
	- **Credit Card Data** → Regulated by **PCI DSS**
	- **Health Data (ePHI)** → Regulated by **HIPAA**
	- **EU Personal Data** → Regulated by **GDPR**

- This affects **which controls must be implemented later**

## STEP 2 : Select Controls

- In this step, organizations choose **security controls** to protect the system
- Controls are usually selected from :
	- **NIST 800-53 Security and Privacy Controls**

- These controls include areas such as :
	- Access control
	- Authentication
	- Logging
	- Network security
	- Incident response

- Organizations select controls **appropriate for their system risk level**

### STEP 2.1 : Select Controls (Special)

- If you found that your system is storing or processing any regulated data
- **Example** **:** 
	- Storing or processing credit card information 
		- we need to make sure you are implementing the appropriate controls to ensure compliance
	- In the above example, since we are storing cardholder data you need to ensure that you are **“PCI Compliant”** by adhering to the controls outlined in the **PCI DSS Standard**
	- ![[Pasted image 20260330180856.png]]

## STEP 3 : Implement Security Controls

- In this step, organizations **deploy the selected security controls**
- Important points :
	- Implementation can be **time-consuming**
	- Controls are **often high-level**, so implementation varies
	- Some controls require **specialized skills**
	- Some may require **custom development**

- **Example Control :**
	- `NIST AC-7(1) UNSUCCESSFUL LOGON ATTEMPTS | AUTOMATIC ACCOUNT LOCK`
	- **Account lockout after failed login attempts**

- **Example Advanced Control :**
	- `NIST CA-8(2) PENETRATION TESTING | RED TEAM EXERCISES`
	- **Penetration testing / Red team exercises**

## STEP 4 : Assess Security Controls

- In this step, a **security assessor or auditor** verifies that controls are properly implemented
- **Security assessor or auditor** may be :
	- Internal security team
	- External auditor
	- Third-party security assessor

- The assessor will :
	- Verify controls exist
	- Check if controls work correctly
	- Identify gaps or weaknesses
	- If issues are found :
		- The organization must **fix the implementation**

## STEP 5 : Authorize The System

- An **Authorizing Official (AO)** will ==“sign off” and formally document and accept the remaining risk within the system==
- This person could be a 
	- CISO 
	- CIO
	- CTO
	- Program Manager
	- Senior leadership
-  If approved → system is **authorized to operate (ATO)**

![[Pasted image 20260330182124.png]]

## STEP 6 : Monitor Security Controls

- Security monitoring is **continuous throughout the system life cycle**
- Activities include :
	- Detecting new vulnerabilities
	- Responding to new threats
	- Monitoring system changes
	- Ensuring security controls remain effective

- **Goal :**
	- Ensure risk **does not increase over time**

---
# RMF Overall Goal

- The overall purpose of RMF is to :
	1. Identify risks in a system
	2. Reduce risk using security controls
	3. Accept the remaining risk
	4. Continuously monitor the system

- The **Authorizing Official ultimately accepts the residual risk**

---
