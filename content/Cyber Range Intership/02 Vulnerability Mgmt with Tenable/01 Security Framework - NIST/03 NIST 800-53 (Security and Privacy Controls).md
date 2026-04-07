>[!Important Information]
>**To View the official NIST 800-37 (RMF) 500 page**
>[Click HERE](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_2_0/home?element=AC)

# NIST 800-53: Security and Privacy Controls

- **NIST 800-53** is a comprehensive catalog of **security and privacy controls** used to protect information systems and sensitive data
- It acts like a **rulebook for securing computer systems** and preventing unauthorized access by attackers
- The document is very large (**~500 pages**) and describes security controls in detail
- In Simple :
    - A **large library of security controls organizations can implement to protect systems and data**
- These controls help organizations with things like :
    - Strong password policies
    - Vulnerability checking
    - Incident response planning
    - Access management

# NIST 800-53 Control Families

- NIST 800-53 includes a very large set of security controls organized into different "families"
- These control families are like different categories of rules that organizations should follow to help keep their information systems and data secure
- **Example :** 
	- The **Access Control (AC)** family includes controls for managing who can access sensitive information and what they can do with it
	- Another example, the **Incident Response (IR)** family includes controls for what to do if something goes wrong, like a hacker breaking into the system

![[Pasted image 20260330192403.png]]

---
# NIST 800-53 : `AC - Access Control` Control Family

![[Pasted image 20260330193324.png]]

- Let’s dive a bit deeper and inspect **Access Control, Control #17 (AC-17)**

![[Pasted image 20260330193503.png]]

## Control AC-17 (Remote Access)

![[Pasted image 20260330193540.png]]

### Control AC-17 Enhancements

![[Pasted image 20260330193706.png]]

![[Pasted image 20260330193826.png]]

---
# Low, Moderate, and High Controls

NIST divides controls into **three impact levels**
## Low
- Minimal security requirements
- Used for systems storing **public or low-risk information**
- **Example :**
	- Public websites
## Moderate
- Systems storing **sensitive but not critical information**
- **Examples :**
	- Employee records
	- Customer data
- Security controls are **more comprehensive**
## High
- Systems storing **extremely sensitive data**
- **Examples :**
	- Classified government information
	- Medical records
- Controls are **most strict and comprehensive**

---
# How to Use NIST 800-53

- The proper way to use NIST 800-53 is :
	1. **Determine which controls apply to the system**
	2. **Implement the selected controls based on system requirements**

- Important :
	- You **should NOT implement every control**
	- Reasons :
		- Some controls **do not apply to your system**
		- Too many controls may **reduce system functionality**

- Organizations should **select only relevant controls**

- ![[Pasted image 20260330194600.png]]

---

# SecOps Control Families

- Common control families used in security operations include :
## Access Control (AC)

- Controls access to systems and data
- Examples :
	- Authentication
	- Access policies
	- Remote access restrictions
## Audit and Accountability (AU)

- Focuses on **monitoring system activity**
- Examples :
	- Audit logs
	- Log analysis
	- Time stamps
## Configuration Management (CM)

- Controls **system configuration and change management**
- Examples :
	- Baseline configuration
	- Change control
	- Configuration monitoring
## Incident Response (IR)

- Controls how organizations **detect and respond to incidents**
- Examples :
	- Incident response plans
	- Detection and analysis
	- Incident response testing
## Maintenance (MA)

- Controls related to **system maintenance and repair**
- Examples :
	- Equipment repair
	- System maintenance procedures
## Media Protection (MP)

- Controls protecting **physical and digital media**
- Examples :
	- Media storage
	- Media access control
	- Media transport
## Personnel Security (PS)

- Controls related to **employee security management**
- Examples :
	- Background checks
	- Security training
	- Employee termination procedures
## Risk Assessment (RA)

- Controls for **identifying and managing security risks**
- Examples :
	- Risk assessment
	- Risk mitigation
	- Risk monitoring

![[Pasted image 20260330195252.png]]

---

# When to Use NIST 800-53

- Organizations reference NIST 800-53 in situations such as :
	- **Compliance with federal regulations (Government)**
	- **Designing and implementing a new system**
	- **Cybersecurity risk assessments**
	- **Regular security audits**
	- **Improving overall cybersecurity posture**

---
