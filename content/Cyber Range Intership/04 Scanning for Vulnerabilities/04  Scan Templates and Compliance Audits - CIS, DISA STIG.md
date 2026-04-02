# Scan Template

- It is a **predefined set of configurations for vulnerability scans**, specifying parameters such as **scan targets, scan policies, and types of vulnerabilities to detect**
- Using a scan template allows you to standardize and streamline scanning processes, ensuring consistency and efficiency across multiple scans or environments
- This is especially **useful for recurring scans**, ensuring that all relevant aspects are consistently assessed **without manually setting parameters each time**

---
# Compliance Audits

- Compliance audits in Tenable refer to **assessments that check whether your systems and processes meet specific regulatory, industry, or internal standards**
- These audits use **predefined policies and benchmarks**
-  You can kind of think of these as settings that need to be made in the OS, such as proper passwords, permissions, and other stuff
	- If they are not configured, they produce “extra” vulnerabilities

## CIS 

- **CIS Benchmarks** provide best-practice security configuration guidelines for IT systems

- **Source :**
	- Developed by the **Center for Internet Security (CIS)**
- **Purpose :**
	- Help organizations **secure operating systems, applications, and network devices**
- **Characteristics :**
	- Widely used in **commercial organizations**
	- Developed through **global security community consensus**
	- Easier to implement than STIG guidelines

- Examples of systems with CIS benchmarks :
	- Windows Server
	- Linux systems
	- AWS and Azure cloud services
	- Network devices

## DISA STIG

- **DISA STIG (Security Technical Implementation Guide)** provides strict security configuration guidelines for IT systems

- **Source :**
	- Developed by the **Defense Information Systems Agency (DISA)** for the **U.S. Department of Defense (DoD)**

- **Purpose :**
	- Ensure systems connected to **DoD (U.S. Department of Defense) networks meet strict security requirements**

 - **Characteristics :**
	- Highly detailed security configurations
	- Strict security requirements
	- Designed for **high-security government environments**

- Example hardening requirements :
	- Strict password complexity rules
	- Strong access control policies
	- Mandatory system auditing

---

