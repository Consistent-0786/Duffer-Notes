# Vulnerability Scanning Methods

- Vulnerability scanners use different **methods to analyze systems for security weaknesses**.
- Each scanning method provides **different levels of access and visibility** into a system.
- Selecting the correct scanning method helps organizations **identify vulnerabilities more effectively**.
- In Simple :
    - Different ways security tools **scan systems to detect vulnerabilities**

# Vulnerability Scanning Process

A vulnerability scanner typically follows several **steps during the scanning process**.
## Host Discovery

- The scanner first checks **whether the target host is online**.
- This helps avoid scanning inactive systems.

Examples :

- Ping scans
- Network discovery scans
## Service and Port Detection

- The scanner identifies **which ports and services are running** on the target system.

Examples :

- Open ports
- Running applications
- Listening services

Goal :

- Determine **potential entry points attackers might exploit**.
## Authentication (If Credentials Are Provided)

- If credentials are available, the scanner attempts to **log into the system**.

This allows the scanner to gather :

- System configuration information
- Installed software
- Patch levels
- User permissions

Authenticated access provides **more accurate vulnerability detection**.
## Vulnerability Identification

- The scanner compares discovered system information with **known vulnerability databases**.

Examples of databases :

- CVE (Common Vulnerabilities and Exposures)
- Vendor vulnerability advisories
- Security knowledge bases

Goal :

- Detect **known vulnerabilities in the system**.
## Data Aggregation and Storage

- The scanner **collects and stores vulnerability data**.

This information is used for :

- Vulnerability reports
- Risk analysis
- Long-term vulnerability tracking
- Compliance monitoring

Organizations use this data to **prioritize remediation efforts**.

# Types of Vuln. Scanning
## Authenticated Scans

- **Authenticated scans** use **valid credentials** to log into the target system.
- This provides access to **internal system information**.

These scans can detect :

- Missing security patches
- Misconfigurations
- Privilege issues
- Vulnerable installed software

### Characteristics

- **Access Level :** High
- **Visibility :** In-depth
- **Accuracy :** Very high

### Typical Use Case

- Identifying **deep system vulnerabilities requiring system access**.

Example :

- Detecting missing OS security patches.
## Unauthenticated Scans

- **Unauthenticated scans** do **not use credentials**.
- The scanner interacts with the system **as an external attacker would**.

These scans detect :

- Open ports
- Public services
- Internet-facing vulnerabilities
- Misconfigured external services

### Characteristics

- **Access Level :** Very Low
- **Visibility :** Surface-level
- **Accuracy :** Limited

### Typical Use Case

- Identifying **external-facing vulnerabilities visible to attackers**.

Example :

- Detecting open web server ports.
## Agent-Based Scans

- **Agent-based scanning** requires installing a **software agent on the system**.
- The agent performs **continuous local monitoring**.

Agents can analyze :

- System configuration
- Installed software
- File integrity
- Patch levels
- Local vulnerabilities

Since the agent runs locally, it reduces **network scanning overhead**.

### Characteristics

- **Access Level :** High
- **Visibility :** In-depth
- **Monitoring :** Continuous

### Typical Use Case

- Continuous **endpoint vulnerability monitoring**.

Example :

- Cloud servers monitored by security agents.

---

# Vulnerability Scanning Comparison

|Scanning Method|Access Level|Visibility|Typical Use Case|
|---|---|---|---|
|Authenticated Scans|High|In-depth|Detect internal system vulnerabilities|
|Unauthenticated Scans|Very Low|Surface-level|Detect external-facing vulnerabilities|
|Agent-Based Scans|High|In-depth|Continuous endpoint monitoring|

---

