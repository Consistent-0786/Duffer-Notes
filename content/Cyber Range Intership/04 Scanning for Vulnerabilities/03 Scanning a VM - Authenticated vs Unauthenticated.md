# Scanning a Virtual Machine: Authenticated vs Unauthenticated (Tenable Lab)

- This lab demonstrates the difference between **authenticated and unauthenticated vulnerability scans**.
    
- The scans are performed using **Tenable Vulnerability Management** against **Azure virtual machines**.
    
- The goal is to observe how **credentialed access impacts vulnerability detection accuracy**.
    
- In Simple :
    
    - Compare **scans without credentials vs scans with credentials** to see how vulnerability detection changes.
        

Resources used in the lab :

- Azure Portal
    
- Tenable Cloud Vulnerability Management
    
- Windows VM / Linux VM
    

Reference links :

---

# Lab Environment Setup

Before performing scans, prepare the lab environment.

## Step 1: Sign Into Required Platforms

Sign into the following platforms :

- Azure Portal  
    [https://portal.azure.com](https://portal.azure.com/)
    
- Tenable Cloud  
    [https://cloud.tenable.com](https://cloud.tenable.com/)
    

---

## Step 2: Review Lab Network Architecture

Observe the **Cyber Range Lab Diagram** to understand :

- Virtual networks
    
- Scan engines
    
- Target machines
    

Understanding the network layout helps determine whether scans are **internal or external**.

---

# Windows VM Vulnerability Scanning

## Step 1: Create Windows Virtual Machine

Create a **Windows 11 Pro VM** in Azure.

Requirements :

- Virtual machine must be accessible
    
- Ensure proper network configuration
    
- Login to the VM after creation
    

---

## Step 2: Configure Firewall and Network Access

Disable Windows Firewall if required.

If a **Network Security Group (NSG)** is attached :

Ensure the scan engine can reach the VM.

Example rule :

Allow inbound traffic from:

```
10.0.0.8
```

This is the **internal scan engine address**.

---

## Important Troubleshooting Steps

If the scan fails :

1. Test NSG connectivity
    
2. Disable Windows Firewall
    
3. Verify RDP port access (3389)
    
4. Test connectivity with ping
    
5. Allow ICMP inbound rule
    
6. Retest connectivity
    

Key observation :

- Some scans are performed **internally**
    
- Others can be performed **externally using public scan engines**
    

---

## Tenable Vulnerability Scan Configuration

After preparing the VM, configure a scan in **Tenable**.

### Create Basic Network Scan

Within Tenable :

1. Create **Basic Network Scan**
    
2. Configure the following parameters
    

---

## Scan Configuration Settings

### Basic Settings

Name :

```
Windows Test Scan
```

Scanner Type :

```
Internal Scanner
```

Important :

Select

```
LOCAL-SCAN-ENGINE-01
```

Targets :

- Use **Private IP** for internal scans
    
- Use **Public IP** if using cloud scanner
    

Internal scanning is:

- Faster
    
- Cheaper
    
- More efficient
    

---

### Discovery Settings

Scan Type :

```
Custom
```

Enable :

- Ping the remote host
    
- Fast network discovery
    

---

### Credentials

For the **first scan**, leave credentials **blank**.

This creates an **Unauthenticated Scan**.

---

## Running the First Scan (Unauthenticated)

Steps :

1. Launch the scan
    
2. Wait for completion
    
3. Export the results
    

Observe :

- Scan duration
    
- Vulnerabilities detected
    
- CVSS scores
    

This scan represents **what attackers see externally**.

---

## Running the Second Scan (Authenticated)

Next, edit the same scan and **add credentials**.

This allows Tenable to **log into the system** and perform deeper analysis.

Before scanning, run the following **PowerShell command on the VM as Administrator** :

```
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord -Force
```

Purpose :

- Allows remote administrative access
    
- Enables Tenable to gather deeper system information
    

After running the command :

1. Add credentials in Tenable
    
2. Launch the scan again
    
3. Export results
    

---

## Comparing Scan Results

After both scans finish, compare the results.

Key comparison points :

### Vulnerability Count

Authenticated scans usually detect **more vulnerabilities**.

Reason :

- The scanner has **system-level visibility**.
    

---

### Vulnerability Types

Authenticated scans detect :

- Missing patches
    
- Local misconfigurations
    
- Installed vulnerable software
    

Unauthenticated scans detect :

- Open ports
    
- Network services
    
- External attack surface
    

---

### Scan Duration

Authenticated scans may take **longer** because they perform deeper checks.

---

# Linux VM Vulnerability Scanning

The same process is repeated with a **Linux (Ubuntu) VM**.

---

## Step 1: Create Linux VM

Create :

```
Ubuntu 24 Virtual Machine
```

Authentication type :

```
Password
```

Record the password.

---

## Step 2: Configure Network Access

Allow inbound traffic through the NSG.

Optional checks :

- Ping VM public IP
    
- SSH into the machine
    

Use :

- Azure Bastion
    
- SSH client
    

---

## First Scan (Unauthenticated)

Create the same **Basic Network Scan**.

Use identical scan settings.

Leave credentials **blank**.

Run scan and export results.

---

## Enabling Root Access for Authenticated Scan

Before running the second scan, enable root login.

Run these commands inside the Linux VM.

#### Set Root Password

```
sudo passwd root
```

---

#### Enable Root SSH Login

```
sudo grep -q '^PermitRootLogin' /etc/ssh/sshd_config && sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' | sudo tee -a /etc/ssh/sshd_config > /dev/null && sudo systemctl restart ssh
```

This allows Tenable to **authenticate as root**.

---

## Second Scan (Authenticated)

Edit the scan and add credentials :

```
username: root
password: root
```

Run the scan again and export results.

---

## Compare Linux Scan Results

Compare both scans and analyze :

- Vulnerability count
    
- Vulnerability severity
    
- Scan duration
    

Key observation :

Authenticated scans detect **significantly more vulnerabilities**.

---

## Important Security Warning

After testing :

- Disable root access
    
- Delete the VM immediately
    

Reason :

Systems with root credentials exposed can be **quickly compromised**.

---

# Cleanup

After completing the lab :

Delete the virtual machines.

Verify cleanup in your **Azure Resource Group**.

---

# Key Takeaways

This lab demonstrates several important concepts :

## Unauthenticated Scans

- Simulate **external attacker perspective**
    
- Detect **surface-level vulnerabilities**
    

---

## Authenticated Scans

- Provide **deep system visibility**
    
- Detect **internal vulnerabilities**
    

---

## Vulnerability Scanning Workflow

Typical scanner workflow :

```
Host Discovery
↓
Port and Service Detection
↓
Authentication (if credentials exist)
↓
Vulnerability Identification
↓
Reporting and Tracking
```

