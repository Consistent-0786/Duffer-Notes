# What is Defender for Key Vault?

- Microsoft Defender for Key Vault is a Defender for Cloud plan that provides threat protection for Azure Key Vaults
- It **focuses on detecting suspicious access and behavior**, not hardening or vulnerability scanning

## What does it protect ?

- **Azure Key Vaults, which store sensitive data like :**
	- Secrets (API keys, passwords)
	- Certificates
	- Cryptographic keys (private keys)

## What does it do ?

- Monitors all **access to Key Vault**
- Detects suspicious or malicious behavior
- Raises security alerts
- Gives **guidance on how to investigate and respond**

- **Example :**
✅ A VM with a managed identity retrieves a secret → normal behavior
🚨 A user accesses Key Vault from a Tor browser → alert raised
🚨 Access from a suspicious IP (based on Microsoft threat intelligence)
🚨 High number of Key Vaults accessed in a short time
🚨 Unusual access patterns
🚨 Policy change followed by secret retrieval

**In Simple :**
- Defender for Key Vault **gives visibility and alerts for suspicious access to secrets, keys, and certificates in Azure Key Vault** 

![[Pasted image 20260124191514.png]]

---
