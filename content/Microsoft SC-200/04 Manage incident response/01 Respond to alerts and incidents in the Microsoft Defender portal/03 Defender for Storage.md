# Defender for Storage (Microsoft Defender for Cloud)

- **Defender for Storage** is a widely used Defender plan within **Microsoft Defender for Cloud**  
- It provides **security and threat protection** for the following Azure storage services :
	- **Azure Blob Storage**
    - **Azure Files**
    - **Azure Data Lake Storage**
## How Defender for Storage Works

- Defender for Storage **protects storage accounts** by leveraging :
	- **Microsoft Threat Intelligence**
        - Uses Indicators of Compromise (IOCs) such as **malicious IP addresses, domains, and file hashes**
        
	- **Microsoft Defender Antivirus**
	    - Scans files uploaded to storage accounts       
	    - Detects and can **block malicious file uploads and malware distribution**      

	- **Sensitive Data Discovery**
	    - Identifies **sensitive information types** (e.g., credit card numbers, social security numbers)
        - Helps **prevent data leakage** from storage accounts
   
## What Defender for Storage Can Do

- Detect and **prevent malware uploads** to storage accounts    
- Block **distribution of malware** hosted in storage    
- Identify and protect **sensitive data** stored in blobs and files    
- Detect **unusual or risky behavior** related to storage access    

## Common Alerts generated Defender for Storage 

**Example of Alerts :**
-  Access from a suspicious IP address	
- Based on Microsoft Threat Intelligence IOCs
- **Potential malware upload to a storage account**    
- **Storage account identified as a source of malware distribution**    
- **Unusual amount of data extracted from a storage account**    
- **Sensitive blob container access level changed to allow public (unauthenticated) access**    

---
