# What is Microsoft Defender for Office 365 (MDO)

- Defender for Office 365 is a security service that protects Microsoft 365 collaboration tools like 
	- **Outlook email**,
	- **Microsoft Teams**,
	- **Office apps (Word, Excel, etc)** from threats

- **It helps by :**
	- Blocking phishing, malicious links, and malware    
	- Protecting users when they open emails, links, or files
	- Detecting and responding to threats
	- Providing security policies, reports, and automated responses    

- ==All of this is **integrated into Microsoft Defender XDR** for centralized threat management==

--- 
# MDO Full Protection Stack Phase

![[Pasted image 20260122093653.png]]
## 01 MDO : Edge Protection (First Phase)

### Defender for Office 365 – Edge Protection 

- **Edge protection** is the first, automatic security layer that **filters traffic _before_ it enters Microsoft 365**  
- While attackers can bypass some controls today, it is still an important baseline defense

- **Key points :**
	- Works **automatically** with minimal admin interaction    
	- False positives are handled through notifications and temporary overrides    
	- Trusted partner connectors can be configured to ensure mail delivery    

### Edge Protection Features

1. **Network throttling**  
    - Protects Microsoft 365 from denial-of-service attacks by limiting how many messages a system can send
    
2. **IP reputation throttling**  
    - Blocks or limits mail from known malicious or high-volume IP addresses
    
3. **Domain reputation**  
    - Blocks messages from known malicious domains based on Microsoft threat intelligence
    
4. **Directory-based edge filtering (DBEF)**  
    - Prevents attackers from harvesting user and domain information via SMTP
    - As it blocks emails that try to guess or collect your company’s email addresses and if the recipient doesn’t exist, the message is rejected before entering Microsoft 365
    
5. **Backscatter detection**  
    - Blocks invalid non-delivery reports (NDRs) used in email-based attacks
	- It stops fake “delivery failed” messages that attackers send to confuse or flood your inbox
    
6. **Enhanced filtering for connectors**  
    - Preserves sender authentication when mail passes through third-party systems and improves detection using :
	    - Anti-spoofing        
	    - Anti-phishing        
	    - Machine learning        
	    - Heuristic analysis
	
	- **In Simple :** 
		- it keeps sender information **intact when emails** pass through other mail systems first, so Microsoft 365 can correctly detect spoofing, phishing, and malicious emails

![[Pasted image 20260122071852.png]]

## 02 MDO : Sender Intelligence Protection (Second Phase)
### Defender for Office 365 – Sender Intelligence 

- **Sender intelligence** focuses on **who is sending the email** and helps stop **spam, phishing, spoofing, and impersonation**  
- **Most features are configurable**
#### Key Features :

1. **Account compromise detection**  
	- Detects **unusual behavior** from a user account and alerts admins
	- If needed, the account is **temporarily blocked** from sending email

2. **Email authentication (SPF, DKIM, DMARC, ARC)**
	- It **verifies** that emails are truly sent **from authorized servers and domains**
		1. **SPF (Sender Policy Framework) :**
		    - **Function :** 
			    - A DNS record that lists all authorized IP addresses and servers allowed to send email on behalf of a domain
		    - **Working :**
			    - When a mail server receives an email, it checks the domain’s SPF record; if the sender's IP is not listed, the email may be flagged as suspicious
			- **In Simple :**
				- It checks if the sending server is allowed

		2. **DKIM (DomainKeys Identified Mail) :**
		    - **Function :** 
			    - Adds a cryptographic digital signature to the email header to verify that the message was not tampered with during transit
		    - **Working :** 
			    - The sender uses a private key to sign the email, and the recipient uses a public key (stored in the sender's DNS) to verify the signature
			- **In Simple :**
				-  It verifies the sender using a digital signature

		3. **DMARC (Domain-based Message Authentication, Reporting, and Conformance) :**
		    - **Function :**
			    - An overarching policy that tells receiving servers what to do if an email fails SPF or DKIM checks
			    - Provides "RUA" (aggregate) and "RUF" (forensic) reports to domain owners, offering visibility into who is sending mail using their domain
		    - **Policies :**
		        - `p=none`: Monitor only; no action is taken
		        - `p=quarantine`: Send unauthenticated emails to the recipient's spam folder
		        - `p=reject`: Block unauthenticated emails entirely
			- **In Simple :**
				- Enforces **SPF / DKIM** and defines what to do if they fail

		4. **ARC (Authenticated Received Chain) :**
		    - **Function :** 
			    - It preserves original authentication results (SPF, DKIM, DMARC) for emails that pass through intermediate servers, such as mailing lists or auto-forwarding services
		    - **Working :** 
			    - Each intermediary adds an "ARC seal" to the email
				- The final recipient uses these seals to validate the original authentication, even if forwarding broke the direct SPF or DKIM checks
			- **In Simple :**
				- It Keeps authentication info when emails are forwarded
    
3. **Spoof intelligence Protection**
	- It detects and blocks fake emails pretending to be from trusted or known domain
		- **Intra-org spoofing** :
			- Fake emails pretending to be internal users, inside the organization 
	    - **Cross-domain spoofing** :
		    - Fake emails pretending to be external trusted domains, outside the organization
    
4. **Bulk filtering Protection**
	- Identifies bulk or mass emails and lets admins decide how strict spam filtering should be

5. **Mailbox intelligence Protection**  
	- Learns who a user normally communicates with and flags emails that only _look_ familiar but are malicious

6. **Mailbox intelligence impersonation**
	- Uses each user’s communication history to detect impersonation attempts

7. **User impersonation protection**
	- Protects **high-value users (executives, finance, IT)** from **impersonation attacks** attempts

8. **Domain impersonation protection**  
	- Detects fake domains that closely resemble with organization’s domain

![[Pasted image 20260122085558.png]]

## 03 MDO : Content Filtering (Third Phase)

1. **Transport custom rules :**   
    - Admin-defined rules that automatically act on emails based on conditions (block, allow, redirect, add warnings)
    
2. **Type blocking :**  
    - Blocks dangerous file types by detecting the _real_ file type, even if the extension is changed
    
3. **Heuristic clustering :**  
    - Identifies suspicious email campaigns by spotting patterns across multiple similar messages
    
4. **Tenant allow/block lists :**  
    - Lets admins manually allow trusted senders or block known bad senders, files, or URLs
    
5. **Content heuristics :**  
    - Analyzes the email body, headers, and structure to detect phishing or malicious intent
    
6. **Linked content detonation :**  
    - Treats files linked in emails as attachments and sandboxes them to check for threats
    
7. **AV engines :**  
    - Uses Microsoft Defender Antivirus to scan attachments for known malware
    
8. **Attachment reputation blocking :**  
    - Blocks attachments based on known malicious file hashes and reputation data
    
9. **ML models :**  
    - Machine learning analyzes email content, behavior, and metadata to detect advanced threats
    
10. **URL reputation blocking :**  
    - Blocks emails containing URLs known to be malicious from threat intelligence feeds
    
11. **Safe attachments :**  
    - Sandboxes attachments to detect unknown or zero-day malware before users open them
    
12. **URL detonation :**  
    - Opens suspicious links in a sandbox at delivery time to see if they behave maliciously

![[Pasted image 20260122092129.png]]

## 04 MDO : Post-Delivery Protection

- **Post-delivery protection** detects and fixes threats **after emails have already been delivered**
- Post-delivery protection **finds missed threats, removes them automatically, and protects users at click time**
### Features

1. **Safe Links**  
    - Checks links _when users click them_. If a link turns malicious later, access is blocked
    
2. **Phish Zero-Hour Auto-Purge (ZAP)**  
    - Automatically removes phishing emails that were delivered before being detected
    
3. **Malware Zero-Hour Auto-Purge (ZAP)**  
    - Automatically removes malware emails that were delivered earlier
    
4. **Spam Zero-Hour Auto-Purge (ZAP)**  
    - Automatically removes spam messages that were delivered
    
5. **Campaigns**  
    - Shows the full attack story (who was targeted, how it spread, impact) to help admins investigate end-to-end
    
6. **End-user reporting**  
    - Lets users report phishing, spam, or false positives directly to admins and Microsoft
    
7. **Office clients**  
    - Safe Links protection works inside Outlook, Word, Excel, PowerPoint, and Teams
    
8. **OneDrive / SharePoint**  
    - Safe Attachments protection for files stored or shared in OneDrive and SharePoint
    
9. **URL detonation**  
    - When a user clicks a link to a file after delivery, the file is sandboxed and a warning is shown until it’s verified safe
   ![[Pasted image 20260122093500.png]]

---
