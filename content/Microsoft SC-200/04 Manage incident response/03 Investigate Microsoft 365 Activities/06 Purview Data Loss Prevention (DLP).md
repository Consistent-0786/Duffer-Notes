# What is Data Loss Prevention (DLP) ?

- **Data Loss Prevention (DLP)** helps organizations **prevent sensitive data from being shared, leaked, or misused** either accidentally or intentionally

- It protects data like :
	- Credit card numbers    
	- Social Security numbers    
	- Health records    
	- Financial and proprietary data    

## How DLP Works

- DLP works by using **DLP policies** to :
	- **Identify** sensitive data    
	- **Monitor** how users interact with it
	- **Protect** it by blocking or restricting actions

- DLP protects data :
	- **At rest** (stored data)
	- **In transit** (emails, sharing)
	- **In use** (copying, uploading, downloading)

## Where DLP is Applied

- DLP policies work across :
	- Microsoft 365 (Exchange, Teams, SharePoint, OneDrive)    
	- Office apps (Word, Excel, PowerPoint)    
	- Windows 10 / 11 and macOS    
	- Non-Microsoft cloud apps
	- On-premises file shares and SharePoint    
	- Microsoft Fabric and Power BI

## How DLP Detects Sensitive Data

DLP uses **deep content analysis**, not just text scanning :

- It detects **sensitive Information Types (regex, keywords, proximity)**    
- Function validation    
- Machine learning

- **Example :** 
	- DLP in Action
		- A user tries to email a **Confidential** document to an external user
	    - A **DLP policy** detects the sensitivity label
    
		- The action is :
		    - **Blocked**, or
		    - **Warned with a policy tip**, or
		    - **Allowed with justification**

## DLP Actions

- DLP can :
	- Show **policy tips** to users    
	- **Block** users / sharing (with or without override)    
	- **Quarantine** sensitive files    
	- **Hide sensitive data** in Teams chats    

## Monitoring and Auditing

- All DLP activities are logged    
- Events appear in :    
    - **Microsoft 365 audit log**
    - **Activity Explorer**

> **In Simple :**
- **DLP prevents data leakage**
- Uses **policies + deep content analysis**
- Works across **M365, endpoints, cloud, and on-prem**
- Logs everything for **visibility and auditing**

---

