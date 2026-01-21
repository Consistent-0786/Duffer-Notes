# Azure Blob Storage

- **Azure Blob Storage** is cheap cloud storage (like **Dropbox in Azure**)    
- It is **not a security or SIEM service**—no threat hunting or KQL queries    

- Logs are sent from **Log Analytics/Sentinel** to **Blob Storage** for long-term retention    
- **Analysts cannot query logs directly** in Blob Storage    

- To analyze old logs, they must be **manually re-ingested into Sentinel**    
- This option is **the cheapest**, but also **the most limited**    

- **When to use it :**
	- Use **Blob Storage** if logs are kept **only for compliance or emergencies**    
	- Use **Sentinel Archive or ADX** if you need to **query or investigate logs regularly**

---

