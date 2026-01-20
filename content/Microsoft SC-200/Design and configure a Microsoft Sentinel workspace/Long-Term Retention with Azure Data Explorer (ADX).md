# Azure Data Explorer (ADX) 

- **ADX is a separate Azure service**, not part of Sentinel, and must be **paid for separately**    
- It’s a **big data analytics platform**, often used for data lakes    
- It **does not include Sentinel/SIEM features** like incidents or automation    

- It **support KQL**, so analysts can still run queries and investigations    
- Logs are first ingested into **Log Analytics / Sentinel**, then **copied to ADX** for long-term storage 
- Keeping logs in **ADX for years is cheaper** than storing them in Sentinel analytics logs    
- Analysts can query **old logs directly in ADX** without using expensive Sentinel storage   

- **Purpose :**
	- Use ADX to **reduce costs** while still enabling **KQL-based investigations on historical data**

---

