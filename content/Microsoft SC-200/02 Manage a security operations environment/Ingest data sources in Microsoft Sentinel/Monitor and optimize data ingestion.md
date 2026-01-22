# Ingestion Delay
  
- Ingestion delay is the **time between when a log is created on a system and when it arrives in Microsoft Sentinel**
- **Example :**
	- Log created at **10:00**
	- Log appears in Sentinel at **10:02**  
    - Therefore, Ingestion delay = **2 minutes**
    
## Why is ingestion delay a problem?

- **As Scheduled analytics rules :**
	- Run on a schedule (e.g., every 5 minutes)
	- Look back in time using the **event timestamp**, not ingestion time

- If logs arrive **late**, some events may :
	- Arrive **after** the rule runs
	- and Fall **outside the next lookback window**  
    
- **Result :** 
	-  **Events are missed and never detected**
    
## How to fix ingestion delay issues

- **Increase the lookback period** of your analytics rule
- **Example :**
	- Ingestion delay: **2 minutes**
	- Rule runs every 5 minutes
	- Change lookback from **5 → 7 minutes**

> This ensures late-arriving logs are still analyzed

## How to measure ingestion delay

- Use **Microsoft Sentinel Workbooks**
- They show the difference between **event time** and **ingestion time**

---

