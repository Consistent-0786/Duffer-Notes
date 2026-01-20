# Microsoft Sentinel : Log storage types & pricing
- **There are basically three types of sentinel logs :**
	- **Analytics logs :**
		- Default and most expensive; used for **real-time security monitoring**, kept **90 days**, pay-as-you-go
    - **Basic logs :**
	    - **Cheaper** option for **high-volume, occasional use** logs; kept **8 days** with limited features
	- **Archive logs :**
		- **Lowest cost** long-term storage (up to **7 years**) for **compliance**; searchable with limits and restorable
    
**Pricing idea :**  
- You mainly pay based on **data ingested**, **how long you keep it**, and **which storage tier you use**
- Best cost optimization is **Analytics → Archive → Restore when needed**

![[Pasted image 20260120221255.png]]

---

