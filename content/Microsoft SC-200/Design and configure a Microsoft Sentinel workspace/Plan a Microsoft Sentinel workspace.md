# Deploying Sentinel

- **There are a few prerequisites to deploy Sentinel :**
	- Azure Tenant
	- Active Azure Subscription
	- Azure Resource Group
	- Azure Log Analytics Workspace

---

# Demo: Create an Azure Resource Group for Sentinel

- Go to [Azure Portal](https://portal.azure.com)
- Click on **Resource groups**
- Click on **Create**

![[Pasted image 20260120181149.png]]
- **Resource group name** : DemoRG
- Click on Review + create

![[Pasted image 20260120181435.png]]

---

# Log Analytics 

- It collects and stores logs for monitoring    
- **Sentinel** is an add-on that works on top of Log Analytics    
- Logs are stored in a **Log Analytics Workspace**    

- Data is saved in **tables**, not a database with relationships    
- There is **no hierarchy** , just a flat list of tables    

- You use **KQL (Kusto Query Language)** to search and analyze logs    
- You can query data from **other workspaces** too    
- Logs are kept **30 days by default**, extendable up to **730 days = 2 years**    

- Access can be controlled **per table (RBAC)**    
- Data is **encrypted** both while moving and when stored

## **Log Analytics Dedicated Cluster** 

- It is a **high-end version of the standard Azure Log Analytics service** 
- Think of a **standard workspace** as a **"shared apartment"** where your logs live on shared hardware, a **dedicated cluster** is like renting an **entire private building** for your logs

- **Log Analytics feature :** 
	- It is a **premium option** for Log Analytics    
	- Uses **dedicated resources** instead of shared ones    
	- **Customer Lockbox**: Microsoft can’t access your data without approval    
	- **Double encryption**: extra protection for stored data    
	- **Availability Zones support**: better reliability and uptime    
	- **Faster cross-workspace queries**    
	- Requires a **minimum of 500 GB data ingestion per day**

## Demo: Create a Log Analytics Workspace

- Go to [Azure Portal](https://portal.azure.com)
- Search for **Log Analytics workspaces**
- Click on **Log Analytics workspaces**

![[Pasted image 20260120184456.png]]

- Select **Resource group :** DemoRG
- Under **Instance Details**
	- Name : DemoLA
- Click on Review + create

![[Pasted image 20260120184649.png]]

---

# Demo: Create a Sentinel Workspace

- Go to [Azure Portal](https://portal.azure.com)
- Search for **Microsoft Sentinel**
- Click on **Microsoft Sentinel**
- Click on **Create**

![[Pasted image 20260120185558.png]]

- Select **Workspace** : DemoLA
- Click on **Add**

![[Pasted image 20260120185648.png]]

---


