# Analytic Rules 

- Analytic Rules are your **SIEM use-cases defined via KQL**
- Sentinel comes with over **500 rule templates**
- Limit of **512 rules per workspace**
> To know Demo : [Click here](obsidian://open?vault=Public&file=Microsoft%20SC-200%2F03%20Configure%20protections%20and%20detections%2F02%20Configure%20detections%20in%20Microsoft%20Sentinel%2FConfigure%20and%20manage%20analytics%20rules%2F02.1%20Demo%20-%20Analytic%20Rules)  
## Types of Analytic Rules :
	
### 1. Scheduled Rules

- **Default and most commonly used** analytic rule type
    
- Run **continuously on a defined schedule**
    
- You choose:
    
    - **Run frequency** (e.g., every 5 minutes, every hour)
        
    - **Lookback period** (from **5 minutes up to 14 days**)
        
- The rule **fires an alert** when the defined condition is met
    
- **No practical limit** on the number of scheduled rules  
    → This is why most organizations use them for SIEM use cases
    

---

### One-Line Summary

**Scheduled rules run on a set schedule, check past data, and generate alerts when conditions are met—making them the default Sentinel rule type.**




	1. Near-Real-Time (NRT)
	2. Fusion
	3. ML Behavior Analytics
	4. Threat Intelligence
	5. Microsoft Security
	6. Anomaly

---

