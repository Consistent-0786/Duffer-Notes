# Analytic Rules 

- Analytic Rules are your **SIEM use-cases defined via KQL**
- Sentinel comes with over **500 rule templates**
- Limit of **512 rules per workspace**

> To know **Analytic Rules Demo :**  [[02.1 Demo - Analytic Rules]]

## Types of Analytic Rules :
	
### 1. Scheduled Rules

- **Default and most commonly used** analytic rule type
- Scheduled rules run on a set schedule, check past data, and generate alerts when conditions are met—making them the default Sentinel rule type

- It run's **continuously on a defined schedule**
     - **Run frequency** (e.g., every 5 minutes, every hour)
     - **Lookback period** (we can set it to run from **5 minutes up to 14 days**)

- The rule **fires an alert** when the defined condition is met  
- **No practical limit** on the number of scheduled rules as there is limit to other rules



	1. Near-Real-Time (NRT)
	2. Fusion
	3. ML Behavior Analytics
	4. Threat Intelligence
	5. Microsoft Security
	6. Anomaly

---

