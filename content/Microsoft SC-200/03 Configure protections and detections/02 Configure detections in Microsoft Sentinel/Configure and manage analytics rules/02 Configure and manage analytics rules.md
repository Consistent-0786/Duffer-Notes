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

- **Limit :**
	- **No practical limit** on the number of scheduled rules as there is limit to other rules

> To create **Analytic Rule : Scheduled Rule Demo** : [[02.2 Demo - Scheduled Analytic Rules (For Entra ID)]]

### 2. Near-Real-Time (NRT) Rules

- NRT Analytic Rules **run's continuously and shall provide "up-to-the-**
	**minute" threat detections**
- NRTs run once **every minute** in reality

- **Limit :**
	- **50 NRT rules per workspace**

> To create **Analytic Rule NRT Rules Demo** : [[02.3 Demo - Near-Real-Time-Rules (NRT)]]

### 3. Fusion Rule

- **Fusion** is an analytic rule for **advanced multi-stage attack detection**    
- Uses **120+ built-in detections** created and **maintained by Microsoft**
    
- Correlates activity across **multiple Microsoft data sources**, such as :    
    - Entra ID Identity Protection        
    - Defender for Cloud        
    - Defender for IoT        
    - Microsoft 365 Defender        
    - Other Microsoft and custom Sentinel data        

- **Microsoft-managed**    
    - We mainly **enable and configure** it and detection logic is **handled by Microsoft**        

- **Limit:**
    - Only **ONE rule per Sentinel workspace**        
    - Can be configured or disabled, but **cannot be duplicated**
  
- **In Simple :** 
	- Fusion is a Microsoft-managed analytic rule that correlates multiple security signals to detect complex, multi-stage attacks using a single rule per workspace

### 4. ML Behavior Analytics Rule

- **Machine learning–based analytic rules**    
- This Rule needs **at least 7 days** to learn normal behavior before generating alerts 
- Monitor only **Windows RDP** and **Linux SSH** logons    

- Detect **unusual behavior** based on predefined scenarios :
	1. **Unusual IP**    
	    - IP address not seen or rarely seen in the last **30 days**
        
	2. **Unusual Geo**    
	    - New or rare **IP, city, country, or ASN** in the last **30 days**
        
	3. **New User**    
	    - A new user logs in from an **unexpected IP and/or geo location**

- **Microsoft-managed detections** (limited configuration)

- **Limit :**
    - **2 rules max per workspace**
	    - 1 for RDP
        - 1 for SSH
 
**In Simple :** 
- ML Behavior Analytic rules use machine learning to detect unusual RDP and SSH logon behavior by comparing activity against a learned baseline

>To create **ML Behavior Analytics Rule Demo :**  [[02.4 Demo - ML Behavior Analytics Rule]]


### 5. Threat Intelligence Rule

- Generate alerts when **Microsoft Defender Threat Intelligence indicators**  
    **match your event logs**    
- **Require paid Microsoft Defender Threat Intelligence**    
    - Rule can be enabled without it, but **no alerts will be generated**     
- **Not used for open-source or custom TI feeds**    
    - Works **only** with Defender Threat Intelligence

- Alerts are **high fidelity** means **Early-stage detection**
- **Very low false positives**
- High confidence in detections

- **In Simple :**
	- Threat Intelligence rules alert when paid Defender Threat Intelligence indicators match log data, providing high-confidence, low-false-positive detections

> To create **Threat Intelligence Rule Demo :**

### 6. Microsoft Security Rule

- **Analytic rules that forward alerts** from other Microsoft security sources
	- Defender for Endpoint    
	- Defender for Identity    
	- Defender for Cloud    
	- Other Microsoft security products

- Convert those alerts into **Sentinel incidents**
- **No detection logic in Sentinel** itself

> To create **Threat Intelligence Rules Demo :** [[02.5 Demo - Threat Intelligence Rules]]

---
