# What are Sensitive Information Types (SITs)?

- **Sensitive Information Types (SITs)** help Microsoft Purview **identify and classify sensitive data** in your organization

- They are the **first step in information protection** and are used to detect things like :
	- Social Security numbers
	- Credit card numbers
	- Bank account numbers

- Purview can identify sensitive data in **three ways** :
	- **Manual** (user applies it)
	- **Pattern-based detection** (SITs
	- **Machine learning**

## Key Facts about SITs

- SITs are **pattern-based classifiers**
- Microsoft provides many **built-in SITs**
- You can also create **custom SITs**
    
- SITs are used by :    
    - Data Loss Prevention (DLP)
    - Sensitivity labels
    - Retention labels
    - Insider Risk Management
    - Communication Compliance
    - Auto-labeling
    - Microsoft Priva        

- **Example :**  
	- If an email contains a **Social Security number**, a **DLP policy** can block it from being sent

## Categories of Sensitive Information Types

1. **Built-in SITs** (provided by Microsoft)    
2. **Named entities** (custom-defined types)    
3. **Exact Data Match (EDM)** (matches exact values)

## Components of a Sensitive Information Type

- Each SIT has these main fields :
	- **Name** –> What the SIT is called
    - **Description** –>  What it detects
    - **Pattern** –>  How detection works

## Pattern Components (VERY IMPORTANT)

- A pattern consists of **four parts** :
 1. **Primary Element :**
- The **main thing being detected**, such as :
	- Regular expression (e.g., SSN format)
	- Keyword list    
	- Dictionary
    - Function

 2. **Supporting Element :**
 - Extra evidence that **increases accuracy**, such as :
	 - Keywords like “Social Security Number”
	- Additional regex patterns

👉 Helps reduce false matches

 3. **Confidence Level :**
- Shows **how sure Purview is** that the data is sensitive :
	- **Low (65)** → More matches, more false positives
	- **Medium (75)** → Balanced
	- **High (85)** → Fewer false positives, more false negatives
    
> **Best practice :**
- Use **high confidence** for small counts (5–10)
- Use **low confidence** for large counts (20+)

3. **Proximity :**
- Defines **how close** the ==**Supporting element** must be to the **Primary element**== (measured in number of characters)

👉 If supporting evidence is too far away, the match **won’t count**

 - **Example :** (SSN Detection)
	- **Primary element**: 9-digit SSN
    - **Supporting elements**: Name, Date of Birth, Account Number
    - **Proximity**: 250 characters
	- Only SSNs with ==supporting data== **within proximity** are detected

> **In Simple :**
	- **SITs identify sensitive data**
	- They use **patterns + confidence + proximity**
    - They power **DLP, labels, insider risk, and compliance**
    - **Higher confidence = fewer false positives**

---

