# Exposure Management (XSPM) in Microsoft Defender XDR

- It is a **unified solution** that continuously identifies, prioritizes, and reduces security exposures across **Microsoft Defender for Endpoints, Identities, Email, and Cloud workloads** from a single platform
- Exposure Management **brings together security exposure data from across the entire Microsoft security stack into a single view** instead of using separate tools for each domain
## It Unifies Exposures from :

- **Endpoints** (devices, OS, applications)   
- **Identities** (users, privileges, MFA status)    
- **Email & collaboration** (phishing risk, mailbox exposure)    
- **Cloud workloads** (VMs, containers, configurations)    
- **Applications & data**

---

# To Access : Exposure Management in Microsoft Defender XDR 

- Go to [Microsoft Defender XDR](https://security.microsoft.com)
- Click on **Exposure Management** tab to expand
- Click on **Overview**

![[Pasted image 20260118151119.png]]

---

# XSPM Attack Surfaces

- XSPM attack surfaces are **all the connected entry points and weaknesses** across microsoft identities, endpoints, email, cloud, applications, and data that **attackers can exploit**
## Attack Paths | Map

### Attack Paths

- An attack path is the step-by-step route an attacker can take to move through different attack surfaces and reach a valuable target
- It shows **how one weakness leads to another**.
- Example :
`Phishing email → stolen credentials → access to device → admin privilege → sensitive data`
### Map

- **An attack map is a visual representation of all attack paths across different attack surfaces.**

## To Access : Attack Surfaces (Attack Paths | Map)

- Go to [Microsoft Defender XDR](https://security.microsoft.com)
- Click on **Exposure Management** tab to expand
- Click on **Attack Surfaces**

![[Pasted image 20260118154026.png]]

---

# XSPM Exposure Insights

## Initiatives 

- **Initiatives are grouped security improvement plans that help reduce exposure and attack paths**
- They organize recommendations in a meaningful way so teams know **what to fix and why**
### 1. Domain Initiatives

- Domain initiatives focus on **improving security posture** within a specific **Attack surface or Domain like : Identity, Endpoint, Email, Cloud, Applications, Data**
### 2. Threat Initiatives

- **Threat initiatives focus on reducing exposure related to specific Threat Actor Techniques.**

## Recommendations

- Recommendations are **specific, actionable steps** provided to reduce exposure and risk
- They are the **building blocks** of ==Initiatives==

## Secure Score

- Secure Score is a numerical value that shows how well an organization is protected based on implemented security controls and reduced exposures
- It measures **security posture**, not active attacks
