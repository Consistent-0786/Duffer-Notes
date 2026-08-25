# Microsoft Entra Global Secure Access (GSA)

## Historical Context
- Remote access evolution over time:
  - 1990s: dial-up modem connections to a Remote Access Server (RAS) / Remote Access Services
  - Early 2000s: shift to VPNs (Virtual Private Networks) for secure connections
- Today's challenge: most company resources are now hosted in the cloud (Microsoft 365, Azure IaaS/PaaS, various SaaS apps), so traditional VPN-centric approaches don't scale well.
- Businesses now want users to work from anywhere, on virtually any device, with seamless secure access - without necessarily standing up VPN gateways for everything.

---

## The Two Core Technologies

![[Pasted image 20260823171101.png]]

Global Secure Access combines two technologies:
1. **Microsoft Entra Internet Access**
2. **Microsoft Entra Private Access**

- Both work together via a client called the **Global Secure Access client**, installed on user devices.
- Users authenticate through this client, gaining secure access to both Microsoft 365 apps and Azure services.
- Managed through the Microsoft Entra portal.

---

## What Is SSE (Secure Service Edge)?
- Combining Entra Internet Access + Entra Private Access creates a **Secure Service Edge (SSE)** solution.
- SSE = securely connecting users at "the edge" to the resources they need, regardless of location or device ownership.

---

## Key Capabilities / Characteristics

### Identity-Centric / Zero Trust Model
- Built around Zero Trust principles.
- Supports Conditional Access policies and compliance policies.
- Devices may be required to meet certain compliance standards to be granted access.

### Remote Network Connectivity
- Allows end users secure access to needed resources from anywhere.

### Web Content Filtering
- Can control which websites/content users can access.
- On company-owned devices, this can be locked down tightly.
- Works with **Defender for Cloud Apps** to restrict, for example, use of personal Dropbox/OneDrive accounts while allowing only business accounts.

### Simplified Traffic Management
- Controls flow and types of network traffic allowed, in conjunction with compliance/security policies.

### Scalability and Flexibility
- Helps avoid the scaling issues of traditional network security infrastructure (e.g., VPN concentrators).
- Supports many device types and locations without heavy additional infrastructure.

### Zero Trust Access to Private Resources
- Everything is authenticated and authorized via Microsoft Entra ID (formerly Azure Active Directory).
- No traditional VPN capability required.
- Follows Conditional Access and compliance policies.
- Policy enforcement happens in **real time** - no reboot or delay needed for restrictions to take effect.

---

## Key Takeaway
- Even without owning the device, an organization can enforce extra lockdown/encryption when accessing company resources - functioning similarly to a VPN but more seamless and identity-driven.
- Global Secure Access represents Microsoft's modern, unified approach to secure access, replacing much of the traditional VPN model with an identity-centric, Zero Trust framework.

---

## Quick Review / Flashcard Candidates
- What two technologies make up Microsoft Entra Global Secure Access? -> Entra Internet Access and Entra Private Access
- What client software is installed on devices to enable Global Secure Access? -> Global Secure Access client
- What does SSE stand for? -> Secure Service Edge
- What security model underpins Global Secure Access? -> Zero Trust
- What tool helps restrict personal cloud storage accounts (e.g., personal Dropbox) while allowing business accounts? -> Defender for Cloud Apps
- Does Conditional Access enforcement in Global Secure Access happen in real time or require a reboot? -> Real time
- What legacy technology does Global Secure Access aim to reduce reliance on? -> Traditional VPNs
- What does Global Secure Access use to authenticate and authorize access? -> Microsoft Entra ID (identity-centric)