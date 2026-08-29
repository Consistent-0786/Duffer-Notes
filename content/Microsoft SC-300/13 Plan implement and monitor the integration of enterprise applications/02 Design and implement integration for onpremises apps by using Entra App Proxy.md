# Entra Application Proxy

## What Is Application Proxy?
- Provides secure remote access to **on-premises web applications**.
- After a single sign-on (SSO) to Entra ID, users can access both cloud and on-premises applications through an external URL or an internal application portal.

---

## The Three Pillars of Application Proxy

### 1. Simple to Use
- Users access on-premises apps the exact same way they already access Microsoft 365 or other SaaS apps integrated with Entra ID.
- No need to change or update the applications themselves.
- User experience is identical to accessing other Entra ID-integrated apps.

### 2. Secure
- On-premises apps can leverage Entra authorization controls such as **Conditional Access** and **MFA**.
- Does NOT require opening any **inbound connections** through on-premises firewalls.

### 3. Cost-Effective
- Traditional on-premises remote access setups typically require a DMZ (demilitarized zone), edge servers, or other infrastructure.
- Application Proxy runs entirely in the cloud - no need for extra network infrastructure or appliances.
- Works purely through authentication, authorization, and Conditional Access.

---

## Architecture Overview
- Users access applications via the **My Apps portal** or a registered application in Entra ID.
- The on-premises application connects to Entra ID via:
  - **Active Directory** (on-premises)
  - **App Proxy Connector**

### Key Components
- **App Proxy Connector**: an agent running on a **Windows Server**.
- The application must be a **registered application in Entra ID** with a supported authentication type, in a private network.

---

## Authentication Flow (Step-by-Step)

![[Pasted image 20260829145443.png]]

1. User is directed to the **Microsoft Entra sign-in page** after accessing the application via its endpoint.
2. Microsoft Entra sends a **token** to the user's client device after successful login.
3. Client sends the token to the **Application Proxy service**, which retrieves the User Principal Name (UPN) and Security Principal Name (SPN) from the token.
4. App Proxy service sends the request to the **App Proxy Connector**.
5. The connector performs single sign-on authentication on behalf of the user against the **on-premises Active Directory**.
6. The connector sends the request to the **on-premises application**.
7. The response is returned through the connector and Application Proxy service back to the user - authentication complete.

---

## Key Benefit: No VPN Required
- Users authenticate against Entra ID, leveraging Conditional Access and other security features.
- Connection to the on-premises app is initiated via **TLS**.
- No VPN needed, no inbound firewall ports need to be opened.
- The on-premises web app is simply exposed to the internet via Entra Application Proxy.

---

## Quick Review / Flashcard Candidates
- What is the primary purpose of Entra Application Proxy? -> Secure remote access to on-premises web applications, without a VPN
- What agent must be installed to connect on-premises apps to Entra ID? -> The App Proxy Connector (runs on a Windows Server)
- Does Application Proxy require inbound firewall ports to be opened? -> No
- What security features can on-premises apps gain through Application Proxy? -> Conditional Access and MFA
- What two identifiers does the App Proxy service retrieve from the token? -> User Principal Name (UPN) and Security Principal Name (SPN)
- What protocol initiates the connection to the on-premises app? -> TLS
- What performs SSO on behalf of the user against on-premises AD? -> The App Proxy Connector
- What traditional infrastructure does App Proxy help you avoid maintaining? -> DMZ, edge servers, VPN infrastructure