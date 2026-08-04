# Microsoft Entra ID - Overview

## What Is Entra ID?
- Cloud-based Identity and Access Management (IAM) service and identity provider.
- Formerly known as Azure Active Directory (Azure AD) - renamed to Entra ID.
- Employees use it to access both external and internal resources.

### External resources it can access
- Microsoft 365
- Azure portal
- Other SaaS applications / cloud services

### Internal resources it can access
- Apps on corporate intranet
- Cloud apps developed for your own organization
- Core purpose: manage identities and ensure the right access to the right resources at the right time.

---

## Key Features of Entra ID

![[Pasted image 20260804200045.png|454]]
### Access Reviews
- Workflow-based approach to continuously review permissions over time.
- Can be automated to a certain degree.
- Ensures access grants (e.g., in Azure) are periodically reviewed.

### Application Proxy
- Makes on-premises resources securely available to employees without requiring a VPN.
- Employees authenticate directly, no VPN needed first.

### B2B and B2C
- Manage external identities and grant them access to your solutions.
- **B2B** (Business to Business): one company interacting with another in terms of identity.
- **B2C** (Business to Consumer): interacting directly with customers/consumers (e.g., e-commerce customers).

### Conditional Access
- Checks certain conditions when a user authenticates to decide whether access should be granted.
- Based on conditional access policies, determines the outcome (allow, block, or require additional action).
- Very prominent/well-known feature in the Microsoft ecosystem.

### Device Management
- Manages cloud and on-premises devices used to access corporate data.

### Domain Services
- Supports legacy protocols like **NTLM** and **Kerberos** for apps that still require them.
- Allows leveraging domain services in the cloud.

### Hybrid Identity
- Enables a single user identity for authentication and authorization across all resources, regardless of location (cloud or on-premises).

### Identity Protection
- Detects potential threats affecting organizational identities.
- Configures policies to respond to suspicious activity and take corrective action.
- Example: alerts if a user authenticates with credentials known to be leaked (e.g., found on the darknet).

### Multi-Factor Authentication (MFA)
- Multiple authentication options available to strengthen sign-in security.

### Privileged Identity Management (PIM)
- Manage, control, and monitor privileged access within the organization.
- Covers access to Entra ID, Azure, and other Microsoft online services.

### Workload Identities
- Gives identity to software workloads (apps, VMs, containers) so they can securely access other services/resources.
- Enables monitoring and control of these non-human identities.

---

## Licensing Tiers

| License | Included Features |
|---|---|
| **Free** | Cloud authentication, Single Sign-On (SSO), B2B setup, Passwordless authentication |
| **Entra ID P1** | Everything in Free, plus: Conditional Access, Dynamic group memberships (attribute-based), Entra Application Proxy |
| **Entra ID P2** | Everything in Free + P1, plus: Identity Protection, Privileged Identity Management (PIM) |
| **Entra ID Governance (add-on)** | NOT standalone - requires P2 as a base. Adds: Identity governance dashboards, Lifecycle workflows, full ID Governance features |

Key point: To get full Entra ID capability, you need **P2 + the Governance add-on** together (the add-on alone does not include P2 features).

---

## Quick Review / Flashcard Candidates
- What was Entra ID formerly called? -> Azure Active Directory (Azure AD)
- What does Application Proxy remove the need for? -> VPN
- B2B vs B2C in Entra ID? -> B2B = business-to-business identity interaction; B2C = business-to-consumer/customer interaction
- Which feature checks conditions at sign-in to allow/block access? -> Conditional Access
- Which feature detects leaked credentials or suspicious sign-in behavior? -> Identity Protection
- Which license tier introduces Identity Protection and PIM? -> Entra ID P2
- Which license tier introduces Conditional Access and Application Proxy? -> Entra ID P1
- Can you get the ID Governance add-on without P2? -> No, it requires P2 as the base license
- What legacy protocols does Domain Services support? -> NTLM and Kerberos
- What is Workload Identity used for? -> Giving identity to non-human resources like apps, VMs, containers