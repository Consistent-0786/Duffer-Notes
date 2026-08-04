# Entra ID Roles

## What Is an Entra ID Role?
- An Entra ID role gives users permission to do something within the **Microsoft ecosystem**.
- Common misconception: Entra ID roles are NOT just for Azure.
- Entra ID roles actually span across the entire Microsoft ecosystem (e.g., Microsoft Teams, Microsoft 365, Azure, Entra ID itself).
- ![[Pasted image 20260804201459.png]]

---
## Example 1: Alice - Teams Administrator
- Role: **Teams Administrator** (a built-in role)
- What she CAN do:
  - Manage Microsoft Teams settings, policies, and configurations
  - Manage meeting settings and messaging policies
  - Manage users within Teams
  - Troubleshoot Teams-related issues
  - Monitor Teams service health
- What she CANNOT do:
  - Modify users in Entra ID
- Key takeaway: this role is scoped specifically to Teams administration, proving Entra ID roles apply beyond just Azure.

---

## Example 2: Sanjay - Security Administrator
- Role: **Security Administrator** (a built-in, **privileged** role)
- Privileged = Microsoft considers this role critical/high-risk.
- What he CAN do:
  - Manage security-related features
  - Monitor security reports
  - Configure security policies (e.g., Conditional Access)
  - Manage security alerts across the organization (e.g., in Defender XDR, Sentinel, Defender for Cloud)

---

## Example 3: IT Audit Team - Global Reader
- Role: **Global Reader** (a built-in, **privileged** role)
- Provides **read-only** access to all settings and resources across:
  - Microsoft 365
  - Azure
  - Entra ID
- Cannot make any changes - view only.
- Common use case: audits, reporting, compliance review.

---

## Built-in Roles
- Roles like Teams Administrator, Security Administrator, and Global Reader are **built-in roles** - already pre-configured by Microsoft.
- Admin task = simply assign the role to the appropriate user or group.
- Full list of built-in roles is available in Microsoft's official documentation.

---

## Key Distinction: Entra ID Roles vs Azure RBAC
- Common misconception: Entra ID is only used to manage access within Azure.
- Reality: Entra ID roles cover the **entire Microsoft ecosystem**, not just Azure resources.
- Azure RBAC is a separate concept, specifically for managing access to Azure resources.
- Upcoming lessons will cover Azure RBAC in detail and clarify when to use Entra ID roles vs Azure RBAC.

---

## Quick Review / Flashcard Candidates
- What does an Entra ID role grant a user? -> Permission to perform actions within the Microsoft ecosystem (not just Azure)
- Is Teams Administrator an Azure-only role? -> No, it manages Microsoft Teams, unrelated to Azure resource access
- What can the Security Administrator role manage? -> Security policies, security alerts, security reports (e.g., via Defender/Sentinel)
- What access level does the Global Reader role provide? -> Read-only access across M365, Azure, and Entra ID
- Is Global Reader a privileged role? -> Yes
- What are "built-in roles"? -> Pre-configured roles by Microsoft that just need to be assigned to users/groups
- What's the key difference between Entra ID roles and Azure RBAC? -> Entra ID roles span the whole Microsoft ecosystem; Azure RBAC is specific to Azure resource access