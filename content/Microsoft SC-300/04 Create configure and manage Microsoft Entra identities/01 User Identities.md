# User Identities in Entra ID

## What Is a User Identity?
- The most intuitive identity type - identities associated with **human beings**.
- Different from **workload identities**, which are associated with resources (e.g., in Azure), not humans.

---

## Types of User Identities

### Synchronized Identities
- Identities synchronized from an **on-premises Active Directory** into Entra ID.
- Typically synchronized using **Entra Connect**.
- Result: the identity exists in both on-premises AD and Entra ID.

### Cloud Identities (Cloud-Only Identities)
- Identities that exist **only in Entra ID**, not in any on-premises Active Directory.

### Guest Identities
- Identities originally created outside your organization, e.g.:
  - Facebook
  - Personal Microsoft account
  - Apple account
  - Google account
- Used to grant external users access as guests within Entra ID.

---

## Key Characteristics of User Identities
- Allow actual humans to access enterprise resources.
- Can be created:
  - Directly in the cloud
  - On-premises (then synchronized to Entra ID)
- Support multiple authentication methods:
  - Username and password
  - Multi-Factor Authentication (MFA)
  - Passwordless authentication

---

## Stored Properties
- User identities store various properties/attributes, such as:
  - Name (e.g., John Robbins)
  - Office/location (e.g., Seattle)
- Entra ID stores many more properties beyond these examples.

---

## Quick Review / Flashcard Candidates
- What is a synchronized identity? -> An identity synced from on-premises Active Directory into Entra ID, typically via Entra Connect
- What is a cloud-only identity? -> An identity that exists only in Entra ID, not in on-premises AD
- What is a guest identity? -> An identity originally created elsewhere (e.g., Google, Facebook, personal Microsoft account) given access as a guest
- What tool is commonly used to sync on-prem AD identities to Entra ID? -> Entra Connect
- How is a user identity different from a workload identity? -> User identity = human; workload identity = associated with a resource (app, VM, etc.)
- What authentication methods do user identities support? -> Username/password, MFA, passwordless authentication