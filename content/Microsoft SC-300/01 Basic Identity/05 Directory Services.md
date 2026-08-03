## Directory Services

**Definition:**
A **Directory Service** is a centralized database that stores and manages **users, devices, and other identities**.

**Simple Explanation:**
A Directory Service keeps all identities in one place and helps organizations manage network resources and identity services.

**Directory Service vs Identity Provider (IdP):**
- **Directory Service** → Usually **on-premises** (e.g., **Active Directory**).
- **Identity Provider (IdP)** → Usually **cloud-based** (e.g., **Microsoft Entra ID**).
- Both centralize identities and provide identity-related services.

**Key Points (SC-300):**
- Stores user and device identities.
- Centralizes identity management.
- Essential for managing network resources.
- Supports large enterprise environments.
- In Microsoft:
  - **Active Directory (AD)** = On-premises Directory Service.
  - **Microsoft Entra ID** = Cloud Identity Provider (IdP).

**Related Terms:**
- **Active Directory (AD)** → Microsoft's on-premises directory service.
- **Microsoft Entra ID** → Microsoft's cloud-based identity provider.
- **LDAP (Lightweight Directory Access Protocol)** → Protocol used by **Active Directory** to access directory data; **not supported by Microsoft Entra ID**.

💡 **Exam Tip:**
- **Directory Service = Active Directory (On-premises).**
- **Identity Provider = Microsoft Entra ID (Cloud).**
- **AD supports LDAP; Microsoft Entra ID does not.**
- Both manage identities, but they are designed for different environments.
