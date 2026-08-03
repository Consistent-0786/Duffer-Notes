## Federation

**Definition:**
**Federation** is a trust relationship between two organizations or domains that allows users to access resources across both without creating separate accounts.

**Simple Explanation:**
Two organizations **trust each other's Identity Providers (IdPs)**, so users can sign in once and access resources in both organizations.

**How Federation Works:**
- Establishes trust between organizations.
- Uses **SAML** or **OAuth** tokens for authentication.
- Enables **Single Sign-On (SSO)** across organizations or cloud services.

**Common Example:**
- **AD FS (Active Directory Federation Services)** is Microsoft's traditional federation solution.

**Modern Microsoft Approach:**
Instead of traditional federation, Microsoft recommends:
- Password Hash Synchronization (PHS)
- Microsoft Entra B2B
- Microsoft Entra B2C
- Hybrid authentication methods in Microsoft Entra ID

**Key Points (SC-300):**
- Federation creates a **trust relationship** between organizations.
- Allows users to access external resources using their existing credentials.
- Supports **cross-organization SSO**.
- Considered a **legacy** approach, but still used in some environments.

💡 **Exam Tip:**
- **Federation = Trust between organizations.**
- **Purpose = Cross-organization authentication + SSO.**
- **AD FS = Traditional Microsoft federation solution.**
- **Modern preference = Microsoft Entra ID with B2B/B2C and hybrid authentication.**