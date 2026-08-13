# Entra ID External Identities

## Purpose
- Enables identities **outside your Entra ID tenant** to collaborate with your organization.
- Two categories of identities to consider:
  - **Internal employees** - already have identities in your own Entra ID tenant; access is managed directly.
  - **Customers and partners** - external identities that need a different mechanism to collaborate.

---

## Ways to Enable External Collaboration

### 1. B2B Collaboration
![[Pasted image 20260813141219.png]]
- Guests use their **own existing identity provider** to access your resources. Examples of identity providers:
  - Apple/iCloud account
  - Google account
  - Another Entra ID tenant
  - Personal Microsoft account
  - Facebook account
- Process:
  - Guest has an identity in their own tenant (e.g., `guestcompany.com`).
  - You invite them into your tenant (e.g., `azuredemos.com`).
  - They join using their **guest identity** and can then access your resources (Azure resources, SharePoint, Teams, etc.).
- **External collaboration settings** in your own tenant define what access/restrictions apply to invited guests.

### 2. B2B Direct Connect
![[Pasted image 20260813141250.png]]
- Also a B2B-style solution, but different from standard B2B Collaboration:
  - Uses **trusted identities**, not guest identities.
  - Requires a **mutual tenant trust** established between both tenants (e.g., `guestcompany.com` and `azuredemos.com` trust each other both ways).
  - No guest identities are created at all - users access resources directly using their identity from their own trusted tenant.
  - Example use case: accessing a shared Teams channel.
- Access and trust level between organizations is defined via **cross-tenant settings**.

### 3. B2C (Business to Consumer)
![[Pasted image 20260813141312.png]]
- Used for external **customers/consumers**, not business partners.
- Customers already have identities with various consumer identity providers:
  - Personal Microsoft account
  - Facebook
  - Google
  - Apple
- These identities connect through an **Entra B2C tenant** to access your application(s).
- Example use case: an e-commerce site (e.g., selling shoes) letting customers log in with an identity they already have.
- Entra B2C tenant features:
  - Provides identity services for one or multiple applications.
  - Offers **customizable branding and sign-up experience**, letting you control the customer journey.

---

## B2B Collaboration vs B2B Direct Connect (Comparison)

| Feature            | B2B Collaboration                               | B2B Direct Connect                          |
| ------------------ | ----------------------------------------------- | ------------------------------------------- |
| Identity type      | Guest identity created in your tenant           | Trusted identity (no guest account created) |
| Trust model        | One-way invite                                  | Mutual tenant trust (two-way)               |
| Governing settings | External collaboration settings                 | Cross-tenant settings                       |
| Example use case   | Accessing SharePoint/Azure resources as a guest | Accessing a shared Teams channel via trust  |

---

## Quick Review / Flashcard Candidates
- What are the three main options under Entra ID External Identities? -> B2B Collaboration, B2B Direct Connect, B2C
- What type of identity is created in B2B Collaboration? -> Guest identity
- What type of identity is used in B2B Direct Connect? -> Trusted identity (no guest account needed)
- What must be established for B2B Direct Connect to work? -> A mutual tenant trust between both organizations
- What settings control guest access in B2B Collaboration? -> External collaboration settings
- What settings control access/trust in B2B Direct Connect? -> Cross-tenant settings
- What is B2C used for? -> Enabling external customers/consumers to access your applications using their existing identity providers
- What can you customize with an Entra B2C tenant? -> Branding and sign-up experience
- Name some identity providers customers might use in B2C. -> Microsoft account, Facebook, Google, Apple