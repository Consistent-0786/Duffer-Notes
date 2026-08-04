# Microsoft Entra Suite - Overview

## Entra vs Entra ID (Common Misconception)
- Microsoft Entra is NOT the same as Entra ID.
- Entra ID = Microsoft's identity provider (formerly Azure Active Directory / Azure AD).
- Microsoft Entra = the entire suite/bundle of Microsoft's identity-related products, of which Entra ID is just one part.
- Exam tip: don't confuse the umbrella suite (Entra) with the specific identity provider product (Entra ID).

---

## The Four Pillars of Microsoft Entra 

![[Pasted image 20260804191722.png|700]]
### Pillar 1: Zero Trust Access Control
- Core product: **Entra ID**
- Microsoft's identity provider (formerly Azure AD).
- Covers core identity and security features/services.

### Pillar 2: Secure Access for Employees
- **Entra Private Access** - enables Zero Trust Network Access (ZTNA).
- **Entra Internet Access** - secure proxy for employees connecting to the internet.
- **Entra ID Governance** - ensures the right people have the right access to the right resources at the right time.
- **Entra Verified ID** - establishes decentralized identity.

### Pillar 3: Secure Access for Customers and Partners
- **Entra External ID** - manages external identities (guests, partners, customers).

### Pillar 4: Secure Access in Any Cloud
- **Entra Permissions Management (EPM)** - manages permissions across Azure, AWS, GCP from a central place.
- **Entra Workload ID** - manages identities associated with workloads (not humans).

---

## Licensing Tiers

| License | What You Get |
|---|---|
| **Free** | Basic Entra ID features only (e.g., identity provisioning). Limited functionality. |
| **Entra ID P1** | All Entra ID features. Some Entra ID Governance and Verified ID features. No Entra ID Protection. No Internet Access or Private Access. |
| **Entra ID P2** | Same as P1, PLUS Entra ID Protection (additional identity security). |
| **Entra Suite** | Full access to the entire Entra suite. |

Key distinction: P1 → P2 upgrade = mainly about gaining **Entra ID Protection**.

---

## Product Deep Dives

### Entra ID Governance
**Market Challenge:**
- Managing user identities, permissions, and entitlements across multiple IT environments from a single place.

**Purpose:**
- Ensure the right people have the right access to the right resources at the right time.

**Key Features:**
- Identity lifecycle governance
- Access lifecycle governance
- Securing privileged access for admins

**Typical scenario:** Employee changes department -> needs different permissions -> Entra ID Governance handles this.

---

### Entra Verified ID
**Market Challenge:**
- People don't own their identity data.
- Individuals lack visibility into how their data is used and how to reclaim it (e.g., data stored with a third-party platform like LinkedIn).

**Purpose:**
- Solve confidentiality issues via a **decentralized identity** approach.
- Verify workplace credentials: citizenship, education, certifications, other identity attributes.
- Example: proving a Microsoft certification via Verified ID.

**Key Features:**
- Decentralized identity
- Verifiable credentials (e.g., certifications)
- Interoperability and standards compliance (works across different solutions)

---

### Entra External ID
**Market Challenge:**
- Rapid increase in external identities needing to collaborate (customers, partners, consultants, auditors).

**Purpose:**
- A Customer Identity and Access Management (CIAM) solution.
- Personalize and secure access to applications for customers and partners.

**Key Features:**
- Flexible user onboarding and authentication for external identities
- B2B identity management (business to business)
- B2C identity management (business to consumer/customer)
- Unified and scalable identity handling

---

### Microsoft Entra Permissions Management (EPM)
**Market Challenge:**
- Enterprises often have 40,000+ permissions granted across Azure, AWS, and GCP.
- Studies show identities typically use only ~1% of granted permissions -> 99% are unused and often over-permissive (violates least privilege).

**Purpose:**
- Provide visibility and control over permissions across multi-cloud environments (Azure, AWS, GCP).
- Also known as CIEM (Cloud Infrastructure Entitlement Management).

**Key Features:**
- Visibility of permissions across Azure, AWS, GCP
- Permission control and enforcement
- Automated permission monitoring

---

### Microsoft Entra Workload ID
**Market Challenge:**
- Workload identities (non-human) accessing critical infrastructure are increasing and now outnumber human identities roughly 10:1.
- Some workload identities are highly privileged and need to be treated as privileged assets.

**Purpose:**
- Secure adaptive access.
- Detect and respond to compromised workload identities.
- Simplify workload identity lifecycle management.

**Key Features:**
- Identity management for workloads
- Certificates and keyless authentication
- Automated lifecycle management for workload identities

---

### Microsoft Entra Internet Access
**Market Challenge:**
- Need to control web traffic with threat protection, content filtering, and policy enforcement for safe/productive internet usage.

**What it is:**
- A secure proxy for outbound internet traffic.

**Purpose:**
- Secure access to internet SaaS and M365 apps/resources.
- Protect the organization from threats via an identity-centric Secure Web Gateway.

**Key Features:**
- Secure Web Gateway (proxy)
- Zero Trust-based access
- Visibility and analytics on internet traffic

---

### Microsoft Entra Private Access
**Market Challenge:**
- Different from Internet Access - this deals with INBOUND access to private/on-premises company resources, not outbound internet traffic.
- Traditional approach requires multiple separate solutions (VPN, certificate-based auth, identity monitoring tools, etc.).

**Purpose:**
- Simplify network architecture by converging multiple security/network solutions into one unified cloud-based service.
- Remove risk and operational complexity of legacy VPNs.
- Boost user productivity.
- Quickly and securely connect remote users (any device, any network) to private apps - on-premises or across clouds.

**Key Features:**
- Zero Trust Network Access (ZTNA)
- Seamless access to private (e.g., on-premises) resources
- Real-time access monitoring and policy enforcement

---

## Quick Comparison: Internet Access vs Private Access
| | Entra Internet Access | Entra Private Access |
|---|---|---|
| Direction | Outbound (employee -> internet) | Inbound (remote user -> private/on-prem apps) |
| Function | Secure Web Gateway / proxy | Replaces VPN with ZTNA |
| Focus | Threat protection, content filtering | Reduce VPN complexity, secure private app access |

---

## Quick Review / Flashcard Candidates
- Is Entra the same as Entra ID? -> No, Entra ID is one product within the larger Entra suite.
- Old name for Entra ID? -> Azure Active Directory (Azure AD)
- What does CIAM stand for? -> Customer Identity and Access Management (used by Entra External ID)
- What does CIEM stand for? -> Cloud Infrastructure Entitlement Management (used by Entra Permissions Management)
- What percentage of granted cloud permissions are typically actually used? -> Around 1%
- Ratio of workload identities to human identities? -> Roughly 10:1
- Which Entra ID license tier adds Entra ID Protection? -> P2 (not included in P1)
- What does Entra Verified ID rely on? -> Decentralized identity model
- Entra Private Access replaces what legacy technology? -> VPN (Virtual Private Network)
- What is B2B vs B2C in Entra External ID? -> B2B = business to business, B2C = business to consumer/customer