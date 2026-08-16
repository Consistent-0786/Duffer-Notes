# Conditional Access

## What Is Conditional Access?
- One of the most important identity/security services in the Microsoft ecosystem - core to nearly every IT security strategy.
- Enforces access control based on **user** and **device** conditions.
- Evaluates signals during authentication, such as:
  - User location
  - Device compliance
  - Risk levels
- Based on evaluation, applies policies to allow, block, or require additional authentication controls (e.g., MFA).
- Helps secure both cloud and on-premises resources through **adaptive security measures**.
- Core enabler of a **Zero Trust security model** - ensures only the right people and devices access critical data.

---

## How It Works: Signals → Policies → Access Decision

### Signals (Inputs)
Conditional Access pulls signals from multiple sources, including:
- **Entra ID** - sign-in and audit logs
- **Identity Protection** - e.g., leaked credentials, sign-in from unfamiliar location
- **Defender for Identity** - installed on on-premises domain controllers; generates alerts for malicious on-prem AD activity
- **Defender for Endpoint** - antivirus/EDR solution monitoring client devices for security incidents
- **Intune** - evaluates device compliance (vulnerabilities, patch status, certificates, etc.)

Note: these five are common examples, but many more signal sources exist.

### Policies (Decision Logic)
Based on the signals received, Conditional Access can:

| Action                      | Example Scenario                                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Allow access**            | No indication of malicious behavior detected                                                                        |
| **Require MFA**             | User signing in from an unfamiliar location                                                                         |
| **Limit access**            | User connecting from an untrusted network (e.g., internet cafe) → allowed read-only SharePoint access, no downloads |
| **Trigger password reset**  | Identity Protection signals the user is authenticating with compromised credentials                                 |
| **Monitor or block access** | Signals strongly indicate a compromised identity                                                                    |

### Resources (Outcome)
- Access decisions apply to resources such as:
  - Azure
  - Dropbox
  - SAP
  - Salesforce
  - Any cloud (Azure, AWS) or on-premises resource

---

## Key Takeaway
- Conditional Access evaluates **every single authentication request** against real-time signals and policies before granting access.
- It's a central pillar of identity security and Zero Trust implementation in the Microsoft ecosystem.

---

## Quick Review / Flashcard Candidates
- What three main conditions does Conditional Access evaluate? -> User location, device compliance, risk levels
- What security model does Conditional Access help implement? -> Zero Trust
- Which signal source is installed on on-premises domain controllers? -> Defender for Identity
- Which signal source evaluates device compliance status (patch level, vulnerabilities)? -> Intune
- Name five possible Conditional Access actions. -> Allow access, require MFA, limit access, trigger password reset, monitor/block access
- What signal could trigger a forced password reset via Conditional Access? -> Identity Protection detecting compromised credentials
- Can Conditional Access apply to on-premises resources, not just cloud? -> Yes