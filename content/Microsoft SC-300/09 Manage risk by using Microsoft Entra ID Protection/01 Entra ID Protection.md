# Entra ID Protection

## What Is Entra ID Protection?

![[Pasted image 20260820211046.png|570]]

- Provides monitoring of identities from a security perspective.
- Main benefits:
  - Prevents identity compromise
  - Enforces policies on identities in Entra ID
  - Integrates seamlessly with **Conditional Access** by feeding it risk signals
- Core purpose: helps organizations **detect, investigate, and remediate** identity-based risks.
- Risk signals can be fed into:
  - Conditional Access (for access decisions)
  - SIEM tools (e.g., Microsoft Sentinel)

---

## How Detections Are Generated
- Microsoft continuously updates its detection catalog based on analysis of trillions of signals gathered from:
  - Active Directory / on-premises identity providers
  - Microsoft accounts (including personal accounts)
  - Xbox/gaming signals
- Detects risky behaviors such as:
  - Unusual IP address usage
  - Password spray attacks
  - Leaked credentials
- **Leaked credentials example:** Microsoft scans the darknet for credential leaks and correlates them against password hashes stored in Entra ID.
- **Password spray example:** detects when multiple passwords are tried across many accounts to find a hit.
- Detections run during each sign-in (real-time sign-in risk evaluation).

---

## Two Types of Risk

| Risk Type | What It Monitors | Possible Actions |
|---|---|---|
| **User Risk** | Risk associated with the identity itself over time | Block access, trigger password change |
| **Sign-In Risk** | Risk associated with a specific sign-in/session | Block access, require MFA |

---

## Detection Types: Offline vs Real-Time

| Detection Type | Time to Surface | Notes |
|---|---|---|
| **Offline** | Up to 48 hours | Takes longer because properties of the risk need deeper evaluation |
| **Real-Time** | ~5-10 minutes | Faster because detection is easier/quicker to verify |

---

## Key Risk Detections (Alerts)

![[Pasted image 20260820210946.png|529]]
### Atypical Travel
- Triggered when a user has two sign-ins from geographically distant locations (e.g., Germany and Japan) within a timeframe that makes travel implausible.
- At least one location is atypical for that user's normal pattern.
- Could be legitimate (business travel) or a genuine compromise.
- **False positives are filtered**: sanctioned VPNs are recognized and ignored.
- Requires a learning period of at least **14 days or 10 logins** before it can trigger.

### Anonymous Token
- Triggered by abnormal token characteristics (e.g., unusually long or short token lifetime).
- Applies to session and refresh tokens used in authentication.

### Suspicious Browser
- Triggered by anomalous browser behavior or suspicious sign-in activity.
- Examples: sign-ins from a different country using the same browser, or use of a **Tor browser** (Tor exit nodes).

### Unfamiliar Sign-In Properties
- Compares current sign-in properties against stored sign-in history.
- Considers properties such as: IP address, asp, location, device, browser, tenant, subnet.
- Triggers an alert when there's a significant deviation from the user's known/typical sign-in properties.

---

## Investigation Workflow (Common Pattern Across Alerts)

### If confirmed True Positive:
- Mark the sign-in as compromised.
- Invoke a password reset.
- Block the user if the attacker already has password reset access.
- Or: perform MFA, then reset password and tokens.

### If determined False Positive:
- Allow the user to self-remediate via a Conditional Access risk policy.
- Or: let an admin manually confirm the sign-in as safe.
- (For Atypical Travel specifically) Can also dismiss if: user is associated with that IP, user is expected to travel, or IP belongs to a sanctioned VPN.

---

## Key Configuration Considerations
- Identity Protection policies are configured at the **Entra ID tenant level** — not per-user or per-group.
- You can only have **one policy per risk type**:
  - One User Risk policy
  - One Sign-In Risk policy
  - (Total of 2 policies possible per tenant)
- Strongly recommended to combine Identity Protection with **Conditional Access** to act on the signals (e.g., block access, require MFA, trigger password reset).

---

## Quick Review / Flashcard Candidates
- What are the two risk types in Identity Protection? -> User Risk and Sign-In Risk
- What's the difference between offline and real-time detections? -> Offline can take up to 48 hours; real-time surfaces in 5-10 minutes
- What triggers an Atypical Travel alert? -> Sign-ins from geographically distant, implausible locations within a short time
- How does Identity Protection avoid false positives for Atypical Travel from VPN use? -> It recognizes and ignores sanctioned/known VPN IPs
- What learning period is required before Atypical Travel can alert? -> At least 14 days or 10 logins
- What does the Anonymous Token detection look for? -> Abnormal token lifetime/characteristics in session or refresh tokens
- What does Suspicious Browser detection flag? -> Anomalous browser behavior, e.g., different country with same browser, or Tor exit node usage
- What does Unfamiliar Sign-In Properties compare against? -> The user's historical sign-in properties (IP, location, device, browser, tenant, subnet)
- At what level are Identity Protection policies configured? -> Entra ID tenant level
- How many policies can exist per risk type? -> One policy per risk type (one for User Risk, one for Sign-In Risk)
- What are common remediation actions for a true positive risky sign-in? -> Mark as compromised, reset password, block user, or require MFA
- What SIEM tool is commonly integrated with Identity Protection in the Microsoft ecosystem? -> Microsoft Sentinel
