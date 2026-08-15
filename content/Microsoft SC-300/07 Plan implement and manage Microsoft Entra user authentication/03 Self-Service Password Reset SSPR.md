# Self-Service Password Reset (SSPR)

## What Is SSPR?
- Allows users to reset their own password without contacting the help desk.
- Main goals:
  - Reduce help desk call volume
  - Save time and cost
  - Provide convenience for users when a password is forgotten or compromised

---

## The Problem SSPR Solves
- Without SSPR: if Alice forgets/mistypes her password, she cannot authenticate.
- Traditional fix: Alice calls the help desk for a manual password reset.
  - Time-consuming
  - Costly (requires more help desk staff)
  - Costly in lost productivity while the user waits and cannot work
- With SSPR: Alice can reset her own password using an alternate authentication method (e.g., Microsoft Authenticator app) - no help desk needed.

---
## Password Writeback (Hybrid Environments)

![[Pasted image 20260815133601.png]]
- In a hybrid environment, SSPR can integrate with **Entra Connect**.
- Process: Alice resets her password in Entra ID → Entra Connect writes the new password back to the **on-premises Active Directory**.
- Result: the correct password exists in both the cloud and on-premises environments simultaneously.

---

## Key Benefits of SSPR

### Cost Management
- Reduces IT support costs by removing the need for help desk involvement in password resets.
- Reduces lost time/productivity costs from lockouts.

### Intuitive Experience
- Requires only a one-time registration process.
- Users can unblock accounts and reset passwords on demand, from any location.
- Gets users back to work faster.

### Flexibility and Security
- Leverages the security and flexibility of a cloud platform (Entra ID).
- Admins can update SSPR settings/security requirements and roll them out without disrupting users.

### Auditing and Tracking
- Robust audit logs capture each step of the password reset process.
- Logs can be pulled via API into a SIEM (e.g., Microsoft Sentinel) for SOC monitoring.

---

## Quick Review / Flashcard Candidates
- What does SSPR stand for? -> Self-Service Password Reset
- What is the main purpose of SSPR? -> Let users reset their own password without help desk involvement, saving time and cost
- What hybrid feature pushes an SSPR password change back to on-premises AD? -> Password Writeback (via Entra Connect)
- What is required before a user can use SSPR? -> A one-time registration process
- Where can SSPR audit logs be sent for SOC monitoring? -> Via API into a SIEM, such as Microsoft Sentinel
- Approximately what percentage of help desk calls typically relate to password resets? -> Around 20 percent