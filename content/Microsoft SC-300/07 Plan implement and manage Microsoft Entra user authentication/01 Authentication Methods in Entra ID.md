# Authentication Methods in Entra ID

## Password
- A secret string of characters known only to the user, used to authenticate an identity.
- Widely used but has significant known flaws (weak, reused, phishable, etc.).

---

## SMS
- A text message sent to the user's phone containing a one-time code (typically 6 digits).
- Password + SMS = a basic form of MFA, but better/stronger options exist.

---

## Voice
- Authentication via a phone call delivering a one-time code (typically 6 digits).
- Functionally similar to SMS - the second factor is "having access to your phone."
- Not considered an ideal method (weaknesses discussed later in the course).

---

## OAuth Tokens
- A secure token issued by an authorization server that grants access without revealing user credentials.
- Removes the need to manage/protect a password directly.

---

## Microsoft Authenticator
- Mobile app that generates time-based one-time passwords (TOTP) or sends push notifications for MFA.
- Widely adopted by enterprises.
- Supports **number matching**:
  - User enters username/password on a device (e.g., laptop) → laptop displays a number (e.g., "55").
  - User must enter that same number in the Authenticator app on their phone.
  - Proves the user has access to both devices and provided valid credentials.

---

## Windows Hello for Business
- Passwordless authentication using biometrics (facial recognition, fingerprint) or a device-tied PIN.
- Fully passwordless — no password management required, even though a PIN is used.
- Biometric data and PIN are stored in the device's **TPM (Trusted Platform Module)** chip, not tied to a memorized password.
- Security is rooted in the TPM chip's protection, which is designed to handle sensitive data like biometrics, private keys, and certificates.

---

## FIDO2 Key
- A physical security key used for passwordless authentication via public-key cryptography.
- Resembles a USB stick — inserted into the device to authenticate.
- Proves possession of the physical key itself.

---

## Certificate-Based Authentication
- Uses a digital certificate to prove identity.
- Relies on a trusted Certificate Authority (CA).

---

## Combining Methods
- Multiple authentication methods can be combined to achieve true Multi-Factor Authentication (MFA).
- Covered in more detail later in the course.

---

# Entra ID Authentication Methods

![[Pasted image 20260814201127.png]]

---

## Quick Review / Flashcard Candidates
- What does Microsoft Authenticator's "number matching" prevent? -> MFA fatigue/accidental approval by requiring the user to match a specific number, not just tap "approve"
- Where are biometrics and PIN stored in Windows Hello for Business? -> The device's TPM (Trusted Platform Module) chip
- Is Windows Hello for Business passwordless? -> Yes
- What does a FIDO2 key physically resemble? -> A USB stick / physical security key
- What is the benefit of OAuth tokens over passwords? -> Grants access without revealing user credentials
- What is the weakness shared by SMS and Voice authentication? -> Both rely solely on "access to your phone" as the second factor, considered less secure
- What does certificate-based authentication rely on to prove identity? -> A trusted Certificate Authority (CA)