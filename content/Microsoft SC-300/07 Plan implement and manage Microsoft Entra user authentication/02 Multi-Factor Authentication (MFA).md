# Entra ID MFA (Multi-Factor Authentication)

## Why MFA Matters
- Scenario: Alice authenticates with just email + password (no MFA).
- If a threat actor obtains Alice's credentials (via phishing, brute forcing, keylogging), they can authenticate as Alice and access resources.
- Introducing MFA (e.g., Microsoft Authenticator) stops this: even if the attacker has the password, they don't have access to Alice's second factor (e.g., her authenticator app), so they cannot complete authentication.

---

## The Three Authentication Factor Categories
True MFA requires combining at least **two different** of the following properties:
1. **Something you know** (e.g., password, PIN)
2. **Something you have** (e.g., phone with authenticator app, FIDO2 key)
3. **Something you are** (e.g., biometrics - face, fingerprint)

---

## What Counts as True MFA? (Examples)

| Combination | Is It True MFA? | Why |
|---|---|---|
| Password + Windows Hello 6-digit PIN | **No** | Both are "something you know" - same factor category, even though the PIN is stored in a TPM chip |
| Password + Microsoft Authenticator | **Yes** | Know (password) + Have (mobile device with app) |
| Password + Windows Hello biometrics | **Yes** | Know (password) + Are (biometrics) |
| Password + FIDO2 key | **Yes** | Know (password) + Have (security key) |

Key insight: A PIN, even though tied to a device via TPM, still counts as "something you know" - not a separate factor from a password.

---

## Security vs Convenience Trade-off

- **Passwords alone**: Low security, but convenient.
- **Password + MFA (e.g., SMS/voice)**: Higher security, but less convenient (extra steps).
- **Passwordless (e.g., Windows Hello with biometrics)**: Best of both worlds - high security AND high convenience.
  - Not phishable or keylog-able.
  - Not crackable via rainbow tables.
  - Simple user experience (e.g., just look at the camera).

---

## Ranking Authentication Methods (Security Perspective)

### Bad
- Passwords alone (especially weak/common ones like "123456").
- Even strong passwords are considered weak overall because they are **not phishing-resistant** and are outdated as a sole method.

### Good
- Password + SMS or Voice (introduces MFA).
- Still **not phishing-resistant**: attackers can use fake phishing sites to capture both the password and the OTP in real time, then relay it to the real site.
- Still better than password alone.

### Better
- Password + OAuth tokens or Certificate-based authentication.
- Improvement over SMS/voice, but certificates can still be **stolen** if an attacker compromises the device and accesses the certificate store.

### Best
- **Passwordless** options:
  - Windows Hello for Business
  - FIDO2 security key
  - Microsoft Authenticator
- These provide true MFA AND are **phishing-resistant**.
- Example: a FIDO2 key cannot be entered into a phishing site - it must be physically present and plugged in.
- Considered the best balance of security and convenience.

---

## Quick Review / Flashcard Candidates
- What are the three MFA factor categories? -> Something you know, something you have, something you are
- Is Password + Windows Hello PIN true MFA? -> No, both are "something you know"
- Is Password + Microsoft Authenticator true MFA? -> Yes, know + have
- Why is SMS/voice MFA not phishing-resistant? -> Attackers can use fake sites to capture and relay both the password and the OTP in real time
- What is the most secure and convenient authentication approach? -> Passwordless (Windows Hello, FIDO2, Microsoft Authenticator)
- Why can certificate-based authentication still be risky? -> Certificates can be stolen if an attacker compromises the device's certificate store
- Which authentication method is considered fully phishing-resistant? -> FIDO2 security key
- On the security vs convenience graph, where do passwords alone sit? -> Low security, high convenience
- Where does passwordless authentication sit on that graph? -> High security, high convenience