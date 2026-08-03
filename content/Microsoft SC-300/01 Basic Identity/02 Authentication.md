## Authentication (AuthN)

**Definition:**
Authentication (AuthN) verifies **who a user is** before granting access to a system.

**Simple Explanation:**
- AuthN = "Who are you?"
- It confirms your identity before you can sign in.

**Example:**
You sign in to Microsoft Entra ID using:
- Username & Password
- Fingerprint (Biometrics)
- One-Time Password (OTP)
- Microsoft Authenticator

If your identity is verified, you are authenticated.

**Common Authentication Protocols:**
- **OAuth** → Lets apps access your data without sharing your password.
- **SAML** → Enables Single Sign-On (SSO) between organizations and applications.
- **Kerberos** → Uses tickets to securely authenticate users within a Windows/Active Directory network.

**Key Points (SC-300):**
- Verifies user identity.
- Uses credentials like passwords, biometrics, or OTPs.
- First step in access control.
- Authentication always happens **before Authorization (AuthZ).**

💡 **Exam Tip:**
- Authentication = Verify Identity
- Authorization = Verify Permissions
- **OAuth = API/App Access**
- **SAML = Web SSO**
- **Kerberos = Windows Domain Authentication**
