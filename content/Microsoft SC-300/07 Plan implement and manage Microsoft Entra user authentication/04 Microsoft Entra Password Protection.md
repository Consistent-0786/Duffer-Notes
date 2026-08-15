# Password Protection in Entra ID

## What Is Password Protection?
- A feature relevant for organizations still relying on traditional passwords (not fully passwordless yet) - which is most organizations currently.
- Prevents use of common, weak, or compromised passwords.
- Enforces **global** and **custom** password ban lists to strengthen account security.

---

## Key Capabilities

### Smart Password Protection Policies
- Blocks common/weak passwords (e.g., "Password123") using ban lists.
- Also blocks known **compromised** passwords - sourced from data associated with Entra Identity Protection.

### Real-Time Password Validation
- Checks passwords **in real time** during:
  - User account creation
  - Password changes
- Prevents users from setting passwords that are easily guessable or previously breached.
- Happens instantly, so there's minimal performance or user impact at scale.

### Hybrid Environment Support
- Password protection extends to **both cloud and on-premises** environments.
- Ensures a consistent password security strategy across all connected systems.

---

## How It Works in a Hybrid Architecture

![[Pasted image 20260815140553.png|360]]
1. On-premises Active Directory holds identities and their credentials.
2. **Entra Connect** synchronizes on-premises users to Entra ID, including password hashes.
3. Password Protection policy is applied at the Entra ID level using:
   - Global banned password list, and/or
   - Custom banned password list
4. This same policy can then be extended and applied to the **on-premises Active Directory** as well.
5. Result: consistent password security enforcement across both cloud and on-prem.

---

## Quick Review / Flashcard Candidates
- What does Entra ID Password Protection block? -> Common, weak, and compromised passwords
- When does password validation occur? -> In real time, during account creation or password changes
- What two types of ban lists can be used? -> Global banned password list and custom banned password list
- What service syncs on-premises identities (and password hashes) to Entra ID? -> Entra Connect
- Can Password Protection be applied to on-premises Active Directory? -> Yes, in hybrid environments
- Where does the compromised password data originate from? -> Entra Identity Protection