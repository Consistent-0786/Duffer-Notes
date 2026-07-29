# Configure and Manage Microsoft Entra ID Roles

## Naming: Azure AD → Microsoft Entra ID
- Microsoft renamed **Azure Active Directory (Azure AD)** to **Microsoft Entra ID**.
- Entra ID now lives in its own portal: **[entra.microsoft.com](https://entra.microsoft.com)** (Microsoft Entra admin center).
- Licensing renamed too:
  - Azure AD Premium P1 → **Entra ID P1**
  - Azure AD Premium P2 → **Entra ID P2**
- Exam tip: Be ready to see *either* name (Azure AD or Entra ID) on the SC-300 exam — Microsoft docs are inconsistent during the transition, and exam content may lag behind the rename.
- Instructor will use "Azure AD" and "Entra ID" interchangeably throughout the course.

---

## Authorization Model in Entra ID
- Entra ID uses an authorization scheme based on **job roles**.
- Permissions can be assigned via:
  - **Direct assignment** to identities
  - **Group membership** (recommended — group users with similar roles, assign permissions once at the group level)
  - **Just-in-time (JIT) role activation** via **Privileged Identity Management (PIM)**
    - Roles/users are made "eligible" rather than permanently assigned
    - PIM will be covered in depth later in the course

### Key definitions
- **Authorization** = scope of permissions a user/security principal has over Azure infrastructure
- **RBAC (Role-Based Access Control)** = common framework underpinning this model

---

## Best Practices (Microsoft-recommended)
- Perform **regular, recurring access reviews** — users must actively confirm they still need their role/access.
- Enable **Multifactor Authentication (MFA)**:
  - Mandatory mindset for **high-privilege roles**
  - Ideally enabled for **all users**
- Apply the **Principle of Least Privilege** — users get only the access they need to do their job, nothing more.

---

## What Is an Azure AD/Entra ID Role?
- A role = a bundled set of **Create, Read, Update, Delete (CRUD)** operations tied to a specific job function.
- Examples:
  - Help desk staff → delegated permission to **reset passwords**
  - App developers → delegated permission to **create app registrations**

---

## Key Built-in Roles to Know
| Role | Purpose |
|---|---|
| **Global Administrator** | The "super role" — highest level of access in Entra ID |
| **User Administrator** | Common role for help desk; allows resetting *non-administrative* passwords |
| **Security Administrator** | For compliance officers; access to sign-in logs and audit log data |

---

## Custom RBAC Roles
- Custom roles **can** be created in Entra ID, but:
  - Functionality has been **stuck/limited for years**
  - Far less flexible than custom roles on the **Azure Resource Manager (resource)** side
- Note: this is a known limitation, not a training gap — just "a fact of life" per the instructor.

---

