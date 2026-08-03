## Authorization (AuthZ)

**Definition:**
Authorization (AuthZ) determines **what a user is allowed to access or do** after they are authenticated.

**Simple Explanation:**
- AuthN = "Who are you?"
- AuthZ = "What can you do?"

**Example:**
You log in to Microsoft Entra ID (Authentication).
Based on your role:
- Reader → Can view resources only.
- Contributor → Can view and edit resources.
- Global Administrator → Full administrative access.

**How Authorization is Implemented:**
1. RBAC (Role-Based Access Control)
   - Access is based on assigned roles.
   - Example: Global Administrator, User Administrator, Reader.

2. ABAC (Attribute-Based Access Control)
   - Access is based on user or resource attributes.
   - Example: Only users in the HR department can access HR files.

**Key Points (SC-300):**
- Determines user permissions.
- Controls access to resources.
- Uses roles, permissions, or policies.
- Ensures users access only what they are authorized to use.
- **Authorization always happens after Authentication (AuthN).**

💡 Exam Tip:
Remember:
Authentication = Verify Identity
Authorization = Verify Permissions