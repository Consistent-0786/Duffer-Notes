# Groups in Entra ID

## Why Do We Need Groups?
- Without groups, admins must assign roles/permissions individually to every user - not scalable.
- Example: a security team of 50 users needing Sentinel access would require 50 individual role assignments.
- With groups: create one group, assign the role/permission to the group once, then add all relevant users to the group.
- Result: managing identities and permissions at scale becomes far more efficient.

---

## Key Features of Entra ID Groups

### Administration
- Provides centralized management for organizing and controlling user access to resources and roles.
- Solves the scalability problem of individual role assignments.

### Security
- Enhances security by enabling role-based access.
- Policies can be applied to group members for secure resource access.

### Automation
- Supports **dynamic group membership** based on predefined rules.
- Greatly simplifies user and access management at scale.

### Self-Service
- Allows users to request group membership or manage their own group access without admin intervention.
- Reduces administrative overhead.

---

## Group Types

| Group Type | Purpose | Members Can Include | Owners Can Include |
|---|---|---|---|
| **Security Groups** | Manage user and computer access to shared resources; all members share the same permission set | Users, devices, service principals, other groups (nested groups) | Users, service principals |
| **M365 Groups** | Collaboration - shared mailbox, calendar, files, SharePoint site, etc. Can include people outside the organization | Users only | Users, service principals |

Key difference: Security Groups = access control focused; M365 Groups = collaboration focused (and membership is restricted to users only, unlike security groups).

---

## Group Membership Types

### Assigned
- Manually add specific users to the group.
- Simplest method - unique/manual permission assignment.
- Example: manually adding a user to a "Security Administrators" group.

### Dynamic (User)
- Uses dynamic membership rules to automatically add/remove members based on attributes.
- If a member's attribute changes, the system re-evaluates the rules and adds/removes them accordingly.

### Dynamic Device
- Same logic as Dynamic (User), but applies **only to devices**, not human identities.
- Automatically adds/removes devices based on device attribute rules.

---

## Dynamic Group Example
- User: Sanjay Gupta
  - City: Bangalore
  - Department: IT
  - Role: SoC Analyst

- Rule logic used:
  - `user.department -eq "IT"` AND `user.role -eq "SoC Analyst"`
- Since both conditions are true, Sanjay is automatically added to:
  1. The "All IT" group
  2. The "Security Operations Center" group

- This demonstrates how multiple attribute conditions can be combined for precise dynamic group assignment.

---

## Quick Review / Flashcard Candidates
- Why use groups instead of individual role assignments? -> Scalability - assign permissions once to a group instead of repeatedly to each user
- What are the two main group types in Entra ID? -> Security Groups and M365 Groups
- Which group type is restricted to users only (no devices/service principals)? -> M365 Groups
- Which group type supports nested groups? -> Security Groups
- What are the three membership types? -> Assigned, Dynamic (User), Dynamic Device
- What does Dynamic Device membership apply to? -> Devices only, not human identities
- What happens when a dynamic group member's attribute changes? -> The system re-evaluates membership rules and adds/removes the member as needed
- What Entra ID feature reduces admin overhead by letting users manage their own group access? -> Self-service