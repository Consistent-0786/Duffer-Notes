## What Are Administrative Units?
- A way to restrict the permissions of a role to a defined portion of your organization, instead of the whole tenant.
- Allow you to logically cluster your Entra ID organization based on custom logic (e.g., geography, division).
- Example use case: delegate the Help Desk Administrator role to regional support specialists so they can only manage users in the region they support.

---

## Role Scope: With vs Without an AU
- If a role is assigned to a user who is **NOT** a member of an administrative unit -> the role's scope is the **entire tenant**.
- If a role is assigned to a user who **IS** a member of an administrative unit -> the AU can restrict/influence the scope of that role.
- Users can belong to **multiple** administrative units at once.
  - Example: Megan Bowen could belong to both a "Seattle" AU and a "Marketing" AU.

---

## Example Scenario: Regional Cloud Engineers
- Company has cloud engineers in US, India, and Europe.
- Solution: create 3 administrative units - one per region (US AU, India AU, Europe AU).
- Associate/cluster the relevant users into their respective regional AU.
- Enables easier, more targeted management of identities per region.

---

## Key Properties of Administrative Units

| Property | Detail |
|---|---|
| Purpose | Simplifies assignment of Entra permissions to objects **within Entra ID itself** (not for managing Azure resources) |
| Multi-AU membership | An object can exist in multiple AUs simultaneously |
| Membership type | Can be **assigned** or **dynamic** (based on properties), similar to groups |
| What can be included | Users, devices, and security groups (not limited to human identities) |
| Licensing requirement | Requires at least an **Entra ID P1** license |
| Nesting | **Not supported** - you cannot place an AU inside another AU |
| Security group permissions | Permissions assigned via an AU do **NOT** apply to members of a security group placed in that AU |

---

## Important Distinction
- AUs are about managing/clustering the **Entra ID tenant itself** (logical organization of identities).
- This is different from using Entra ID to manage **Azure resources** (that's a separate concept, covered elsewhere e.g. Azure RBAC).

---

## Quick Review / Flashcard Candidates
- What is the main purpose of an Administrative Unit? -> To restrict a role's scope to a defined portion of the organization instead of the whole tenant
- What is a role's scope if the user is not part of any AU? -> Entire tenant
- Can a user belong to multiple AUs? -> Yes
- Can AUs be nested within each other? -> No
- What license is required to use AUs? -> At least Entra ID P1
- Can devices and security groups be added to an AU, not just users? -> Yes
- Do AU permissions apply to members of a security group added to the AU? -> No
- What is AUs' primary management scope: Entra ID itself, or Azure resources? -> Entra ID itself