![[Untitled document (14).pdf]]

# Assign Built-in and Custom Azure RBAC Roles

## Overview

Azure RBAC roles can be assigned to identities at a specific Azure scope.

This guide covers how to assign:

- Built-in Azure RBAC roles
- Custom Azure RBAC roles
- Roles to users, groups, service principals, or managed identities
- Permanent or eligible role assignments

The assignment workflow is largely the same for built-in and custom roles.

## Prerequisites

- Access to the Azure Portal.
- An existing resource group.
- A built-in or custom RBAC role to assign.
- Appropriate permissions to create role assignments.

For this demonstration, use the previously created:

`RBAC-demo`

---

## Step 1 — Open Access Control (IAM)

1. Open the **Azure Portal**.
2. Navigate to the `RBAC-demo` resource group.
3. Select **Access control (IAM)**.
4. Click **Add**.
5. Select **Add role assignment**.

This opens the role assignment wizard.

---

# Part 1 — Assign a Built-in Role

## Step 2 — Select a Built-in Role

The first step displays the built-in Azure RBAC roles available for assignment.

You can search for a specific role or resource type.

For example:

1. Search for **Virtual machine**.
2. Review the available roles.

You may see roles such as:

- **Virtual Machine Contributor**
- **Virtual Machine User Login**

3. Select the role you want to assign.
4. Click **Next**.

> Built-in roles are predefined by Azure and contain a predefined set of permissions.

---

## Step 3 — Select the Identity

The next step determines **who or what receives the role**.

Azure allows you to assign roles to:

- Users
- Groups
- Service principals
- Managed identities

For users and groups:

1. Select **Users, groups, or service principals**.
2. Click **Select members**.
3. Search for the user or group.
4. Select the desired identity.
5. Click **Select**.

The selected identity should now appear as a member.

6. Click **Next**.

---

## Step 4 — Configure the Assignment Type

Azure allows you to choose how the role assignment should behave.

### Eligible

An **eligible** assignment means the identity does not continuously use the role.

The user must activate the role when they need it, and the activation can be limited to a specific period.

This is the **recommended approach**, particularly for privileged roles.

An eligible assignment can also be time-bound.

### Active

An **active** assignment means the role is immediately available to the identity.

Depending on the configuration, it can remain permanently assigned.

> **Security recommendation:** Avoid permanently assigning privileged roles where possible. Permanent high-privilege assignments can contribute to **privilege creep** and increase security risk.

For a simple demonstration, you can select:

- **Assignment type:** Active
- **Duration:** Permanent

For production environments, especially with privileged roles, prefer temporary or eligible access where appropriate.

---

## Step 5 — Review and Assign

1. Review the role assignment configuration.
2. Click **Review + assign**.
3. Click **Review + assign** again to confirm.

Azure will create the role assignment.

The selected identity now has the permissions provided by the assigned role at the specified scope.

> In many environments, administrators may already have sufficient permissions through other roles, such as highly privileged directory or subscription roles. The assignment workflow can still be practiced for demonstration purposes.

---

# Part 2 — Assign a Custom Role

The workflow for assigning a custom role is almost identical to assigning a built-in role.

## Step 6 — Start a New Role Assignment

1. From **Access control (IAM)**, click **Add**.
2. Select **Add role assignment**.

You will again see the list of available roles.

---

## Step 7 — Find the Custom Role

1. Search for the custom role you created previously.

For example:

`Custom Role Demo`

2. Select the custom role.
3. Click **Next**.

> Custom roles appear alongside the built-in roles once they have been created and propagated through Azure.

---

## Step 8 — Select the Member

1. Select **Users, groups, or service principals**.
2. Click **Select members**.
3. Select the desired user.
4. Click **Select**.
5. Click **Next**.

---

## Step 9 — Review and Assign the Custom Role

1. Review the assignment configuration.
2. Click **Review + assign**.
3. Confirm by clicking **Review + assign** again.

The custom RBAC role is now assigned to the selected identity.

---

## Built-in vs. Custom Role Assignment

The **assignment process is essentially the same** for both types of roles.

||Built-in Role|Custom Role|
|---|---|---|
|Role definition|Predefined by Azure|Defined by your organization|
|Permissions|Fixed by Azure|Selected by you|
|Assignment workflow|IAM → Add role assignment|IAM → Add role assignment|
|Can assign to users/groups|Yes|Yes|
|Can assign to service principals|Yes|Yes|
|Can assign to managed identities|Yes|Yes|
|Assignment type|Active or eligible, where supported|Active or eligible, where supported|

## Security Best Practices

- Prefer **least privilege** when selecting roles.
- Avoid permanent privileged assignments when they aren't necessary.
- Prefer **eligible** or time-bound access for privileged roles where appropriate.
- Regularly review existing role assignments.
- Use custom roles when built-in roles provide more permissions than required.
- Be especially careful when assigning roles at broad scopes such as subscriptions.

## Final Checklist

- [ ]  Open the target resource group.
- [ ]  Open **Access control (IAM)**.
- [ ]  Select **Add → Add role assignment**.
- [ ]  Select a built-in or custom role.
- [ ]  Select the appropriate identity.
- [ ]  Choose the assignment type.
- [ ]  Configure the duration if applicable.
- [ ]  Review the assignment.
- [ ]  Click **Review + assign**.
- [ ]  Confirm the assignment.
- [ ]  Verify that the role appears under the resource's role assignments.

## Key Takeaway

Assigning built-in and custom Azure RBAC roles follows the same basic workflow:

**IAM → Add role assignment → Select role → Select identity → Configure assignment → Review + assign**

The main difference is how the role itself was defined: **built-in roles are provided by Azure, while custom roles contain permissions defined by your organization.**