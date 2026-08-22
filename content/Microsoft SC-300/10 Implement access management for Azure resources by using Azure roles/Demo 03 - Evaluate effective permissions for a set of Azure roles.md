![[Untitled document (15).pdf]]

# Evaluate Effective Azure RBAC Permissions

## Overview

Azure provides a built-in **Check access** feature that allows you to determine the effective permissions a user, group, service principal, or managed identity has on a specific Azure resource.

This is particularly useful when permissions are coming from multiple role assignments or are being **inherited from a higher level in the Azure resource hierarchy**.

---

## Step 1 — Open Access Control (IAM)

1. Open the **Azure Portal**.
    
2. Navigate to the target resource group.
    
    Example:
    
    `RBAC-demo`
    
3. Select **Access control (IAM)**.
    

---

## Step 2 — Open Check Access

Within **Access control (IAM)**:

1. Click **Check access**.

This allows you to inspect the access of individual identities to the current resource.

> The same approach can be used with Azure resources more generally, not just resource groups.

---

## Step 3 — Select the Identity Type

Azure allows you to check access for different types of identities:

- Users
- Groups
- Service principals
- Managed identities

For users, groups, and service principals:

1. Select the appropriate identity type.
2. Search using an email address or display name.
3. Select the identity you want to investigate.

---

## Step 4 — Review Current Role Assignments

After selecting the identity, Azure displays the role assignments that currently apply to the resource.

In this example, the resource being evaluated is the **resource group**.

The user has two active role assignments applicable to the resource group:

- **Owner**
- **Virtual Machine Contributor**

These roles contribute to the user's effective permissions on the resource group.

---

## Step 5 — Check for Deny Assignments

The access information also shows whether the identity has any:

- **Deny assignments**
- **Classic administrator roles**

In this example, there are no deny assignments or classic administrator roles.

> Deny assignments are important because they can prevent an identity from performing actions even when a role assignment appears to grant the required permission.

---

## Step 6 — Check Eligible Role Assignments

Azure also displays **eligible role assignments** separately from active assignments.

In the example, the user has:

**Custom Role Demo — Eligible**

This means the custom role was assigned as **eligible**, rather than active.

The user is therefore eligible to activate the role when required, but the role is not currently active.

### Active vs. Eligible

|Assignment|Meaning|
|---|---|
|**Active**|Permissions are currently available to the identity.|
|**Eligible**|The identity can activate the role when needed.|

This distinction is especially useful for privileged access management because it reduces the need for users to hold privileged permissions continuously.

---

# Step 7 — Understand Permission Inheritance

One of the most important things to understand when evaluating Azure RBAC permissions is **inheritance**.

Azure follows a resource hierarchy:

```text
Management Group
       ↓
Subscription
       ↓
Resource Group
       ↓
Resource
```

Permissions assigned at a higher level can be inherited by resources underneath that level.

### Example

Suppose a user is assigned:

**Owner → Subscription**

Because the subscription sits above the resource group in the hierarchy, that Owner permission is inherited by the resource group.

Therefore, the user does **not** need a separate:

**Owner → Resource Group**

assignment.

The subscription-level Owner role already provides the applicable permissions at the resource-group level.

> **Important:** Always check existing inherited permissions before creating additional role assignments. Adding redundant roles can unnecessarily increase privileges and make access management harder to maintain.

---

## Understanding Effective Access

When troubleshooting Azure permissions, don't look only at roles assigned directly to the resource.

Effective access can come from:

1. Direct role assignments.
2. Inherited role assignments from higher scopes.
3. Eligible role assignments.
4. Other applicable access mechanisms.
5. Deny assignments that restrict access.

The **Check access** feature brings these details together so you can understand why an identity has—or does not have—access.

---

## Example

For the `RBAC-demo` resource group, the access evaluation might look like:

```text
User
│
├── Owner
│   └── Inherited from Subscription
│
├── Virtual Machine Contributor
│   └── Assigned to Resource Group
│
└── Custom Role Demo
    └── Eligible
```

The important point is that the **Owner** permission does not necessarily originate from the resource group itself. It can be inherited from the subscription.

---

## Troubleshooting Workflow

When trying to understand why a user can or cannot perform an action:

1. Open the relevant Azure resource.
2. Go to **Access control (IAM)**.
3. Select **Check access**.
4. Search for the affected identity.
5. Review **active role assignments**.
6. Review **eligible role assignments**.
7. Check for **deny assignments**.
8. Determine whether roles are assigned directly or inherited.
9. Trace inherited permissions up the Azure resource hierarchy.

---

## Final Checklist

- [ ]  Open the target Azure resource.
- [ ]  Open **Access control (IAM)**.
- [ ]  Click **Check access**.
- [ ]  Select the identity type.
- [ ]  Search for the user, group, service principal, or managed identity.
- [ ]  Review active role assignments.
- [ ]  Review eligible role assignments.
- [ ]  Check for deny assignments.
- [ ]  Check for classic administrator roles where applicable.
- [ ]  Identify inherited permissions.
- [ ]  Trace permissions through the Azure resource hierarchy.

## Key Takeaway

Azure's **Check access** feature is a practical way to determine an identity's effective access to a resource.

The most important concept is to remember that **permissions can be inherited**. A role assigned at the subscription level can apply to resource groups and resources underneath it, so an identity may have more access than is immediately obvious from the resource's direct role assignments.