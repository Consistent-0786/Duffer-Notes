![[Untitled document (28).pdf]]

# Create App Roles for an App Registration in Microsoft Entra ID

## Overview

**App roles** are custom roles defined by an application to represent permissions that can be assigned to users, groups, or applications.

The application defines and publishes these roles, and its code interprets the assigned roles during authorization.

This guide covers:

- Opening the app roles configuration.
- Creating a custom app role.
- Selecting allowed member types.
- Defining role values.
- Understanding why role values must be coordinated with the application developer.

## Prerequisites

Before creating an app role, you should have:

- An existing app registration in Microsoft Entra ID.
- Access to configure the app registration.
- An understanding of the permissions and authorization model supported by the application.
- Coordination with the application's developer or development team.

> **Important:** App role values are application-specific. Work with the application's developer to determine which values the application recognizes and how those values map to application permissions.

## Step 1 — Open App Roles

1. Open **Microsoft Entra ID** in the Azure portal.
2. Navigate to **App registrations**.
3. Select the application you want to configure.

For this example, select the **demo** application.

4. Open **Manage**.
5. Select **App roles**.

The **App roles** page displays the roles currently defined for the application.

## Step 2 — Create a New App Role

1. Select the option to create a new **App role**.
2. Enter a name for the role.

For example:

```text
Admin
```

The name identifies the role and is displayed when configuring assignments.

## Step 3 — Select Allowed Member Types

Choose which identities can be assigned the role.

The available member types include:

- **Users and groups**
- **Applications**
- Both users/groups and applications

For the example, allow both:

```text
Users and groups
Applications
```

This means the role can be assigned to users or groups as well as applications.

## Step 4 — Define the Role Value

The **Value** field is particularly important.

The value represents the permission or authorization identifier that the application will use when evaluating the role.

Example values could include:

```text
write
read
delete
```

Depending on the application, values might instead represent more specific operations, such as:

```text
create-user
delete-user
create-vm
```

The exact values are determined by the application.

> **Important:** Do not invent role values based solely on what seems logical. The application must be designed to recognize and interpret the values you configure.

### Example

An application might define permissions such as:

|Role value|Possible meaning|
|---|---|
|`write`|Allows write operations|
|`read`|Allows read operations|
|`delete`|Allows delete operations|
|`create-user`|Allows user creation|
|`delete-user`|Allows user deletion|
|`create-vm`|Allows VM creation|

These are examples only. The actual values must match the authorization model implemented by the application.

## Step 5 — Add a Description

Enter a description that explains the purpose of the role.

For example:

```text
Admin role
```

A useful description makes the role easier to understand when it is assigned later.

## Step 6 — Create the Role

After configuring the role:

1. Review the role name.
2. Verify the allowed member types.
3. Verify the role value.
4. Verify the description.
5. Click **Apply**.

The new role is added to the application.

## Example

The demonstration creates an application role with the following configuration:

```text
Name: Admin
Allowed member types: Users and groups, Applications
Description: Admin role
```

The role can contain application-specific values such as:

```text
write
read
delete
```

The exact values depend on what the application supports.

## Technical Explanation

### What Is an App Role?

An app role is a custom authorization role defined by an application.

The basic model is:

```text
Microsoft Entra ID
       ↓
App Role
       ↓
User / Group / Application assignment
       ↓
Application
       ↓
Authorization decision
```

The important distinction is that **Microsoft Entra ID stores and provides the role information, while the application determines what that role means**.

### Why the Developer Must Define the Values

Suppose an application expects a role value called:

```text
create-vm
```

The application can check whether the authenticated identity has that role and, if present, allow VM creation.

If you instead create a role with an arbitrary value such as:

```text
make-server
```

the application may not recognize it.

Therefore, the administrator configuring Entra ID and the developer implementing the application need to agree on:

- Role names.
- Role values.
- Supported member types.
- The operations associated with each role.
- How the application uses the roles during authorization.

## Troubleshooting

### Problem: A role exists in Entra ID, but the application does not grant the expected permission.

**Solution:** Verify that the role **Value** exactly matches a value that the application recognizes and that the application's authorization logic actually uses that role.

### Problem: You are unsure what values to enter.

**Solution:** Consult the application's developer or documentation. The valid values are application-specific and should not be guessed.

## Final Checklist

- [ ]  Open **Microsoft Entra ID**.
- [ ]  Navigate to **App registrations**.
- [ ]  Select the application.
- [ ]  Open **Manage → App roles**.
- [ ]  Create a new **App role**.
- [ ]  Enter the role name.
- [ ]  Select the appropriate **Allowed member types**.
- [ ]  Define the role **Value** according to the application's authorization model.
- [ ]  Add a useful description.
- [ ]  Click **Apply**.
- [ ]  Verify that the new role appears in the application's app roles.
- [ ]  Confirm the role values with the application developer.

