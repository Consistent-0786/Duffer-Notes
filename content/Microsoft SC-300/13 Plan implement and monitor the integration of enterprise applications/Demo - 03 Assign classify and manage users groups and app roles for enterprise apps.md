![[Untitled document (22).pdf]]

# Manage Owners, Roles, Users, and Groups for an Enterprise Application

## Overview

Enterprise applications in Microsoft Entra ID can be managed by assigning:

- **Owners** who are responsible for the application.
- **Administrative roles** that determine who can manage the application.
- **Users and groups** that are assigned to the application.
- **Application roles** that define the roles available within the application.

This guide uses the previously created **Box** enterprise application as an example.

## Prerequisites

- An existing enterprise application in **Microsoft Entra ID**.
- Sufficient permissions to manage the enterprise application.
- Users or groups that need access to the application.
- Appropriate administrative roles available in the tenant.

## Step 1 — Assign an Owner

An owner provides a clear point of responsibility for an enterprise application.

Without an assigned owner, it may be unclear who is responsible for managing or supporting the application.

1. Open the **Box** enterprise application.
2. Navigate to **Owners**.
3. Click **Add**.
4. Select the user who should be responsible for the application.
5. Click **Select**.

The selected user is now an owner of the enterprise application.

> **Important:** Assigning an owner establishes clear responsibility for managing the application and provides a point of contact when questions or issues arise.

The assigned owner has the appropriate ownership role for the application's configuration, indicating both responsibility for and the ability to configure the enterprise application.

## Step 2 — Review Roles and Administrators

Enterprise applications can also have administrators who are responsible for managing the application's configuration.

1. Open the **Box** enterprise application.
2. Navigate to **Roles and administrators**.
3. Review the available roles.

The available roles can include:

- **Cloud Application Administrator** — can be used to manage the enterprise application.
- **Custom roles** — custom administrative roles configured in the tenant.
- Other applicable administrative roles.

### Assign an Administrative Role

To give a user administrative capabilities for the enterprise application:

1. Select **Cloud Application Administrator**.
2. Assign the role to the appropriate user.
3. Verify that the user has been assigned the role.

This allows the selected user to administer the Box enterprise application according to the permissions associated with the role.

> **Important:** Administrative roles and application access serve different purposes. An administrator manages the enterprise application configuration, while users and groups can be assigned to the application for access.

## Step 3 — Assign Users and Groups

Users and groups can be explicitly assigned to an enterprise application.

1. Return to the **Box** enterprise application.
2. Navigate to **Users and groups**.
3. Click **Add users/groups**.
4. Select the user or group that should have access.
5. Click **Assign**.

For example, you can select an individual user and assign that user to the Box enterprise application.

After the assignment is completed, the user or group appears in the application's **Users and groups** list.

## Owners vs. Administrators vs. Application Users

These assignments have different purposes:

|Assignment|Purpose|
|---|---|
|**Owner**|Identifies who is responsible for the enterprise application.|
|**Administrative role**|Gives a user administrative capabilities for managing the application.|
|**User/group assignment**|Determines which users or groups are assigned to the enterprise application.|
|**Application role**|Represents a role that can be assigned within the application where applicable.|

## Final Checklist

- [ ]  Open the **Box** enterprise application.
- [ ]  Assign an appropriate **Owner**.
- [ ]  Verify the owner and their responsibility for the application.
- [ ]  Review **Roles and administrators**.
- [ ]  Assign **Cloud Application Administrator** when administrative access is required.
- [ ]  Review any available custom roles.
- [ ]  Open **Users and groups**.
- [ ]  Add the required users or groups.
- [ ]  Click **Assign**.
- [ ]  Verify that the assignments are visible in the enterprise application.

## Key Takeaway

Microsoft Entra ID provides separate mechanisms for managing responsibility, administration, and application access. **Owners** establish accountability, **administrative roles** provide management capabilities, and **user/group assignments** determine who is assigned to the enterprise application.

Keeping these responsibilities separate makes enterprise application management clearer and easier to control.