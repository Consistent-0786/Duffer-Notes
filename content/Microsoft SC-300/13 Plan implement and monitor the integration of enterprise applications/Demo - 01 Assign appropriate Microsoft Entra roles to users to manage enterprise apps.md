![[Untitled document (20).pdf]]

# Assign Microsoft Entra Roles for Managing Enterprise Applications

## Overview

This guide explains how to assign appropriate **Microsoft Entra ID roles** to users who need to manage enterprise applications and app registrations.

The two prominent roles discussed are:

- **Application Administrator** — provides broad administrative capabilities across enterprise applications, app registrations, and application proxy.
- **Cloud Application Administrator** — provides enterprise application management capabilities but excludes app registrations and application proxy management.

The key principle is to assign the **least-privileged role that satisfies the user's responsibilities**.

## Prerequisites

- Access to the **Azure portal**.
- Sufficient permissions to view and assign Microsoft Entra roles.
- A clear understanding of what application-management tasks the user needs to perform.

## Step 1 — Open Microsoft Entra Roles and Administrators

1. Open the **Azure portal**.
2. Use the search bar to search for **Roles**.
3. Select **Microsoft Entra Roles and Administrators**.
4. In the roles list, search for **Application**.

The two relevant roles are:

- **Application Administrator**
- **Cloud Application Administrator**

## Step 2 — Review the Application Administrator Role

1. Select **Application Administrator**.
2. Use the **Add assignments** option to assign the role to a user.
3. Review the **Description** to understand the capabilities provided by the role.
4. Review the associated **Permissions** to see the specific permissions included.

The **Application Administrator** role can be used to:

- Add, manage, and configure **enterprise applications**.
- Manage and configure **app registrations**.
- Manage **on-premises application proxy** functionality.
- Perform broad administrative tasks related to applications.

> **Important:** Application Administrator is a privileged role because it includes one or more privileged permissions.

### When to Use Application Administrator

Use **Application Administrator** when the user needs broad application-management capabilities, particularly when they need to work with:

- Enterprise applications
- App registrations
- Application Proxy

This is the more privileged of the two roles discussed in this guide.

## Step 3 — Review the Cloud Application Administrator Role

1. Return to **Microsoft Entra Roles and Administrators**.
2. Select **Cloud Application Administrator**.
3. Review the role **Description** and **Permissions**.

The **Cloud Application Administrator** role can:

- Add, manage, and configure **enterprise applications**.

However, it does **not** provide the same capabilities as Application Administrator for:

- **App registrations**
- **Application Proxy**

### When to Use Cloud Application Administrator

Use **Cloud Application Administrator** when the user's responsibilities are focused specifically on managing **enterprise applications** and do not require management of app registrations or Application Proxy.

Although this role is also considered privileged, it has fewer permissions than **Application Administrator**.

## Role Comparison

|Capability|Application Administrator|Cloud Application Administrator|
|---|---|---|
|Manage enterprise applications|Yes|Yes|
|Configure enterprise applications|Yes|Yes|
|Manage app registrations|Yes|No|
|Configure app registrations|Yes|No|
|Manage Application Proxy|Yes|No|
|Privileged role|Yes|Yes|
|Relative privilege level|Higher|Lower|

## Choosing the Appropriate Role

Choose the role based on the tasks the user actually needs to perform:

1. If the user only needs to manage **enterprise applications**, consider **Cloud Application Administrator**.
2. If the user also needs to manage **app registrations** or **Application Proxy**, use **Application Administrator**.
3. Prefer the role with the **minimum permissions required** for the user's responsibilities.

> **Important:** Avoid assigning the more privileged Application Administrator role when the user's responsibilities can be fulfilled with Cloud Application Administrator.

## Final Checklist

- [ ]  Open **Azure portal**.
- [ ]  Navigate to **Microsoft Entra Roles and Administrators**.
- [ ]  Search for **Application** roles.
- [ ]  Review **Application Administrator** capabilities.
- [ ]  Review **Cloud Application Administrator** capabilities.
- [ ]  Determine which application-management tasks the user requires.
- [ ]  Assign the least-privileged appropriate role.
- [ ]  Verify that the assigned role provides the required capabilities.

## Key Takeaway

**Application Administrator** is the broader and more privileged role, covering enterprise applications, app registrations, and Application Proxy. **Cloud Application Administrator** is more narrowly focused on enterprise applications.

The appropriate role should be selected according to the user's actual responsibilities, with preference given to the **least-privileged role that meets the requirements**.