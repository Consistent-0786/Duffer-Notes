![[Untitled document (24).pdf]]
# Create and Manage Application Collections in Microsoft Entra ID

## Overview

Application collections allow administrators to organize enterprise applications into logical groups and provide users with a more structured application-launching experience.

Collections appear in the user's **My Apps** experience and the **Office** web experience. This guide demonstrates how to create a collection called **Modern Work with M365**, add Microsoft 365 applications to it, assign an owner and user, and verify the result.

## Prerequisites

- Access to **Microsoft Entra ID**.
- Enterprise applications available in the tenant.
- Appropriate permissions to manage enterprise applications and application collections.
- A user who can be assigned to the collection.

## Step 1 — Open the App Launcher

1. Open **Microsoft Entra ID**.
2. Navigate to **Enterprise applications**.
3. Under **Manage**, select **App launchers**.
4. Click **New collection**.

Creating a collection allows applications to be presented together as a logical group in the user's application-launching experience.

## Step 2 — Name the Collection

1. Enter a name for the collection.

For this example, use:

```text
Modern Work with M365
```

The term **Modern Work** is commonly used by Microsoft for workplace-related services and technologies, including Microsoft 365 services, Intune, and Microsoft 365 Copilot.

2. Click **Next**.

## Step 3 — Add Applications

1. Select **Add Application**.
2. Browse or search for the applications you want to include.
3. Select the relevant applications.
4. Click **Add**.

For the **Modern Work with M365** example, applications can include typical Microsoft 365 services such as:

- Outlook
- Word
- Excel
- SharePoint
- Other relevant Microsoft 365 applications

> **Tip:** A collection does not need to contain every available application. Add the applications that logically belong together for the intended users.

5. Click **Next**.

## Step 4 — Assign an Owner

Define who is responsible for the application collection.

1. Select the appropriate owner.
2. In the example, the current administrator is selected as the owner.
3. Click **Next**.

Assigning an owner provides a clear point of responsibility for the collection.

## Step 5 — Assign Users

Specify which users should have access to the collection.

1. Select the appropriate user.
2. Click **Select**.
3. Click **Next**.

The assigned user will be able to see the collection in their application-launching experience.

## Step 6 — Review and Create the Collection

Before creating the collection, review the summary.

Verify:

- **Collection name** — Modern Work with M365
- **Selected applications** — the Microsoft 365 applications added to the collection
- **Owner** — the selected owner
- **User** — the assigned user

If everything is correct, click **Create**.

The collection is then created successfully.

## Step 7 — Verify the Collection in My Apps

After creating the collection, verify how it appears to the user.

1. Open a new browser window.
2. Navigate to:

```text
myapps.microsoft.com
```

3. Sign in as the assigned user if required.
4. Locate the **Modern Work with M365** collection.

The collection should contain the applications that were added during configuration.

The My Apps experience can also display other enterprise applications available in the tenant. For example, the previously created **Box** enterprise application can appear alongside the collection.

## Collection Structure

The resulting experience can be thought of as:

```text
My Apps
├── Modern Work with M365
│   ├── Outlook
│   ├── Word
│   ├── Excel
│   ├── SharePoint
│   └── Other selected applications
│
└── Other enterprise applications
    └── Box
```

The collection provides organization without changing the underlying enterprise applications themselves.

## Final Checklist

- [ ]  Open **Enterprise applications** in Microsoft Entra ID.
- [ ]  Navigate to **Manage → App launchers**.
- [ ]  Click **New collection**.
- [ ]  Give the collection an appropriate name.
- [ ]  Add the required enterprise applications.
- [ ]  Assign an owner.
- [ ]  Assign the required users.
- [ ]  Review the collection configuration.
- [ ]  Click **Create**.
- [ ]  Open `myapps.microsoft.com`.
- [ ]  Verify that the collection and its applications are visible to the assigned user.

## Key Takeaway

**Application collections** provide a way to organize enterprise applications into logical groups and improve the user's application-launching experience. Administrators can define the collection, add relevant applications, assign ownership, and control which users receive the collection.