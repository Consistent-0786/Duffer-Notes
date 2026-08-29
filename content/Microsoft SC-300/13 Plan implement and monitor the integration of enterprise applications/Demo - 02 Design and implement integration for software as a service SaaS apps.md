![[Untitled document (21).pdf]]

# Create an Enterprise Application from the Microsoft Entra Gallery

## Overview

Microsoft Entra ID provides a gallery of **Software as a Service (SaaS) applications** that can be added as enterprise applications.

This guide demonstrates how to add a SaaS application from the **Microsoft Entra application gallery**, using **Box** as an example.

The gallery also provides information and filtering options for authentication, account management, and application categories.

## Prerequisites

- Access to **Microsoft Entra ID**.
- Sufficient permissions to create enterprise applications.
- A SaaS application available in the Microsoft Entra application gallery.

## Step 1 — Open Enterprise Applications

1. Open **Microsoft Entra ID**.
2. Navigate to **Enterprise applications**.
3. Select **New application**.

This opens the application gallery, where you can select from available SaaS applications.

## Step 2 — Explore the Application Gallery

The Microsoft Entra application gallery contains a range of SaaS applications that can be integrated with Entra ID.

You can filter the available applications based on several criteria.

### Authentication

Authentication-related filters can be used to find applications supporting specific sign-in methods, such as:

- **Single sign-on**
- **Password-based** authentication
- **SAML-based** authentication
- **Linked sign-on**

### Account Management

You can also filter applications based on account-management capabilities, such as **automated provisioning**.

### Categories

Applications can additionally be filtered by their assigned categories to make it easier to find a particular type of SaaS application.

## Step 3 — Select Box from the Gallery

For this example, use **Box**, a SaaS service for storing data in the cloud.

1. Search for **Box** in the application gallery.
2. Select **Box**.
3. Review the application information displayed by Entra ID.

The application information includes details such as:

- **Publisher** — Box
- **Provisioning** — Supports automatic provisioning
- **Single sign-on mode** — Supports password-based, SAML-based, or linked sign-on
- **URL** — The application's associated URL

## Step 4 — Add the Application

1. Keep the application name as **Box**.
2. Review the displayed application information.
3. Click **Create**.

Microsoft Entra ID adds the selected application to the tenant and creates the corresponding enterprise application object.

## Step 5 — Verify the Enterprise Application

After the application is created, Entra ID redirects you to the newly created **Box** enterprise application.

The application page displays properties such as:

- **Name**
- **Application ID**
- **Object ID**

You can also access **Getting Started** guides from the application page to help with subsequent configuration.

## Final Checklist

- [ ]  Open **Microsoft Entra ID**.
- [ ]  Navigate to **Enterprise applications**.
- [ ]  Click **New application**.
- [ ]  Search the application gallery.
- [ ]  Review authentication, provisioning, and category filters as needed.
- [ ]  Select **Box**.
- [ ]  Review the application's available capabilities.
- [ ]  Keep the application name as **Box**.
- [ ]  Click **Create**.
- [ ]  Verify that the **Box** enterprise application was created.
- [ ]  Review the application's IDs and **Getting Started** guides.

## Key Takeaway

The Microsoft Entra application gallery provides a convenient way to add pre-integrated **SaaS applications** as enterprise applications. Before selecting an application, review its supported **authentication**, **provisioning**, and account-management capabilities to determine whether it meets your integration requirements.
