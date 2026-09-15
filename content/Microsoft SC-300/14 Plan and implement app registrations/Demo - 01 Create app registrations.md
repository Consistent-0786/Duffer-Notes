
![[Untitled document (25).pdf]]

# Create an App Registration in Microsoft Entra ID

## Overview

An **app registration** creates an application object in **Microsoft Entra ID** that can be used for authentication and other identity-related scenarios.

This guide covers:

- Creating a new app registration.
- Choosing the appropriate account type.
- Configuring a redirect URI for an application you own.
- Understanding the identifiers created by the registration.

## Prerequisites

Before starting, you need:

- Access to a Microsoft Entra ID tenant.
- Permission to create app registrations.
- An application name.
- If configuring a redirect URI, the callback URL used by your application.

## Step 1 — Open App Registrations

1. Open **Microsoft Entra ID** in the Azure portal.
2. Navigate to **App registrations**.
3. Click **New registration**.

Creating the registration creates an application object in Microsoft Entra ID that can be referenced for authentication and other application scenarios.

## Step 2 — Enter the Application Name

1. In **Name**, enter a name for the application.
2. For the example in this guide, use:

```text
demo
```

## Step 3 — Choose the Supported Account Types

The **Supported account types** setting determines who can use or access the application.

The available options are:

|Account type|Description|
|---|---|
|Accounts in this organizational directory only|**Single-tenant** application. Only users/accounts in the current Entra ID tenant can access the application.|
|Accounts in any organizational directory|**Multi-tenant** application. Accounts from other Entra ID tenants can access the application.|
|Accounts in any organizational directory and personal Microsoft accounts|**Multi-tenant** application that also supports personal Microsoft accounts, such as accounts used with services such as Skype or Xbox.|
|Personal Microsoft accounts|The application is available only to personal Microsoft accounts.|

For this example, leave the first option selected:

> **Accounts in this organizational directory only** creates a single-tenant application. The application is limited to the current tenant.

### Why the account type matters

This setting determines **who can interact with your application**. Choose the option based on whether the application is intended for users in your organization, users from other organizations, personal Microsoft accounts, or a combination of these.

## Step 4 — Configure the Redirect URI

A **Redirect URI** specifies where Microsoft Entra ID sends the authentication response after the user successfully authenticates.

This is particularly relevant when registering an application that you own, such as a web application.

For the example, the redirect URI is:

```text
https://example.com/auth
```

Configure the URI appropriate for your own application's authentication endpoint.

> **Important:** The redirect URI is part of the authentication flow. It tells the application where to receive the result after authentication with Microsoft Entra ID.

### When you need a Redirect URI

If you are registering an application that you own, such as a web application, you typically configure a redirect URI that the application uses to receive the successful authentication response.

If you are simply consuming a third-party SaaS application, such as Dropbox, the redirect URI is generally handled by the application/service provider rather than something you configure as part of registering that SaaS application yourself.

## Step 5 — Register the Application

After configuring the application:

1. Review the application name.
2. Verify the supported account type.
3. Verify the redirect URI, if required.
4. Click **Register**.

Microsoft Entra ID creates the application registration.

## Step 6 — Review the Application Identifiers

After registration, the application receives identifiers including:

- **Application (client) ID** — identifies the application registration.
- **Object ID** — identifies the corresponding application object in the Entra ID tenant.

These identifiers can be used when configuring authentication and other integrations involving the application.

## Example

The example application created in the video uses:

```text
Application name: demo
Account type: Accounts in this organizational directory only
Redirect URI: https://example.com/auth
```

After registration, the **demo** application appears under **App registrations → All applications**.

## Technical Explanation

### App Registration

An app registration creates an application object in Microsoft Entra ID. The registration provides an identity that an application can use when interacting with Microsoft Entra ID, including authentication scenarios.

### Single-Tenant vs. Multi-Tenant

The supported account type determines the scope of users who can authenticate to the application.

- **Single-tenant:** Users/accounts from the current Entra ID tenant.
- **Multi-tenant:** Users/accounts from multiple Entra ID tenants.
- **Multi-tenant + personal accounts:** Organizational accounts plus supported personal Microsoft accounts.
- **Personal accounts only:** Personal Microsoft accounts.

## Final Checklist

- [ ]  Open **Microsoft Entra ID**.
- [ ]  Navigate to **App registrations**.
- [ ]  Click **New registration**.
- [ ]  Enter the application name.
- [ ]  Select the appropriate **Supported account types**.
- [ ]  Configure a **Redirect URI** if required by the application.
- [ ]  Click **Register**.
- [ ]  Verify the **Application (client) ID**.
- [ ]  Verify the **Object ID**.
- [ ]  Confirm the application appears under **All applications**.