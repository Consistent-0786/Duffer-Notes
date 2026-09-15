![[Untitled document (27).pdf]]

# Configure API Permissions for an App Registration in Microsoft Entra ID

## Overview

**API permissions** define which APIs an app registration can access and what level of access it has.

This guide covers:

- Viewing existing API permissions.
- Adding permissions for Microsoft APIs.
- Adding permissions for APIs used by your organization.
- Understanding **Delegated permissions** vs. **Application permissions**.
- Understanding why some permissions require administrator consent.

## Prerequisites

Before starting, you need:

- An existing app registration in Microsoft Entra ID.
- Access to the relevant Entra ID tenant.
- Knowledge of which API your application needs to access.
- Appropriate administrative privileges if the selected permissions require admin consent.

## Step 1 — Open API Permissions

1. Open **Microsoft Entra ID** in the Azure portal.
2. Navigate to **App registrations**.
3. Select the application you want to configure.

For this example, select the **demo** application.

4. Open **API permissions**.

The page displays the API permissions currently configured for the application.

## Step 2 — Review the Default Microsoft Graph Permission

A newly created app registration can have a default Microsoft Graph permission that allows the application to:

- Sign in users.
- Read the signed-in user's basic profile information.

Review the existing permissions before adding additional ones.

## Step 3 — Add an API Permission

To add another API permission:

1. Click **Add a permission**.
2. Select the type of API you want to access.

The available options include:

- **Microsoft APIs** — commonly used Microsoft APIs.
- **APIs my organization uses** — APIs that have been exposed or registered within your organization.

If your organization has not defined any additional APIs, there may be no entries under **APIs my organization uses**.

## Step 4 — Select the API

For this example, select a Microsoft API such as **SharePoint**.

After selecting the API, Microsoft Entra ID asks you to choose the type of permission the application requires.

This is an important decision because it determines **how the application obtains access to the API**.

## Step 5 — Choose Delegated Permissions or Application Permissions

There are two major permission models:

### Delegated Permissions

**Delegated permissions** allow an application to access an API on behalf of a signed-in user.

The effective access depends on the permissions available to both the application and the signed-in user.

For example:

1. A user signs in to the application.
2. The application obtains a token representing that user's access.
3. The application calls the API on behalf of that user.
4. The user's permissions determine what the application can access.

> **Important:** With delegated permissions, the application acts on behalf of the signed-in user. The user therefore needs sufficient permissions to perform the requested operation.

### Application Permissions

**Application permissions** grant permissions directly to the application.

This is intended for scenarios where the application needs to run without a signed-in user, such as:

- Background services.
- Daemons.
- Automated processes.

In this model, the application authenticates and calls the API using its own identity rather than acting on behalf of a user.

### Delegated vs. Application Permissions

|Permission type|Runs as|User required?|Typical scenario|
|---|---|---|---|
|Delegated|Signed-in user|Yes|Interactive application|
|Application|Application identity|No|Background service or daemon|

## Step 6 — Select the Required Permission

For the SharePoint example, the video demonstrates an application permission such as:

```text
Sites.FullControl.All
```

This permission provides full control over all SharePoint site collections.

> **Warning:** Highly privileged application permissions can provide broad access to organizational data. Grant only the permissions the application actually requires.

To add the permission:

1. Select the required permission.
2. Click **Add permissions**.

The permission is then added to the app registration.

## Step 7 — Grant Administrator Consent When Required

Some API permissions require **administrator consent**.

For example, the SharePoint application permission demonstrated in the video requires admin consent.

The permission can therefore appear in the application's API permissions, but the application cannot use it successfully until the required consent has been granted.

> **Important:** Adding an API permission and granting consent are separate steps. A permission that requires administrator consent must be approved by an appropriate administrator before the application can use it.

## Example

The video uses SharePoint to demonstrate the difference between the two permission models.

### Delegated scenario

The application accesses SharePoint as the signed-in user:

```text
Application → Signed-in User → SharePoint API
```

The user's permissions determine what the application can do.

### Application scenario

The application accesses SharePoint using its own identity:

```text
Application → SharePoint API
```

The application's assigned permissions determine what it can do.

The demonstrated application permission is:

```text
Sites.FullControl.All
```

This grants full control over all SharePoint site collections and therefore represents a highly privileged permission.

## Technical Explanation

### Delegated Permissions

Delegated permissions are appropriate when an application needs to perform actions **on behalf of a user**.

The application does not simply receive unrestricted access to the API. Instead, the API request is made in the context of the signed-in user's access.

### Application Permissions

Application permissions are appropriate when the application needs to operate **without a user being signed in**.

This is common for backend services, automation, and daemon-style applications.

Because the application acts independently of a user, application permissions can provide significant access to organizational resources.

## Troubleshooting

### Problem: The API permission appears to be configured, but the application cannot use it.

**Solution:** Check whether the permission requires administrator consent. If so, the required administrator must grant consent before the application can use the permission.

### Problem: The application needs to run without a signed-in user.

**Solution:** Use **Application permissions** rather than **Delegated permissions**, provided the target API supports the required application permission.

### Problem: The application should access an API as the signed-in user.

**Solution:** Use **Delegated permissions** and ensure the signed-in user has the required access to the API resource.

## Final Checklist

- [ ]  Open **Microsoft Entra ID**.
- [ ]  Navigate to **App registrations**.
- [ ]  Select the required application.
- [ ]  Open **API permissions**.
- [ ]  Review the existing permissions.
- [ ]  Click **Add a permission**.
- [ ]  Select the required API.
- [ ]  Choose **Delegated permissions** or **Application permissions**.
- [ ]  Select only the permissions the application requires.
- [ ]  Click **Add permissions**.
- [ ]  Check whether administrator consent is required.
- [ ]  Obtain administrator consent when necessary.
- [ ]  Verify that the application's effective API access matches the intended design.