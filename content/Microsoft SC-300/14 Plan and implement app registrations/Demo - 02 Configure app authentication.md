![[Untitled document (26).pdf]]

# Configure Authentication for an App Registration in Microsoft Entra ID

## Overview

Authentication settings for an app registration determine how an application integrates with **Microsoft Entra ID** for user authentication.

This guide covers:

- Opening the authentication settings for an existing app registration.
- Selecting the appropriate application platform.
- Configuring redirect URIs and front-channel logout URLs.
- Understanding platform-specific configuration.
- Reviewing supported account types.
- Configuring public client flows.
- Saving the authentication configuration.

## Prerequisites

Before starting, you need:

- An existing app registration in Microsoft Entra ID.
- Access to the relevant Entra ID tenant.
- Knowledge of the platform used by your application.
- For a web application, the appropriate redirect URI.

## Step 1 — Open the App Registration

1. Open **Microsoft Entra ID** in the Azure portal.
2. Navigate to **App registrations**.
3. Select the application you want to configure.

For this example, select the **demo** app registration.

## Step 2 — Open Authentication Settings

1. In the app registration, open the **Manage** menu.
2. Select **Authentication**.

The **Authentication** page contains the platform-specific authentication configuration for the application.

## Step 3 — Add a Platform

The platform configuration determines which authentication settings are available.

1. Under **Platform configurations**, click **Add a platform**.
2. Select the platform that matches your application.

The available platform categories include:

- **Web**
- **Single-page application**
- **iOS/macOS**
- **Android**
- **Mobile and desktop applications**

> **Important:** Select the platform that your application actually uses. The available configuration options depend on the selected platform.

## Step 4 — Configure a Web Application

If the application is a web application:

1. Select **Web**.
2. Configure the **Redirect URIs**.

The redirect URI tells Microsoft Entra ID where to return the authentication response after the user authenticates.

For example:

```text
https://example.com/auth
```

The application uses this endpoint to receive the result of the authentication process.

### Configure a Front-Channel Logout URL

For a web application, you can also specify a **Front-channel logout URL**.

This URL is used when Microsoft Entra ID needs to notify the application that the user has logged out. The application can use the request to clear relevant user data or perform its logout processing.

## Step 5 — Configure Other Platforms

Different application platforms require different configuration values.

### iOS/macOS

When configuring an **iOS/macOS** application, a **Bundle ID** is required.

### Android

Select **Android** when the application is an Android application and provide the platform-specific information requested by Entra ID.

### Mobile and Desktop Applications

Select **Mobile and desktop applications** when the application uses the corresponding mobile or desktop authentication workflow.

### Single-Page Applications

For a browser-based single-page application, select **Single-page application** and configure the settings required for that platform.

The exact settings should be based on the platform your application uses.

## Step 6 — Review Supported Account Types

The authentication configuration also reflects the application's supported account types.

For an existing app registration, the available choices may be limited by the account type selected when the application was originally registered.

In the scenario shown, the available choices are:

- **Single tenant**
- **Multi tenant**

The personal Microsoft account options that were available during initial registration are not available for this existing registration.

> **Important:** If you need to change the application to one of the account-type configurations that is no longer available for the existing registration, you need to create a new app registration.

## Step 7 — Configure Advanced Settings

The authentication page also contains **Advanced settings**.

One of the available settings is **Allow public client flows**.

This setting is **off by default** in the configuration shown.

When enabled, it allows mobile and desktop authentication workflows, including:

- Public-client authentication scenarios.
- Username/password-based flows where supported.
- Single sign-on (SSO) for domain-joined Windows devices.

> **Security consideration:** Public client flows should only be enabled when they are required by the application's authentication architecture.

## Step 8 — Save the Configuration

After configuring the appropriate platform and authentication settings:

1. Review the configuration.
2. Verify the redirect URI and other platform-specific values.
3. Review the account type and advanced settings.
4. Click **Save**.

The authentication configuration is then applied to the app registration.

## Technical Explanations

### Platform Configuration

The platform determines how the application interacts with Microsoft Entra ID during authentication.

For example:

|Platform|Example configuration|
|---|---|
|Web|Redirect URI, front-channel logout URL|
|Single-page application|SPA-specific redirect/authentication configuration|
|iOS/macOS|Bundle ID|
|Android|Android-specific application configuration|
|Mobile and desktop|Mobile/desktop authentication configuration|

### Redirect URI

A **redirect URI** is the location to which Microsoft Entra ID returns the authentication response after authentication.

The URI must correspond to an endpoint that the application can handle.

```text
https://example.com/auth
```

### Front-Channel Logout URL

A **Front-channel logout URL** allows Microsoft Entra ID to send a logout notification to the application.

The application can then perform actions such as clearing user session data.

### Public Client Flows

A public client is an application that cannot safely keep a client secret, such as certain mobile or desktop applications.

The **Allow public client flows** setting enables authentication flows appropriate for these scenarios.

## Final Checklist

- [ ]  Open **Microsoft Entra ID**.
- [ ]  Navigate to **App registrations**.
- [ ]  Select the required app registration.
- [ ]  Open **Manage → Authentication**.
- [ ]  Add the platform used by the application.
- [ ]  Configure the required platform-specific settings.
- [ ]  Configure **Redirect URIs** for a web application.
- [ ]  Configure the **Front-channel logout URL** if required.
- [ ]  Verify the supported account type.
- [ ]  Review **Advanced settings**.
- [ ]  Enable **Allow public client flows** only when required.
- [ ]  Click **Save**.
- [ ]  Verify that the authentication configuration matches the application's platform.