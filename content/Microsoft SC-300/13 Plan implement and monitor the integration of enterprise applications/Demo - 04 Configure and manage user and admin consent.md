![[Untitled document (23).pdf]]

# Configure User Consent, Admin Consent, and Permission Classifications in Microsoft Entra ID

## Overview

Microsoft Entra ID provides controls for managing how users and administrators grant consent to applications.

The **Consent and permissions** settings cover three main areas:

- **User consent settings** — control when users and group owners can grant application consent themselves.
- **Admin consent settings** — control how users request administrator approval when they cannot provide consent themselves.
- **Permission classifications** — classify API permissions according to their impact so they can be used in consent policies.

These settings are particularly important for controlling **data privacy** and **information security** when applications request access to organizational or user data.

## Prerequisites

- Access to **Microsoft Entra ID**.
- Appropriate permissions to configure enterprise application consent settings.
- An understanding of your organization's data privacy and information security requirements.

## Step 1 — Open Consent and Permissions

1. Open **Microsoft Entra ID**.
2. Navigate to **Enterprise applications**.
3. Under **Security**, select **Consent and permissions**.

The page contains the settings for user consent, administrator consent, and permission classifications.

## Step 2 — Configure User Consent Settings

User consent settings determine when **end users and group owners** are allowed to grant consent to applications and when administrator approval is required.

Application consent allows an application to access requested organizational or user information. Depending on the permissions requested, this information may include **personally identifiable information (PII)**.

### Available User Consent Options

The transcript describes three possible approaches:

1. **Do not allow user consent**
    
    - Users cannot grant consent to applications themselves.
    - An administrator is required to approve applications.
2. **Allow user consent for apps from verified publishers, for selected permissions**
    
    - Users can provide consent only when the application meets the configured requirements.
    - Permissions are restricted to those classified as having a **low impact**.
3. **Allow user consent for applications**
    
    - Users in the organization can consent to applications accessing organizational and user data.
    - This provides considerably more freedom to users but can introduce additional **data privacy and security risks**.

> **Important:** Allowing broad user consent should be evaluated against your organization's data privacy and information security requirements. Applications may request access to sensitive organizational or user information.

## Step 3 — Configure Admin Consent Settings

Administrator consent settings determine how users can request approval for applications they cannot consent to themselves.

1. Open the **Admin consent settings** section.
2. Decide whether users are allowed to request administrator consent.
3. If enabled, configure the **reviewers** who can process consent requests.

Reviewers can be specified using:

- Individual users
- Groups
- Specific directory roles

Additional settings control how consent requests are communicated and managed.

### Request Notifications

You can configure whether reviewers receive **email notifications** for consent requests.

### Expiration Reminders

You can also determine whether **expiration reminders** are sent.

### Consent Request Expiration

You can configure how long a consent request remains valid.

The range described in the video is:

- **Minimum:** 1 day
- **Maximum:** 60 days

## Step 4 — Configure Permission Classifications

Permission classifications allow API permissions to be categorized according to their impact.

These classifications can then be referenced by consent policies to determine which permissions users are allowed to consent to.

1. Return to **User consent settings** if necessary.
2. Select **Permission classifications**.
3. Review the available permission classifications.
4. Use **Add permissions** to add API permissions to the classification.

The classifications discussed are:

- **Low**
- **Medium**
- **High**

The transcript notes that **medium** and **high** classifications were in preview at the time of the recording.

> **Note:** Permission classifications provide a way to distinguish lower-impact permissions from permissions that require greater administrative control.

## Step 5 — Add API Permissions to a Classification

1. Click **Add permissions**.
2. Select the relevant service or API.
3. Select the API permissions you want to classify.
4. Add the selected permissions.

Available APIs can include **Microsoft APIs**, such as Microsoft Graph, as well as APIs used by your organization.

### Example — Microsoft Graph

For example, a permission from the **Microsoft Graph API** can be added to the classification.

The example in the video uses:

```text
API: Microsoft Graph
Permission: User.Read
Description: Allows the user to sign in and read the user profile.
```

The selected permission can then be included in the appropriate permission classification.

## Step 6 — Build a Set of Classified Permissions

Continue adding permissions according to your organization's requirements.

For each API:

1. Click **Add permissions**.
2. Select the service/API.
3. Review its available API permissions.
4. Select the permissions that should be classified.
5. Add the selected permissions to the appropriate classification.

This allows you to build a controlled set of permissions that can subsequently be referenced by **user consent** and **admin consent policies**.

## How the Settings Work Together

The three configuration areas serve different purposes:

|Setting|Purpose|
|---|---|
|**User consent settings**|Determines when users can grant application consent themselves.|
|**Admin consent settings**|Controls whether and how users can request administrator approval.|
|**Permission classifications**|Defines which API permissions are considered low, medium, or high impact for use in consent policies.|

The permission classifications can therefore support the user-consent policy. For example, an organization can configure user consent to permit only applications requesting appropriately classified, lower-impact permissions.

## Final Checklist

- [ ]  Open **Microsoft Entra ID**.
- [ ]  Navigate to **Enterprise applications**.
- [ ]  Open **Security → Consent and permissions**.
- [ ]  Configure **User consent settings**.
- [ ]  Decide whether users can grant consent themselves.
- [ ]  Consider restricting consent to applications from **verified publishers** and selected permissions.
- [ ]  Configure **Admin consent settings**.
- [ ]  Decide whether users can request administrator consent.
- [ ]  Configure appropriate reviewers.
- [ ]  Configure email notifications and expiration reminders as required.
- [ ]  Set the consent-request expiration period between **1 and 60 days**, according to requirements.
- [ ]  Open **Permission classifications**.
- [ ]  Add relevant APIs and permissions.
- [ ]  Classify permissions according to their impact.
- [ ]  Use the classifications as part of your consent policies.

## Key Takeaway

Microsoft Entra ID provides layered controls for application consent. **User consent settings** determine what users can approve themselves, **admin consent settings** establish an approval process for applications requiring administrator involvement, and **permission classifications** provide a way to categorize API permissions by impact.

Together, these controls help organizations balance application usability with **data privacy and information security** requirements.