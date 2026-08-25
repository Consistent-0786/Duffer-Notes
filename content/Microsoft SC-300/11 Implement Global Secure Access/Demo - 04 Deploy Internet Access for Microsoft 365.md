![[Untitled document (19).pdf]]

# Configure the Global Secure Access Microsoft Traffic Profile

## Overview

The **Microsoft traffic** profile controls how traffic destined for Microsoft services is handled by Global Secure Access.

The profile can include workloads such as:

- Microsoft Entra ID
- Microsoft Graph
- SharePoint Online
- Exchange Online
- Other Microsoft applications

Traffic-forwarding policies are organized by workload, allowing administrators to decide whether traffic for each workload should be **forwarded** through Global Secure Access or **bypassed**.

## Prerequisites

Before configuring the Microsoft traffic profile:

- Global Secure Access should be activated.
- The Global Secure Access traffic-forwarding configuration should be accessible.
- Determine which Microsoft workloads should be forwarded or bypassed.
- Determine which users or groups should receive the profile.

## Step 1 — Open the Microsoft Traffic Profile

1. Open the Microsoft Entra admin center.
2. Navigate to **Global Secure Access**.
3. Open the traffic-forwarding configuration.
4. Locate **Microsoft traffic**.
5. Review the **Learn More** information if additional details are required.

The Microsoft traffic profile covers Microsoft services such as Entra ID, Microsoft Graph, SharePoint Online, and Exchange Online.

## Step 2 — Enable the Microsoft Traffic Profile

1. Locate the **Microsoft traffic** profile.
2. Enable the profile.
3. Confirm the activation.

Once enabled, the **Microsoft Traffic Policies** section becomes available for configuring individual workloads.

## Step 3 — Review Microsoft Traffic Policies

Under **Microsoft Traffic Policies**, the demonstrated configuration includes:

- **Exchange Online**
- **SharePoint Online**
- **Entra ID**
- **Microsoft Graph**

Expand each workload to review its associated traffic definitions.

These definitions include IP addresses and URLs used to identify the traffic belonging to the workload.

## Step 4 — Choose Forward or Bypass

For each Microsoft workload, determine how its traffic should be handled.

### Forward

When traffic is **forwarded**, it travels through the Global Secure Access environment.

This allows the traffic to be processed by the applicable security layers and policies, including controls such as Microsoft Defender and Conditional Access.

### Bypass

When traffic is configured to **bypass**, the traffic does not go through the Global Secure Access forwarding path.

> **Important:** The choice between forwarding and bypassing directly affects which Global Secure Access security controls are applied to the traffic. Configure each workload according to the organization's security requirements.

## Step 5 — Configure Each Workload

For each workload:

1. Expand the relevant Microsoft traffic policy.
2. Review the associated IP addresses and URLs.
3. Choose whether the traffic should be **forwarded** or **bypassed**.
4. Repeat the process for the other Microsoft workloads.
5. Save the configuration.

The video demonstrates selecting the desired behavior from the individual workload settings and then saving the configuration.

## Step 6 — Assign the Profile to Users and Groups

The Microsoft traffic profile can be scoped to specific users or groups.

1. Open the profile's user and group assignment section.
2. Review the current assignment.
3. Select the users or groups who should receive the profile.
4. To apply it broadly, assign the profile to **all users**.
5. Alternatively, select specific groups for a more targeted deployment.
6. Save or confirm the assignment.

The demonstrated configuration is prepared for assignment but is not initially assigned to everyone.

## Example — Assign to All Users

For a broad deployment:

1. Open the assignment settings.
2. Select **All users**.
3. Confirm the assignment.

The profile will then apply to users running the Global Secure Access client who fall within that assignment.

## Example — Assign to Specific Groups

For a controlled rollout:

1. Open the assignment settings.
2. Select the desired user or group.
3. Confirm the assignment.
4. Leave users outside the selected groups unassigned.

This allows the profile to be introduced incrementally.

## Understanding the Three Global Secure Access Profiles

The three profiles covered in the configuration are:

|Profile|Primary purpose|
|---|---|
|**Private access**|Handles traffic to defined private/internal resources|
|**Internet access**|Handles general internet traffic|
|**Microsoft traffic**|Handles traffic for Microsoft services and workloads|

The Microsoft traffic profile further allows individual workloads to be **forwarded** or **bypassed**.

## Final Checklist

- [ ]  Open **Global Secure Access**.
- [ ]  Locate the **Microsoft traffic** profile.
- [ ]  Enable the profile if required.
- [ ]  Open **Microsoft Traffic Policies**.
- [ ]  Review **Exchange Online**.
- [ ]  Review **SharePoint Online**.
- [ ]  Review **Entra ID**.
- [ ]  Review **Microsoft Graph**.
- [ ]  Review the associated URLs and IP addresses.
- [ ]  Choose **Forward** or **Bypass** for each workload.
- [ ]  Save the traffic policy configuration.
- [ ]  Assign the profile to the appropriate users or groups.
- [ ]  Verify the final assignment scope before deploying the client.

## Key Takeaway

The **Microsoft traffic profile** provides workload-level control over Microsoft service traffic. Administrators can choose which Microsoft workloads are **forwarded through Global Secure Access** and which are **bypassed**, then control who receives the configuration through user and group assignments.

Understanding these three profiles—**Private access, Internet access, and Microsoft traffic**—is an important prerequisite before deploying the Global Secure Access client.