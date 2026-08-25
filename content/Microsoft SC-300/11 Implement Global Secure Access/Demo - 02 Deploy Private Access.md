![[Untitled document (17).pdf]]

# Configure Global Secure Access Traffic Forwarding Profiles

## Overview

Global Secure Access uses different **traffic forwarding profiles** to determine how traffic from the Global Secure Access client is handled.

These profiles can control traffic associated with:

- Internet access
- Private/internal network access
- Microsoft 365 services

This guide focuses specifically on the **Private access** profile and how it can be enabled and assigned to users or groups.

## Prerequisites

Before configuring traffic forwarding:

- Global Secure Access should already be activated in the Microsoft Entra tenant.
- The Global Secure Access administration area should be accessible.
- Users who will receive the profile should be identified if the profile will not apply to everyone.

## Step 1 — Open Traffic Forwarding

1. Open the Microsoft Entra admin center.
2. Navigate to **Global Secure Access**.
3. Open **Connect**.
4. Select **Traffic Forwarding**.

The Traffic Forwarding page contains the available Global Secure Access profiles.

## Step 2 — Review the Traffic Forwarding Profiles

The Traffic Forwarding area provides three profile types for managing how client traffic is handled.

The video focuses on:

**Private access**

Private access is intended for traffic destined for resources on a private/internal network.

## Step 3 — Enable the Private Access Profile

By default, the **Private access** profile shown in the video is disabled.

To enable it:

1. Locate **Private access**.
2. Select the option to enable the profile.
3. Review the confirmation message.
4. Confirm that you want to enable the profile.

Enabling the profile directs Global Secure Access clients to acquire traffic associated with that profile.

> **Important:** Enabling a profile determines which Global Secure Access clients can receive the associated traffic-forwarding behavior. Consider the intended scope before assigning the profile broadly.

## Step 4 — Assign Users and Groups

After enabling Private access, determine which users or groups should receive the profile.

1. Open the user/group assignment option.
2. Select **View**.
3. Choose the appropriate users or groups.
4. Alternatively, configure the profile for **all users** if that is appropriate for the environment.
5. Confirm the assignment.

If applied to everyone, the profile will apply to all users who are using the Global Secure Access client.

## Technical Explanation — Private Access

The **Private access** profile is designed for traffic destined for resources within a private/internal network.

The video describes Microsoft's **Quick Access** capability as a way to define the internal resources that should be accessible through this configuration.

Depending on the configuration, administrators can define resources using identifiers such as:

- Fully qualified domain names (FQDNs)
- IP addresses

This allows specific internal resources to be defined for access rather than treating every resource as part of the configuration.

### Example

A private network resource could be represented by an internal FQDN or IP address and included in the appropriate Private access configuration.

The exact resources and configuration depend on the organization's environment.

## Step 5 — Review the Documentation

The **Learn More** option provides additional information about Private access, including:

- Prerequisites
- Configuration information
- Known limitations
- Client installation information

Review these details before deploying Private access in a production environment.

> **Important:** The video does not cover the complete Private access configuration or client installation process. Do not infer additional deployment steps solely from this procedure.

## Example — Assigning Private Access to Everyone

A basic assignment workflow is:

1. Enable **Private access**.
2. Select **View** under the user/group assignment section.
3. Choose **All users**.
4. Confirm the assignment.

This causes the profile to apply to all users using the Global Secure Access client.

## Configuration Decision

In the demonstrated environment, the instructor **does not ultimately enable Private access**.

The profile is enabled only to demonstrate the configuration process and is then turned back off.

For an actual deployment, enable the profile only if Private access is required for the environment.

## Final Checklist

- [ ]  Open **Global Secure Access**.
- [ ]  Navigate to **Connect → Traffic Forwarding**.
- [ ]  Review the available traffic-forwarding profiles.
- [ ]  Locate **Private access**.
- [ ]  Determine whether Private access is required.
- [ ]  If required, enable the profile.
- [ ]  Assign appropriate users or groups.
- [ ]  Configure the required private resources.
- [ ]  Review the **Learn More** documentation, including prerequisites and known limitations.
- [ ]  Verify that the profile is enabled only for the intended scope.

## Key Takeaway

**Traffic Forwarding profiles determine how Global Secure Access handles different categories of client traffic.** The Private access profile is used for accessing defined private/internal resources, with user or group assignments controlling who receives the configuration.