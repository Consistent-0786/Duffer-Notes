![[Untitled documesadasdasnt - Google Docs.pdf]]

# Configure the Global Secure Access Internet Access Profile

## Overview

The **Internet access** profile controls how Global Secure Access handles internet traffic from clients.

The profile applies to internet traffic except for traffic covered by the Microsoft traffic profile. Administrators can configure traffic-processing rules, including bypass rules, and can associate the profile with Microsoft Entra Conditional Access policies.

This guide covers:

- Reviewing Internet access policies
- Understanding bypass and acquire rules
- Creating custom traffic rules
- Integrating the profile with Conditional Access
- Assigning the profile to users or groups

## Prerequisites

Before configuring the Internet access profile:

- Global Secure Access should be activated.
- The Global Secure Access administration portal should be accessible.
- Determine which users or groups should receive the profile.
- If Conditional Access will be used, ensure the required Conditional Access configuration is available.

## Step 1 — Open the Internet Access Profile

1. Open the Microsoft Entra admin center.
2. Navigate to **Global Secure Access**.
3. Open the traffic-forwarding configuration.
4. Locate **Internet access**.

The Internet access profile applies to internet traffic except for traffic handled by the Microsoft traffic profile.

## Step 2 — Review Internet Access Policies

1. Open **Internet access**.
2. Select **View** to review the Internet access policies.

The demonstrated configuration contains policy categories such as:

- **Custom bypass**
- **Default bypass**
- **Default acquire**

The existing policies also contain IP addresses used to determine how particular traffic should be handled.

## Step 3 — Configure Traffic Rules

Additional rules can be created when more control over internet traffic is required.

Depending on the configuration, rules can use criteria such as:

- Fully qualified domain names (FQDNs)
- IP addresses
- Subnet ranges

### Custom Bypass

A **custom bypass** rule can be used when specific traffic should not be routed through the Global Secure Access client.

For example, an administrator could define a particular FQDN, IP address, or subnet range as a bypass.

> **Important:** Bypass rules determine which traffic does not go through Global Secure Access. Define them carefully so that required security controls are not unintentionally bypassed.

## Step 4 — Integrate Internet Access with Conditional Access

The Internet access profile can work in conjunction with Microsoft Entra **Conditional Access** policies.

Conditional Access can be used to determine whether specific access attempts should be allowed or restricted.

To review Conditional Access:

1. Open **Protection** in the Microsoft Entra admin center.
2. Select **Conditional Access**.
3. Review or configure the policies that should govern the relevant access.

This allows Internet access configuration to work alongside broader identity and access controls.

## Step 5 — Enable the Internet Access Profile

After configuring the required policies:

1. Return to the **Internet access** profile.
2. Select the option to enable the profile.
3. Confirm the activation.

The profile must then be assigned to the users or groups for whom it should apply.

## Step 6 — Assign Users and Groups

1. Open the user and group assignment section.
2. Select **View**.
3. Choose the users or groups that should receive the Internet access profile.
4. Confirm the assignment.

The profile does not necessarily need to be assigned to everyone. It can be scoped to a specific group of users.

### Example — Assign to All Users

To apply the profile broadly:

1. Select **View** under the assignment section.
2. Select **All users**.
3. Confirm the selection.

In the demonstrated configuration, the Internet access profile is assigned to **all users**.

## Example — Assign to a Specific Group

For a more controlled deployment:

1. Open the assignment interface.
2. Select the specific user or group.
3. Confirm the selection.
4. Leave other users unassigned.

This approach can be useful when deploying Global Secure Access incrementally.

## Final Configuration

The demonstrated configuration ends with the **Internet access** profile enabled and assigned to all users.

The important configuration areas are:

- Internet traffic forwarding
- Bypass and acquire policies
- Custom traffic rules
- Conditional Access
- User and group assignments

## Final Checklist

- [ ]  Open **Global Secure Access**.
- [ ]  Locate the **Internet access** profile.
- [ ]  Review the existing Internet access policies.
- [ ]  Review **Custom bypass**, **Default bypass**, and **Default acquire** rules.
- [ ]  Add custom rules if required.
- [ ]  Define FQDNs, IP addresses, or subnet ranges where appropriate.
- [ ]  Review the relationship with **Conditional Access**.
- [ ]  Enable the Internet access profile.
- [ ]  Assign the profile to the intended users or groups.
- [ ]  Verify the final assignment scope.

## Key Takeaway

The **Internet access** profile provides control over internet traffic handled by Global Secure Access. Administrators can define traffic rules and bypasses, integrate the configuration with Conditional Access, and determine exactly which users or groups receive the profile.

