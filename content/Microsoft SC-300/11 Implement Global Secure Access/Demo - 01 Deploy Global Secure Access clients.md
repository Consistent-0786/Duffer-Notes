![[Untitled document (16).pdf]]

# Install and Initial Setup of Microsoft Global Secure Access

## Overview

Microsoft Global Secure Access provides a cloud-based security and access layer that can help enforce security controls for users accessing cloud services from different locations.

This guide covers the **initial tenant-side setup** required before deploying the Global Secure Access client to a Windows computer.

The main concepts covered are:

- Global Secure Access
- Microsoft Entra ID
- Cloud Access Security Broker (CASB)
- Zero Trust
- Microsoft Entra Conditional Access
- Adaptive Access
- Global Secure Access client activation

> **Important:** This guide covers the initial setup only. It does not cover the complete deployment or configuration of the Global Secure Access client.

## Prerequisites

Before beginning, you need:

- A Windows-based client for the eventual client installation.
    - Physical Windows host
    - Windows virtual machine, such as a Hyper-V VM
- A Microsoft Entra tenant.
- Appropriate licensing for the Global Secure Access capabilities being used.
- Administrative access to the Microsoft Entra admin center.

The video indicates that Microsoft Entra ID Premium P1 or P2 is required for the described capabilities and notes that Microsoft is moving toward including them with Microsoft 365 E3 and E5.

## Understanding Global Secure Access

Global Secure Access provides a cloud-based approach to access security rather than relying exclusively on traditional on-premises security appliances or VPN-based solutions.

A traditional Cloud Access Security Broker (CASB) could be deployed as an on-premises appliance alongside the firewall. Global Secure Access provides similar cloud access security capabilities in a model better suited to users who work remotely or travel.

### Zero Trust

Global Secure Access supports a Zero Trust security model in which access is continuously authenticated and evaluated rather than automatically trusted based on the user's network location.

This is particularly useful when users access organizational cloud services from outside the corporate network.

## Step 1 — Open the Microsoft Entra Admin Center

1. Open the Microsoft Entra admin center at `entra.microsoft.com`.
2. Locate **Global Secure Access** in the portal navigation.
3. Open the Global Secure Access section.

> **Note:** Microsoft frequently changes the Microsoft Entra portal interface. The exact location or appearance of **Global Secure Access** may differ from the interface shown in the video.

## Step 2 — Open Session Management

1. Under **Global Secure Access**, open **Settings**.
2. Select **Session management**.
3. Locate the relevant Global Secure Access activation settings.

The same area can also be reached through the client download workflow. Attempting to download the client leads to the tenant activation process if Global Secure Access has not yet been activated.

## Step 3 — Activate Global Secure Access

Before using Global Secure Access, activate it for the Microsoft 365/Azure tenant.

1. On the Session Management page, select **Activate**.
2. Allow Microsoft Entra to complete the onboarding process.
3. Wait for the activation to finish.

> **Important:** Activation can take several minutes. Do not assume that the process has failed if the activation does not complete immediately.

Once activation is complete, return to:

**Global Secure Access → Settings → Session management**

## Step 4 — Configure Adaptive Access

After activating Global Secure Access, configure Adaptive Access.

1. Open **Settings**.
2. Select **Session management**.
3. Open **Adaptive access**.
4. Locate the adaptive access settings.
5. Enable **CA signaling for Entra ID**.

This enables features used by Microsoft Entra Conditional Access.

### Technical Explanation — Conditional Access

Microsoft Entra Conditional Access allows administrators to define policies controlling when and under what conditions access is permitted.

This is an important component of the Zero Trust approach because access decisions can be based on conditions rather than simply trusting a user or network.

## Step 5 — Review Conditional Access

After enabling CA signaling, review the Conditional Access configuration.

1. Open **Protection** in the Microsoft Entra admin center.
2. Select **Conditional Access**.
3. Open **Named locations**.
4. Review the available network-location configuration.

The environment can now use Conditional Access to control access based on configured locations and other conditions.

The video specifically demonstrates the availability of **All compliant network locations** and the ability to control locations through Conditional Access.

## Initial Setup Complete

At this point, the initial tenant-side setup for Global Secure Access is complete.

The basic sequence is:

1. Activate Global Secure Access.
2. Configure Adaptive Access.
3. Enable **CA signaling for Entra ID**.
4. Review **Conditional Access** and **Named locations**.
5. Proceed with the subsequent Global Secure Access client deployment and configuration.

> **Important:** Activating Global Secure Access and configuring Adaptive Access is only the starting point for a full deployment. Additional configuration and client deployment are required before the capability is fully operational in an environment.

## Troubleshooting

### Problem: Global Secure Access does not activate immediately

**Solution:** Wait several minutes. Tenant activation can take some time to complete.

### Problem: The Microsoft Entra portal does not look like the interface shown

**Solution:** Microsoft frequently changes the Microsoft Entra portal interface. Search the portal for **Global Secure Access**, **Settings**, **Session management**, or the relevant configuration area rather than relying on the exact navigation shown in the video.

## Final Checklist

- [ ]  Open the Microsoft Entra admin center.
- [ ]  Locate **Global Secure Access**.
- [ ]  Open **Settings → Session management**.
- [ ]  Select **Activate** and wait for tenant activation.
- [ ]  Open **Adaptive access**.
- [ ]  Enable **CA signaling for Entra ID**.
- [ ]  Open **Protection → Conditional Access**.
- [ ]  Review **Named locations**.
- [ ]  Verify that the initial Global Secure Access configuration is active.
- [ ]  Proceed to the client deployment phase.

## Key Takeaway

The first step in deploying Microsoft Global Secure Access is **tenant activation and security-policy preparation**, not simply installing the Windows client. Activate Global Secure Access, enable its Conditional Access signaling through Adaptive Access, and review the Conditional Access location configuration before proceeding with client deployment.

