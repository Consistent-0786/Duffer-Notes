# Entra Connect

## What Is Entra Connect?
- A key service for organizations operating in a **hybrid environment** (on-premises Active Directory + Entra ID in the cloud).
- Core purpose: synchronize identity information between on-premises AD and Entra ID.

---

## Core Sign-In / Authentication Methods

### Password Hash Synchronization
- Synchronizes the **password hash** of users from on-premises Active Directory to Entra ID.

### Pass-Through Authentication (PTA)
- Allows users to use the **same password** on-premises and in the cloud.
- Does NOT require additional Federated infrastructure (unlike ADFS).

### Federation Integration
- Optional part of Entra Connect.
- Used to configure a hybrid environment using on-premises **AD FS (Active Directory Federation Services)**.
- Provides ADFS management capabilities: certificate renewal, additional ADFS server deployments.
- Considered **legacy** - password hash sync and pass-through authentication are the more modern, preferred approaches.

---

## Synchronization
- Entra Connect synchronizes users, groups, and other objects from on-premises to Entra ID.
- Ensures identity information matches between on-premises and cloud.
- Synchronization also includes password hashes.
- Supports **writeback**: changes from Entra ID can be written back to on-premises Active Directory, keeping both environments consistent.

---

## Health Monitoring: Entra Connect Health
- Provides robust monitoring from a central location in the Microsoft Entra Admin Center.
- Lets you verify Entra Connect is operating in a healthy state.
- Critical because if Entra Connect fails, synchronization between cloud (Entra ID) and on-premises AD stops entirely.
- Supports alerts and analytics for early failure detection.

---

## Entra Connect Sync vs Entra Cloud Sync

### Entra Connect Sync
- Synchronizes on-premises AD with Entra ID for hybrid identity management.
- Ensures a unified identity across on-premises and cloud environments.
- Considered the **legacy** on-premises deployment model for identity synchronization.

### Entra Cloud Sync
- Lightweight, **cloud-based** service.
- Syncs on-premises directory identities to Entra ID **without** needing full on-premises sync infrastructure.
- Considered the **more modern** approach.
- Ideal for simplifying identity management and scaling across distributed environments with minimal infrastructure.

---

## Feature Comparison: Connect Sync vs Cloud Sync

![[Pasted image 20260814135143.png]]

**Key takeaway: Choice between Connect Sync and Cloud Sync depends on which specific features your organization needs.**

---

## Architecture Overview
- On-premises Active Directory synchronizes → via Entra Connect → to Entra ID (cloud).
- Identities, users, and groups are synced.
- Writeback allows updates from Entra ID to flow back to on-premises AD, keeping both environments in sync.

---

## Quick Review / Flashcard Candidates
- What does Password Hash Synchronization sync? -> The password hash of on-premises AD users to Entra ID
- What does Pass-Through Authentication allow, without requiring ADFS? -> Same password on-prem and cloud, no federation infrastructure needed
- Is Federation (ADFS) considered modern or legacy? -> Legacy
- What is Entra Connect Health used for? -> Monitoring the health/performance of synchronization
- Which sync method is considered legacy: Connect Sync or Cloud Sync? -> Connect Sync
- Which sync method is lightweight and cloud-based? -> Cloud Sync
- Which sync method supports device objects? -> Connect Sync only
- Which sync method supports pass-through authentication? -> Connect Sync only
- Which sync method supports multiple active agents for high availability? -> Cloud Sync only
- What is "writeback" in the context of Entra Connect? -> Writing changes from Entra ID back to on-premises Active Directory