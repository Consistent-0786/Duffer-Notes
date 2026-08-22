# Azure RBAC vs Entra ID Roles

## Common Misconception
- It is a very common misconception that Entra ID roles are used for permission management in Azure, or vice versa.
- This is incorrect - the two systems are fundamentally different in scope and purpose.

---

## Key Difference 1: Scope

### Azure RBAC
- Primarily manages access to **Azure resources**: virtual machines, storage accounts, databases, networking components.
- Purpose: control who can read, write, or manage specific resources within Azure Resource Manager.
- Example: assigning a user the **Contributor** role to manage a virtual machine.

### Entra ID Roles
- Manage access to **directory-level features and services** within Entra ID.
- Purpose: focus on identity and access management tasks - managing users, groups, applications, directory settings.
- Example: assigning a user the **Global Administrator** role to manage user accounts and groups in Entra ID (NOT Azure resources).

---

## Key Difference 2: Resource Targets

### Azure RBAC
- Targets Azure resources: databases, VMs, etc.
- Defines actions such as read, write, delete for specific Azure services.

### Entra ID Roles
- Targets identity-related resources within the Entra ID tenant: users, groups, services.
- Defines permissions related to managing user identity, security policies, authentication settings.

---

## Full Comparison Table

| Aspect | Azure RBAC | Entra ID Roles |
|---|---|---|
| **Scope** | Azure resources | Identity management (users, groups) |
| **Purpose** | Manage access to Azure services | Manage Entra ID and Active Directory features |
| **Targeted Resources** | VMs, databases, etc. | Users, groups, applications, policies |
| **Common Roles** | Contributor, Reader, Owner | Global Admin, User Admin, Security Admin |
| **Granularity** | Resource-level permissions (can also apply at subscription/management group level) | Tenant-wide permissions |
| **Common Use Cases** | Assigning resource-specific permissions (e.g., for a VM) | Assigning directory-wide administrative tasks |
| **Where It's Used** | Azure subscriptions, resource groups, management groups, individual resources | Entra ID |

---

## Key Point on Granularity
- Azure RBAC permissions are tied to specific resources/scopes (resource, resource group, subscription, management group).
- Entra ID roles grant **tenant-wide** permissions - e.g., a Global Reader role applies across the **entire tenant**, not just a specific resource.

---

## Quick Review / Flashcard Candidates
- What is the primary scope of Azure RBAC? -> Azure resources (VMs, storage accounts, databases, networking)
- What is the primary scope of Entra ID roles? -> Identity and directory management (users, groups, applications, settings)
- Give an example of a common Azure RBAC role. -> Contributor, Reader, or Owner
- Give an example of a common Entra ID role. -> Global Administrator, User Administrator, or Security Administrator
- Is Azure RBAC granularity resource-level or tenant-wide? -> Resource-level (can extend to subscription/management group level)
- Is Entra ID role granularity resource-level or tenant-wide? -> Tenant-wide
- Can Entra ID roles manage Azure resource permissions directly? -> No - that's the job of Azure RBAC
- Can Azure RBAC manage Entra ID directory settings like users and groups? -> No - that's the job of Entra ID roles
- Where is Azure RBAC applied (scope levels)? -> Subscriptions, resource groups, management groups, individual resources
- Where are Entra ID roles applied? -> Within the Entra ID tenant