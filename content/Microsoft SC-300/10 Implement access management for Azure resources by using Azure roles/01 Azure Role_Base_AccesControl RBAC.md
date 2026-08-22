# Azure Role-Based Access Control (RBAC)

## Azure RBAC vs Entra ID Roles
- Azure RBAC is **fundamentally different** from Entra ID roles.
- Azure RBAC only administers access to **Azure resources**.
- It CANNOT be used to manage access to things like Microsoft Teams - that's the job of Entra ID roles.
- Key distinction: Entra ID roles = whole Microsoft ecosystem; Azure RBAC = Azure only.

---

## Example Scenario
- Alice (developer) needs access to Azure Kubernetes Service (AKS) and Azure Functions.
- Sanjay (cybersecurity professional) needs access to Sentinel and Log Analytics.
- Both need role assignments via Azure RBAC to do their jobs.

---

## The Three Elements of an Azure RBAC Role Assignment

### 1. Security Principal
- The entity receiving the permissions. Can be:
  - **User** (e.g., Alice or Sanjay - individual with a Microsoft/Entra ID account)
  - **Group**
  - **Service Principal** (secure identity used by applications/services to access resources)
  - **Managed Identity** (best practice - e.g., giving a VM a managed identity, then granting that identity access to a storage account)

### 2. Role Definition
- A collection of permissions defining what actions the security principal can perform on Azure resources.
- Components:
  - **Actions**: specific permissions granted (e.g., read, write, delete)
  - **Not Actions**: explicitly denied actions (if none are defined, it's an **implicit deny** by default for anything not in Actions)
  - **Data Actions**: permissions related to data access (specific to services like Azure Storage and SQL)
  - **Assignable Scope**: defines where the role can be assigned

#### Example: Azure Sentinel Contributor (built-in role)
- Description: can manage all aspects of Azure Sentinel **except access control**.
- Typical of "Contributor" roles: can do almost anything except manage access (that requires "Owner").
- Actions include: read/write on the workspace, broad access via the Security Insights provider.
- No "Not Actions" defined (no explicit deny).
- Key permissions: managing alert rules, managing incidents, managing connected Log Analytics workspaces.

### 3. Scope
- Defines the **boundary** where the security principal can access resources under the assigned role.
- Scope levels (broadest to narrowest):
  - Management Group
  - Subscription
  - Resource Group
  - Resource
- Role assigned at a higher level (e.g., Management Group) applies to all resources beneath it; assigned at Resource level applies only to that specific resource.

---

## Example Role Assignments
- Alice (Developer): **AKS Cluster Admin** + **Azure Functions Contributor** (both built-in roles)
- Sanjay (Security Analyst): **Sentinel Contributor** + **Log Analytics Contributor** (both built-in roles)

---

## Custom Roles

### What Are Custom Roles?
- Used when you need more granular control over permissions than built-in roles provide.
- Allow you to define exactly which actions a user/group can perform.
- Can combine specific permissions from multiple built-in roles.
- Help avoid giving users more permissions than needed (supports **principle of least privilege**).

### Example: Combining Roles
- Alice's AKS Cluster Admin + Azure Functions Contributor permissions could be combined into one custom role called "Developer" tailored exactly to what she needs.

### Example: SOC Team Custom Roles
- Scenario: A SOC has different sub-teams (threat hunters, incident responders, SOC analysts) needing different, specific access levels.
- Built-in roles may be too broad or too narrow for these specific needs.
- Example - **SOC Threat Hunter custom role**:
  - Needs: access to threat hunting queries, ability to read security incidents
  - Does NOT need: ability to manage incidents, alter Sentinel configuration, or modify automation rules
  - This is implemented via specific Actions and Not Actions in the custom role definition.

---

## Custom Roles: Advantages vs Disadvantages

### Advantages
- **Granular control** - permissions matched exactly to job needs, minimizing over-permissioning.
- **Tailored to business needs** - built-in roles are generic; custom roles can match your specific operational structure.
- **Enhances security and compliance** - supports the principle of least privilege more precisely.

### Disadvantages
- **Complex management** - many custom roles across users/groups can create confusion about who has access to what.
- **Maintenance overhead** - roles need ongoing updates as environments grow, services change, or people change jobs.
- **Risk of misconfiguration** - overly restrictive roles block legitimate work; overly permissive roles introduce security risk.

---

## Key Takeaway
- Aim for a good balance between Azure built-in roles and custom roles - leverage the benefits of custom roles without introducing unnecessary management complexity.

---

## Quick Review / Flashcard Candidates
- What is the key difference between Azure RBAC and Entra ID roles? -> Azure RBAC only covers Azure resources; Entra ID roles cover the whole Microsoft ecosystem
- What are the three elements of an Azure RBAC role assignment? -> Security Principal, Role Definition, Scope
- What are the four security principal types? -> User, Group, Service Principal, Managed Identity
- What is the best practice for giving a VM access to a storage account? -> Assign it a Managed Identity and grant that identity RBAC access
- What happens if no "Not Actions" are defined in a role? -> Implicit deny applies to anything not explicitly allowed
- What are the four scope levels in Azure RBAC, from broadest to narrowest? -> Management Group, Subscription, Resource Group, Resource
- What can "Contributor" roles typically NOT do? -> Manage access control (that requires "Owner")
- Why use custom roles instead of built-in roles? -> For granular, tailored permissions matching principle of least privilege
- What's a major disadvantage of custom roles? -> Increased management complexity and maintenance overhead