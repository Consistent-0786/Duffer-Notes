# Managed Identities in Azure

## What Is a Managed Identity?
- An identity you can provide and associate with an Azure resource.
- Key benefit: **no need to manage credentials** - authentication is fully managed by Azure (no passwords, certificates, etc. to handle manually).
- Used to authenticate from one Azure resource to another Azure resource.
- Note: AuthN = Authentication, AuthZ = Authorization (industry-standard abbreviations used throughout the course).

---

## Example Use Cases
- A **virtual machine** can use a managed identity to access an **Azure Key Vault** (secrets, passwords, API keys).
- A **Function App** (serverless code execution environment) can use a managed identity to access a **storage account** containing critical data.
- In both cases, no credentials need to be manually managed - Azure handles it entirely.

---

## Two Types of Managed Identities

### System-Assigned Managed Identity
- Created **together with** the Azure resource (e.g., enabled at VM creation time).
- **Lifecycle is tied to the resource** - if the VM is deleted, the identity is deleted too.
- Can only be associated with a **single resource** - cannot be shared across multiple resources.

### User-Assigned Managed Identity
- Created as a **standalone Azure resource**, independent of any specific resource.
- Can then be associated with one or more resources afterward.
- **Independent lifecycle** - deleting the associated VM does NOT delete the identity.
- Can be associated with **multiple Azure resources simultaneously** (e.g., one identity shared across 4 VMs, all accessing the same Key Vault).

---

## Comparison Table

| Property | System-Assigned | User-Assigned |
|---|---|---|
| Creation | Created together with the Azure resource | Created as a standalone resource |
| Lifecycle | Tied to the resource (deleted when resource is deleted) | Independent (persists after resource deletion) |
| Sharing across resources | Only one resource (1:1) | Can be shared across multiple resources |

---

## Best Practice Recommendation
- **Default to System-Assigned** managed identities whenever possible - it's simpler and more convenient.
- Using User-Assigned identities for single-resource scenarios adds unnecessary complexity (you must remember to manually delete the identity when the resource is deleted).
- User-Assigned identities make sense specifically when you need to **share one identity across multiple resources**.

---

## Quick Review / Flashcard Candidates
- What is the main benefit of managed identities? -> No need to manually manage credentials - Azure handles authentication
- What are the two types of managed identities? -> System-Assigned and User-Assigned
- Which type shares its lifecycle with the resource it's created with? -> System-Assigned
- Which type can be associated with multiple resources at once? -> User-Assigned
- If you delete a VM with a System-Assigned identity, what happens to the identity? -> It is deleted along with the VM
- If you delete a VM with a User-Assigned identity, what happens to the identity? -> It remains - it has an independent lifecycle
- Which type is recommended as the default/easier choice? -> System-Assigned
- What do managed identities allow Azure resources to do? -> Authenticate to other Azure resources without managing credentials
- What do AuthN and AuthZ stand for? -> Authentication and Authorization