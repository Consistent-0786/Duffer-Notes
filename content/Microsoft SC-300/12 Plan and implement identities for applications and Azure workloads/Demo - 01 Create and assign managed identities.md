<iframe src="https://drive.google.com/file/d/1mRSFMe54AfkCOrnbwNIgO09BQHfAJbAi/view?usp=sharing" width="640" height="480" allow="autoplay"></iframe>
# Configure Azure Managed Identities for Resource-to-Resource Access

## Overview

Azure Managed Identities allow Azure resources to authenticate to other Azure services without storing credentials in application code.

This guide demonstrates how to:

- Create a resource group for a managed identity demonstration.
- Create a virtual machine and Azure SQL Database.
- Enable a **system-assigned managed identity** on a virtual machine.
- Grant that identity an Azure RBAC role on the SQL resource.
- Create a **user-assigned managed identity**.
- Understand the lifecycle differences between system-assigned and user-assigned identities.
- Clean up the demonstration resources afterward.

The key concept is that the virtual machine can use its managed identity to authenticate to another Azure resource without requiring credentials to be stored in the VM or application code.

## Prerequisites

You need:

- An Azure subscription.
- Permission to create resource groups and Azure resources.
- Permission to manage identities and role assignments.
- Access to the Azure portal.

The demonstration uses:

- A Windows Server 2019 virtual machine.
- An Azure SQL Database.
- A resource group named `MI Demo`.

> **Important:** The virtual machine and SQL Database are created for demonstration purposes. The video intentionally skips detailed configuration of these resources because the focus is managed identities.

## Step 1 — Create the Resource Group

1. Open the Azure portal.
2. Navigate to **Resource groups**.
3. Select **Create**.
4. Select the Azure subscription you want to use.
5. Enter `MI Demo` as the resource group name.
6. Select **Review and create**.
7. After validation succeeds, select **Create**.

This resource group will contain the resources used throughout the demonstration.

## Step 2 — Create the Virtual Machine

1. Open the **Virtual machines** service.
2. Select **Create**.
3. Select the `MI Demo` resource group.
4. Name the virtual machine `MI Demo`.
5. Select a Windows Server image.

The demonstration uses **Windows Server 2019**.

6. Provide a username, such as `demo`.
7. Provide a password as required during VM creation.
8. Set **Public inbound ports** to **None**.
9. Select **Review + create**.
10. After validation succeeds, select **Create**.

The VM does not need to be configured in detail because it is being used only to demonstrate managed identity functionality.

## Step 3 — Create the Azure SQL Database

While the VM is deploying, create the SQL resource.

1. Open the **SQL databases** service.
2. Select **Create SQL Database**.
3. Select the `MI Demo` resource group.
4. Enter `SQL Demo` as the database resource name.
5. Provide a database name, such as `Sqldemo`.
6. Select **Create new** to create a SQL server.
7. Give the SQL server a unique name, such as `SQL Demo MI`.

> **Note:** Azure resource names may need to be globally unique. If a name is already in use, choose another name.

8. Configure authentication as appropriate for the demonstration.
9. Select an identity where required.
10. Select **OK**.
11. Select **Review + create**.
12. After validation succeeds, select **Create**.
13. Wait for the deployment to complete.

## Step 4 — Open the Virtual Machine Identity Settings

After the resources have finished deploying:

1. Open the **Virtual machines** service.
2. Select the `MI Demo` virtual machine.
3. Navigate to **Security → Identity**.

The Identity page provides options for both:

- **System assigned**
- **User assigned**

## Technical Explanation — System-Assigned Managed Identity

A system-assigned managed identity is created specifically for an Azure resource.

Important characteristics include:

- It is tied to the lifecycle of the associated resource.
- A resource can have one system-assigned managed identity.
- The identity is automatically deleted when the associated resource is deleted.

This makes system-assigned identities convenient when the identity is intended to exist only for the lifetime of a particular resource.

## Step 5 — Enable the System-Assigned Identity

1. On the VM's **Identity** page, locate **System assigned**.
2. Change **Status** to **On**.
3. Select **Save**.
4. Review the warning explaining that the VM will be registered with Microsoft Entra ID.
5. Confirm the operation.

Once enabled, Azure creates a managed identity associated with the virtual machine.

The VM can now be granted permissions to access Azure resources protected by Microsoft Entra ID and Azure RBAC.

> **Important:** Creating the managed identity does not automatically grant the VM access to other Azure resources. You must separately assign the required permissions.

## Step 6 — Open Access Control for the SQL Resource

Next, grant the VM's managed identity access to the SQL resource.

1. Open the SQL resource created earlier.
2. Select **Access control (IAM)**.
3. Open **Role assignments**.
4. Review the existing role assignments.

The existing assignments will vary depending on the subscription and your account permissions.

## Step 7 — Add an RBAC Role Assignment

1. Select **Add**.
2. Select **Add role assignment**.
3. Select the required role.

The demonstration uses a SQL contributor role.

4. Select **Next**.
5. Under the member selection, choose **Managed identity**.
6. Select **Select members**.
7. Choose the appropriate subscription.
8. Select the resource group containing the VM.
9. Locate the VM's newly created managed identity.
10. Select the managed identity.
11. Confirm the selection.
12. Select **Review and assign**.

The resulting role assignment grants the VM's managed identity the selected permissions on the SQL resource.

### Technical Explanation — Managed Identity + RBAC

The important part of this configuration is that the VM itself is the identity receiving the role assignment.

Conceptually:

```text
Virtual Machine
      │
      │ System-assigned managed identity
      ▼
Microsoft Entra ID
      │
      │ Azure RBAC role assignment
      ▼
Azure SQL resource
```

The VM can therefore authenticate as its managed identity instead of requiring credentials to be embedded in code.

## Step 8 — Review User-Assigned Managed Identity

Return to the VM:

1. Open the virtual machine.
2. Select **Security → Identity**.
3. Review the **User assigned** section.

A user-assigned managed identity differs from a system-assigned identity because it exists as a separate Azure resource.

### System-Assigned vs. User-Assigned

|Characteristic|System-assigned|User-assigned|
|---|---|---|
|Lifecycle|Tied to the Azure resource|Independent resource|
|Created as|Part of the resource|Standalone Azure resource|
|Deleted with associated resource|Yes|No|
|Can be assigned to resources|Associated resource|Can be assigned to supported Azure resources|
|Administrative overhead|Generally lower|Generally higher|

The key lifecycle difference is important.

If the VM is deleted:

- Its **system-assigned identity** is also deleted.
- A separately created **user-assigned identity** remains available.

## Step 9 — Create a User-Assigned Managed Identity

A user-assigned identity must first be created as a standalone resource.

1. In the Azure portal, search for **Managed Identities**.
2. Open the **Managed Identities** service.
3. Select **Create**.
4. Select the `MI Demo` resource group.
5. Provide a name, such as `user-assigned-MI`.
6. Select **Review + create**.
7. Select **Create**.

The managed identity is now an independent Azure resource.

## Step 10 — Assign the User-Assigned Identity

After creating the user-assigned identity, it can be associated with supported Azure resources such as the virtual machine.

The same general RBAC approach demonstrated with the system-assigned identity can then be used to grant the user-assigned identity access to other Azure resources.

The video does not demonstrate the complete role-assignment process for the user-assigned identity.

> **Important:** Do not assume that creating a user-assigned managed identity automatically gives it permissions. Resource access still requires the appropriate role assignment or other supported authorization mechanism.

## When to Use Each Identity Type

### System-Assigned Managed Identity

Use a system-assigned identity when:

- The identity should exist only with the resource.
- The identity does not need to survive resource deletion.
- You want to minimize administrative overhead.

The demonstrated best practice is to use system-assigned identities where they meet the requirements.

### User-Assigned Managed Identity

A user-assigned identity is useful when:

- The identity needs an independent lifecycle.
- The same identity needs to be associated with multiple supported resources.
- The identity must remain available when an associated resource is deleted or recreated.

## Best Practice

> **Recommendation:** Prefer system-assigned managed identities when they satisfy the requirements, because their lifecycle is tied directly to the resource and they generally reduce administrative overhead.

Use user-assigned identities when their independent lifecycle or reuse across resources provides a specific benefit.

## Cleanup — Delete the Demonstration Resources

The VM and SQL Database can incur costs, so delete the demonstration resources when finished.

1. Open **Resource groups**.
2. Select the `MI Demo` resource group.
3. Select **Delete resource group**.
4. Enter the resource group name to confirm deletion.
5. Select **Delete**.
6. Wait for the deletion to complete.

Because the demonstration resources are contained within the resource group, deleting the resource group removes the resources created for the demo.

> **Important:** Clean up demonstration resources when they are no longer needed to avoid unnecessary Azure charges.

## Final Checklist

- [ ]  Create the `MI Demo` resource group.
- [ ]  Create the demonstration Windows Server 2019 VM.
- [ ]  Create the Azure SQL Database and SQL server.
- [ ]  Open the VM's **Security → Identity** settings.
- [ ]  Enable the VM's **System assigned** identity.
- [ ]  Save the identity configuration.
- [ ]  Open the SQL resource's **Access control (IAM)** settings.
- [ ]  Add the appropriate RBAC role assignment.
- [ ]  Select **Managed identity** as the member type.
- [ ]  Select the VM's managed identity.
- [ ]  Review and assign the role.
- [ ]  Review the difference between system-assigned and user-assigned identities.
- [ ]  Create a standalone user-assigned managed identity.
- [ ]  Assign it to resources if required.
- [ ]  Delete the `MI Demo` resource group when the demonstration is complete.

## Key Takeaway

Azure Managed Identities allow Azure resources to authenticate to other Azure services **without storing credentials in code**.

The most important distinction is lifecycle:

- **System-assigned identity:** tied to the resource and deleted with it.
- **User-assigned identity:** an independent Azure resource that can outlive the resources to which it is assigned.

Use system-assigned identities when possible to reduce administrative overhead, and use user-assigned identities when an independently managed or reusable identity is required.
