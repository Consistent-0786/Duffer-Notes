![[Untitled document (13).pdf]]

# Create a Custom Azure RBAC Role

## Overview

Azure RBAC (Role-Based Access Control) allows you to control what users, groups, or identities can do within Azure.

A **custom RBAC role** lets you define a specific set of permissions instead of using one of Azure's built-in roles such as **Owner**, **Contributor**, or **Virtual Machine Contributor**.

This guide walks through creating a custom Azure RBAC role from scratch.

## Prerequisites

- Access to an Azure subscription.
- Sufficient permissions to create resource groups and custom RBAC roles.
- Access to the Azure portal.

## Step 1 — Create a Resource Group

1. Open the **Azure Portal**.
    
2. Navigate to **Resource groups**.
    
3. Click **Create**.
    
4. Select the appropriate subscription.
    
5. Enter a resource group name.
    
    Example:
    
    `RBAC-demo`
    
6. Select a region.
    
    > The region is not important for this demonstration, so the default option can be used.
    
7. Click **Review + create**.
    
8. Click **Create**.
    
9. Wait for the resource group to finish deploying.
    
10. Open the newly created resource group.
    

## Step 2 — Open Access Control (IAM)

1. Inside the resource group, select **Access control (IAM)**.
2. Click **Add**.
3. Select **Add custom role**.

This opens the custom role creation wizard.

## Step 3 — Define the Custom Role

Enter the basic information for the role:

- **Custom role name:** For example, `Custom Role Demo`
- **Description:** Add a short description explaining the purpose of the role.
- **Baseline permissions:** Choose how you want to build the role.

Azure provides several ways to create a custom role:

- **Clone an existing role**
    - Owner
    - Contributor
    - Virtual Machine Contributor
    - Other built-in roles
- **Start from scratch**
- **Import a JSON definition**

For this example, choose **Start from scratch** and click **Next**.

## Step 4 — Configure Permissions

The **Permissions** section determines what the custom role is allowed to do.

There are two important concepts:

- **Add permissions** — explicitly grants the selected actions.
- **Exclude permissions** — explicitly prevents specific actions from being included.

By default, permissions are not available to the custom role unless they are explicitly added.

### Add Permissions

1. Click **Add permissions**.
2. Browse or search for the required Azure resource provider.

For example:

1. Search for **Compute**.
2. Select the **Microsoft Compute** resource provider.
3. Review the available permissions.
4. Scroll through the list to find the required actions.
5. Select the permissions you want to include.

Azure indicates the type of permission, such as:

- **Read** — allows viewing resources or information.
- **Write** — allows modifying or creating resources.

Select the required permissions.

6. Click **Add**.

The selected permissions will now appear in your custom role definition.

> **Tip:** Grant only the permissions that are actually required. This helps follow the principle of least privilege.

## Step 5 — Configure the Assignable Scope

1. Click **Next**.
2. Review the **Assignable scopes**.

The assignable scope determines where the custom role can be assigned.

For this demonstration, the scope is the resource group created earlier within the Azure subscription.

3. Click **Next**.

## Step 6 — Review the JSON Definition

Azure automatically generates a **JSON representation** of the custom role based on the permissions you selected.

Review the generated JSON.

From this screen, you can:

- View the role definition.
- Copy the JSON.
- Download the JSON.
- Edit the JSON.

> The JSON is generated from the permissions and scope configured in the previous steps.

Click **Next** when you are satisfied with the definition.

## Step 7 — Review and Create the Role

The final screen displays a summary of the custom role.

Review:

- Role name
- Description
- Permissions
- Assignable scopes
- Role definition

If everything looks correct, click **Create**.

Azure will create the custom RBAC role.

## Step 8 — Verify the Role

After creation, Azure may display a message indicating that the role can take **a few minutes to appear throughout Azure**.

Wait for the role to propagate before attempting to use it elsewhere.

## Final Checklist

- [ ]  Open Azure Portal.
- [ ]  Create or select a resource group.
- [ ]  Open **Access control (IAM)**.
- [ ]  Select **Add → Add custom role**.
- [ ]  Provide a name and description.
- [ ]  Choose **Start from scratch**.
- [ ]  Add the required permissions.
- [ ]  Review the read/write permissions.
- [ ]  Configure the assignable scope.
- [ ]  Review the generated JSON.
- [ ]  Review the final role definition.
- [ ]  Click **Create**.
- [ ]  Allow a few minutes for the role to propagate.

## Key Takeaway

A custom Azure RBAC role is essentially a collection of explicitly defined permissions that can be assigned at specific Azure scopes. The Azure portal provides a guided way to build the role, while also exposing the underlying **JSON role definition** for inspection, copying, downloading, or editing.