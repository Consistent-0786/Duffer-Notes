# Copilot for Security – Authentication & RBAC

## 1. Authentication

- Uses **“on behalf of” authentication**    
    - Copilot acts **as the user** to access security data via plugins        
    - For eg = Prompting Copilot to access Sentinel → uses **your permissions**        
- **User licenses matter**: Copilot cannot access services if **you lack a license**

## 2. Copilot for Security Roles

- **Roles must be assigned** to access Copilot (embedded or standalone)    
- Current roles :    
    1. **Copilot Owner** → full access, manage plugins, settings        
    2. **Copilot Contributor** → run prompts and prompt books, limited management
        
- Roles control :    
    - **Plugin availability** (depends on your access)        
    - **Actions**: configure settings, assign permissions, run commands
    
- Copilot roles are **distinct from Microsoft internal roles**    
    - Only control Copilot features

## 3. Microsoft Roles (Entra & Azure)

- **Microsoft Entra Roles** (Identity/AD)    
    - Security Administrator / Global Administrator → inherit **Copilot Owner** access automatically        
    - Other roles (e.g., Reader) → limited access
    
- **Azure RBAC Roles**
    
    - Control **access to Azure resources**, e.g., security capacity units        
    - Separate from Copilot platform roles

## 4. Role-Based Permissions Summary

|Action|Copilot Owner|Copilot Contributor|Security Admin|Global Reader|
|---|---|---|---|---|
|Run Prompt|✅|✅|✅|✅|
|Run Prompt Books|✅|✅|✅|✅|
|Manage Plugins|✅|❌|✅|❌|
|Configure Settings|✅|❌|✅|❌|

> **In Simple :** 
>- Copilot **cannot exceed your access rights**    
  >  - It only acts **on behalf of your user**        
  >  - Cannot access resources or services you are not authorized for
> - Each plugin may have **specific role and license requirements**

---
