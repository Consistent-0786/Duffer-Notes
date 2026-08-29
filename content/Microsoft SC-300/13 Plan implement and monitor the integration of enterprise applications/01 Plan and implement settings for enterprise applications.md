# Application Identities in Entra ID

## What Is an Application Identity?
- A way to give **applications** (not humans, not managed Azure resources) their own identity in Entra ID so they can authenticate.
- Applications can reside **anywhere**: on-premises, in Azure, or in other hyperscalers (e.g., AWS, GCP) - not limited to Azure-hosted apps.

---

## How It Works: App Registration
- To give an application an identity in your Entra ID tenant, you perform an **App Registration**.
- App Registration = giving the application an identity within your Entra ID tenant.
- Once registered, you decide how the application will authenticate:
  - Via a **secret**
  - Via a **certificate**

---

## What the Identity Can Be Used For
- Once the app has an identity, it can authenticate to other resources, such as:
  - A virtual machine in Azure
  - A SQL database
  - A storage account
  - On-premises resources
- Because the app now has an Entra ID identity, it can also leverage Entra ID features like **Conditional Access**.

---

## Key Considerations
- The application does NOT need to be an Azure application - it can be on-premises or hosted in any cloud.
- The application must be **registered** (via App Registration) before it can interact with an identity and access other resources.
- Authentication method choice: **secret** or **certificate**.

---

## Quick Review / Flashcard Candidates
- What process gives an application an identity in Entra ID? -> App Registration
- Does the application need to be hosted in Azure to get an Entra ID identity? -> No, it can be on-premises or in any cloud
- What are the two authentication options for an application identity? -> Secret or certificate
- What Entra ID feature can an application identity leverage once registered? -> Conditional Access
- What must happen before an app can authenticate to other resources using its identity? -> It must first be registered via App Registration