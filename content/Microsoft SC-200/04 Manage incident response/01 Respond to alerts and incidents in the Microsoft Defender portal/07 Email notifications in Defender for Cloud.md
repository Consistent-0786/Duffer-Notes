# Email notifications in Defender for Cloud

- Defender for Cloud allows you to configure **email notifications** for recommendations and security alerts
- This helps ensure the right people are informed when security issues occur
## Who can receive emails ?

You can define recipients in two ways :
- **By role :**    
    - Subscription Owner        
    - Account Admin        
    - Service Admin        
    - Contributor      

- **By email address :**    
    - Manually specify one or more email addresses        
    - Not tied to Azure roles

## What notifications can be sent ?

- You can choose the **minimum alert severity :**    
    - Low        
    - Medium        
    - High        

- Severity selection works like this :
	- Selecting **Low** sends Low Medium and High alerts
	- Selecting **Medium** sends Medium and High alerts
	- Selecting **High** sends only High alerts

## How often emails are sent ?

- Alerts are **grouped** and not sent individually    
- Email frequency depends on severity :    
    - High severity alerts → one email every **6 hours**        
    - Medium severity alerts → one email every **12 hours*      
    - Low severity alerts → one email every **24 hours**

---

