# What is a Policy in MDCA ?

- A **policy** in Microsoft Defender for Cloud Apps is a **security rule** that :
	- Watches user and app activity    
	- Checks for risky or unwanted behavior    
	- Takes action automatically when conditions are met    

- **Example :**
	- If a user downloads a large amount of data from Dropbox, **alert the admin or block the activity**

## Policy Management

- Policy management in MDCA lets you **create rules** to :
	- Monitor user activity in cloud apps    
	- Detect risky behavior (e.g., unusual logins, data downloads)    
	- Automatically take action (alert, block, suspend user, require sign-in again)    

 > Think of it as **“if this happens, then do this”** security rules

## Policy Templates

- Policy templates are **pre-built policies** provided by Microsoft to :
	- Quickly protect common scenarios
	- Detect known risks without starting from scratch

- **Examples :**
	- Impossible travel
	- Mass data download
	- Suspicious admin activity
    
> Think of templates as **ready-made security rules** you can enable or customize

---

# Demo : Create a Cloud App Policies -> Policy Template

# To create Policy templates

**Start url:** [https://security.microsoft.com/cloudapps/policies/templates?type=eq(NEW_SERVICE%2CAUDIT)&name=eq(Administrative)&tid=d03d0415-c1c9-4b94-80ad-4bc2a3b7ca98](https://security.microsoft.com/cloudapps/policies/templates?type=eq\(NEW_SERVICE%2CAUDIT\)&name=eq\(Administrative\)&tid=d03d0415-c1c9-4b94-80ad-4bc2a3b7ca98)

**Tab Name:** Policy templates - Microsoft Defender

### Click on the link "Microsoft Defender"
![[Pasted image 20260122203206.png]]


### Click on the button " Cloud apps "
![[Pasted image 20260122203209.png]]


### Click on the button "Policies "
![[Pasted image 20260122203212.png]]


### For this demo , we will click on the link "Policy templates"
![[Pasted image 20260122203215.png]]


### Click on "Administrative activity from a non-corporate IP address Alert when an admin user performs an adminis..."
![[Pasted image 20260122203221.png]]


### Click on the link "Create policy"
![[Pasted image 20260122203225.png]]


**Tab Name:** Create activity policy - Microsoft Defender

### Click on the button "Create"
![[Pasted image 20260122203229.png]]

---

