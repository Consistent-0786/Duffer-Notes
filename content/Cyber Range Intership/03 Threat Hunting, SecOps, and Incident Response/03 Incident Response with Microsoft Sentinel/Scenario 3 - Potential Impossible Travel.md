# Detection and Analysis

During analysis , it was discovered that there was only one (1) account flagged for potential impossible travel
Affected Account UPN name : "josh.madakor@gmail.com"

```kql
let _StartTime = datetime(2026-4-10T09:37:00); // Start time : 4/10/2026, 09:37 PM
let _EndTime = datetime(2026-4-17T09:37:00); //End time : 4/17/2026, 09:37 PM
let _ExceedNumberofTravel = 2; 
SigninLogs
| where TimeGenerated between (_StartTime .. _EndTime )
| where ResultSignature == "SUCCESS"
| extend City = tostring(LocationDetails.city) 
        , State = tostring(LocationDetails.state) 
        , Country = tostring(LocationDetails.countryOrRegion)
| project UserPrincipalName , UserType , ResultSignature , City , State , Country
| summarize ImpossibleTravel = count() by UserPrincipalName , Country  
| where ImpossibleTravel > _ExceedNumberofTravel
| sort by ImpossibleTravel desc 
```

---

On observing the account , nothing really alarming 
All logins within 3 hours train ride withing the same country 

```kql
let _StartTime = datetime(2026-4-10T09:37:00); // Start time : 4/10/2026, 09:37 PM
let _EndTime = datetime(2026-4-17T09:37:00); //End time : 4/17/2026, 09:37 PM
SigninLogs
| where TimeGenerated between (_StartTime .. _EndTime )
| where ResultSignature == "SUCCESS"
| extend City = tostring(LocationDetails.city) 
        , State = tostring(LocationDetails.state) 
        , Country = tostring(LocationDetails.countryOrRegion)
| project UserPrincipalName , UserType , ResultSignature , City , State , Country
| where UserPrincipalName == "josh.madakor@gmail.com"
```

---
# Containment

Forced password reset for the affected account
Revoked all active sessions and sign-ins
Required re-authentication with MFA
Temporarily blocked sign-in pending verification of user activity
Reviewed recent sign-in logs and locations for further anomalies

---
# Post Analysis

No further suspicious activity observed after containment; account secured

---
