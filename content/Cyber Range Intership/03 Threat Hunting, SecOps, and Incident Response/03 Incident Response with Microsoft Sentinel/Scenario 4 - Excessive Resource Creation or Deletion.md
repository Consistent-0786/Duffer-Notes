# Detection and Analysis

During the investigation of "Excessive Resource Creation or Deletion" incident , 
Investigation revealed 705 successful delete operations performed by caller `ef669d55-9245-4118-8ba7-f78e3e7d0212` from IP `52.143.192.11` within a short timeframe. 
No write operations were observed. Further analysis is ongoing to determine the resource types affected, behavioral patterns, and whether this activity aligns with historical usage or represents anomalous behavior.

``` kql
let _Exceed_Limit = 5;
let _TimeRange = 7d;
AzureActivity
| where TimeGenerated >= ago(_TimeRange)
| where ActivityStatusValue == "Success"
| where OperationNameValue endswith "WRITE" or OperationNameValue endswith "DELETE"
| where OperationNameValue !contains "MICROSOFT.SECURITYINSIGHTS/INCIDENTS"
| where OperationNameValue !contains "MICROSOFT.SECURITYINSIGHTS/ALERTRULES"
| extend OperationType = case(
    OperationNameValue endswith "write", "Write",
    OperationNameValue endswith "delete", "Delete",
    "Other"
)
| summarize OperationCount = count(), 
            WriteCount = countif(OperationType == "Write"),
            DeleteCount = countif(OperationType == "Delete")
    by Caller , CallerIpAddress 
| where OperationCount >= _Exceed_Limit
| sort by OperationCount desc
```

---

705 delete operations were performed on `MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE` within the resource group `STUDENT-RG-CE3B556210FE46CB1EA83705DECBAC7CD66690FC7F43C3604DCF837F7E16F1E0`. 
Such deletions are consistent with bulk resource cleanup, potentially triggered by virtual machine or resource group deletion. Additional validation is being performed to confirm whether this activity aligns with expected behavior.

```kql
let _TimeRange = 7d;
AzureActivity
|where TimeGenerated >= ago(_TimeRange)
| where Caller == "ef669d55-9245-4118-8ba7-f78e3e7d0212"
| where ActivityStatusValue == "Success"
| where OperationNameValue endswith "delete"
| summarize Count = count() by Caller , ResourceGroup, OperationNameValue, ResourceId, ResourceProviderValue 
| sort by Count
```

---

To find the identity, i checked Entra id (Enterprise Applications) , and found that caller "ef669d55-9245-4118-8ba7-f78e3e7d0212"  is linked with a automated script named "Azure Traffic Manager and DNS" 

---

# Containment

- No containment required - activity matches approved admin automation for resource cleanup
- Confirmed with admin team that this script is not malicious but still continue monitor for any unusual behavior

---

# Post Analysis

- Activity confirmed as legitimate admin automation for resource cleanup.
- No indicators of compromise or malicious intent observed.
- Behavior aligns with expected bulk deletion patterns.
- Monitoring will continue to ensure consistency with normal operations.

---

