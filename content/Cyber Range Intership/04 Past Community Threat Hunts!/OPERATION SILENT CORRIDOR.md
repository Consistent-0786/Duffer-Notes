During the investigation of the incident **OPERATION SILENT CORRIDOR** , it was discovered that on `2026-02-23 09:41:59 UTC`, the user `HALDRIC\s.brandt` on device `WS-ENG04` successfully initiated a TCP network connection using `WMIC.exe` from local IP `10.1.36.210:51000` to remote IP `10.1.31.206:53891`.

```kql
// Base filter. Use this at the top of every query.
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where todatetime(EventTime) between (datetime(2026-02-20T00:00:00) .. datetime(2026-03-06T00:00:00))
| where MdeTable == "DeviceNetworkEvents" 
| where InitiatingProcessFileName == "WMIC.exe" 
| project EventTime , DeviceName , InitiatingProcessAccountDomain , InitiatingProcessAccountName , ActionType , RemoteIP , RemotePort , LocalIP , LocalPort , Protocol , InitiatingProcessFileName  
| sort by EventTime asc
```

![[Pasted image 20260510175617.png]]

---

