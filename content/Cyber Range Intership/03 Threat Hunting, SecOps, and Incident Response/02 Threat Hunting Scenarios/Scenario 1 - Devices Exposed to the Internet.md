# My Report for the Incident

- windows-target- is Internet Facing for several days :

```

DeviceInfo

| where DeviceName startswith "windows-target-" and IsInternetFacing == "1"

| sort by Timestamp desc

```

- Last Internet Facing Timestamp :

```

Apr 12, 2026 8:24:43 AM

```

---

- Several bad actors has been discovered for attempting login to target machine :

  

```

DeviceLogonEvents

| where DeviceName startswith "windows-target-"

| where LogonType has_any ("Network","Interactive" , "RemoteInteractive" , "Unlock")

| where ActionType == "LogonFailed"

| summarize Failed_Login_Attempts_Count = count() by  ActionType , RemoteIP ,LogonType, DeviceName

```
![[Pasted image 20260414174422.png|564]]
 

---

- No Successful logon has been made by the listed bad actors ip-address to the target machine within (7-days period):

```

let _Remoteip = dynamic(["94.26.68.55", "216.122.172.240","94.26.68.54","79.127.147.207","192.24.230.115","80.94.95.166","27.102.138.102"]);

DeviceLogonEvents

| where DeviceName startswith "windows-target-"

| where ActionType == "LogonSuccess"

| where RemoteIP has_any (_Remoteip)

| summarize Count = count() by ActionType , DeviceName

| sort by Timestamp desc

```

```

< No Output data >

```

---

- The target machine has not been accessed by the legitimate machine host user-name (labuser) since 30-days :

```

DeviceLogonEvents

| where DeviceName startswith "windows-target-"

| where ActionType == "LogonSuccess"

| sort by Timestamp desc

```

```

< No Output data >

```

---

- As there are zero(0) login made by the labuser account so there are no chance of unusual or unexpected location login attempt discovered

- As there were zero(0) login attempts made by the labuser account so there are no chances of brute-force or account taken over attacks

---

Conclusion :

- Though the device was exposed to the Internet and clear brute-force attempts has been taken ,

there are no sign's of brute-force success and unauthorized access for the legitimate "labuser" account
