# Threat Hunt Report (Unauthorized TOR Usage)

## **Detection of Unauthorized TOR Browser Installation and Use on Workstation**

Detection was performed using endpoint telemetry by identifying TOR-related file creation, process execution, and network connections to known TOR ports (9001, 9030, 9050, 9150) and suspicious external nodes.

---

## **Steps Taken**

- Reviewed `DeviceFileEvents` to identify TOR-related artifacts on the endpoint. Detected that user **"ice"** downloaded the TOR browser package:  
    **`C:\Users\ice\Downloads\tor-browser-windows-x86_64-portable-15.0.10.exe`**  
    on **2026-04-22T13:50:58Z** on device **"karan-mde-vm-win"**.
- Identified that the TOR browser was installed using a silent execution command:  
    `"tor-browser-windows-x86_64-portable-15.0.10.exe" /S`, indicating deliberate non-interactive installation to avoid user prompts or detection.
- Observed creation of a suspicious file:  
    **`C:\Users\ice\Desktop\tor-shopping-list.txt.txt`**, suggesting user activity associated with TOR usage.
- Pivoted to `DeviceProcessEvents` and confirmed execution of TOR components. Found that:
    - **`tor.exe`** was executed from the TOR installation directory
    - Parent process: **`firefox.exe`** located at:  
        **`C:\Users\ice\Desktop\tor browser\browser\firefox.exe`**
    - Execution occurred at **2026-04-22T13:52:55Z** under user **"ice"**
- Analyzed command-line arguments and confirmed TOR initialization with standard parameters, including:
    - SOCKS proxy: **127.0.0.1:9150**
    - ControlPort: **9151**
- Investigated `DeviceNetworkEvents` to validate external communication. Identified multiple outbound connections initiated by TOR processes to external IP addresses over ports commonly associated with TOR traffic (9001, 443, 465).
- Observed connections to multiple suspicious domains and IP addresses consistent with TOR entry/relay node behavior and anonymized browsing activity.
- Correlated file, process, and network telemetry across the same device and timeframe to confirm complete TOR usage lifecycle (download → install → execution → network communication).

---

## **Chronological Events**

- **2026-04-22 13:50:58 UTC** – TOR browser installer downloaded to:  
    `C:\Users\ice\Downloads\tor-browser-windows-x86_64-portable-15.0.10.exe`
- **Shortly after download** – Silent installation executed using `/S` flag.
- **Post-installation** – TOR browser components staged under:  
    `C:\Users\ice\Desktop\tor browser\browser\firefox.exe`
- **Post-installation** – Suspicious file created:  
    `C:\Users\ice\Desktop\tor-shopping-list.txt.txt`
- **2026-04-22 13:52:55 UTC** – TOR process execution initiated:
    - `tor.exe` launched via parent process `firefox.exe`
    - TOR configuration enabled SOCKS proxy (127.0.0.1:9150)
- **Following execution** – Multiple outbound connections established to external TOR nodes and suspicious domains over ports **9001, 443, 465**
- **Subsequent activity** – Continued encrypted communication consistent with active TOR browsing sessions

---

## **Summary**

The investigation conclusively identified unauthorized installation and usage of the TOR browser on endpoint **"karan-mde-vm-win"** by user **"ice"**. The user downloaded the TOR installer, executed a silent installation, and launched TOR processes that established anonymized, encrypted connections to external nodes.

The presence of TOR-specific configuration parameters, execution chain (Firefox → TOR), and network communication over known TOR ports confirms intentional use of anonymization techniques to bypass enterprise security controls and potentially access restricted resources.

---

## **Response Taken**

TOR usage was confirmed on endpoint **karan-mde-vm-win**. The device was isolated and the user's direct manager was notified.

---
