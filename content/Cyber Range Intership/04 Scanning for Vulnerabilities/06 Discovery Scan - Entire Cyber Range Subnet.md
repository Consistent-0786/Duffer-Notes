### Discovery Scan: Entire Cyber Range Subnet 

- It means scanning a whole network range (subnet) to **find all active devices/assets** (like servers, PCs, routers).
- Tools **Tenable (Host Discovery Scan)** are used to see **what IPs are alive, what ports are open, and what services are running**.

---

### If you find an asset (device) :

1. **Note basic info**
    - IP address
    - Open ports
    - Running services (e.g., web server, SSH)
2. **Identify it**
    - Guess its role (server, user machine, IoT device, etc.)
    - Check hostname or banners if available

---

### How to identify who owns the asset:

- Check **internal records** (asset inventory, CMDB)
- Use **DNS / hostname info**
- Look at **MAC address vendor**
- Ask **network/admin team**
- Check **who is assigned that IP range**

---

### In short:

- Scan → Find devices → Collect info → Match with records → Identify owner

---
