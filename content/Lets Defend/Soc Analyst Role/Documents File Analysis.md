# 📄 Document File Analysis

---

## 🔹 Simple Static File Analysis

---

### 1️⃣ Generate File Hashes (MD5 & SHA-256)

```bash
md5sum file-name
sha256sum file-name
```

---

### 2️⃣ Check Hash Reputation (Malware Detection)

Upload the hash or file to:

- 🌐 **VirusTotal**
    
    ```text
    https://virustotal.com
    ```
    

---

### 3️⃣ Extract File Metadata using **ExifTool**

```bash
exiftool file-name
```

✔ Useful for:

- Author details
    
- Creation/modification time
    
- Embedded metadata
    

---

### 4️⃣ Extract Readable Strings using **strings**

```bash
strings file-name
```

🔍 Look for:

- IP addresses
    
- URLs / domains
    
- Suspicious file paths
    
- Hardcoded commands or payloads
    

---

### 5️⃣ Detect Encrypted Strings using **xorsearch**

```bash
xorsearch file-name format
```

📌 Example formats:

- `http`
    
- `url`
    
- `cmd`
    

---

## 🔹 Advanced Static File Analysis — Part 1

---

### 📦 Requirements

Install **oletools** before proceeding:

```bash
sudo -H pip install -U oletools
```

---

### 1️⃣ Extract OLE Metadata using **olemeta**

```bash
olemeta file-name
```

✔ Displays:

- Author
    
- Timestamps
    
- Application details
    

---

### 2️⃣ Detect Malicious Indicators using **oleid**

```bash
oleid file-name
```

🚩 Identifies:

- VBA macros
    
- Embedded objects
    
- Suspicious features
    

---

### 3️⃣ Analyze VBA Macros using **olevba**

```bash
olevba file-name
```

✨ Highlights:

- Auto-execution keywords
    
- Suspicious functions
    
- Encoded/obfuscated strings
    

---

## 🔹 Advanced Static File Analysis — Part 2

---

### 1️⃣ Extract VBA Code from `.doc` File

```bash
olevba file.doc > file.vba
```

---

### 2️⃣ Decode / De-obfuscate VBA Code

```bash
olevba --deobf --reveal file.vba > file_deobf.vba
```

✔ Makes analysis easier by revealing hidden logic.

---

### 3️⃣ Open De-obfuscated VBA in VS Code

```bash
code file_deobf.vba
```

🧠 Manually analyze:

- URLs
    
- PowerShell commands
    
- File drop locations
    

---

### 4️⃣ Clean VBA Script (Important Step)

- Open `file.vba`
    
- ❌ Delete everything **except valid VBScript**
    
- 💾 Save as:
    

```text
file01.vba
```

📺 Reference Video:

```text
https://youtu.be/ym6Crrn-D2c?t=776
```

---

### 5️⃣ Analyze VBA Behavior using **vmonkey**

```bash
vmonkey file01.vba
```

⚠ Runs the macro logic **safely** without executing malware.

---

## 🔹 Sandbox Analysis

---

### 🧪 Online Sandbox Platforms

Use these for **dynamic analysis**:

- 🔬 Hybrid Analysis
    
- 🦠 VirusTotal
    
- ▶ ANY.RUN
    
- 🧪 Joe Sandbox
    

✔ Observe:

- Network activity
    
- Process creation
    
- File drops
    
- Command execution
    

---
