## What is Local File Inclusion (LFI)?
Local File Inclusion (LFI), is the security vulnerability that occurs when a file is included without sanitizing the data obtained from a user. It differs from RFI because the file that is intended to be included is on the ==same web server that the web application is hosted on==.

Attackers can read sensitive files on the web server, they can see the files containing passwords that would allow them to access the server remotely.

## What is Remote File Inclusion (RFI)?
Remote File Inclusion (RFI) is a vulnerability that occurs when a file is included without sanitizing the data received from a user. It differs from LFI because the included file is ==hosted on another server==.

Attackers lure victims through websites on remote servers and trick them into running malicious code on the servers they have prepared.

---
## How does LFI & RFI work?
RFI and LFI vulnerabilities arise when ==data received from a user is used directly in the system or to include a file on a remote server==

![[local-file-inclusion-code-example.png]]
- The code given below selects the website language using a `language` parameter from the user. Normally, input like `en` results in a safe file path like:
```url
website/en/home.php
```

- However, an attacker can exploit this by passing a payload such as:
```bash
`/../../../../../../../../../etc/passwd%00`
```

- This causes the path to resolve as:
```url
website//../../../../../../../../../etc/passwd%00/home.php
```

The `"../"` traverses directories up to the root, and `%00` (null byte) truncates the rest, preventing `"home.php"` from being processed. As a result, the server includes `/etc/passwd`, exposing sensitive system data.

---
## Detecting LFI & RFI Attacks
- **When examining a web request from a user, examine all fields.**
- **Look for any special characters:** Within the data received from users, look for notations such as ***'/', `.`, `\`.***
- **Become familiar with files commonly used in LFI attacks:** In an LFI attack, the attacker reads the files on the server. Knowing the critical file names on the server will help you detect LFI attacks.
- **Look for acronyms such as HTTP and HTTPS:** In RFI attacks, the attacker injects the file into their own device and allows the file to run.
- To host a file, attackers usually set up a **small web server** on their own device and display the file using an HTTP protocol. You should therefore look for notations such as 'http' and 'https' to help you detect RFI attacks.

---

