## What is XML External Entity?
XML (Extensible Markup Language) is a markup language that is used for structuring and storing data in a structured format that is both human-readable and machine-readable. XML was developed as a successor to HTML (Hypertext Markup Language) and is widely used for data exchange between different systems and platforms, particularly on the web.

While XML was once widely used for a variety of purposes, its usage has declined in recent years as newer data formats like JSON have gained popularity with its simplicity, ease of use, and better support for modern web technologies.

XXE (XML External Entity) vulnerability is a type of security vulnerability that affects applications that parse XML input. In an XXE attack, an attacker injects malicious XML data into an application that uses an XML parser without proper validation, which can result in the application processing external entities that can be controlled by the attacker.

---
## XML External Entity Possible Vectors
1. Form fields that accept XML input
2. XML files uploaded by users
3. APIs that accept XML requests
4. XML files used for configuration or other purposes

---
## Detecting XML External Entity Attacks
 - The most important things to detect XXE attacks on the logs, you should check specific keyword like:
	- **DOCTYPE**
	- **ELEMENT**
	- **ENTITY**
So for the detecting !DOCTYPE keyword in nginx logs, we can use regex like;
```
^(\S+) - (\S+) \[(.*?)\] "(\S+) (.*?)\?(?=.*?\b21DOCTYPE\b).*? HTTP\/\d\.\d" (\d+) (\d+) "(.*?)" "(.*?)"
```

1. **Basic XXE Payload**
![[img7.png]]

2. **Blind XXE Payload**
![[img8.png]]

3. **XXE Payload with PHP Filter**
![[img9.png]]

### Example 
- Nginx log might look like when an XXE attack occurs via a vulnerable parameter on a GET request (This methodology is the same as analyzing POST requests)
![[img10.png]]

---
## Prevention Methods for XML External Entity
**Disable external entities:** One of the most effective ways to prevent XXE attacks is to disable the processing of external entities in the XML parser configuration. This can be done by setting the appropriate parser configuration or using a secure XML parser that has external entity processing disabled by default.

**Input validation and sanitization:** Always validate and sanitize all XML input before parsing it. This includes checking for malicious input such as nested XML entities, XML injections, and other forms of malicious input.

**Use secure parsers:** Use the latest version of a secure XML parser that has been specifically designed to prevent XXE attacks. These parsers have features that can help detect and prevent XXE attacks.

**Use whitelist filtering:** Implementing a whitelist of allowed entities and DTDs can help reduce the risk of XXE attacks by blocking any input that is not on the whitelist.

**Implement access controls:** Implement proper access controls to restrict access to sensitive data and resources. This can help limit the damage in case an XXE vulnerability is exploited.

**Use secure coding practices:** Use secure coding practices, such as input validation, data sanitization, and error handling, to minimize the risk of XXE attacks.

---
