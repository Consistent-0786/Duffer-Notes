## Types of XSS
Cross-site scripting (XSS) is a type of injection-based web security vulnerability that can be incorporated into legitimate web applications, allowing malicious code to be executed.
- Types 
	1. **Reflected XSS (Non-Persistent)**: This is a non-persistent type of XSS where the XSS payload must be present in the request. It is the most common type of XSS.
	2. **Stored XSS (Persistent)**: This type of XSS is where the attacker can permanently upload the XSS payload to the web application. Compared to other types, Stored XSS is the most dangerous type of XSS.
	3. **DOM Based XSS**: DOM Based XSS is an XSS attack where the attack payload is executed as a result of modifying the DOM "environment" in the victim's browser used by the original client-side script so that the client-side code runs in an "unexpected" manner. (OWASP)

---
## How Attackers Take Advantage of XSS Attacks
- Steal a user’s session information
- Capture credentials

---
## Detecting XSS Attacks
- **Look for keywords:** The easiest way to detect XSS attacks is to look for keywords such as =="alert" and "script"== that are commonly used in XSS payloads.
- **Learn about commonly used XSS payloads:** Attackers tend to use the same payloads to look for vulnerabilities before exploiting an XSS vulnerability. Therefore, familiarizing yourself with commonly used XSS payloads would make it easier for you to detect XSS vulnerabilities. You can examine some commonly used payloads [==here==](https://github.com/payloadbox/xss-payload-list).
- **Check for the use of special characters:** Check data coming from a user to see if any special characters commonly used in XSS payloads, such as ==greater than (>) or less than (<)==, are present
### Example 
To redirect the user to a malicious site [google.com]
- Payload 
		``<script>window.location=’https://google.com’</script>``
-  In-Url 
		``https://letsdefend.io/xss_example.php?user=%3Cscript%3Ewindow.location=%27https://google.com%27%3C/script%3E``

---
## How to Prevent a XSS Vulnerability
- **Sanitize data coming from a user:** Never trust data that you receive from a user. If user data needs to be processed and stored, it should first be encoded with "HTML Encoding" using special characters, only then can it be stored.
- **Use a framework:** Most frameworks come with preventative measures against XSS attacks.
- **Use the framework correctly:** Almost all frameworks used to develop web applications come with a sanitation feature, but if this is not used properly, there is still a chance for XSS vulnerabilities to occur.
- **Keep your framework up-to-date:** Frameworks are developed by humans, so they too can contain XSS vulnerabilities. However, these types of vulnerabilities are usually patched with security updates. You should therefore make sure that you have completed the security updates for your framework on a regular basis.

---
