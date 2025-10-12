## What is Open Redirection?
Open redirection is a web security vulnerability that occurs when a website or web application redirects users to a different URL without proper validation or sanitization of the target URL
### Types 
1. **URL-based open redirection:** This is the most common type of open redirection vulnerability. It occurs when a website takes a URL or a URL parameter as input and uses it in a redirect without proper validation or sanitization. An attacker can craft a malicious URL that includes a different domain or malicious URL as a parameter which will be included in the redirect, leading to an unintended redirection to a malicious website.
2. **JavaScript-based open redirection:** This type of open redirection vulnerability occurs when a website uses JavaScript to perform a redirect, but the target URL is obtained from untrusted or user-controlled sources without proper validation or sanitization. An attacker can manipulate the JavaScript code or input data to execute a malicious redirect to a different domain or URL.
3. **Meta refresh-based open redirection:** This type of open redirection vulnerability occurs when a website uses the HTML "meta refresh" tag to redirect users to another URL automatically, and the target URL is obtained from untrusted or user-controlled sources without proper validation or sanitization. An attacker can manipulate the meta refresh tag or input data to trigger a malicious redirect to a different domain or URL.
4. **Header-based open redirection:** This type of open redirection vulnerability occurs when a website uses HTTP headers, such as "Location" header, to perform a redirect, but the target URL is obtained from untrusted or user-controlled sources without proper validation or sanitization. An attacker can manipulate the header value or input data to trigger a malicious redirect to a different domain or URL.
5. **Parameter-based open redirection:** This type of open redirection vulnerability occurs when a website uses a parameter in the URL or in a form submission as part of the redirect process, but fails to properly validate or sanitize the parameter value. An attacker can manipulate the parameter value to trigger a redirect to a malicious URL.

---
## Detecting Open Redirect Attacks
1. If there is a ==consecutive requests to query string parameters such as ?next (http://website.com/param.php?next=), or ?url ( http://website.com/…?url=), with payloads like http://attacker.com or attacker.com (URL structure)==
2. For the WAF or other middleware products, sometimes payloads can have bypass techniques like;
    1. Localhost
        1. http://[::]:25/
        2. http://①②⑦.⓪.⓪.⓪
    2. CDIR
        1. http://127.0.0.0
    3. Decimal Bypass
        1. http://2130706433/ = http://127.0.0.1
    4. Hexadecimal Bypass
        1. http://0x7f000001/ = http://127.0.0.1
3. Encoded characters like ==%2f = /==
4. Automated detection method 
		`/^.*"GET.*\?.*=(https%3a%2f%2f[a-z0-9-]+%2e[a-z]{2,}).+?.*HTTP\/.*".*$/gm`
### Example 
- Encoded 
![[encoded-open.png]]

- Decoded 
![[decoded-open.png]]

---
## Prevention Methods for Open Redirection

**Validate and sanitize input:** Always validate and sanitize any user-supplied input that is used in the redirection process. This includes URL parameters, form submissions, and any other input that is used in generating redirect URLs. Validate that the input conforms to expected formats, such as valid URLs or whitelisted domains, and sanitize it to remove any malicious or unexpected characters.

**Use a whitelist approach:** Instead of trying to blacklist or filter out specific characters or patterns from user input, it's generally safer to use a whitelist approach where only known and trusted values are allowed. Define a whitelist of trusted domains or URLs to which the application is allowed to redirect, and validate that the user-supplied input matches the whitelist.

**Avoid using user-controlled data in redirects:** Avoid using user-controlled data, such as input from URL parameters or form submissions, directly in the redirect process. If possible, use other means of redirection, such as using HTTP headers or server-side redirects that do not rely on user-controlled data.

**Implement proper authorization and authentication:** Ensure that only authorized users are allowed to trigger redirects. Implement proper authentication and authorization mechanisms to verify the legitimacy of the user and their actions.

**Implement secure coding practices:** Follow secure coding practices, such as using secure coding libraries or frameworks, keeping software up-to-date with the latest security patches, and conducting regular security reviews and vulnerability assessments.

**Educate users about potential risks:** Educate users about the potential risks of clicking on suspicious or unexpected URLs, and encourage them to be cautious when clicking on links from unknown sources or providing personal information on websites.

**Stay informed about web security best practices:** Stay updated with the latest web security best practices and guidelines, such as the OWASP Top Ten Project, and incorporate them into your development processes.

---
