## Directory Traversal Possible Vectors
1. **User input:** Attackers can manipulate user input parameters, such as URLs, file paths, and form fields, to access files outside of the intended directory. This can be done by adding "../" or other special characters to the input.
2. **Cookies:** If a web application stores user data in cookies, attackers can try to manipulate the cookie value to access files outside of the intended directory.
3. **HTTP headers:** Attackers can manipulate HTTP headers, such as the Referer or User-Agent header, to access files outside of the intended directory.
4. **File upload:** If a web application allows file uploads, attackers can upload malicious files that contain directory traversal attacks.
5. **Direct requests:** Attackers can try to access files and directories directly by guessing or brute-forcing the file names or paths.
6. **URL manipulation:** Attackers can try to manipulate the URL of a web application to access files outside of the intended directory. For example, they can add "/../" to the URL to go up one directory level.
7. **Malicious links:** Attackers can send users malicious links that contain directory traversal attacks. When the user clicks on the link, the attack is executed on their computer.

---
## Detecting Directory Traversal Attacks
![[img5.png]]
- These are really basic payloads for directory traversal attacks. So, we should keep in mind ../ (dot dot slash), encoded and double encoded ../ is the key values for this attack type. Here is the basic example for detecting these payloads on nginx access.log file;
		`/^.*"GET.*\?.*=(%2e%2e%2f).+?.*HTTP\/.*".*$/gm`

- As a bypass technique, attackers may also use unicode encode characters to bypass WAF or any other product.
![[img7-1.png]]

- In that case, Nginx access log will be like;
![[img8.png]]

- Payloads for the Directory Traversal attacks
**Linux**                      
/etc/issue
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts

**Windows**	
c:/boot.ini
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf

![[directory-log.png]]

---
## Prevention Methods for Directory Traversal Attacks
**Input validation and sanitization:** Validate and sanitize all user input, especially the file paths and the directory names. This can involve using regular expressions or other methods to check the input for valid characters, and to limit the input to known values or directories.

**Access controls:** Limit the web server's access to only the files and directories required for the application to function. Use file the system permissions and access controls to restrict access to sensitive files and directories.

**Relative file paths:** Use relative file paths instead of absolute paths whenever possible. This can prevent attackers from using the "../" character to navigate up to higher-level directories.

**Whitelisting:** Use a whitelist approach where only specific characters are allowed in the file name parameter. This can be done using a validation library or a custom validation function.

**Secure coding practices:** Use secure coding practices, such as avoiding the use of user input directly in file path concatenation, using secure file upload mechanisms, and avoiding the use of insecure functions like eval() and system().

**Web application firewall:** Use a web application firewall (WAF) to detect and block directory traversal attacks. WAFs can analyze incoming traffic for malicious requests and prevent attacks from reaching the web application.

---
