## What are Command Injection Attacks?
Command injection attacks are attacks that occur when data received from a user is not sanitized and is passed directly to the operating system shell.

---
## How does Command Injection work?
Suppose we have a basic web application that copies the user's file to the **"/tmp"** folder. 
The web application code is shown below:
![[web-application-code-example.png]]
Under normal circumstances, if used correctly, the application will work normally. 
For example, *if we upload a file called "letsdefend.txt", it will successfully copy the file to the "/tmp" folder*.

So what if we upload a ==File== called **"letsdefend;ls;.txt"** 
The command would be:

- Command: **cp letsdefend;ls;.txt**

The ";" indicates that the command has ended. So if we look at the payload above, there are three different commands that the operating system executes. These are:
	``1. cp letsdefend``
	``2. ls``
	``3. .txt``

---
## Detecting Command Injection Attacks
- **When examining a web request, look at all areas:** The command injection vulnerability may be in different areas depending on how the web application works. Therefore, you should check all areas of the web request.
- **Look for keywords related to the terminal language:** Check the data received from the user for keywords related to terminal commands such as ==dir, ls, cp, cat, type==, etc.
- **Learn about commonly used command injection payloads:** When attackers discover a command injection vulnerability, they usually create a ==reverse shell== to make their work easier. Therefore, knowing commonly used command injection payloads will make it easier to detect a command injection attack.
### Example
- Its a Shellshock Vulnerability detected in 2014 
- Look at the **User-Agent** field request executing Bash command
```Http request
> GET / HTTP/1.1
> Host: yourcompany.com
> User-Agent: () { :;}; echo "NS:" $(</etc/passwd)
> Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
> Accept-Encoding: gzip, deflate
> Accept-Language: en-US,en;q=0.9
> Connection: close
```

---
## How to Prevent Command Injection
- **Always sanitize data you receive from a user:** Never trust anything you receive from a user. Not even a file name!
- **Limit user privileges:** Whenever possible, set web application user rights at a lower level. Few web applications require users to have administrator rights. 
- **Use virtualization technologies such as dockers.**

---
