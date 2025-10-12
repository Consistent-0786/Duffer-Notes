## Types of SQL Injections 
1. **In-band SQLi (Classic SQLi)**: When an SQL query is sent and responded to on the same channel, we call this in-band SQLi. This is easier for attackers to exploit than other categories of SQLi.

2. **Inferential SQLi (Blind SQLi):** SQL queries that receive a response that cannot be seen are called Inferential SQLi. They are also called "Blind SQLi" because the response cannot be seen.

3. **Out-of-band SQLi**: If the response to an SQL query is communicated through another channel, this type of SQLi is called "out-of-band SQLi". For example, if the attacker receives replies to the SQL queries via DNS, this is called out-of-band SQLi.d SQLi.

---
## ## What Attackers Gain from SQL Injection Attacks
- Authentication bypass
- Command execution
- Exfiltration of sensitive data
- Creating/Deleting/Updating database entries

---
## Detecting SQL Injection Attacks
- **When examining a web request, check all areas that come from the user:** As SQL injection attacks are not limited to the form areas, you should also check the HTTP request headers such as the "User-Agent".
- **Look for SQL keywords:** Look for words such as =="INSERT", "SELECT", and "WHERE"== in the data received from users.
- **Check any special characters:** Look for ==apostrophes ('), dashes (-), or parentheses== used in SQL or special characters commonly used in SQL attacks in the data received from the user.
- **Familiarise yourself with commonly used SQL injection payloads:** Although SQL payloads change depending on the web application, attackers still use some common payloads to test for SQL injection vulnerabilities. If you are familiar with these payloads, you can easily detect SQL injection payloads. You can find some commonly used SQL injection payloads [==here==](https://github.com/payloadbox/sql-injection-payload-list).
## Detecting Automated SQL Injection Tools
Attackers use many automated tools to detect SQL injection vulnerabilities. One of the well-known tools is Sqlmap. However, let's look at the bigger picture rather than focusing on one particular tool.

You can use the following methods to detect SQL injection tools:

1. **Look at the User-Agent:** Automated tools usually have their names and versions recorded. You can look at the ==User-Agent== to detect these automated tools.
  
2. **Check the frequency of requests:** Automated tools are designed to send an estimated number of requests per second to test payloads as quickly as possible. A normal user might send 1 request per second, so looking at the number of requests per second will tell you if the requests are from an automated tool or not.
  
3. **Look at the content of the payload:** Automated tools usually include their own names in their payloads. For example, an SQL injection payload sent by an automated tool might look like this: ==sqlmap’ OR 1=1==
  
4. **If the payload is complicated:** This detection method may not always work, but based on my experience I could say that automated tools send more complicated payloads.


---
## How to Prevent SQL Injections
- **Use a framework:** Of course, just using a framework is not enough to prevent a SQL injection attack. However, it is still very important to use the framework according to the documentation.
- **Keep your framework up to date:** Keep your web application secure by following security updates according to the framework you use.
- **Always sanitize data received from a user:** Never trust data received from a user. In addition, sanitize all data (such as headers, URLs, etc.), not just form data.
- **Avoid the use of raw SQL queries:** You may be in the habit of writing raw SQL queries, but you should take advantage of the security provided by the framework.

---
