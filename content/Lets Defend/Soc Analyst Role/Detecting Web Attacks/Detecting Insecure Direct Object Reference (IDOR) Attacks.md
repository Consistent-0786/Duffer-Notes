
## What is IDOR?
**I**nsecure **D**irect **O**bject **R**eference (IDOR) is a vulnerability caused by the absence or improper use of an authorization mechanism. It allows one person to access an object that belongs to another.

---
## Detecting IDOR Attacks
- **Check all parameters:** An IDOR vulnerability can occur in any parameter. Therefore, do not forget to check all parameters.
- **Look at the number of requests made to the same page:** When attackers discover an IDOR vulnerability, they usually want to access the information of all the other users, so they typically perform a ==brute-force attack==. This is why you may see many requests for the same page from one source.
- **Try to find a pattern:** Attackers will plan a brute-force attack to reach all objects. Since they will be performing the attack on successive and predictable values, such as whole numbers, you can try to find a pattern in the requests you see. For example, if you see requests like ==id=1, id=2, id=3==, you might be suspicious.
### Example 
- It retrieves the “**id”** variable from the user and then displays data that belongs to the user who made the request
```url
> Change the id parameter to view other user details
URL: https://letsdefend.io/get_user_information?id=1 
```

---
## How to Prevent IDOR
- Always check that the person making the request is authorized to provide a secure environment without an IDOR vulnerability.
- In addition, unnecessary parameters should be removed and only the minimum number of parameters should be taken from the user. If we think about the previous example, we don't need to get the "id" parameter. Instead of getting the "id" parameter from the user, we can use the session information to identify the person who made the request.

---
