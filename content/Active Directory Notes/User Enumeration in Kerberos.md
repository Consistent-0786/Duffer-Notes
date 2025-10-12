# User Enumeration

`User Enumeration' happens when it is possible to determine valid  
usernames on a system that implements an authentication mechanism.

```
Authentication Request (username, password) -----> Authenticator
```

This happens when the system showcases different behavior based on  
whether a username exists in the underlying data store or not.

Typical situations that allow for user enumeration:

- **Different error messages**
    

```
username does not exist --> Invalid username  
username does exist     --> Invalid password
```

- **Timing differences**
    

```
username does not exist --> less code --> faster response  
username does exist     --> more code --> slower response
```

---

## User Enumeration in Kerberos

In Kerberos it is possible to enumerate valid users by observing the  
following facts:

- If pre-authentication is disabled for a given user, then by  
    initiating an auth request with a valid username, the KDC will reply  
    with a valid `AS-REP' message.
    
- If pre-authentication is enabled for a given user, by default the  
    KDC will respond with different messages depending if the username  
    exists or not:
    
    - `KRB5KDC_ERR_PREAUTH_REQUIRED'  
        If pre-auth is required and the user exists
        
    - `KRB5KDC_ERR_C_PRINCIPAL_UNKNOW'  
        If the user does not exist
        

---

To actually perform such attack in practice you can use many different  
tools, such as:

- [kerbrute on GitHub](https://github.com/ropnop/kerbrute)  
    A tool to quickly bruteforce and enumerate valid Active Directory  
    accounts through Kerberos Pre-Authentication
    
- [Rubeus](https://github.com/GhostPack/Rubeus)  
    Rubeus is a C# toolset for raw Kerberos interaction and abuses.
    
- [GetNPUsers.py - Impacket](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)  
    This script will attempt to list and get TGTs for those users that  
    have the property 'Do not require Kerberos preauthentication' set  
    (UF_DONT_REQUIRE_PREAUTH).
    

---

## Practical Example

The following powershell script will create 5 random users taken from  
a list of 100.

```powershell
$users = 1..100 | ForEach-Object { "user$_" }
$iterations = 5
for ($i = 0; $i -lt $iterations; $i++) {
    $randomUser = $users | Get-Random
    
    $samAccountName = $randomUser
    $userPrincipalName = "$randomUser@hexdump.lab"
    $givenName = "User"
    $surname = $randomUser
    $password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
    
    New-ADUser -SamAccountName $samAccountName -UserPrincipalName $userPrincipalName -GivenName $givenName -Surname $surname -Name $randomUser -AccountPassword $password -Enabled $true -PassThru    
}
```

Let's now see how it is possible to enumerate them. First, let's  
generate the list of users:

```bash
touch users.txt

for i in {1..100}; do
    echo "user$i" >> users.txt
done
```

---

First let's install `kerbrute`:

```bash
go install github.com/ropnop/kerbrute@latest
```

We can use the following modules:

```
bruteforce    Bruteforce username:password combos, from a file or stdin  
bruteuser     Bruteforce a single user's password from a wordlist  
passwordspray Test a single password against a list of users  
userenum      Enumerate valid domain usernames via Kerberos
```

To enumerate usernames we can use the `userenum` module:

```bash
~/go/bin/kerbrute userenum -d hexdump.lab --dc dc1.hexdump.lab users.txt
```

---

Delete the created usernames:

```powershell
$usersToDelete = @("user3", "user50", "user70", "user81", "user85")
foreach ($user in $usersToDelete) {
    Remove-ADUser -Identity $user -Confirm:$false
}
```

---

## Possible Remediations

To reduce the risk of user enumeration you can set a limit on the  
number of unsuccessful logins before locking out the account.

```
Computer Configuration -> Policies  
                       -> Windows Settings  
                       -> Security Settings  
                       -> Account Policies  
                       -> Account Lockout Policy.
```

You can configure the following values:

- `Account lockout threshold`  
    This security setting determines the number of failed logon attempts  
    that causes a user account to be locked out. A locked-out account  
    cannot be used until it is reset by an administrator or until the  
    lockout duration for the account has expired.
    
- `Account lockout duration`  
    This security setting determines the number of minutes a locked-out  
    account remains locked out before automatically becoming unlocked.
    
- `Reset account lockout counter after`  
    This security setting determines the number of minutes that must  
    elapse after a failed logon attempt before the failed logon attempt  
    counter is reset to 0 bad logon attempts.
    

---

Finally, make sure that `pre-authentication` is enabled by default for  
every user to avoid `AS-REP` roasting attacks.

- [Roasting Attacks on Kerberos](https://www.youtube.com/watch?v=fVTZEIZIEqg)
    

---
