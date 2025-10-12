# DCSync Attack
The DCSync attack is a technique used in post-exploitation scenarios in order to extract sensitive data from an AD domain by abusing the AD replication feature, which determines how Domain 
Controllers synchronize data between themselves

```example
DC1 <----> DC2
```

The DCSync attack tricks a Domain Controller into thinking the attacker is another legitimate DC that needs replication data

The replication data pulled with this attack includes also :
- NTLM password hashes (including krbtgt)
- Kerberos keys
- Password history

This means that DCSync can be combined with other attacks, such as the Golden Ticket attack, to establish persistence into a domain :
- [[Ticket Forging Attacks]]
