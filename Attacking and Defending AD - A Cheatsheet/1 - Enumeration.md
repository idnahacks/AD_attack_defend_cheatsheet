# Enumeration
This is absolutely key, and you should always come back to this step any time you escalate to a new user or gain access to a new machine.

PowerView makes things a little more easy, but can be picked up by AMSI and therefore might make things a little more noisy in a real engagement if you attempt to bypass this.

## Domain Enumeration
### PowerView (will need to bypass AMSI)
 - Get Current Domain
`Get-NetDomain`
 - Get information about a different domain
`Get-NetDomain -Domain <DomainName>`
 - Get Domain SID
`Get-DomainSID`
 - Get Domain Controllers
`Get-NetDomainController`
`Get-NetDomainController -Domain <DomainName>`
 - Get Domain Policies
 `Get-DomainPolicy`
  - Get Password policy
 `(Get-DomainPolicy)."system access"`
  - Get Kerberos policy
 `(Get-DomainPolicy)."kerberos policy"`
 
 ### AD Module
 - Get Current Domain
`Get-ADDomain`
 - Get information about a different domain
`Get-ADDomain -Identity <Domain>`
 - Get Domain SID
`Get-DomainSID`
 - Get Domain Controllers
`Get-ADDomainController`
 - Get Domain Controllers from a different domain
`Get-ADDomainController -Identity <DomainName>`

## Review all users
### Powerview (will need to bypass AMSI)

 - Show all users
 `Get-NetUser`
  - Show a particular user
 `Get-NetUser -SamAccountName <user>`
 `Get-NetUser | select cn`
 `Get-Userproperty`
 - Show the samaccountname field from all users from a specified domain
`Get-netuser -domain <domainName> | select -expandproperty samaccountname`
 - Show last password change
`Get-UserProperty -Properties pwdlastset`
 - Search for a string in a user's attribute
`Find-UserField -SearchField Description -SearchTerm "wtver"`
 - Find users with sessions on a machine
`Get-NetLoggedon -ComputerName <ComputerName>`
 - Enumerate sessions on a machine
`Get-NetSession -ComputerName <ComputerName>`
 - Enumerate the domain to look for user sessions
`Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName`

### AD Module
 - Show a user's properties
`Get-ADUser -Filter * -Identity <user> -Properties *`
 - Search for a string in a user's attribute
`Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description`

## Review all computers
### Powerview (will need to bypass AMSI)
`get-netcomputer -domain <domainName>`
`Get-NetComputer -FullData`
`Get-DomainGroup`

 - Enumerate live machines
`Get-Netcomputer -Ping`

### AD Module
`Get-ADComputer -Filter * -Properties *`

## Groups
### Powerview (will need to bypass AMSI)
 - Get group members
`Get-NetGroupMember -GroupName "<GroupName>" -Domain <DomainName>`
_Built-In Groups are good to check for membership e.g. Remote Desktop Users, Server Operators, Print Operators etc_

 - Get attributes of a group
`Get-NetGroup -GroupName <GroupName> -FullData`

 - Domain Admins (members and properties)
`get-netgroupmember -groupname "Domain Admins" -recurse | select -expandproperty membername`

`Get-DomainGroup -Identity <GroupName> | Select-Object -ExpandProperty Member`

Enterprise Admins (members and properties)
 - First establish the forest domain name
`get-netforestdomain -verbose`

 - Then query the Enterprise Admins
`get-netgroupmember -groupname "Enterprise Admins" -domain <forestdomain> -recurse | select -expandproperty membername`

### AD Module
`Get-ADGroup -Filter * `

## Shares
### Powerview (will need to bypass AMSI)
 - Enumerate Domain Shares
`Find-DomainShare`
 - Enumerate Domain Shares the current user has access
`Find-DomainShare -CheckShareAccess`
 - Enumerate "Interesting" Files on accessible shares
`Find-InterestingDomainShareFile -Include *passwords*`
`Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC –Verbose`
 - Check ACLs for a path
`Get-PathAcl -Path "\\Path\Of\A\Share"`

## OUs
### Powerview (will need to bypass AMSI)
 - To list all the OUs we will use
`Get-NetOU -FullData`
 - To find out what machines are in a particular OU
`Get-NetOU <OUName> | %{Get-NetComputer -ADSPath $_}`

## GPOs
### Powerview (will need to bypass AMSI)
 `Get-NetGPO -FullData`
 `Get-NetGPO -GPOname <The GUID of the GPO>`
 `get-netgpogroup -verbose`
  - List GPOs assigned to an OU
```
$adspath = (get-netou studentmachines -fulldata).gplink
Get-NetGPO -ADSpath '$adspath'
```
 - FInd users that are part of a machines's local admins group
 `Find-GPOComputerAdmin -ComputerName <ComputerName>`
 - Returns all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
`Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName`
 - Enumerate GPOs where a specified user or group has interesting permissions
`Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}  | ?{$_.IdentityReference -match "<user>"}`

## ACLs
### Powerview (will need to bypass AMSI)
 - Return the ACLs associated with the specified account
`Get-ObjectAcl -SamAccountName <AccountName> -ResolveGUIDs`
`Get-ObjectAcl -ADSprefix 'CN=Administrator, CN=Users' -Verbose`
 - Return ACLs for the Domain Admins group
`Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs`
 - Return ACLs for the Users group, just displaying the ActiveDirectoryRights field
`Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs | select -expandproperty IdentityReference ActiveDirectoryRights`
 - Enumerate ACLs for all GPOs
`Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}`
 - Search for interesting ACEs
`Invoke-ACLScanner -ResolveGUIDs`
 - Check ACLs for a path
`Get-PathAcl -Path "\\Path\Of\A\Share"`
 - Enumerate GPOs where a specified user or group has interesting permissions
`Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}  | ?{$_.IdentityReference -match "<user>"}`
 - Check for modify rights/permissions for a specified user or group
`Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "<user>"}`

## Forests & Trusts
### Powerview (will need to bypass AMSI)
 - Enumerate all domains in the forest
`Get-NetForestDomain`
`Get-NetForestDomain Forest <ForestName>`
 - Map the Trusts in the forest
`Get-NetForestTrust`
`Get-NetForestTrust -Forest <ForestName>`
`Get-NetDomainTrust`
`Get-NetForestDomain -Verbose | Get-NetDomainTrust`
 - List External Trusts
`Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}`
`Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}`

### AD Module
 - Enumerate the Domain Trusts
`Get-ADTrust -Filter *`
`Get-ADTrust -Identity <DomainName>`
 - Enumerate Forest trusts
`Get-ADForest`
`Get-ADForest -Identity <ForestName>`
 - List all the domains in the forest
`(Get-ADForest).Domains`

## Applocker
### AD Module 
 - Review Local AppLocker Effective Policy
`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

## User Hunting
### Powerview (will need to bypass AMSI)
 - Find all machines in the current domain where the current user has local admin access
`Find-LocalAdminAccess -Verbose`
 - Find local admins on all machines of the domain:
`Invoke-EnumerateLocalAdmin -Verbose`
 - Find computers were a Domain Admin OR a specified user has a session
```
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -Stealth
```
 - Confirm admin access
`Invoke-UserHunter -CheckAccess`

## BloodHound Ingestors
 - Using exe ingestor
`.\SharpHound.exe --CollectionMethod All --LDAPUser <UserName> --LDAPPass <Password> --JSONFolder <PathToFile>`
 - Using PowerShell ingestor
```
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>
```