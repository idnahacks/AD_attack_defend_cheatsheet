# Attacking and Defending Active Directory - A Cheatsheet
A list of commands, tools and notes about enumerating and exploiting Active Directory and how to defend against these attacks.

Massive kudos to the following people that I've taken a lot of this from:

S1ckB0y1337 from the awesome cheatsheet here https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet

Nikhal Mittal http://www.labofapenetrationtester.com/ and the course from Pentester Academy.

## Enumeration
This is absolutely key, and you should always come back to this step any time you escalate to a new user or gain access to a new machine.

PowerView makes things a little more easy, but can be picked up by AMSI and therefore might make things a little more noisy in a real engagement if you attempt to bypass this.

### Domain Enumeration
#### PowerView (will need to bypass AMSI)
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
  - Get Password policy (useful for not locking accounts in a brute force or password spray scenario)

`(Get-DomainPolicy)."system access"`
  - Get Kerberos policy (useful for things like Golden Ticket attacks)

`(Get-DomainPolicy)."kerberos policy"`
 
 #### AD Module
 - Get Current Domain
`Get-ADDomain`
 - Get information about a different domain
`Get-ADDomain -Identity <Domain>`
 - Get Domain SID
`(Get-ADDomain).DomainSID`
 - Get Domain Controllers
`Get-ADDomainController`
 - Get Domain Controllers from a different domain
`Get-ADDomainController -Identity <DomainName>`

### User Enumeration
#### Powerview (will need to bypass AMSI)

 - Show all users
 `Get-NetUser`
  - Show a particular user
 `Get-NetUser -SamAccountName <user>`
 `Get-NetUser -Username <user>`
 `Get-NetUser | select cn`
  - Get a list of all properties for users
 `Get-Userproperty`
 - Show the samaccountname field from all users from a specified domain
`Get-netuser -domain <domainName> | select -expandproperty samaccountname`
 - Show last password change
`Get-UserProperty -Properties pwdlastset`
 - Show logon count of a user (handy for detecting decoy or stale accounts)
`Get-UserProperty -Properties logoncount`
 - Search for a string in a user's attribute
`Find-UserField -SearchField Description -SearchTerm "pass"`
`Find-UserField -SearchField Description -SearchTerm "built"`
 - Find users with sessions on a machine
`Get-NetLoggedon -ComputerName <ComputerName>`
 - Enumerate sessions on a machine
`Get-NetSession -ComputerName <ComputerName>`
 - Enumerate the domain to look for user sessions
`Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName`

#### AD Module
 - Show a user's properties
`Get-ADUser -Identity <user> -Properties *`
 - Search for a string in a user's attribute
`Get-ADUser -Filter 'Description -like "*pass*"' -Properties Description | select Name,Description`

`Get-ADUser -Filter 'Description -ne $null' -Properties Description | select Name,Description`
 - Get a list of all properties for users
`Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name`
 - Show the last password set date for users
`Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}`
 - Show users with password not required attribute set
`Get-ADUser -Filter 'PasswordNotRequired -eq $True' -Properties PasswordNotRequired | select Name,PasswordNotRequired`

### Computer Enumeration
#### Powerview (will need to bypass AMSI)
 - List all computer objects in the domain
`Get-NetComputer -Domain <domainName>`
 - Show all properties of computer objects in the domain
`Get-NetComputer -FullData`
 - Enumerate live machines
`Get-Netcomputer -Ping`
 - Look for stale computer objects
`Get-NetComputer -FullData | select dnshostname,lastlogon`
 - Get actively logged on users on a computer (needs local admin rights on the target)
`Get_NetLoggedOn -ComputerName <computername>`
 - Get locally logged on users on a computer (needs remote registry on the target - this is enabled by default on Server OSes)
`Get-LoggedonLocal -ComputerName <computername>`
 - Get the last logged on user on a computer (needs admin rights and remote registry on the target)
`Get-LastLoggedOn -Computername <computername>`

#### AD Module
 - List all computer objects in the domain
`Get-ADComputer -Filter * | select name`
 - Show all properties of computer objects in the domain
`Get-ADComputer -Filter * -Properties *`
 - List all Server 2016 computer objects
`Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem`
 - Enumerate live machines
`Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}`

### Enumerating Groups
#### Powerview (will need to bypass AMSI)
##### Domain Groups
  - Get all groups in the current domain
`Get-NetGroup`
`Get-DomainGroup`
`Get-NetGroup -Domain <targetdomain>`
 - List all groups with admin in the name
`Get-NetGroup *admin*`
`Get-DomainGroup *admin* | select distinguishedname`
 - Get attributes of a group
`Get-NetGroup -GroupName <GroupName> -FullData` 
 - Get group members (**recurse** includes nested group membership)
`Get-NetGroupMember -GroupName "<GroupName>" -Recurse -Domain <DomainName>`
_Built-In Groups are good to check for membership e.g. Remote Desktop Users, Server Operators, Print Operators etc_

 - Domain Admins (members and properties)
`Get-NetGroupMember -GroupName "Domain Admins" -Recurse | select -expandproperty membername`

 - Enterprise Admins (members and properties)
	 - First establish the forest domain name, then query the Enterprise ADmins
`get-netforestdomain -verbose`
`get-netgroupmember -groupname "Enterprise Admins" -domain <forestdomain> -recurse | select -expandproperty membername`
 
 - Get group membership for a user
`Get-NetGroup -Username "<username>"`
##### Local Machine Groups
 - Get local groups on a machine (needs local admin privs)
`Get-NetLocalGroup -ComputerName <computername> -ListGroups`
 - Get members of local groups on a machine (needs local admin privs)
`Get-NetLocalGroup -ComputerName <computername> -Recurse`

#### AD Module
 - Get all groups in the current domains
`Get-ADGroup -Filter * | select Name`
`Get-ADGroup -Filter * -Properties *`
 - List all groups with admin in the name
`Get-ADGroup -Filter 'Name -like "*admin*"' | select Name`
 - Get group members (**recursive** includes nested group membership)
`Get-ADGroupMember -Identity "Domain Admins" -Recursive`
 - Get group membership for a user
`Get-ADPrincipalGroupMembership -Identity <username>`
 
### Enumerating Shares
#### Powerview (will need to bypass AMSI)
 - Get all fileservers in the domain (lots of users log into these, lots of creds available if you can compromise a file server, as well as l00t!)
`Get-NetFileServer`
 - Enumerate Domain Shares
`Find-DomainShare`
`Invoke-ShareFinder`
 - Enumerate Domain Shares the current user has access
`Find-DomainShare -CheckShareAccess`
 - Enumerate "Interesting" Files on accessible shares
`Find-InterestingDomainShareFile -Include *passwords*`
`Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC –Verbose`
`Invoke-FileFinder`
 - Check ACLs for a path
`Get-PathAcl -Path "\\Path\Of\A\Share"`

### Enumerating OUs
#### Powerview (will need to bypass AMSI)
 - To list all the OUs we will use
`Get-NetOU -FullData`
 - To find out what machines are in a particular OU
`Get-NetOU <OUName> | %{Get-NetComputer -ADSPath $_}`

### Enumerating GPOs
It is not possible to enumerate the settings within a GPO from any command line tool. The closest thing is to export RSoP with Get-GPResultantsetOfPolicy.

#### Powerview (will need to bypass AMSI)
 `Get-NetGPO -FullData`
 `Get-NetGPO -GPOname <The GUID of the GPO>`
 `Get-NetGPO | select displayname`
 `Get-NetGPO -ComputerName <computername>`
  - Get GPOs which use Restricted Groups or groups.xml for interesting users (Restricted Groups add domain users to machine local groups via GPO)
 `Get-NetGPOGroup -Verbose`
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

#### Group Policy Module
`Get-GPO -All`
 - Get RSoP report
	 - `Get-GPResultantsetOfPolicy -ReportType Html -Path <outfile>`

### Enumerating ACLs
#### Powerview (will need to bypass AMSI)
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

### Enumerating Forests & Trusts
#### Powerview (will need to bypass AMSI)
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

#### AD Module
 - Enumerate the Domain Trusts
`Get-ADTrust -Filter *`
`Get-ADTrust -Identity <DomainName>`
 - Enumerate Forest trusts
`Get-ADForest`
`Get-ADForest -Identity <ForestName>`
 - List all the domains in the forest
`(Get-ADForest).Domains`

### Enumerating Applocker Policy
#### AD Module 
 - Review Local AppLocker Effective Policy
`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

### BloodHound Ingestors
 - Using exe ingestor
`.\SharpHound.exe --CollectionMethod All --LDAPUser <UserName> --LDAPPass <Password> --JSONFolder <PathToFile>`
 - Using PowerShell ingestor
```
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>
```