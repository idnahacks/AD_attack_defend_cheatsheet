# Privilege Escalation

## User Hunting
### Powerview (will need to bypass AMSI)
 - Find all machines in the current domain where the current user has local admin access
`Find-LocalAdminAccess -Verbose`
 - Find local admins on all machines of the domain:
`Invoke-EnumerateLocalAdmin -Verbose`
 - Find computers where a Domain Admin (default option) OR a specified user has a session
```
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```
 - The above are very noisy, so a stealth flag can be added. This just checks for high value targets to reduce noise.
`Invoke-UserHunter -Stealth`

 - Confirm admin access
`Invoke-UserHunter -CheckAccess`

## Admin Access enumeration
You can look to see where else your current user has local admin access. This might give you access to a machine where a higher priveleged user has a session

 - Powerview has
`Find-LocalAdminAccess`
 - Nishang (https://github.com/samratashok/nishang) has
`Find-PSRemotingLocalAdminAccess`
 - With WMI
`Find-WMILocalAdminAccess`
 - Or
`Invoke-CheckLocalAdminAcess`