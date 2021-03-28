# Local Privilege Escalation
Once you've established a connection to a target machine, you may need to escalate to Administrator, or another local user.
Getting Administrative privileges can enable you to do things such as switch off AV, install tools and services, as well as grab credentials from other user's with local sessions straight out of memory. All the good stuff basically.

## PowerUp
https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc
`. .\PowerUp.ps1`
There are many more options available inside PowerUp than are listed below. It's advised to read the ReadMe above for the latest information and functions.

### Running all privilege escalation checks
PowerUp can run through its list of escalation vectors and check if any are possible on the machine
`Invoke-AllChecks`

### Automatic
PowerUp can also automate the process
`Invoke-PrivEsc`

### Service misconfiguration abuse
- Find local services that are configured with unquoted whitespace. This weak configuration allows us to inject a malicious process into the path.
`Get-ServiceUnquoted`
 - To take advantage of this we need to be able to write to the path. PowerUp allows us to easily check for this.
`Get-ModifiableService`
 - The abuse function adds our current user to the local Administrators group. It will also restore the abused service back to its original state to try to avoid detection
`Invoke-ServiceAbuse -Name '<servicename>' -UserName '<usertoescalate>'`
 - Log off and on again to get local admin

## BeRoot
https://github.com/AlessandroZ/BeRoot
 - Run BeRoot.exe

## Admin Access enumeration
You can look to see where else your current user has local admin access using the following
 - Powerview has
`Find-LocalAdminAccess`
 - Nishang (https://github.com/samratashok/nishang) has
`Find-PSRemotingLocalAdminAccess`
 - With WMI
`Find-WMILocalAdminAccess`
 - Or
`Invoke-CheckLocalAdminAcess`

## Confirming Admin access
 - Confirm admin access with PowerView
`Invoke-UserHunter -CheckAccess`



