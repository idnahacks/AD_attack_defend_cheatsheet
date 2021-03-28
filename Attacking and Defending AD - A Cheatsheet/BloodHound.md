# BloodHound
https://github.com/BloodHoundAD/BloodHound
https://bloodhound.readthedocs.io/en/latest/index.html

BloodHound is an amazing tool to help find weak spots in AD configurations, highlighting paths to Domain Admins using these weak configurations and current session data, as well as many others.

It is recommended to run BloodHound on your attacker machine and run the ingestor on the victim machine. The output of the ingestor should then be transferred back to the attacker machine where the information can be imported and enumerated.

## Installation
### Kali
The following steps show how to install and configure BloodHound and neo4j on Kali Linux. The instructions may also work on other Debian flavours, I've never tried! (https://bloodhound.readthedocs.io/en/latest/installation/linux.html)

 - Install BloodHound and its dependencies:
 `sudo apt-get install bloodhound`
 
  - BloodHound runs on neo4j, so that needs configuring:
`sudo neo4j console`

 - Browse to http://localhost:7474
 - Login using default credentials neo4j:neo4j
 - You will be prompted to change the credentials. Store these securely, you'll need them to run BloodHound in the future

### Windows
https://bloodhound.readthedocs.io/en/latest/installation/windows.html
 - Install Oracle JDK 11 (https://www.oracle.com/java/technologies/javase-jdk11-downloads.html)
 - Download neo4j Community Server Edition zip from https://neo4j.com/download-center/#community
 - Unzip the neo4j file
 - running a command prompt as Adminstrator browse to the unzipped neo4j folder and the bin directory and run
`neo4j.bat install service`
 - Errors relating to Java not being found might require your JAVA\_HOME environment variable is set to the JDK folder (example: C:\\Program Files\\Java\\jdk-11.0.6)
 - Once installed start the database
`net start neo4j`
 - You should see the message, “The neo4j Graph Database - neo4j service was started successfully.”
 - Browse to http://localhost:7474
 - Login using default credentials neo4j:neo4j
 - You will be prompted to change the credentials. Store these securely, you'll need them to run BloodHound in the future
 - Download and unzip the GUI from https://github.com/BloodHoundAD/BloodHound/releases/download/4.0.2/BloodHound-win32-x64.zip

## Running BloodHound
### Kali
- On the attacker machine run
`bloodhound`
 - Login with the neo4j credentials set earlier

### Windows
 - Run bloodhound.exe from the location you extracted the GUI into earlier
 - Login with the neo4j credentials set earlier

## BloodHound Ingestors
On the victim machine run one of the following to get the Ingestors to enumerate the domain and store the information in a format that BloodHound can use:
*Note that the creds are optional if you want to run as the current user. There are also other options below if you want to change shell to one that is a different user.*
- Using exe ingestor
`.\SharpHound.exe --CollectionMethod All --LDAPUser <UserName> --LDAPPass <Password> --JSONFolder <PathToFile>`
 - Using PowerShell ingestor
```
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>
```
 - Take the output and transfer it to your attacker machine and import it into BloodHound and watch it go.

If you're logged in as a local user on the victim machine you can establish a session as a domain user with the following command
`runas /user:<user>@<domain> powershell`
If the machine is not a domain member use the following
`runas /netonly /user:<user>@<domain> powershell`