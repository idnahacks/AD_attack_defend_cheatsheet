# DSRM
## What is it?
On all Domain Controllers there is a local administrator account called 'Administrator' which was used to originally promote the server to a Domain Controller. This account can be used as a backup if the server ever needs to be booted into Directory Services Restore Mode.

## How can you use it?
If you know the DSRM account password, or its NTLM hash, you can enable it for use with a registry change and then login to the DC as that account with administrator privileges.

## Why would you use it?
It is very unlikely that the DSRM password is getting changed regularly. This can give a very long persistence time.