# Security Descriptors
## What is this?
A useful and very silent persistence backdoor to implant once you already have Domain Admin privileges is to modify the ACL associated with a remote access mechanism eg. WMI or PowerShell Remoting.

It should be noted that the account that is granted the permissions to remote onto the server does not gain elevated privileges, however even low privileged access can be useful.

You can use the privileges to modify keys to the registry which can unlock access to machine and local user account hashes (and then use these with a silver ticket attack) and domain cached credentials using the DAMP toolkit. 