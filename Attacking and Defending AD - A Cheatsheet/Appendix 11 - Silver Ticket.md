# Silver Ticket
## What is it?
If you already have the NTLM hash of the target service you can perform a Silver Ticket attack by directly providing the TGS to the application server.

If you have the hash of the target service you can access it as any user, including a domain administrator.

While technically a Persistence technique, there are circumstances that might present privilege escalation routes.

## How does it work?
Because services rarely check the Privileged Attribute Certificate (PAC) you can impersonate any user when presenting the valid TGS to the application server.

## Why would you do it?
This will give you access to some services on a single machine. As you can impersonate a privileged user with a Silver Ticket attack you might be able to access sensitive information or run commands that you couldn't before.

It is very quiet and hard to detect and can therefore be preferable to a Golden Ticket, however the persistence is less by default.

Services that can be useful for silver tickets are:
 - HOST (allows you to create and run scheduled tasks)
 - WMI (allows you to run remote commands)
 - CIFS (allows you to read fileshares)