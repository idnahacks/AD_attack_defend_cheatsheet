# Custom SSP
## What is this?
A Security Support Provider (SSP) is a DLL which provides ways for an application to obtain an authenticated connection.

e.g.
 - NTLM
 - Kerberos
 - Wdigest
 - CredSSP

## How can it be abused?
Mimikatz provides a DLL called mimilib.dll which is a custom SSP which captures local logons, service accounts and machine accounts in clear text in a log file.

Once you have Domain Admin privileges it can be injected into LSASS or it can be loaded by dropping mimilib.dll to the system32 directory on the domain controller and adjusting the registry to load this new Custom SSP.

All local logons are then captured in c:\windows\system32\kiwissp.log. However as this path already requires local admin privileges this method of persistence is useless out of the box and just serves as a PoC.
You could edit the mimilib source code to change the path to something that only your unprivileged user can read. 