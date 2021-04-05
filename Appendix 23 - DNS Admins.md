# DNS Admins
## How it works
Members of the DNSAdmins group can load arbitrary DLLs with SYSTEM privileges on the DNS server. Domain Controllers are frequently running as DNS servers.

## How can this be abused?
If you can compromise a member of DNSAdmins you can escalate privileges to DA by loading a malicious DLL onto the DC.

The DNS service would need to be restarted, and so the compromised user would either need permissions to do this, or you could wait until the next restart.

Loading something like mimilib.dll to log local logons would be better than running a reverse shell in the dll. This is because a reverse shell would stop the DNS service from starting fully and therefore all DNS queries would fail while the shell was active, meaning it would likely get detected.