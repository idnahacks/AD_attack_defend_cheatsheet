# Pass the hash
A pass the hash attack uses the NTLM hash of an account to authenticate **locally**. e.g. you can use pass the hash to authenticate against a target machine's local administrator account.

# Over Pass the hash
Over pass the hash takes the NTLM hash of the target user, wraps it up in a token and then presents this to the DC to generate a valid Kerberos ticket and authenticate.


