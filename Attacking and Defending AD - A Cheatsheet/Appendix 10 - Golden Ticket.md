# Golden Ticket
## What is it?
A Golden Ticket attack is performed by forging the TGT ticket  that is sent to the Domain Controller as part of the TGS-REQ Kerberos authentication process.

## How does it work?
It works because the only validation the KDC performs at this stage is that if it can decrypt the incoming TGT (e.g. it was originally encrypted using the krbtgt hash). If you know the krbtgt hash, you can forge the TGT.

This attack will also work for deleted users for up to 20 minutes as the Domain Controller doesn't perform account validation until the TGT is older than 20 minutes. So if we create a TGT using the Golden Ticket attack we can impersonate deleted/revoked users.

## When would it be performed
If you have access to the krbtgt NTLM hash you can use this ticket to impersonate any user e.g. a Domain Admin.
As you would normally need Domain Admin to get the krbtgt hash in the first place this is generally used as a persistence mechanism.

## How to remediate?
The krbtgt password needs to be changed twice in order to remediate this, to overwrite the password history.