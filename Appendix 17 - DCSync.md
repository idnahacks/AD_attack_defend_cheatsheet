# DCSync
## What is it?
The DCSync attack is something that can be used if a user has the rights to Replicate Directory Changes for the domain.
This privilege can be abused to extract the hashes from the domain.

## When can it be used?
If your account has Replication rights, it's possible that this could be used to get access to user hashes of a more privileged account.

This method could also be used for persistence by providing the krbtgt hash for use in a Golden Ticket attack.