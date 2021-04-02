# Skeleton Key
## What is it?
This is a persistence technique that injects a skeletong key into the LSASS process on a DC which allows any valid user to be accessed across the domain with the skeleton key password.

It is not persistent across reboots.

It requires Domain Admin privileges to be run.

It is not replicated across DCs. You need to authenticate against the DC with the skeleton key injected.